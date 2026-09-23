from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import os
import shutil
import socket
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from .collectors.auth import collect_auth
from .collectors.audit import collect_audit
from .collectors.host import (
    account_change_events,
    account_snapshot,
    file_change_events,
    file_snapshot,
    process_snapshot,
    suspicious_process_events,
)
from .collectors.kernel import collect_kernel
from .collectors.network import collect_network
from .config import Settings
from .db import EventStore
from .decision import (
    DecisionProvider,
    JevDecisionProvider,
    LocalDecisionProvider,
    OpenAICompatibleDecisionProvider,
    OpenRouterJevDecisionProvider,
)
from .models import Decision, SecurityEvent


SEVERITY_RANK = {
    "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


class MonitoringService:
    def __init__(self, store: EventStore, settings: Settings):
        self.store = store
        self.local = LocalDecisionProvider()
        self.provider = build_provider(settings)
        self.ai_max_per_hour = settings.ai_max_per_hour
        self.ai_max_per_day = settings.ai_max_per_day
        self.ai_min_severity = (
            settings.ai_min_severity if settings.ai_min_severity in SEVERITY_RANK else "high"
        )
        self.ai_cooldown_seconds = settings.ai_cooldown_seconds
        self.allowed_listeners = settings.allowed_listeners
        self.last_auth_check = time.time() - 60
        self.errors: dict[str, str] = {}
        self.running = False

    @property
    def last_error(self) -> str | None:
        return "; ".join(f"{key}: {value}" for key, value in self.errors.items()) or None

    def capabilities(self) -> dict[str, object]:
        return {
            "journal": shutil.which("journalctl") is not None,
            "procfs": os.path.isdir("/proc/net"),
            "file_integrity": True,
            "account_monitoring": True,
            "process_monitoring": True,
            "auditd_available": shutil.which("ausearch") is not None,
            "audit_log_readable": os.access("/var/log/audit/audit.log", os.R_OK),
            "ai_calls_last_hour": self._budget_counts()[0],
            "ai_calls_last_day": self._budget_counts()[1],
            "ai_max_per_hour": self.ai_max_per_hour,
            "ai_max_per_day": self.ai_max_per_day,
            "ai_min_severity": self.ai_min_severity,
            "ai_cooldown_seconds": self.ai_cooldown_seconds,
        }

    def ingest(
        self, event: SecurityEvent, prefer_ai: bool = True, correlate: bool = True
    ) -> int | None:
        event.host = socket.gethostname()
        event_id = self.store.add_event(event)
        if event_id is None:
            return None
        decision = self._decide(event, prefer_ai and self._should_use_ai(event))
        self.store.add_decision(event_id, decision)
        if correlate:
            self._correlate(event)
        return event_id

    def _decide(self, event: SecurityEvent, use_ai: bool) -> Decision:
        if use_ai and self.provider.name != "local-rules":
            blocked_reason = self._reserve_ai_call(event)
            if blocked_reason:
                decision = self.local.decide(event)
                decision.rationale += f" External AI skipped: {blocked_reason}."
                return decision
            try:
                decision = self.provider.decide(self._event_for_ai(event))
                self.errors.pop("ai", None)
                return self._enforce_severity_floor(event, decision)
            except RuntimeError as error:
                self.errors["ai"] = str(error)
                decision = self.local.decide(event)
                decision.rationale += " The configured AI provider was unavailable."
                return decision
        return self.local.decide(event)

    def _budget_counts(self) -> tuple[int, int]:
        now = time.time()
        state, attempts = self._load_ai_budget(now)
        return sum(item >= now - 3600 for item in attempts), len(attempts)

    def _load_ai_budget(self, now: float) -> tuple[dict, list[float]]:
        state = self.store.get_state("ai_budget", {})
        source = (
            state.get("attempts", [])
            if state.get("initialized")
            else self.store.recent_external_call_timestamps()
        )
        attempts = [float(item) for item in source if now - float(item) < 86400]
        return state, attempts

    def _reserve_ai_call(self, event: SecurityEvent) -> str | None:
        now = time.time()
        state, attempts = self._load_ai_budget(now)
        subjects = {
            str(key): float(value) for key, value in state.get("subjects", {}).items()
            if now - float(value) < max(self.ai_cooldown_seconds, 86400)
        }
        hourly = sum(item >= now - 3600 for item in attempts)
        subject = self._ai_subject(event)
        state = {"initialized": True, "attempts": attempts, "subjects": subjects}
        self.store.set_state("ai_budget", state)
        if self.ai_max_per_hour <= 0 or hourly >= self.ai_max_per_hour:
            return "hourly budget reached"
        if self.ai_max_per_day <= 0 or len(attempts) >= self.ai_max_per_day:
            return "daily budget reached"
        if now - subjects.get(subject, 0) < self.ai_cooldown_seconds:
            return "cooldown for an equivalent incident"
        attempts.append(now)
        subjects[subject] = now
        self.store.set_state("ai_budget", {
            "initialized": True, "attempts": attempts, "subjects": subjects,
        })
        return None

    @staticmethod
    def _ai_subject(event: SecurityEvent) -> str:
        evidence = event.evidence
        stable = {
            "event_type": event.event_type, "actor": event.actor,
            "source_ip": event.source_ip, "destination_ip": event.destination_ip,
            "destination_port": event.destination_port, "process": event.process,
            "path": evidence.get("path") or evidence.get("persistence_path"),
            "executable": evidence.get("executable"),
        }
        return hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @staticmethod
    def _enforce_severity_floor(event: SecurityEvent, decision: Decision) -> Decision:
        overridden = False
        if SEVERITY_RANK.get(decision.severity, 0) < SEVERITY_RANK[event.severity]:
            decision.severity = event.severity
            overridden = True
        if event.severity in {"high", "critical"}:
            if decision.classification == "benign":
                decision.classification = "suspicious"
                overridden = True
            if decision.recommended_action in {"record", "monitor"}:
                decision.recommended_action = "investigate"
                overridden = True
            decision.requires_human_review = True
        if overridden:
            decision.rationale += " Local policy preserved the deterministic risk floor."
        return decision

    @staticmethod
    def _event_for_ai(event: SecurityEvent) -> SecurityEvent:
        sensitive_names = {"message", "raw", "command_line", "command"}

        def clean(value, key: str = ""):
            lowered = key.lower()
            if key in sensitive_names or any(
                marker in lowered for marker in ("password", "secret", "token", "api_key", "cookie")
            ):
                return "[redacted]"
            if isinstance(value, dict):
                return {str(k): clean(v, str(k)) for k, v in value.items()}
            if isinstance(value, list):
                return [clean(item, key) for item in value[:50]]
            if isinstance(value, str):
                return value[:1000]
            return value

        return replace(event, evidence=clean(event.evidence))

    def _should_use_ai(self, event: SecurityEvent) -> bool:
        return SEVERITY_RANK[event.severity] >= SEVERITY_RANK[self.ai_min_severity]

    def _correlate(self, event: SecurityEvent) -> None:
        if event.category == "persistence" and event.event_type.startswith("file_"):
            self._correlate_persistence(event)
            return
        if event.event_type == "firewall_packet_blocked":
            self._correlate_firewall(event)
            return
        if event.event_type not in {"ssh_login_failed", "ssh_login_succeeded"}:
            return
        try:
            observed = datetime.fromisoformat(event.observed_at)
        except ValueError:
            observed = datetime.now(UTC)
        cutoff = (observed - timedelta(minutes=5)).isoformat()
        failures = self.store.recent_events(
            "ssh_login_failed", event.source_ip, event.actor, cutoff
        )
        if event.event_type == "ssh_login_failed" and len(failures) == 3:
            incident = SecurityEvent(
                source="correlator", category="incident", event_type="ssh_bruteforce",
                summary=(
                    f"Possible SSH brute force: {len(failures)} failures for "
                    f"{event.actor} from {event.source_ip}"
                ), severity="high", observed_at=event.observed_at,
                actor=event.actor, source_ip=event.source_ip,
                evidence={
                    "failure_count": len(failures), "window_seconds": 300,
                    "related_event_ids": [row["id"] for row in failures],
                },
            )
            self.ingest(incident, correlate=False)
        if event.event_type == "ssh_login_succeeded" and failures:
            incident = SecurityEvent(
                source="correlator", category="incident",
                event_type="ssh_failures_then_success",
                summary=(
                    f"SSH login succeeded after {len(failures)} failures for "
                    f"{event.actor} from {event.source_ip}"
                ), severity="critical", observed_at=event.observed_at,
                actor=event.actor, source_ip=event.source_ip,
                evidence={
                    "failure_count": len(failures), "window_seconds": 300,
                    "related_event_ids": [row["id"] for row in failures],
                },
            )
            self.ingest(incident, correlate=False)

    def _correlate_persistence(self, event: SecurityEvent) -> None:
        try:
            observed = datetime.fromisoformat(event.observed_at)
        except ValueError:
            observed = datetime.now(UTC)
        recent_privilege = self.store.recent_event_types(
            ("sudo_command", "su_session_opened"),
            (observed - timedelta(minutes=10)).isoformat(),
        )
        if not recent_privilege:
            return
        incident = SecurityEvent(
            source="correlator", category="incident",
            event_type="privilege_then_persistence",
            summary="Persistence changed shortly after privileged activity",
            severity="high", observed_at=event.observed_at,
            evidence={
                "persistence_path": event.evidence.get("path"),
                "privilege_event_ids": [row["id"] for row in recent_privilege[-10:]],
                "window_seconds": 600,
            },
        )
        self.ingest(incident, correlate=False)

    def _correlate_firewall(self, event: SecurityEvent) -> None:
        if not event.source_ip:
            return
        try:
            observed = datetime.fromisoformat(event.observed_at)
        except ValueError:
            observed = datetime.now(UTC)
        blocked = self.store.recent_events(
            "firewall_packet_blocked", event.source_ip, None,
            (observed - timedelta(minutes=5)).isoformat(),
        )
        ports = {row["destination_port"] for row in blocked if row["destination_port"]}
        if len(ports) != 10:
            return
        incident = SecurityEvent(
            source="correlator", category="incident", event_type="port_scan",
            summary=f"Possible port scan from {event.source_ip}: 10 blocked ports",
            severity="high", observed_at=event.observed_at, source_ip=event.source_ip,
            evidence={
                "blocked_ports": sorted(ports), "window_seconds": 300,
                "related_event_ids": [row["id"] for row in blocked[-50:]],
            },
        )
        self.ingest(incident, correlate=False)

    def collect_once(self) -> int:
        count = 0
        network_events = collect_network()
        for event in network_events:
            if self.ingest(event) is not None:
                count += 1
        count += self._correlate_new_listeners(network_events)

        cursor = self.store.get_state("journal_cursor")
        events, error, new_cursor = collect_auth(self.last_auth_check, cursor)
        self.last_auth_check = time.time()
        if error:
            self.errors["journal"] = error
        else:
            self.errors.pop("journal", None)
            if new_cursor:
                self.store.set_state("journal_cursor", new_cursor)
        for event in events:
            if self.ingest(event) is not None:
                count += 1

        kernel_cursor = self.store.get_state("kernel_journal_cursor")
        kernel_events, kernel_error, new_kernel_cursor = collect_kernel(
            self.last_auth_check - 60, kernel_cursor
        )
        if kernel_error:
            self.errors["kernel_journal"] = kernel_error
        else:
            self.errors.pop("kernel_journal", None)
            if new_kernel_cursor:
                self.store.set_state("kernel_journal_cursor", new_kernel_cursor)
        for event in kernel_events:
            if self.ingest(event) is not None:
                count += 1

        count += self._collect_host_changes()
        count += self._collect_audit()
        return count

    def _collect_audit(self) -> int:
        path = "/var/log/audit/audit.log"
        if not os.access(path, os.R_OK):
            return 0
        previous = self.store.get_state("audit_state", {})
        events, current, error = collect_audit(previous)
        if error:
            self.errors["auditd"] = error
            return 0
        self.errors.pop("auditd", None)
        self.store.set_state("audit_state", current)
        count = 0
        for event in events:
            if self.ingest(event) is not None:
                count += 1
        return count

    def _correlate_new_listeners(self, events: list[SecurityEvent]) -> int:
        listeners = [event for event in events if event.event_type == "listening_port"]
        current = {
            f"{event.evidence.get('protocol')}|{event.destination_ip}|"
            f"{event.destination_port}|{event.evidence.get('executable')}": event.to_dict()
            for event in listeners
        }
        previous = self.store.get_state("listener_snapshot", {})
        self.store.set_state("listener_snapshot", current)
        if not previous:
            return 0
        count = 0
        for key in set(current) - set(previous):
            item = current[key]
            evidence = item["evidence"]
            executable = str(evidence.get("executable") or "")
            protocol = str(evidence.get("protocol") or "").removesuffix("6")
            risky = (
                item["destination_port"] in {4444, 5555, 6667}
                or executable.startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))
                or executable.endswith(" (deleted)")
            )
            if self._listener_allowed(protocol, item["destination_port"], item.get("process")):
                continue
            if protocol == "udp" and item["destination_port"] > 1024 and not risky:
                continue
            incident = SecurityEvent(
                source="correlator", category="incident",
                event_type="new_listening_port",
                summary=(
                    f"New listening port {item['destination_port']} opened by "
                    f"{item.get('process') or 'an unknown process'}"
                ), severity="high" if risky else "medium",
                destination_ip=item["destination_ip"],
                destination_port=item["destination_port"],
                process=item.get("process"), evidence={
                    **evidence, "baseline_key": key,
                },
            )
            if self.ingest(incident, correlate=False) is not None:
                count += 1
        return count

    def _listener_allowed(
        self, protocol: str, port: int | None, process: str | None
    ) -> bool:
        if port is None:
            return False
        for rule in self.allowed_listeners:
            parts = rule.split(":", 2)
            if len(parts) != 3:
                continue
            rule_protocol, rule_port, process_pattern = parts
            if rule_protocol == protocol and rule_port == str(port) and fnmatch.fnmatch(
                process or "", process_pattern
            ):
                return True
        return False

    def _collect_host_changes(self) -> int:
        count = 0
        collectors = (
            ("file_snapshot", file_snapshot, file_change_events),
            ("account_snapshot", account_snapshot, account_change_events),
            ("process_snapshot", process_snapshot, suspicious_process_events),
        )
        for state_key, snapshot_function, event_function in collectors:
            try:
                previous = self.store.get_state(state_key, {})
                current = snapshot_function()
                events = event_function(previous, current)
                self.store.set_state(state_key, current)
                self.errors.pop(state_key, None)
                for event in events:
                    if self.ingest(event) is not None:
                        count += 1
            except (OSError, ValueError) as error:
                self.errors[state_key] = str(error)
        return count

    async def run(self, interval: float) -> None:
        self.running = True
        while self.running:
            try:
                await asyncio.to_thread(self.collect_once)
                self.errors.pop("service", None)
            except Exception as error:  # keep collection alive and expose the failure
                self.errors["service"] = f"{type(error).__name__}: {error}"
            await asyncio.sleep(interval)

    def stop(self) -> None:
        self.running = False


def build_provider(settings: Settings) -> DecisionProvider:
    provider = settings.ai_provider
    if provider == "local":
        return LocalDecisionProvider()
    if provider == "jev":
        if not settings.typesafe_api_key:
            raise ValueError("TYPESAFE_API_KEY is required when AI provider is jev")
        return JevDecisionProvider(settings.typesafe_api_key, settings.jev_model)
    if provider == "openrouter":
        if not settings.openrouter_api_key or not settings.openrouter_model:
            raise ValueError(
                "OPENROUTER_API_KEY and OPENROUTER_MODEL are required for OpenRouter"
            )
        normalized_model = settings.openrouter_model.removeprefix("~")
        if normalized_model.startswith("typesafe/jev-"):
            return OpenRouterJevDecisionProvider(
                settings.openrouter_api_key, settings.openrouter_model
            )
        return OpenAICompatibleDecisionProvider(
            settings.openrouter_api_key, settings.openrouter_model,
            "https://openrouter.ai/api/v1", "openrouter",
        )
    if provider == "openai-compatible":
        if not settings.ai_base_url or not settings.ai_model:
            raise ValueError("AI_BASE_URL and AI_MODEL are required")
        return OpenAICompatibleDecisionProvider(
            settings.ai_api_key, settings.ai_model,
            settings.ai_base_url, "openai-compatible",
        )
    raise ValueError(f"Unknown JEVGUARD_AI_PROVIDER: {provider}")


def seed_demo(service: MonitoringService) -> int:
    examples = [
        SecurityEvent(
            source="demo", category="authentication", event_type="ssh_login_failed",
            summary="Repeated SSH login failures for admin",
            severity="medium", actor="admin", source_ip="203.0.113.42",
            evidence={"attempts": 8, "window_seconds": 90, "demo": True},
        ),
        SecurityEvent(
            source="demo", category="network", event_type="listening_port",
            summary="New TCP listener on port 4444",
            severity="high", destination_ip="0.0.0.0", destination_port=4444,
            process="unknown", evidence={"protocol": "tcp", "state": "listen", "demo": True},
        ),
        SecurityEvent(
            source="demo", category="privilege", event_type="sudo_command",
            summary="Sudo command executed by developer",
            severity="medium", actor="developer", process="sudo",
            evidence={"command": "/usr/bin/systemctl status ssh", "demo": True},
        ),
        SecurityEvent(
            source="demo", category="persistence", event_type="file_created",
            summary="New cron entry launches a script from /tmp",
            severity="high", actor="www-data", process="cron",
            evidence={"path": "/etc/cron.d/update", "target": "/tmp/update.sh", "demo": True},
        ),
    ]
    return sum(service.ingest(event, prefer_ai=False) is not None for event in examples)
