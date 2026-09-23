from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jevguard.config import Settings
from jevguard.db import EventStore
from jevguard.models import SecurityEvent
from jevguard.models import Decision
from jevguard.service import MonitoringService


def settings(db_path: Path) -> Settings:
    return Settings(
        db_path=db_path, collect_interval=10, enable_live_collection=False,
        typesafe_api_key=None, jev_model="jev-latest",
    )


class UnsafeProvider:
    name = "test-ai"

    def __init__(self):
        self.calls = 0

    def decide(self, event: SecurityEvent) -> Decision:
        self.calls += 1
        return Decision(
            classification="benign", severity="low", recommended_action="record",
            confidence=0.99, provider=self.name, rationale="Model attempted downgrade.",
            input_tokens=450, output_tokens=50, cost_usd=0.00002,
        )


def ssh_event(kind: str, when: datetime, cursor: str) -> SecurityEvent:
    return SecurityEvent(
        source="journalctl", category="authentication", event_type=kind,
        summary=kind, severity="medium", observed_at=when.isoformat(),
        actor="alice", source_ip="192.0.2.25",
        evidence={"journal_cursor": cursor},
    )


def test_correlates_ssh_failures_and_success(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    now = datetime.now(UTC)
    for index in range(3):
        service.ingest(ssh_event(
            "ssh_login_failed", now + timedelta(seconds=index), f"f{index}"
        ))
    service.ingest(ssh_event(
        "ssh_login_succeeded", now + timedelta(seconds=4), "success"
    ))
    event_types = [row["event_type"] for row in store.list_events(limit=20)]
    assert "ssh_bruteforce" in event_types
    assert "ssh_failures_then_success" in event_types


def test_raw_network_event_does_not_need_ai(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    event = SecurityEvent(
        source="procfs", category="network", event_type="network_connection",
        summary="connection", severity="informational",
    )
    assert service._should_use_ai(event) is False


def test_medium_event_stays_local_and_visible(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    provider = UnsafeProvider()
    service.provider = provider
    service.ingest(SecurityEvent(
        source="journalctl", category="authentication",
        event_type="ssh_login_failed", summary="failed", severity="medium",
        evidence={"journal_cursor": "m1"},
    ))
    event = store.list_events()[0]
    assert provider.calls == 0
    assert event["severity"] == "medium"
    assert event["provider"] == "local-rules"


def test_ai_cannot_downgrade_deterministic_high_event(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    provider = UnsafeProvider()
    service.provider = provider
    service.ingest(SecurityEvent(
        source="correlator", category="incident", event_type="port_scan",
        summary="scan", severity="high", source_ip="192.0.2.40",
    ))
    with store.connect() as connection:
        decision = connection.execute(
            "SELECT * FROM decisions ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert provider.calls == 1
    assert decision["severity"] == "high"
    assert decision["classification"] == "suspicious"
    assert decision["recommended_action"] == "investigate"
    assert decision["requires_human_review"] == 1


def test_ai_budget_and_cooldown_survive_service_restart(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    configured = replace(
        settings(store.path), ai_max_per_hour=10, ai_max_per_day=20,
        ai_cooldown_seconds=3600,
    )
    first = MonitoringService(store, configured)
    first_provider = UnsafeProvider()
    first.provider = first_provider
    first.ingest(SecurityEvent(
        source="correlator", category="incident", event_type="port_scan",
        summary="first", severity="high", source_ip="192.0.2.41",
        evidence={"sequence": 1},
    ))
    second = MonitoringService(store, configured)
    second_provider = UnsafeProvider()
    second.provider = second_provider
    second.ingest(SecurityEvent(
        source="correlator", category="incident", event_type="port_scan",
        summary="second", severity="high", source_ip="192.0.2.41",
        evidence={"sequence": 2},
    ))
    assert first_provider.calls == 1
    assert second_provider.calls == 0
    assert second.capabilities()["ai_calls_last_hour"] == 1


def test_persistent_hourly_budget_blocks_different_incidents(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    configured = replace(
        settings(store.path), ai_max_per_hour=1, ai_max_per_day=10,
        ai_cooldown_seconds=0,
    )
    first = MonitoringService(store, configured)
    first_provider = UnsafeProvider()
    first.provider = first_provider
    first.ingest(SecurityEvent(
        source="correlator", category="incident", event_type="port_scan",
        summary="first", severity="high", source_ip="192.0.2.50",
    ))
    second = MonitoringService(store, configured)
    second_provider = UnsafeProvider()
    second.provider = second_provider
    second.ingest(SecurityEvent(
        source="correlator", category="incident", event_type="port_scan",
        summary="second", severity="high", source_ip="192.0.2.51",
    ))
    assert first_provider.calls == 1
    assert second_provider.calls == 0


def test_existing_external_history_seeds_daily_budget(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    old_event = SecurityEvent(
        source="test", category="incident", event_type="old",
        summary="old external call", severity="high",
    )
    event_id = store.add_event(old_event)
    assert event_id is not None
    store.add_decision(event_id, Decision(
        classification="suspicious", severity="high",
        recommended_action="investigate", confidence=0.8, provider="old-ai",
    ))
    configured = replace(
        settings(store.path), ai_max_per_hour=10, ai_max_per_day=1,
        ai_cooldown_seconds=0,
    )
    service = MonitoringService(store, configured)
    provider = UnsafeProvider()
    service.provider = provider
    service.ingest(SecurityEvent(
        source="correlator", category="incident", event_type="port_scan",
        summary="new", severity="high", source_ip="192.0.2.60",
    ))
    assert provider.calls == 0
    assert service.capabilities()["ai_calls_last_day"] == 1


def test_detects_new_listener_after_baseline(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    baseline = SecurityEvent(
        source="procfs", category="network", event_type="listening_port",
        summary="ssh", destination_ip="0.0.0.0", destination_port=22,
        process="sshd", evidence={"protocol": "tcp", "pid": 10},
    )
    added = SecurityEvent(
        source="procfs", category="network", event_type="listening_port",
        summary="new", destination_ip="0.0.0.0", destination_port=4444,
        process="payload", evidence={
            "protocol": "tcp", "pid": 20, "executable": "/tmp/payload",
        },
    )
    assert service._correlate_new_listeners([baseline]) == 0
    assert service._correlate_new_listeners([baseline, added]) == 1
    incident = store.list_events()[0]
    assert incident["event_type"] == "new_listening_port"
    assert incident["severity"] == "high"


def test_listener_whitelist_and_pid_changes_do_not_open_incidents(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    ssh = SecurityEvent(
        source="procfs", category="network", event_type="listening_port",
        summary="ssh", destination_ip="0.0.0.0", destination_port=22,
        process="sshd", evidence={
            "protocol": "tcp", "pid": 10, "executable": "/usr/bin/sshd",
        },
    )
    assert service._correlate_new_listeners([]) == 0
    assert service._correlate_new_listeners([ssh]) == 0
    ssh.evidence["pid"] = 99
    assert service._correlate_new_listeners([ssh]) == 0
    assert not store.list_events()


def test_ephemeral_udp_listener_does_not_open_incident(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    service._correlate_new_listeners([])
    udp = SecurityEvent(
        source="procfs", category="network", event_type="listening_port",
        summary="udp", destination_ip="0.0.0.0", destination_port=49152,
        process="browser", evidence={
            "protocol": "udp", "pid": 20, "executable": "/usr/bin/browser",
        },
    )
    assert service._correlate_new_listeners([udp]) == 0
    assert not store.list_events()


def test_correlates_privilege_then_persistence(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    now = datetime.now(UTC)
    service.ingest(SecurityEvent(
        source="journalctl", category="privilege", event_type="sudo_command",
        summary="alice used sudo", severity="medium", observed_at=now.isoformat(),
        actor="alice", evidence={"command": "systemctl enable example.service"},
    ))
    service.ingest(SecurityEvent(
        source="file-monitor", category="persistence", event_type="file_created",
        summary="Unit created", severity="high",
        observed_at=(now + timedelta(seconds=3)).isoformat(),
        evidence={"path": "/etc/systemd/system/example.service"},
    ))
    incident = next(
        row for row in store.list_events(limit=10)
        if row["event_type"] == "privilege_then_persistence"
    )
    assert incident["severity"] == "high"
    assert incident["evidence"]["persistence_path"].endswith("example.service")


def test_correlates_blocked_ports_as_scan(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    now = datetime.now(UTC)
    for port in range(20, 30):
        service.ingest(SecurityEvent(
            source="kernel", category="network",
            event_type="firewall_packet_blocked", summary="blocked",
            severity="medium", observed_at=now.isoformat(),
            source_ip="192.0.2.44", destination_port=port,
            evidence={"journal_cursor": f"k-{port}"},
        ))
    incident = next(
        row for row in store.list_events(limit=30) if row["event_type"] == "port_scan"
    )
    assert incident["severity"] == "high"
    assert len(incident["evidence"]["blocked_ports"]) == 10


def test_ai_copy_redacts_raw_commands_and_secrets(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    service = MonitoringService(store, settings(store.path))
    event = SecurityEvent(
        source="test", category="process", event_type="suspicious_process",
        summary="test", severity="high", evidence={
            "command_line": "tool --token visible-secret",
            "api_key": "visible-secret",
            "executable": "/tmp/tool",
        },
    )
    sanitized = service._event_for_ai(event)
    assert sanitized.evidence["command_line"] == "[redacted]"
    assert sanitized.evidence["api_key"] == "[redacted]"
    assert sanitized.evidence["executable"] == "/tmp/tool"
