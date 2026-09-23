from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime

from ..models import SecurityEvent


FAILED_SSH = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
ACCEPTED_SSH = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
SUDO_COMMAND = re.compile(
    r"(?P<actor>\S+)\s+: .*USER=(?P<target>\S+)\s+; COMMAND=(?P<command>.*)"
)
SU_OPEN = re.compile(
    r"session opened for user (?P<target>[^ (]+).* by (?P<actor>[^ (]+)"
)


def collect_auth(
    since_epoch: float, after_cursor: str | None = None
) -> tuple[list[SecurityEvent], str | None, str | None]:
    command = ["journalctl", "--no-pager", "--output", "json"]
    if after_cursor:
        command.extend(("--after-cursor", after_cursor))
    else:
        command.extend(("--since", f"@{int(since_epoch)}"))
    command.extend((
        "_COMM=sshd", "+", "_COMM=sshd-session",
        "+", "_SYSTEMD_UNIT=sshd.service", "+", "_SYSTEMD_UNIT=ssh.service",
        "+", "_COMM=sudo", "+", "_COMM=su",
        "+", "_COMM=useradd", "+", "_COMM=usermod",
        "+", "_COMM=groupadd", "+", "_COMM=passwd",
        "+", "_COMM=systemd-coredump",
    ))
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=5, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
        return [], str(error), after_cursor
    if result.returncode not in {0, 1}:
        return [], result.stderr.strip() or f"journalctl exited {result.returncode}", after_cursor

    events: list[SecurityEvent] = []
    last_cursor = after_cursor
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        last_cursor = record.get("__CURSOR") or last_cursor
        event = _parse_record(record)
        if event:
            events.append(event)
    return events, None, last_cursor


def _parse_record(record: dict) -> SecurityEvent | None:
    message = str(record.get("MESSAGE", ""))
    comm = str(record.get("_COMM", ""))
    timestamp = record.get("__REALTIME_TIMESTAMP")
    observed_at = (
        datetime.fromtimestamp(int(timestamp) / 1_000_000, UTC).isoformat()
        if timestamp else datetime.now(UTC).isoformat()
    )
    evidence = {
        "message": message[:2000], "journal_cursor": record.get("__CURSOR"),
        "comm": comm, "systemd_unit": record.get("_SYSTEMD_UNIT"),
    }

    match = FAILED_SSH.search(message)
    if match:
        return SecurityEvent(
            source="journalctl", category="authentication",
            event_type="ssh_login_failed",
            summary=f"Failed SSH login for {match['user']} from {match['ip']}",
            severity="medium", observed_at=observed_at,
            actor=match["user"], source_ip=match["ip"], evidence=evidence,
        )
    match = ACCEPTED_SSH.search(message)
    if match:
        root_login = match["user"] == "root"
        return SecurityEvent(
            source="journalctl", category="authentication",
            event_type="ssh_login_succeeded",
            summary=(
                f"Direct root SSH login from {match['ip']}"
                if root_login else
                f"Successful SSH login for {match['user']} from {match['ip']}"
            ),
            severity="high" if root_login else "low", observed_at=observed_at,
            actor=match["user"], source_ip=match["ip"], evidence=evidence,
        )
    if comm == "sudo":
        if any(term in message.lower() for term in (
            "authentication failure", "incorrect password", "not in the sudoers"
        )):
            return SecurityEvent(
                source="journalctl", category="privilege",
                event_type="sudo_failed", summary="Failed sudo authentication",
                severity="high", observed_at=observed_at,
                actor=str(record.get("_UID", "unknown")), evidence=evidence,
            )
        command_match = SUDO_COMMAND.search(message)
        if command_match:
            evidence.update({
                "target_user": command_match["target"],
                "command": command_match["command"][:1500],
            })
            return SecurityEvent(
                source="journalctl", category="privilege",
                event_type="sudo_command", summary=(
                    f"{command_match['actor']} used sudo as {command_match['target']}"
                ), severity="medium", observed_at=observed_at,
                actor=command_match["actor"], process="sudo", evidence=evidence,
            )
    if comm == "su" and "session opened" in message:
        match = SU_OPEN.search(message)
        return SecurityEvent(
            source="journalctl", category="privilege", event_type="su_session_opened",
            summary="User switching session opened", severity="medium",
            observed_at=observed_at,
            actor=match["actor"] if match else str(record.get("_UID", "unknown")),
            process="su", evidence={
                **evidence, "target_user": match["target"] if match else None,
            },
        )
    if comm in {"useradd", "usermod", "groupadd", "passwd"} and message:
        return SecurityEvent(
            source="journalctl", category="account",
            event_type=f"account_tool_{comm}",
            summary=f"Account management activity: {comm}", severity="high",
            observed_at=observed_at, process=comm, evidence=evidence,
        )
    if comm == "systemd-coredump":
        return SecurityEvent(
            source="journalctl", category="process", event_type="process_crashed",
            summary="Process crash recorded by systemd-coredump", severity="medium",
            observed_at=observed_at,
            process=str(record.get("COREDUMP_COMM") or record.get("COREDUMP_EXE") or "unknown"),
            evidence={
                **evidence, "signal": record.get("COREDUMP_SIGNAL_NAME"),
                "executable": record.get("COREDUMP_EXE"),
            },
        )
    return None
