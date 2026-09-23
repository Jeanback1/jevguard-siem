from __future__ import annotations

import os
import re
import shlex
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..models import SecurityEvent


AUDIT_ID = re.compile(r"msg=audit\((?P<timestamp>[0-9.]+):(?P<id>\d+)\)")


def _fields(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator:
            values[key] = value.strip('"')
    return values


def collect_audit(
    state: dict[str, Any], path: Path = Path("/var/log/audit/audit.log")
) -> tuple[list[SecurityEvent], dict[str, Any], str | None]:
    try:
        stat = path.stat()
    except OSError as error:
        return [], state, str(error)
    inode = stat.st_ino
    if not state:
        return [], {"inode": inode, "offset": stat.st_size}, None
    offset = int(state.get("offset", 0)) if state.get("inode") == inode else 0
    try:
        with path.open("r", errors="replace") as handle:
            handle.seek(min(offset, stat.st_size))
            lines = handle.readlines()
            new_state = {"inode": inode, "offset": handle.tell()}
    except OSError as error:
        return [], state, str(error)

    groups: dict[str, list[str]] = defaultdict(list)
    for line in lines:
        match = AUDIT_ID.search(line)
        if match:
            groups[match["id"]].append(line.strip())
    events: list[SecurityEvent] = []
    for audit_id, records in groups.items():
        joined = " ".join(records)
        fields = _fields(joined)
        record_types = {
            match.group(1) for record in records
            if (match := re.search(r"type=([A-Z_]+)", record))
        }
        executable = fields.get("exe") or fields.get("comm")
        success = fields.get("success") or fields.get("res")
        if "EXECVE" in record_types:
            suspicious = bool(executable and executable.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")))
            events.append(SecurityEvent(
                source="auditd", category="process", event_type="process_executed",
                summary=f"Process execution recorded by auditd: {executable or 'unknown'}",
                severity="high" if suspicious else "informational",
                actor=fields.get("auid") or fields.get("uid"), process=fields.get("comm"),
                evidence={
                    "audit_id": audit_id, "executable": executable,
                    "success": success, "record_types": sorted(record_types),
                    "raw": records[:20],
                },
            ))
        elif "AVC" in record_types:
            events.append(SecurityEvent(
                source="auditd", category="access_control", event_type="access_denied",
                summary="Mandatory access-control denial", severity="medium",
                actor=fields.get("uid"), process=fields.get("comm"),
                evidence={"audit_id": audit_id, "raw": records[:20]},
            ))
        elif record_types & {"USER_AUTH", "USER_ACCT", "USER_CMD"}:
            failed = str(success).lower() in {"failed", "no", "0"}
            events.append(SecurityEvent(
                source="auditd", category="authentication",
                event_type="audit_auth_failed" if failed else "audit_auth_activity",
                summary="Audit authentication failure" if failed else "Audit authentication activity",
                severity="high" if failed else "low", actor=fields.get("acct"),
                evidence={"audit_id": audit_id, "result": success, "raw": records[:20]},
            ))
    return events, new_state, None
