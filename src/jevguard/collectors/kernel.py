from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime

from ..models import SecurityEvent


FIREWALL_MARKERS = ("UFW BLOCK", "UFW REJECT", "NFT DROP", "NFT REJECT", "IN=")
FIELD = re.compile(r"(?:^|\s)(SRC|DST|SPT|DPT|PROTO)=([^\s]+)")


def collect_kernel(
    since_epoch: float, after_cursor: str | None = None
) -> tuple[list[SecurityEvent], str | None, str | None]:
    command = ["journalctl", "--no-pager", "--output", "json", "-k"]
    if after_cursor:
        command.extend(("--after-cursor", after_cursor))
    else:
        command.extend(("--since", f"@{int(since_epoch)}"))
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
        event = parse_kernel_record(record)
        if event:
            events.append(event)
    return events, None, last_cursor


def parse_kernel_record(record: dict) -> SecurityEvent | None:
    message = str(record.get("MESSAGE", ""))
    upper = message.upper()
    if not any(marker in upper for marker in FIREWALL_MARKERS):
        return None
    fields = {key: value for key, value in FIELD.findall(message)}
    if not fields.get("SRC") and not fields.get("DPT"):
        return None
    timestamp = record.get("__REALTIME_TIMESTAMP")
    observed_at = (
        datetime.fromtimestamp(int(timestamp) / 1_000_000, UTC).isoformat()
        if timestamp else datetime.now(UTC).isoformat()
    )

    def port(name: str) -> int | None:
        try:
            return int(fields[name])
        except (KeyError, ValueError):
            return None

    action = "rejected" if "REJECT" in upper else "blocked"
    destination = fields.get("DST")
    destination_port = port("DPT")
    return SecurityEvent(
        source="kernel", category="network", event_type="firewall_packet_blocked",
        summary=(
            f"Firewall {action} {fields.get('PROTO', 'traffic')} from "
            f"{fields.get('SRC', 'unknown')} to {destination or 'this host'}"
            + (f":{destination_port}" if destination_port is not None else "")
        ),
        severity="medium", observed_at=observed_at,
        source_ip=fields.get("SRC"), destination_ip=destination,
        source_port=port("SPT"), destination_port=destination_port,
        evidence={
            "action": action, "protocol": fields.get("PROTO"),
            "journal_cursor": record.get("__CURSOR"), "message": message[:2000],
        },
    )
