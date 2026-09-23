from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from typing import Any

from ..models import SecurityEvent


TCP_STATES = {
    "01": "established", "02": "syn_sent", "03": "syn_received",
    "06": "time_wait", "07": "closed", "08": "close_wait",
    "09": "last_ack", "0A": "listen", "0B": "closing",
}


def _endpoint(value: str, ipv6: bool) -> tuple[str, int]:
    address_hex, port_hex = value.split(":")
    raw = bytes.fromhex(address_hex)
    if ipv6:
        chunks = [raw[index:index + 4][::-1] for index in range(0, 16, 4)]
        address = str(ipaddress.IPv6Address(b"".join(chunks)))
    else:
        address = socket.inet_ntoa(raw[::-1])
    return address, int(port_hex, 16)


def _socket_processes(proc_root: Path = Path("/proc")) -> dict[str, dict[str, Any]]:
    owners: dict[str, dict[str, Any]] = {}
    try:
        processes = [path for path in proc_root.iterdir() if path.name.isdigit()]
    except OSError:
        return owners
    for process_dir in processes:
        try:
            comm = (process_dir / "comm").read_text().strip()
            cmdline = (process_dir / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                errors="replace"
            ).strip()[:1000]
            status = (process_dir / "status").read_text()
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            uid = int(uid_line.split()[1])
            exe = os.readlink(process_dir / "exe")
            links = list((process_dir / "fd").iterdir())
        except (OSError, StopIteration, ValueError):
            continue
        info = {
            "pid": int(process_dir.name), "uid": uid, "comm": comm,
            "cmdline": cmdline, "exe": exe,
        }
        for link in links:
            try:
                target = os.readlink(link)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                owners[target[8:-1]] = info
    return owners


def collect_network(
    proc_root: Path = Path("/proc/net"), process_root: Path = Path("/proc")
) -> list[SecurityEvent]:
    owners = _socket_processes(process_root)
    parsed: list[dict[str, Any]] = []
    for protocol, ipv6 in (
        ("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)
    ):
        try:
            lines = (proc_root / protocol).read_text().splitlines()[1:]
        except (FileNotFoundError, PermissionError, OSError):
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            try:
                local_ip, local_port = _endpoint(fields[1], ipv6)
                remote_ip, remote_port = _endpoint(fields[2], ipv6)
            except (ValueError, OSError):
                continue
            state = TCP_STATES.get(fields[3], fields[3].lower())
            parsed.append({
                "protocol": protocol, "local_ip": local_ip,
                "local_port": local_port, "remote_ip": remote_ip,
                "remote_port": remote_port, "state": state,
                "inode": fields[9],
                "listener": state == "listen" or (
                    protocol.startswith("udp") and remote_port == 0
                ),
            })

    own_ports = {
        item["local_port"] for item in parsed
        if item["listener"] and owners.get(item["inode"], {}).get("pid") == os.getpid()
    }
    events: list[SecurityEvent] = []
    for item in parsed:
        owner = owners.get(item["inode"])
        if owner and owner["pid"] == os.getpid():
            continue
        loopback = item["local_ip"] in {"127.0.0.1", "::1"} and item["remote_ip"] in {
            "127.0.0.1", "::1"
        }
        if loopback and ({item["local_port"], item["remote_port"]} & own_ports):
            continue
        event_type = "listening_port" if item["listener"] else "network_connection"
        severity = (
            "low" if item["listener"] and item["local_port"] not in {22, 53, 80, 443}
            else "informational"
        )
        summary = (
            f"{item['protocol'].upper()} listener on {item['local_ip']}:{item['local_port']}"
            if item["listener"] else
            f"{item['protocol'].upper()} {item['local_ip']}:{item['local_port']} "
            f"to {item['remote_ip']}:{item['remote_port']}"
        )
        events.append(SecurityEvent(
            source="procfs", category="network", event_type=event_type,
            summary=summary, severity=severity,
            source_ip=item["remote_ip"] if not item["listener"] else None,
            destination_ip=item["local_ip"],
            source_port=item["remote_port"] if not item["listener"] else None,
            destination_port=item["local_port"],
            process=owner["comm"] if owner else None,
            evidence={
                "protocol": item["protocol"], "state": item["state"],
                "socket_inode": item["inode"],
                "pid": owner["pid"] if owner else None,
                "uid": owner["uid"] if owner else None,
                "executable": owner["exe"] if owner else None,
                "command_line": owner["cmdline"] if owner else None,
            },
        ))
    return events
