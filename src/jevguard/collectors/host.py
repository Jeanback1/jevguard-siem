from __future__ import annotations

import hashlib
import os
import pwd
from pathlib import Path
from typing import Any

from ..models import SecurityEvent


CRITICAL_FILES = (
    Path("/etc/passwd"), Path("/etc/group"), Path("/etc/shadow"),
    Path("/etc/sudoers"), Path("/etc/ssh/sshd_config"),
    Path("/etc/hosts"), Path("/etc/resolv.conf"), Path("/etc/ld.so.preload"),
)
PERSISTENCE_DIRS = (
    Path("/etc/systemd/system"), Path("/etc/cron.d"), Path("/etc/cron.daily"),
    Path("/var/spool/cron"),
)


def _file_record(path: Path) -> dict[str, Any] | None:
    try:
        stat = path.stat()
        if not path.is_file():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return {
            "sha256": digest.hexdigest(), "size": stat.st_size,
            "mode": oct(stat.st_mode & 0o7777), "uid": stat.st_uid,
            "gid": stat.st_gid,
        }
    except (OSError, PermissionError):
        return None


def file_snapshot(home: Path | None = None) -> dict[str, dict[str, Any]]:
    home = home or Path.home()
    paths = list(CRITICAL_FILES)
    paths.extend((home / ".ssh" / "authorized_keys", home / ".bashrc", home / ".profile"))
    directories = list(PERSISTENCE_DIRS) + [
        home / ".config" / "systemd" / "user",
        home / ".config" / "autostart",
    ]
    for directory in directories:
        try:
            paths.extend(path for path in directory.rglob("*") if path.is_file())
        except (OSError, PermissionError):
            continue
    snapshot: dict[str, dict[str, Any]] = {}
    for path in sorted(set(paths)):
        record = _file_record(path)
        if record:
            snapshot[str(path)] = record
    return snapshot


def file_change_events(
    previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> list[SecurityEvent]:
    if not previous:
        return []
    events: list[SecurityEvent] = []
    for path in sorted(set(previous) | set(current)):
        before, after = previous.get(path), current.get(path)
        if before == after:
            continue
        change = "created" if before is None else "deleted" if after is None else "modified"
        persistence = (
            any(path.startswith(str(directory)) for directory in PERSISTENCE_DIRS)
            or "/.config/systemd/user/" in path
            or "/.config/autostart/" in path
        )
        category = "persistence" if persistence else "file_integrity"
        severity = "high" if persistence or path in {
            "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/ld.so.preload",
        } else "medium"
        events.append(SecurityEvent(
            source="file-monitor", category=category,
            event_type=f"file_{change}", severity=severity,
            summary=f"Security-sensitive file {change}: {path}",
            evidence={"path": path, "change": change, "before": before, "after": after},
        ))
    return events


def account_snapshot() -> dict[str, Any]:
    users: dict[str, Any] = {}
    try:
        for entry in pwd.getpwall():
            users[entry.pw_name] = {
                "uid": entry.pw_uid, "gid": entry.pw_gid,
                "home": entry.pw_dir, "shell": entry.pw_shell,
            }
    except OSError:
        pass
    groups: dict[str, list[str]] = {}
    try:
        import grp
        for entry in grp.getgrall():
            groups[entry.gr_name] = sorted(entry.gr_mem)
    except OSError:
        pass
    return {"users": users, "groups": groups}


def account_change_events(previous: dict[str, Any], current: dict[str, Any]) -> list[SecurityEvent]:
    if not previous:
        return []
    events: list[SecurityEvent] = []
    old_users, new_users = previous.get("users", {}), current.get("users", {})
    for username in sorted(set(old_users) | set(new_users)):
        before, after = old_users.get(username), new_users.get(username)
        if before == after:
            continue
        change = "created" if before is None else "deleted" if after is None else "modified"
        events.append(SecurityEvent(
            source="account-monitor", category="account",
            event_type=f"user_{change}", severity="high",
            summary=f"User account {change}: {username}", actor=username,
            evidence={"before": before, "after": after, "change": change},
        ))
    old_groups, new_groups = previous.get("groups", {}), current.get("groups", {})
    for group in sorted(set(old_groups) | set(new_groups)):
        before, after = old_groups.get(group), new_groups.get(group)
        if before == after:
            continue
        severity = "high" if group in {"root", "wheel", "sudo", "docker"} else "medium"
        events.append(SecurityEvent(
            source="account-monitor", category="account",
            event_type="group_membership_changed", severity=severity,
            summary=f"Group membership changed: {group}",
            evidence={"group": group, "before": before, "after": after},
        ))
    return events


def process_snapshot(proc_root: Path = Path("/proc")) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    try:
        processes = [path for path in proc_root.iterdir() if path.name.isdigit()]
    except OSError:
        return snapshot
    for process_dir in processes:
        try:
            stat_fields = (process_dir / "stat").read_text().split()
            start_time = stat_fields[21]
            status = (process_dir / "status").read_text()
            uid = int(next(line for line in status.splitlines() if line.startswith("Uid:")).split()[1])
            ppid = int(next(line for line in status.splitlines() if line.startswith("PPid:")).split()[1])
            comm = (process_dir / "comm").read_text().strip()
            cmdline = (process_dir / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                errors="replace"
            ).strip()[:1000]
            exe = os.readlink(process_dir / "exe")
        except (OSError, StopIteration, ValueError, IndexError):
            continue
        key = f"{process_dir.name}:{start_time}"
        snapshot[key] = {
            "pid": int(process_dir.name), "ppid": ppid, "uid": uid,
            "comm": comm, "cmdline": cmdline, "exe": exe,
        }
    return snapshot


def suspicious_process_events(
    previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> list[SecurityEvent]:
    if not previous:
        return []
    events: list[SecurityEvent] = []
    for key in set(current) - set(previous):
        process = current[key]
        exe = process["exe"]
        reason = None
        severity = "medium"
        if exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            reason, severity = "executable launched from a temporary directory", "high"
        elif exe.endswith(" (deleted)"):
            reason, severity = "running executable was deleted", "high"
        elif process["uid"] == 0 and exe.startswith("/home/"):
            reason = "root process launched an executable from a home directory"
        if not reason:
            continue
        events.append(SecurityEvent(
            source="procfs", category="process", event_type="suspicious_process",
            severity=severity, process=process["comm"],
            summary=f"Suspicious process: {process['comm']} ({reason})",
            evidence={**process, "reason": reason},
        ))
    return events
