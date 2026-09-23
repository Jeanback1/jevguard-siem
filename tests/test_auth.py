import json
from subprocess import CompletedProcess

from jevguard.collectors import auth


def test_collects_sshd_session_failures_and_successes(monkeypatch):
    records = [
        {
            "_COMM": "sshd-session",
            "_SYSTEMD_UNIT": "sshd.service",
            "__CURSOR": "cursor-failed",
            "__REALTIME_TIMESTAMP": "1787698010000000",
            "MESSAGE": "Failed password for jean from 192.0.2.25 port 45018 ssh2",
        },
        {
            "_COMM": "sshd-session",
            "_SYSTEMD_UNIT": "sshd.service",
            "__CURSOR": "cursor-accepted",
            "__REALTIME_TIMESTAMP": "1787698020000000",
            "MESSAGE": "Accepted password for jean from 192.0.2.25 port 45019 ssh2",
        },
    ]
    output = "\n".join(json.dumps(record) for record in records)

    def fake_run(command, **kwargs):
        assert "_COMM=sshd-session" in command
        assert "_SYSTEMD_UNIT=sshd.service" in command
        return CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(auth.subprocess, "run", fake_run)

    events, error, cursor = auth.collect_auth(0)

    assert error is None
    assert [event.event_type for event in events] == [
        "ssh_login_failed",
        "ssh_login_succeeded",
    ]
    assert events[0].source_ip == "192.0.2.25"
    assert events[0].actor == "jean"
    assert events[0].evidence["journal_cursor"] == "cursor-failed"
    assert cursor == "cursor-accepted"


def test_direct_root_ssh_login_is_high_severity():
    event = auth._parse_record({
        "_COMM": "sshd-session",
        "MESSAGE": "Accepted publickey for root from 192.0.2.50 port 50000 ssh2",
    })
    assert event is not None
    assert event.event_type == "ssh_login_succeeded"
    assert event.actor == "root"
    assert event.severity == "high"
    assert "Direct root" in event.summary
