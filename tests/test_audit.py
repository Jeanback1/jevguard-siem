from pathlib import Path

from jevguard.collectors.audit import collect_audit


def test_audit_collector_baselines_then_reads_exec(tmp_path: Path):
    log = tmp_path / "audit.log"
    log.write_text("")
    events, state, error = collect_audit({}, log)
    assert events == []
    assert error is None

    with log.open("a") as handle:
        handle.write(
            'type=SYSCALL msg=audit(1787699000.1:42) success=yes '
            'auid=1000 uid=0 comm="payload" exe="/tmp/payload"\n'
            'type=EXECVE msg=audit(1787699000.1:42) argc=1 a0="/tmp/payload"\n'
        )
    events, new_state, error = collect_audit(state, log)
    assert error is None
    assert len(events) == 1
    assert events[0].event_type == "process_executed"
    assert events[0].severity == "high"
    assert new_state["offset"] > state["offset"]
