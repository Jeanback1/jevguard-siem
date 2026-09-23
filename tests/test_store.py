from pathlib import Path

from jevguard.db import EventStore
from jevguard.decision import LocalDecisionProvider
from jevguard.models import SecurityEvent
from jevguard.models import Decision


def test_store_deduplicates_snapshot_events(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    event = SecurityEvent(
        source="test", category="network", event_type="listening_port",
        summary="listener", destination_port=8080,
    )
    event_id = store.add_event(event)
    assert event_id is not None
    assert store.add_event(event) is None
    store.add_decision(event_id, LocalDecisionProvider().decide(event))
    rows = store.list_events()
    assert len(rows) == 1
    assert rows[0]["provider"] == "local-rules"


def test_summary_counts_categories(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    store.add_event(SecurityEvent(
        source="test", category="authentication", event_type="login",
        summary="login",
    ))
    summary = store.summary()
    assert summary["total_events"] == 1
    assert summary["by_category"] == {"authentication": 1}


def test_summary_reports_external_ai_usage(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    event_id = store.add_event(SecurityEvent(
        source="test", category="incident", event_type="test", summary="test",
    ))
    assert event_id is not None
    store.add_decision(event_id, Decision(
        classification="suspicious", severity="high",
        recommended_action="investigate", confidence=0.8, provider="test-ai",
        input_tokens=450, output_tokens=50, cost_usd=0.00002,
    ))
    usage = store.summary()["ai_usage_24h"]
    assert usage == {
        "calls": 1, "metered_calls": 1, "input_tokens": 450,
        "output_tokens": 50, "cost_usd": 0.00002,
    }


def test_state_and_event_status(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    store.set_state("cursor", {"value": "abc"})
    assert store.get_state("cursor") == {"value": "abc"}
    event_id = store.add_event(SecurityEvent(
        source="test", category="incident", event_type="test",
        summary="test incident",
    ))
    assert event_id is not None
    assert store.update_status(event_id, "investigating") is True
    assert store.list_events()[0]["status"] == "investigating"
    assert store.update_status(event_id, "invalid") is False


def test_initialization_recalculates_legacy_review_flags(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    event = SecurityEvent(
        source="procfs", category="network", event_type="network_connection",
        summary="routine", severity="informational",
    )
    event_id = store.add_event(event)
    assert event_id is not None
    store.add_decision(event_id, Decision(
        classification="insufficient_evidence", severity="informational",
        recommended_action="record", confidence=0.35, provider="local-rules",
        requires_human_review=True,
    ))
    EventStore(store.path)
    with store.connect() as connection:
        flag = connection.execute(
            "SELECT requires_human_review FROM decisions WHERE event_id = ?",
            (event_id,),
        ).fetchone()[0]
    assert flag == 0


def test_initialization_moves_isolated_ssh_failure_to_monitoring(tmp_path: Path):
    store = EventStore(tmp_path / "test.db")
    event = SecurityEvent(
        source="journalctl", category="authentication",
        event_type="ssh_login_failed", summary="one failure", severity="medium",
        evidence={"journal_cursor": "legacy"},
    )
    event_id = store.add_event(event)
    assert event_id is not None
    store.add_decision(event_id, Decision(
        classification="suspicious", severity="medium",
        recommended_action="investigate", confidence=0.72,
        provider="local-rules", requires_human_review=True,
    ))
    EventStore(store.path)
    with store.connect() as connection:
        decision = connection.execute(
            "SELECT recommended_action, requires_human_review FROM decisions "
            "WHERE event_id = ?", (event_id,),
        ).fetchone()
    assert decision["recommended_action"] == "monitor"
    assert decision["requires_human_review"] == 0
