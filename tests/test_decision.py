import pytest

from jevguard.decision import (
    LocalDecisionProvider,
    OpenAICompatibleDecisionProvider,
    OpenRouterJevDecisionProvider,
    apply_policy,
)
from jevguard.models import Decision, SecurityEvent


def test_isolated_failed_ssh_is_monitored_until_correlated():
    event = SecurityEvent(
        source="test", category="authentication",
        event_type="ssh_login_failed", summary="failed",
    )
    decision = LocalDecisionProvider().decide(event)
    assert decision.classification == "suspicious"
    assert decision.recommended_action == "monitor"
    assert decision.requires_human_review is False


def test_low_confidence_informational_event_stays_in_monitoring():
    decision = Decision(
        classification="benign", severity="low", recommended_action="record",
        confidence=0.5, provider="test",
    )
    assert apply_policy(decision).requires_human_review is False


def test_confident_benign_event_can_be_recorded():
    decision = Decision(
        classification="benign", severity="informational",
        recommended_action="record", confidence=0.95, provider="test",
    )
    assert apply_policy(decision).requires_human_review is False


def test_medium_monitor_decision_does_not_enter_incident_queue():
    decision = Decision(
        classification="suspicious", severity="medium",
        recommended_action="monitor", confidence=0.55, provider="test",
    )
    assert apply_policy(decision).requires_human_review is False


def test_high_event_requires_review_even_when_model_calls_it_benign():
    decision = Decision(
        classification="benign", severity="high",
        recommended_action="record", confidence=0.99, provider="test",
    )
    assert apply_policy(decision).requires_human_review is True


def test_explicit_investigation_requires_review_at_medium_severity():
    decision = Decision(
        classification="suspicious", severity="medium",
        recommended_action="investigate", confidence=0.9, provider="test",
    )
    assert apply_policy(decision).requires_human_review is True


def test_generic_llm_confidence_is_capped_for_review():
    provider = OpenAICompatibleDecisionProvider(
        "key", "model", "https://example.com/v1", "test-provider"
    )
    decision = provider._validated_decision({
        "classification": "benign",
        "severity": "informational",
        "recommended_action": "record",
        "confidence": 0.99,
        "rationale": "Routine activity",
    })
    assert decision.confidence == 0.79
    assert decision.requires_human_review is False


def test_remote_plain_http_provider_is_rejected():
    with pytest.raises(ValueError):
        OpenAICompatibleDecisionProvider(
            "key", "model", "http://example.com/v1", "test-provider"
        )


def test_openrouter_jev_provider_has_specialized_identity():
    provider = OpenRouterJevDecisionProvider("key", "~typesafe/jev-latest")
    assert provider.name == "openrouter-jev"
