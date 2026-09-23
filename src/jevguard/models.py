from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
import hashlib
import json


SEVERITIES = ("informational", "low", "medium", "high", "critical")


@dataclass
class SecurityEvent:
    source: str
    category: str
    event_type: str
    summary: str
    severity: str = "informational"
    observed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    host: str = "localhost"
    actor: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    process: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        stable = {
            "source": self.source,
            "category": self.category,
            "event_type": self.event_type,
            "host": self.host,
            "actor": self.actor,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "process": self.process,
            "evidence": self.evidence,
        }
        payload = json.dumps(stable, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Decision:
    classification: str
    severity: str
    recommended_action: str
    confidence: float
    provider: str
    probabilities: dict[str, Any] = field(default_factory=dict)
    requires_human_review: bool = True
    rationale: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
