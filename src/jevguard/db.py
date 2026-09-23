from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import Decision, SecurityEvent


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    observed_at TEXT NOT NULL,
    host TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    process TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE,
    classification TEXT NOT NULL,
    severity TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    confidence REAL NOT NULL,
    provider TEXT NOT NULL,
    probabilities_json TEXT NOT NULL,
    requires_human_review INTEGER NOT NULL,
    rationale TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);

CREATE TABLE IF NOT EXISTS collector_state (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class EventStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(events)")
            }
            if "status" not in columns:
                connection.execute(
                    "ALTER TABLE events ADD COLUMN status TEXT NOT NULL DEFAULT 'new'"
                )
            decision_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(decisions)")
            }
            for name, definition in (
                ("input_tokens", "INTEGER NOT NULL DEFAULT 0"),
                ("output_tokens", "INTEGER NOT NULL DEFAULT 0"),
                ("cost_usd", "REAL NOT NULL DEFAULT 0"),
            ):
                if name not in decision_columns:
                    connection.execute(f"ALTER TABLE decisions ADD COLUMN {name} {definition}")
            connection.execute(
                """UPDATE decisions
                   SET recommended_action = 'monitor'
                   WHERE event_id IN (
                       SELECT id FROM events
                       WHERE severity = 'medium'
                         AND event_type IN ('ssh_login_failed', 'new_listening_port')
                   )"""
            )
            connection.execute(
                """UPDATE decisions
                   SET requires_human_review = CASE
                       WHEN severity IN ('high', 'critical')
                         OR classification = 'malicious'
                         OR recommended_action IN ('investigate', 'recommend_containment')
                         OR EXISTS (
                             SELECT 1 FROM events
                             WHERE events.id = decisions.event_id
                               AND events.severity IN ('high', 'critical')
                         )
                       THEN 1 ELSE 0 END"""
            )

    def add_event(self, event: SecurityEvent) -> int | None:
        values = event.to_dict()
        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO events (
                    fingerprint, observed_at, host, source, category, event_type,
                    summary, severity, actor, source_ip, destination_ip,
                    source_port, destination_port, process, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.fingerprint(), values["observed_at"], values["host"],
                    values["source"], values["category"], values["event_type"],
                    values["summary"], values["severity"], values["actor"],
                    values["source_ip"], values["destination_ip"],
                    values["source_port"], values["destination_port"],
                    values["process"], json.dumps(values["evidence"], sort_keys=True),
                ),
            )
            return cursor.lastrowid if cursor.rowcount else None

    def get_state(self, key: str, default: Any = None) -> Any:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value_json FROM collector_state WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row["value_json"]) if row else default

    def set_state(self, key: str, value: Any) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO collector_state(key, value_json, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, json.dumps(value, sort_keys=True)),
            )

    def recent_events(
        self, event_type: str, source_ip: str | None, actor: str | None,
        since: str,
    ) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM events
                WHERE event_type = ? AND source_ip IS ? AND actor IS ?
                  AND observed_at >= ?
                ORDER BY observed_at ASC
                """,
                (event_type, source_ip, actor, since),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_event_types(self, event_types: tuple[str, ...], since: str) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in event_types)
        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT * FROM events WHERE event_type IN ({placeholders})
                    AND observed_at >= ? ORDER BY observed_at ASC""",
                (*event_types, since),
            ).fetchall()
        return [dict(row) for row in rows]

    def update_status(self, event_id: int, status: str) -> bool:
        if status not in {"new", "investigating", "resolved", "false_positive"}:
            return False
        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET status = ? WHERE id = ?", (status, event_id)
            )
            return cursor.rowcount == 1

    def recent_external_call_timestamps(self) -> list[float]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT unixepoch(created_at) timestamp FROM decisions
                   WHERE provider <> 'local-rules'
                     AND created_at >= datetime('now', '-1 day')"""
            ).fetchall()
        return [float(row["timestamp"]) for row in rows if row["timestamp"] is not None]

    def add_decision(self, event_id: int, decision: Decision) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO decisions (
                    event_id, classification, severity, recommended_action,
                    confidence, provider, probabilities_json,
                    requires_human_review, rationale, input_tokens,
                    output_tokens, cost_usd
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id, decision.classification, decision.severity,
                    decision.recommended_action, decision.confidence,
                    decision.provider, json.dumps(decision.probabilities),
                    int(decision.requires_human_review), decision.rationale,
                    decision.input_tokens, decision.output_tokens, decision.cost_usd,
                ),
            )

    def list_events(
        self, limit: int = 100, severity: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("e.severity = ?")
            params.append(severity)
        if category:
            clauses.append("e.category = ?")
            params.append(category)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(min(max(limit, 1), 500))
        query = f"""
            SELECT e.*, d.classification, d.recommended_action, d.confidence,
                   d.provider, d.requires_human_review, d.rationale,
                   d.probabilities_json, d.input_tokens, d.output_tokens,
                   d.cost_usd
            FROM events e LEFT JOIN decisions d ON d.event_id = e.id
            {where}
            ORDER BY e.observed_at DESC LIMIT ?
        """
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._decode(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        with self.connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            severity_rows = connection.execute(
                "SELECT severity, COUNT(*) count FROM events GROUP BY severity"
            ).fetchall()
            category_rows = connection.execute(
                "SELECT category, COUNT(*) count FROM events GROUP BY category"
            ).fetchall()
            review = connection.execute(
                """SELECT COUNT(*) FROM decisions d JOIN events e ON e.id=d.event_id
                   WHERE d.requires_human_review = 1
                     AND e.status IN ('new', 'investigating')"""
            ).fetchone()[0]
            monitored = connection.execute(
                """SELECT COUNT(*) FROM decisions d JOIN events e ON e.id=d.event_id
                   WHERE d.requires_human_review = 0
                     AND e.status IN ('new', 'investigating')"""
            ).fetchone()[0]
            usage = connection.execute(
                """SELECT COUNT(*) calls,
                          SUM(CASE WHEN input_tokens > 0 OR output_tokens > 0
                                   OR cost_usd > 0 THEN 1 ELSE 0 END) metered_calls,
                          COALESCE(SUM(input_tokens), 0) input_tokens,
                          COALESCE(SUM(output_tokens), 0) output_tokens,
                          COALESCE(SUM(cost_usd), 0) cost_usd
                   FROM decisions
                   WHERE provider <> 'local-rules'
                     AND created_at >= datetime('now', '-1 day')"""
            ).fetchone()
        return {
            "total_events": total,
            "requires_review": review,
            "monitored": monitored,
            "by_severity": {row["severity"]: row["count"] for row in severity_rows},
            "by_category": {row["category"]: row["count"] for row in category_rows},
            "ai_usage_24h": dict(usage),
        }

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        probabilities = item.pop("probabilities_json", None)
        item["probabilities"] = json.loads(probabilities) if probabilities else {}
        if item.get("requires_human_review") is not None:
            item["requires_human_review"] = bool(item["requires_human_review"])
        return item
