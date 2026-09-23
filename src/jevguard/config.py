from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    db_path: Path
    collect_interval: float
    enable_live_collection: bool
    typesafe_api_key: str | None
    jev_model: str
    ai_provider: str = "local"
    openrouter_api_key: str | None = None
    openrouter_model: str | None = None
    ai_api_key: str | None = None
    ai_base_url: str | None = None
    ai_model: str | None = None
    ai_max_per_hour: int = 10
    ai_max_per_day: int = 100
    ai_min_severity: str = "high"
    ai_cooldown_seconds: int = 3600
    allowed_listeners: tuple[str, ...] = (
        "tcp:22:sshd", "udp:53:*", "udp:5353:*",
    )

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
        return cls(
            db_path=Path(os.getenv("JEVGUARD_DB_PATH", "data/jevguard.db")),
            collect_interval=max(
                2.0, float(os.getenv("JEVGUARD_COLLECT_INTERVAL", "10"))
            ),
            enable_live_collection=_boolean(
                "JEVGUARD_ENABLE_LIVE_COLLECTION", True
            ),
            typesafe_api_key=os.getenv("TYPESAFE_API_KEY") or None,
            jev_model=os.getenv("JEVGUARD_JEV_MODEL", "jev-latest"),
            ai_provider=os.getenv("JEVGUARD_AI_PROVIDER", "local").strip().lower(),
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY") or None,
            openrouter_model=os.getenv("OPENROUTER_MODEL") or None,
            ai_api_key=os.getenv("AI_API_KEY") or None,
            ai_base_url=os.getenv("AI_BASE_URL") or None,
            ai_model=os.getenv("AI_MODEL") or None,
            ai_max_per_hour=max(0, int(os.getenv("JEVGUARD_AI_MAX_PER_HOUR", "10"))),
            ai_max_per_day=max(0, int(os.getenv("JEVGUARD_AI_MAX_PER_DAY", "100"))),
            ai_min_severity=os.getenv("JEVGUARD_AI_MIN_SEVERITY", "high").lower(),
            ai_cooldown_seconds=max(
                0, int(os.getenv("JEVGUARD_AI_COOLDOWN_SECONDS", "3600"))
            ),
            allowed_listeners=tuple(
                item.strip() for item in os.getenv(
                    "JEVGUARD_ALLOWED_LISTENERS",
                    "tcp:22:sshd,udp:53:*,udp:5353:*",
                ).split(",") if item.strip()
            ),
        )
