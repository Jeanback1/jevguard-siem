from __future__ import annotations

import argparse
import json

import uvicorn

from .config import Settings
from .db import EventStore
from .models import SecurityEvent
from .service import MonitoringService, seed_demo


def main() -> None:
    parser = argparse.ArgumentParser(prog="jevguard")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="start the local dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    commands.add_parser("collect-once", help="collect current host telemetry")
    commands.add_parser("seed-demo", help="insert safe demonstration events")
    commands.add_parser(
        "test-ai", help="send one safe synthetic event to the configured provider"
    )
    args = parser.parse_args()
    settings = Settings.from_env()

    if args.command == "serve":
        uvicorn.run(
            "jevguard.api:create_app", host=args.host, port=args.port,
            factory=True, reload=False,
        )
        return

    service = MonitoringService(EventStore(settings.db_path), settings)
    if args.command == "collect-once":
        print(f"Stored {service.collect_once()} new events")
    elif args.command == "seed-demo":
        print(f"Stored {seed_demo(service)} demonstration events")
    elif args.command == "test-ai":
        event = SecurityEvent(
            source="provider-test",
            category="authentication",
            event_type="ssh_login_failed",
            summary="Synthetic failed SSH login used to test the configured provider",
            severity="medium",
            actor="demo-user",
            source_ip="192.0.2.25",
            evidence={"attempts": 6, "window_seconds": 60, "synthetic": True},
        )
        decision = service.provider.decide(event)
        print(json.dumps({
            "provider": decision.provider,
            "classification": decision.classification,
            "severity": decision.severity,
            "recommended_action": decision.recommended_action,
            "confidence": decision.confidence,
            "requires_human_review": decision.requires_human_review,
            "rationale": decision.rationale,
        }, indent=2))


if __name__ == "__main__":
    main()
