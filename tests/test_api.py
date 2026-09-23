from pathlib import Path

from jevguard.api import StatusUpdate, create_app
from jevguard.models import SecurityEvent
from jevguard.config import Settings


def test_dashboard_api_and_static_page(tmp_path: Path):
    settings = Settings(
        db_path=tmp_path / "api.db",
        collect_interval=10,
        enable_live_collection=False,
        typesafe_api_key=None,
        jev_model="jev-latest",
    )
    app = create_app(settings)
    endpoints = {
        route.path: route.endpoint
        for route in app.routes
        if hasattr(route, "endpoint")
    }
    health = endpoints["/api/health"]()
    summary = endpoints["/api/summary"]()
    index = endpoints["/"]()

    assert health["decision_provider"] == "local-rules"
    assert summary["total_events"] == 0
    assert str(index.path).endswith("index.html")

    event_id = app.state.store.add_event(SecurityEvent(
        source="test", category="incident", event_type="test",
        summary="test incident",
    ))
    response = endpoints["/api/events/{event_id}/status"](
        event_id, StatusUpdate(status="resolved")
    )
    assert response["status"] == "resolved"
