from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import Settings
from .db import EventStore
from .models import SEVERITIES
from .service import MonitoringService


STATIC_DIR = Path(__file__).parent / "static"


class StatusUpdate(BaseModel):
    status: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = EventStore(settings.db_path)
    service = MonitoringService(store, settings)
    task: asyncio.Task[None] | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        nonlocal task
        if settings.enable_live_collection:
            task = asyncio.create_task(service.run(settings.collect_interval))
        yield
        service.stop()
        if task:
            task.cancel()

    app = FastAPI(title="JevGuard Linux SIEM", version="0.1.0", lifespan=lifespan)
    app.state.store = store
    app.state.service = service

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "live_collection": settings.enable_live_collection,
            "decision_provider": service.provider.name,
            "collector_error": service.last_error,
            "collector_errors": service.errors,
            "capabilities": service.capabilities(),
        }

    @app.get("/api/summary")
    def summary():
        return store.summary()

    @app.get("/api/events")
    def events(
        limit: int = Query(100, ge=1, le=500),
        severity: str | None = Query(None),
        category: str | None = Query(None),
    ):
        if severity and severity not in SEVERITIES:
            return []
        return store.list_events(limit=limit, severity=severity, category=category)

    @app.post("/api/collect")
    def collect():
        return {"new_events": service.collect_once()}

    @app.patch("/api/events/{event_id}/status")
    def update_status(event_id: int, update: StatusUpdate):
        if not store.update_status(event_id, update.status):
            raise HTTPException(status_code=400, detail="Invalid event or status")
        return {"id": event_id, "status": update.status}

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
