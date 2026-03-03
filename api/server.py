from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.routes import flows, settings, dns, intercept, cert, ws, replay
from state.shared import ProxyState

logger = logging.getLogger("pRoxy.api")
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


_shutdown_event: asyncio.Event | None = None


async def _drain_traffic_queue(state: ProxyState) -> None:
    """Background task: pull FlowRecords from the thread-safe queue and fan out to WebSocket clients."""
    loop = asyncio.get_event_loop()
    while True:
        try:
            record = await loop.run_in_executor(None, state.traffic_queue.get, True, 0.2)
        except Exception:
            continue
        data = record.model_dump()
        dead: list[asyncio.Queue] = []
        for q in list(ws.ws_clients):
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            ws.ws_clients.discard(q)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _shutdown_event
    _shutdown_event = asyncio.Event()
    state = ProxyState()
    task = asyncio.create_task(_drain_traffic_queue(state))
    print("[pRoxy.api] Drain task started")
    yield
    # Signal WebSocket handlers to stop, then cancel drain task
    _shutdown_event.set()
    # Wake up all WS client queues so they see the shutdown
    for q in list(ws.ws_clients):
        try:
            q.put_nowait(None)
        except asyncio.QueueFull:
            pass
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app() -> FastAPI:
    app = FastAPI(title="pRoxy", version="1.0.0", lifespan=lifespan)

    # API routes
    app.include_router(flows.router)
    app.include_router(settings.router)
    app.include_router(dns.router)
    app.include_router(intercept.router)
    app.include_router(cert.router)
    app.include_router(replay.router)
    app.include_router(ws.router)

    # Serve frontend static files
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

    return app
