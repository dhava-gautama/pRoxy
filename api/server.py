from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from api.auth import get_current_user, security, AUTH_DISABLED
from api.routes import flows, settings, dns, intercept, cert, ws, replay, collections, stress, recon, scanner, tamper, auth_test, exploit, analytics, threat_detection, rules, proxy, tcp_proxy, content_processing, wireguard, ssl, proxy_manager, openapi, importer, sessions, issues, authz, scripts, system
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
    app = FastAPI(
        title="pRoxy",
        version="1.0.0",
        description="Web-based MITM Proxy with Real-time Dashboard",
        lifespan=lifespan
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, specify allowed origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routes (protected by global auth dependency)
    app.include_router(flows.router)
    app.include_router(settings.router)
    app.include_router(dns.router)
    app.include_router(intercept.router)
    app.include_router(cert.router)
    app.include_router(replay.router)
    app.include_router(collections.router)
    app.include_router(stress.router)
    app.include_router(recon.router)
    app.include_router(scanner.router)
    app.include_router(tamper.router)
    app.include_router(auth_test.router)
    app.include_router(exploit.router)
    app.include_router(analytics.router)
    app.include_router(threat_detection.router)
    app.include_router(rules.router)
    app.include_router(proxy.router)
    app.include_router(tcp_proxy.router)
    app.include_router(content_processing.router)
    app.include_router(wireguard.router)
    app.include_router(ssl.router)
    app.include_router(proxy_manager.router)
    app.include_router(openapi.router)
    app.include_router(importer.router)
    app.include_router(sessions.router)
    app.include_router(issues.router)
    app.include_router(authz.router)
    app.include_router(scripts.router)
    app.include_router(system.router)
    app.include_router(ws.router)

    # Serve frontend static files (authentication handled by query param)
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

    if not AUTH_DISABLED:
        print("[pRoxy.auth] Authentication enabled. Use ?key=YOUR_KEY in dashboard URL")
    else:
        print("[pRoxy.auth] Authentication disabled via PROXY_DISABLE_AUTH")

    return app
