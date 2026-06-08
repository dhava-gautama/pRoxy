from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.exceptions import WebSocketException

from api.auth import verify_auth_key, AUTH_DISABLED

router = APIRouter()
logger = logging.getLogger("pRoxy.ws")

# Managed by the drain task in server.py
ws_clients: set[asyncio.Queue] = set()


@router.websocket("/ws/traffic")
async def traffic_ws(websocket: WebSocket):
    # Check authentication for WebSocket connection
    if not AUTH_DISABLED:
        # Check for auth key in query parameters
        key = websocket.query_params.get("key")
        if not key or not verify_auth_key(key):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication required")
            return

    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    ws_clients.add(q)
    try:
        while True:
            data = await q.get()
            if data is None:
                break  # Shutdown signal
            await websocket.send_json(data)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        logger.debug("WebSocket closed")
    finally:
        ws_clients.discard(q)
