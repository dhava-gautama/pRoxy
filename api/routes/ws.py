from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()
logger = logging.getLogger("pRoxy.ws")

# Managed by the drain task in server.py
ws_clients: set[asyncio.Queue] = set()


@router.websocket("/ws/traffic")
async def traffic_ws(websocket: WebSocket):
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
