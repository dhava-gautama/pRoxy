from __future__ import annotations

import json
import time
import urllib.parse

from fastapi import APIRouter, HTTPException, UploadFile, File, Depends
from fastapi.responses import JSONResponse

from api.auth import get_current_user, AUTH_DISABLED
from state.models import FlowRecord, WSMessage
from state.shared import ProxyState
from api.decoders import protobuf_decoder

router = APIRouter(
    prefix="/api/flows",
    tags=["flows"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()


@router.get("")
def list_flows(limit: int = 200, offset: int = 0):
    return state.get_flows(limit=limit, offset=offset)


@router.get("/lite")
def list_flows_lite(limit: int = 500, offset: int = 0):
    """Return flows without bodies for faster list loading."""
    return state.get_flows_lite(limit=limit, offset=offset)


@router.get("/search")
def search_flows(q: str = "", regex: bool = False, limit: int = 200):
    if not q:
        return []
    return state.search_flows(q, is_regex=regex, limit=limit)


@router.get("/export/har")
def export_har(limit: int = 5000):
    """Export flows as HAR 1.2 format."""
    flows = state.get_flows(limit=limit)
    entries = []
    for f in flows:
        entry = {
            "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(f.timestamp)),
            "time": f.duration_ms,
            "request": {
                "method": f.method,
                "url": f.url,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in f.request_headers.items()],
                "queryString": [],
                "bodySize": len(f.request_body),
                "postData": {"mimeType": f.request_content_type, "text": f.request_body} if f.request_body else None,
            },
            "response": {
                "status": f.status_code,
                "statusText": f.reason,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in f.response_headers.items()],
                "content": {
                    "size": len(f.response_body),
                    "mimeType": f.response_content_type,
                    "text": f.response_body,
                },
                "bodySize": len(f.response_body),
            },
            "cache": {},
            "timings": {"send": 0, "wait": f.duration_ms, "receive": 0},
        }
        if f.flow_type == "websocket" and f.ws_messages:
            entry["_webSocketMessages"] = [
                {
                    "time": msg.timestamp,
                    "opcode": 1 if msg.is_text else 2,
                    "data": msg.content,
                    "type": "send" if msg.direction == "client" else "receive",
                }
                for msg in f.ws_messages
            ]
        entries.append(entry)

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "pRoxy", "version": "1.0"},
            "entries": entries,
        }
    }
    return JSONResponse(content=har, headers={
        "Content-Disposition": "attachment; filename=proxy_export.har"
    })


@router.post("/import/har")
async def import_har(file: UploadFile = File(...)):
    """Import flows from HAR file."""
    try:
        content = await file.read()
        har = json.loads(content)
        entries = har.get("log", {}).get("entries", [])
        imported = 0
        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            url = req.get("url", "")
            parsed = urllib.parse.urlparse(url)
            flow = FlowRecord(
                id=f"import-{imported}-{int(time.time()*1000)}",
                timestamp=time.time(),
                method=req.get("method", "GET"),
                scheme=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                path=parsed.path + ("?" + parsed.query if parsed.query else ""),
                url=url,
                request_headers={h["name"]: h["value"] for h in req.get("headers", [])},
                request_body=(req.get("postData") or {}).get("text") or "",
                request_content_type=(req.get("postData") or {}).get("mimeType") or "",
                status_code=resp.get("status", 0),
                reason=resp.get("statusText", ""),
                response_headers={h["name"]: h["value"] for h in resp.get("headers", [])},
                response_body=(resp.get("content") or {}).get("text") or "",
                response_content_type=(resp.get("content") or {}).get("mimeType") or "",
                completed=resp.get("status", 0) > 0,
                duration_ms=entry.get("time", 0),
            )
            ws_msgs = entry.get("_webSocketMessages", [])
            if ws_msgs:
                flow.flow_type = "websocket"
                flow.ws_messages = [
                    WSMessage(
                        direction="client" if m.get("type") == "send" else "server",
                        content=m.get("data", ""),
                        timestamp=m.get("time", 0),
                        is_text=m.get("opcode", 1) == 1,
                        size=len(m.get("data", "").encode("utf-8")),
                    )
                    for m in ws_msgs
                ]
            state.store_flow(flow)
            imported += 1
        return {"imported": imported}
    except Exception as e:
        raise HTTPException(400, f"Invalid HAR file: {e}")


@router.post("/{flow_id}/ws/send")
async def ws_send_message(flow_id: str, data: dict):
    """Inject a WebSocket message into an active connection."""
    content = data.get("content", "")
    to_client = data.get("to_client", False)
    if not content:
        raise HTTPException(400, "content is required")
    addon = state.proxy_addon
    if addon is None:
        raise HTTPException(503, "Proxy addon not available")
    ok = addon.inject_ws_message(flow_id, content, to_client)
    if not ok:
        raise HTTPException(404, "WebSocket connection not active")
    return {"ok": True}


@router.get("/{flow_id}/ws/active")
def ws_check_active(flow_id: str):
    """Check if a WebSocket connection is still active."""
    addon = state.proxy_addon
    if addon is None:
        return {"active": False}
    return {"active": flow_id in addon.get_active_ws_ids()}


@router.get("/{flow_id}/curl")
def flow_to_curl(flow_id: str):
    """Generate a cURL command for a flow."""
    flow = state.get_flow(flow_id)
    if flow is None:
        raise HTTPException(404, "Flow not found")
    parts = [f"curl -X {flow.method}"]
    for k, v in flow.request_headers.items():
        parts.append(f"  -H '{k}: {v}'")
    if flow.request_body and not flow.request_body.startswith("<binary"):
        escaped = flow.request_body.replace("'", "'\\''")
        parts.append(f"  -d '{escaped}'")
    parts.append(f"  '{flow.url}'")
    return {"curl": " \\\n".join(parts)}


@router.get("/{flow_id}")
def get_flow(flow_id: str):
    flow = state.get_flow(flow_id)
    if flow is None:
        raise HTTPException(404, "Flow not found")
    return flow


@router.get("/{flow_id}/protobuf")
def decode_flow_protobuf(flow_id: str):
    """Decode protobuf content from a flow"""
    flow = state.get_flow(flow_id)
    if flow is None:
        raise HTTPException(404, "Flow not found")

    decoded = protobuf_decoder.decode_flow(flow)
    if decoded is None:
        raise HTTPException(400, "Flow does not contain decodable protobuf content")

    return decoded


@router.delete("/{flow_id}")
def delete_flow(flow_id: str):
    if not state.delete_flow(flow_id):
        raise HTTPException(404, "Flow not found")
    return {"ok": True}


@router.delete("")
def clear_flows():
    import logging
    from api.routes import ws
    import asyncio
    logger = logging.getLogger("pRoxy.flows")

    try:
        n = state.clear_flows()
        logger.info(f"Successfully cleared {n} flows")

        # Notify WebSocket clients about the clear operation
        if ws.ws_clients:
            clear_notification = {
                "type": "flows_cleared",
                "deleted": n,
                "timestamp": time.time()
            }
            dead_clients = []
            for client in list(ws.ws_clients):
                try:
                    client.put_nowait(clear_notification)
                except Exception:
                    dead_clients.append(client)

            # Clean up dead clients
            for client in dead_clients:
                ws.ws_clients.discard(client)

        return {"deleted": n}
    except Exception as e:
        logger.error(f"Error clearing flows: {e}")
        raise HTTPException(500, f"Failed to clear flows: {e}")
