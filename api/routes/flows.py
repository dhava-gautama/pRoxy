from __future__ import annotations

import json
import time
import urllib.parse

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse

from state.models import FlowRecord, ReplayRequest
from state.shared import ProxyState

router = APIRouter(prefix="/api/flows", tags=["flows"])
state = ProxyState()


@router.get("")
def list_flows(limit: int = 200, offset: int = 0):
    return state.get_flows(limit=limit, offset=offset)


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
                request_body=(req.get("postData") or {}).get("text", ""),
                request_content_type=(req.get("postData") or {}).get("mimeType", ""),
                status_code=resp.get("status", 0),
                reason=resp.get("statusText", ""),
                response_headers={h["name"]: h["value"] for h in resp.get("headers", [])},
                response_body=(resp.get("content") or {}).get("text", ""),
                response_content_type=(resp.get("content") or {}).get("mimeType", ""),
                completed=resp.get("status", 0) > 0,
                duration_ms=entry.get("time", 0),
            )
            state.store_flow(flow)
            imported += 1
        return {"imported": imported}
    except Exception as e:
        raise HTTPException(400, f"Invalid HAR file: {e}")


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


@router.delete("/{flow_id}")
def delete_flow(flow_id: str):
    if not state.delete_flow(flow_id):
        raise HTTPException(404, "Flow not found")
    return {"ok": True}


@router.delete("")
def clear_flows():
    n = state.clear_flows()
    return {"deleted": n}
