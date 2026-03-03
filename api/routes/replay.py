from __future__ import annotations

import time
import httpx
from fastapi import APIRouter, HTTPException
from state.models import ReplayRequest, FlowRecord
from state.shared import ProxyState

router = APIRouter(prefix="/api/replay", tags=["replay"])
state = ProxyState()


@router.post("")
async def replay_request(req: ReplayRequest):
    """Send an HTTP request and return the response. Acts as a built-in Repeater."""
    try:
        start = time.time()
        async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=True) as client:
            response = await client.request(
                method=req.method,
                url=req.url,
                headers=req.headers or None,
                content=req.body.encode("utf-8") if req.body else None,
            )
        duration = round((time.time() - start) * 1000, 1)

        # Build response data
        resp_headers = dict(response.headers)
        ct = resp_headers.get("content-type", "")
        try:
            body = response.text if response.text else ""
        except Exception:
            body = f"<binary {len(response.content)} bytes>"

        # Store as a flow record
        import urllib.parse
        parsed = urllib.parse.urlparse(req.url)
        flow = FlowRecord(
            id=f"replay-{int(time.time()*1000)}",
            timestamp=time.time(),
            method=req.method,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            path=parsed.path + ("?" + parsed.query if parsed.query else ""),
            url=req.url,
            request_headers=req.headers,
            request_body=req.body,
            request_content_type=req.headers.get("content-type", ""),
            status_code=response.status_code,
            reason=response.reason_phrase or "",
            response_headers=resp_headers,
            response_body=body[:512_000],
            response_content_type=ct,
            completed=True,
            duration_ms=duration,
        )
        state.store_flow(flow)
        state.traffic_queue.put(flow)

        return {
            "id": flow.id,
            "status_code": response.status_code,
            "reason": response.reason_phrase,
            "headers": resp_headers,
            "body": body[:512_000],
            "duration_ms": duration,
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")
