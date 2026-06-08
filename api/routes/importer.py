"""Import captured traffic from HAR archives or pRoxy flow exports.

Auto-detects the payload shape:
  * HAR  — a dict with a top-level ``log.entries`` list (browser/DevTools export).
  * Flow list — a list of FlowRecord-like dicts (or a dict with a ``flows`` key),
    e.g. a previous pRoxy export.

Each parsed entry becomes a FlowRecord stored in ProxyState and pushed onto the
live traffic queue so it shows up in the UI immediately. Per-entry failures are
caught and counted rather than failing the whole import.
"""
from __future__ import annotations

import datetime
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Body, HTTPException

from state.models import FlowRecord
from state.shared import ProxyState

router = APIRouter(prefix="/api/import", tags=["import"])
state = ProxyState()


def _headers_to_dict(headers: Any) -> dict[str, str]:
    """Convert a HAR header list [{name, value}, ...] into a dict."""
    result: dict[str, str] = {}
    if isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict) and "name" in h:
                result[str(h["name"])] = str(h.get("value", ""))
    return result


def _parse_started(started: Any) -> float:
    """Parse a HAR startedDateTime (ISO 8601) into epoch seconds, else 0.0."""
    if not isinstance(started, str) or not started:
        return 0.0
    try:
        # Python's fromisoformat accepts a trailing 'Z' only on 3.11+; normalize.
        normalized = started.replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(normalized).timestamp()
    except (ValueError, OverflowError):
        return 0.0


def _entry_to_flow(entry: dict, index: int) -> FlowRecord:
    """Map a single HAR entry to a FlowRecord."""
    request = entry.get("request") or {}
    response = entry.get("response") or {}

    url = str(request.get("url", ""))
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme else 0)

    req_headers = _headers_to_dict(request.get("headers"))
    post_data = request.get("postData") or {}
    request_body = str(post_data.get("text", "")) if isinstance(post_data, dict) else ""
    request_content_type = ""
    if isinstance(post_data, dict):
        request_content_type = str(post_data.get("mimeType", ""))
    if not request_content_type:
        request_content_type = req_headers.get("Content-Type", req_headers.get("content-type", ""))

    content = response.get("content") or {}
    response_body = str(content.get("text", "")) if isinstance(content, dict) else ""
    response_content_type = str(content.get("mimeType", "")) if isinstance(content, dict) else ""

    return FlowRecord(
        id=f"import-{index}",
        timestamp=_parse_started(entry.get("startedDateTime")),
        method=str(request.get("method", "")),
        scheme=parsed.scheme,
        host=parsed.hostname or "",
        port=port,
        path=parsed.path + (("?" + parsed.query) if parsed.query else ""),
        url=url,
        request_headers=req_headers,
        request_body=request_body,
        request_content_type=request_content_type,
        status_code=int(response.get("status", 0) or 0),
        reason=str(response.get("statusText", "")),
        response_headers=_headers_to_dict(response.get("headers")),
        response_body=response_body,
        response_content_type=response_content_type,
        completed=True,
    )


def _store(flow: FlowRecord) -> None:
    """Persist a flow and push it onto the live traffic queue."""
    state.store_flow(flow)
    state.traffic_queue.put(flow)


@router.post("/har")
def import_traffic(body: Any = Body(...)) -> dict:
    """Import a parsed HAR dict or a pRoxy flow list.

    Returns ``{"imported": n, "errors": [...]}``. Empty/unrecognized input -> 400.
    """
    errors: list[str] = []
    imported = 0

    # ── HAR archive: {"log": {"entries": [...]}} ──
    if isinstance(body, dict) and isinstance(body.get("log"), dict):
        entries = body["log"].get("entries")
        if not isinstance(entries, list):
            raise HTTPException(400, "HAR 'log.entries' must be a list")
        for i, entry in enumerate(entries):
            try:
                if not isinstance(entry, dict):
                    raise ValueError("entry is not an object")
                _store(_entry_to_flow(entry, i))
                imported += 1
            except Exception as e:
                errors.append(f"entry {i}: {e}")
        return {"imported": imported, "errors": errors}

    # ── Generic flow list: a bare list, or {"flows": [...]} ──
    flows: Any = None
    if isinstance(body, list):
        flows = body
    elif isinstance(body, dict) and isinstance(body.get("flows"), list):
        flows = body["flows"]

    if flows is None:
        raise HTTPException(400, "Unrecognized import format: expected a HAR object or a flow list")
    if not flows:
        raise HTTPException(400, "No entries to import")

    for i, item in enumerate(flows):
        try:
            if not isinstance(item, dict):
                raise ValueError("flow is not an object")
            data = dict(item)
            data.setdefault("id", f"import-{i}")
            data.setdefault("timestamp", 0.0)
            _store(FlowRecord(**data))
            imported += 1
        except Exception as e:
            errors.append(f"flow {i}: {e}")

    return {"imported": imported, "errors": errors}
