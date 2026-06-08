"""Authorization / IDOR tester.

Replay a single request under multiple authentication profiles and diff the
responses to surface broken access control (IDOR / missing authz checks).

The idea: take one request (supplied directly or seeded from a captured flow),
then send it once per profile with that profile's header overrides merged in.
Compare every alternate profile against a chosen baseline (the authorized,
high-privilege identity). If an alternate identity gets an effectively identical
successful response, that profile is flagged as possible broken access control.

This is a legitimate testing feature of an authorized pentest tool — it only
replays requests the operator already has and explicitly configures.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx
from fastapi import APIRouter, HTTPException

from api.routes.replay import _do_request
from state.shared import ProxyState

router = APIRouter(prefix="/api/authz", tags=["authz"])
state = ProxyState()

# A response counts as "effectively the same" as the baseline when both succeed
# (2xx) and the body lengths are within this fraction of each other.
_LENGTH_TOLERANCE = 0.10
_SNIPPET_LEN = 200


def _is_2xx(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


@router.post("/test")
async def authz_test(data: dict) -> dict:
    """Replay one request under multiple auth profiles and diff the responses."""
    method = data.get("method", "GET")
    url = data.get("url", "")
    headers: dict = dict(data.get("headers") or {})
    body = data.get("body", "") or ""
    profiles = data.get("profiles") or []
    baseline_name = data.get("baseline")

    # Seed request fields from a captured flow when they weren't supplied.
    flow_id = data.get("flow_id")
    if flow_id:
        flow = state.get_flow(flow_id)
        if flow is None:
            raise HTTPException(400, f"Flow not found: {flow_id}")
        if not url:
            url = flow.url
        if "method" not in data:
            method = flow.method or method
        if not headers:
            headers = dict(flow.request_headers or {})
        if not body:
            body = flow.request_body or ""

    if not url:
        raise HTTPException(400, "Missing 'url' and no resolvable 'flow_id'")
    if not profiles:
        raise HTTPException(400, "At least one profile is required")

    results: list[dict[str, Any]] = []
    for profile in profiles:
        name = profile.get("name", "")
        overrides = profile.get("headers") or {}
        # Profile headers win over the base request headers.
        merged = {**headers, **overrides}
        try:
            resp = await _do_request(method, url, merged, body)
            resp_body = resp.get("body", "") or ""
            results.append({
                "name": name,
                "status_code": resp.get("status_code"),
                "length": len(resp_body),
                "snippet": resp_body[:_SNIPPET_LEN],
                "duration_ms": resp.get("duration_ms"),
                "error": None,
            })
        except httpx.RequestError as e:
            results.append({
                "name": name,
                "status_code": None,
                "length": 0,
                "snippet": "",
                "duration_ms": None,
                "error": str(e),
            })

    # Pick the baseline result: the named one, else the first.
    baseline = None
    if baseline_name:
        baseline = next((r for r in results if r["name"] == baseline_name), None)
    if baseline is None:
        baseline = results[0]

    flagged: list[str] = []
    for r in results:
        if r is baseline:
            continue
        if not _is_2xx(r["status_code"]) or not _is_2xx(baseline["status_code"]):
            continue
        base_len = baseline["length"]
        if base_len == 0:
            same_length = r["length"] == 0
        else:
            same_length = abs(r["length"] - base_len) <= _LENGTH_TOLERANCE * base_len
        if same_length:
            flagged.append(r["name"])

    if flagged:
        analysis = (
            f"Possible broken access control: {len(flagged)} profile(s) "
            f"({', '.join(flagged)}) received a successful response "
            f"effectively identical to baseline '{baseline['name']}'. "
            f"These identities may be accessing resources they should not."
        )
    else:
        analysis = (
            f"No broken access control detected against baseline "
            f"'{baseline['name']}'. Alternate profiles differed in status or "
            f"response length."
        )

    return {
        "results": results,
        "baseline": baseline["name"],
        "flagged": flagged,
        "analysis": analysis,
    }
