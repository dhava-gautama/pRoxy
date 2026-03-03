from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from state.shared import ProxyState

router = APIRouter(prefix="/api/intercept", tags=["intercept"])
state = ProxyState()


@router.get("/queue")
def get_intercept_queue():
    return state.get_intercept_queue()


class ResolveBody(BaseModel):
    action: str  # "forward" or "drop"
    modified_body: Optional[str] = None
    modified_headers: Optional[dict[str, str]] = None


@router.post("/{flow_id}/{phase}")
def resolve_intercept(flow_id: str, phase: str, body: ResolveBody):
    if body.action not in ("forward", "drop"):
        raise HTTPException(400, "action must be 'forward' or 'drop'")
    if phase not in ("request", "response"):
        raise HTTPException(400, "phase must be 'request' or 'response'")
    key = f"{flow_id}:{phase}"
    ok = state.resolve_intercept(
        key,
        body.action,
        modified_body=body.modified_body,
        modified_headers=body.modified_headers,
    )
    if not ok:
        raise HTTPException(404, "Flow not in intercept queue")
    return {"ok": True}
