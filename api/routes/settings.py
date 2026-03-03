from __future__ import annotations

from fastapi import APIRouter

from state.shared import ProxyState

router = APIRouter(prefix="/api/settings", tags=["settings"])
state = ProxyState()


@router.get("")
def get_settings():
    return state.get_settings()


@router.post("")
def update_settings(body: dict):
    return state.update_settings(body)
