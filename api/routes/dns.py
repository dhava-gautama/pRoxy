from __future__ import annotations

from fastapi import APIRouter

from state.shared import ProxyState

router = APIRouter(prefix="/api/dns", tags=["dns"])
state = ProxyState()


@router.get("")
def get_dns():
    return state.get_dns()


@router.post("")
def update_dns(body: dict):
    return state.update_dns(body)
