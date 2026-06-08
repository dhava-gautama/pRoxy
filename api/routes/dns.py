from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from api.auth import create_auth_dependencies

from state.shared import ProxyState

router = APIRouter(prefix="/api/dns", tags=["dns"], dependencies=create_auth_dependencies())
state = ProxyState()


@router.get("")
def get_dns():
    return state.get_dns()


@router.post("")
def update_dns(body: dict):
    try:
        return state.update_dns(body)
    except ValidationError:
        raise HTTPException(422, "Invalid DNS settings")