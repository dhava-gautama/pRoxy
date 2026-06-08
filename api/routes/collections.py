from __future__ import annotations

import time
from fastapi import Depends,  APIRouter, HTTPException

from api.auth import get_current_user, AUTH_DISABLED
from state.models import SavedCollection
from state.shared import ProxyState

router = APIRouter(prefix="/api/collections", tags=["collections"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()


@router.get("")
def list_collections():
    return [c.model_dump() for c in state.get_collections()]


@router.get("/{collection_id}")
def get_collection(collection_id: str):
    c = state.get_collection(collection_id)
    if c is None:
        raise HTTPException(404, "Collection not found")
    return c.model_dump()


@router.post("")
async def create_collection(data: dict):
    col = SavedCollection(
        id=data.get("id") or f"col-{int(time.time()*1000)}",
        name=data.get("name", "Untitled"),
        requests=data.get("requests", []),
    )
    return state.save_collection(col).model_dump()


@router.put("/{collection_id}")
async def update_collection(collection_id: str, data: dict):
    existing = state.get_collection(collection_id)
    if existing is None:
        raise HTTPException(404, "Collection not found")
    col = SavedCollection(
        id=collection_id,
        name=data.get("name", existing.name),
        requests=data.get("requests", [r.model_dump() for r in existing.requests]),
    )
    return state.save_collection(col).model_dump()


@router.delete("/{collection_id}")
def delete_collection(collection_id: str):
    if not state.delete_collection(collection_id):
        raise HTTPException(404, "Collection not found")
    return {"ok": True}