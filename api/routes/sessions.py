"""Save and load capture sessions.

Flows live in ProxyState in-memory only and are lost on restart. This route
persists the current flows to a JSON file on disk and restores them later,
letting users keep named snapshots of captured traffic across restarts.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from state.models import FlowRecord
from state.shared import ProxyState

router = APIRouter(prefix="/api/sessions", tags=["sessions"])
state = ProxyState()

SESSIONS_DIR = Path.home() / ".pRoxy" / "sessions"

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_name(name: str) -> str:
    """Validate a session name, rejecting path traversal.

    Rejects empty names, names containing path separators or ``..``, names
    starting with ``.`` (hidden files), and anything outside [A-Za-z0-9._-].
    """
    if not name or "/" in name or "\\" in name or ".." in name or name.startswith("."):
        raise HTTPException(400, "Invalid session name")
    if not _NAME_RE.fullmatch(name):
        raise HTTPException(400, "Invalid session name")
    return name


def _path_for(name: str) -> Path:
    return SESSIONS_DIR / f"{_safe_name(name)}.json"


class SaveRequest(BaseModel):
    name: str


class LoadRequest(BaseModel):
    name: str
    clear: bool = True


@router.get("")
def list_sessions():
    """List saved sessions: [{name, count, size_bytes, modified}]."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    sessions = []
    for path in sorted(SESSIONS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            count = len(data) if isinstance(data, list) else 0
        except (ValueError, OSError):
            continue
        stat = path.stat()
        sessions.append({
            "name": path.stem,
            "count": count,
            "size_bytes": stat.st_size,
            "modified": stat.st_mtime,
        })
    return sessions


@router.post("/save")
def save_session(req: SaveRequest):
    """Dump the current flows to a named session file."""
    path = _path_for(req.name)
    flows = state.get_flows(limit=100000)
    data = [f.model_dump() for f in flows]
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return {"name": req.name, "count": len(data)}


@router.post("/load")
def load_session(req: LoadRequest):
    """Restore flows from a named session file into ProxyState."""
    path = _path_for(req.name)
    if not path.exists():
        raise HTTPException(404, "Session not found")
    data = json.loads(path.read_text())
    if req.clear:
        state.clear_flows()
    loaded = 0
    for d in data:
        try:
            state.store_flow(FlowRecord(**d))
            loaded += 1
        except Exception:
            continue
    return {"loaded": loaded}


@router.delete("/{name}")
def delete_session(name: str):
    """Delete a named session file."""
    path = _path_for(name)
    if not path.exists():
        raise HTTPException(404, "Session not found")
    path.unlink()
    return {"ok": True}
