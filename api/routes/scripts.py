"""Manage custom mitmproxy addon scripts loaded by the proxy."""
from __future__ import annotations

import re

from fastapi import APIRouter, File, HTTPException, UploadFile

from proxy.engine import SCRIPTS_DIR, collect_custom_scripts
from state.shared import ProxyState

router = APIRouter(prefix="/api/scripts", tags=["scripts"])
state = ProxyState()

_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\.py$")

_NOTE = ("Restart the proxy to load newly added/removed scripts; "
         "edits to an already-loaded script hot-reload automatically.")

_SAMPLE = '''import logging

class MyAddon:
    def request(self, flow):
        flow.request.headers["X-pRoxy"] = "1"

    def response(self, flow):
        logging.info("%s -> %s", flow.request.pretty_url, flow.response.status_code)

addons = [MyAddon()]
'''


def _safe_name(name: str) -> str:
    """Allow only a simple *.py filename — no paths/traversal."""
    if "/" in name or "\\" in name or ".." in name or not _NAME_RE.fullmatch(name):
        raise HTTPException(400, "Invalid script name (must be a simple *.py filename)")
    return name


@router.get("")
def list_scripts() -> dict:
    """List addon scripts in the scripts directory and their load status."""
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    loaded = set(collect_custom_scripts(state.get_settings()))
    scripts = []
    for p in sorted(SCRIPTS_DIR.glob("*.py")):
        scripts.append({
            "name": p.name,
            "path": str(p.resolve()),
            "size": p.stat().st_size,
            "loaded": str(p.resolve()) in loaded,
            "ignored": p.name.startswith("_"),  # _-prefixed files are not loaded
        })
    return {
        "scripts_dir": str(SCRIPTS_DIR),
        "scripts": scripts,
        "custom_scripts": state.get_settings().custom_scripts,
        "note": _NOTE,
    }


@router.get("/sample")
def sample_script() -> dict:
    """Return a minimal addon template to start from."""
    return {"filename": "my_addon.py", "content": _SAMPLE}


@router.post("/upload")
async def upload_script(file: UploadFile = File(...)) -> dict:
    """Upload a .py mitmproxy addon into the scripts directory."""
    name = _safe_name(file.filename or "")
    content = (await file.read()).decode("utf-8", errors="replace")
    try:
        compile(content, name, "exec")  # reject files that don't parse as Python
    except SyntaxError as e:
        raise HTTPException(400, f"Script has a syntax error: {e}")
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    dest = SCRIPTS_DIR / name
    dest.write_text(content)
    return {"name": name, "path": str(dest.resolve()), "bytes": len(content), "note": _NOTE}


@router.delete("/{name}")
def delete_script(name: str) -> dict:
    """Delete a script from the scripts directory."""
    name = _safe_name(name)
    p = SCRIPTS_DIR / name
    if not p.is_file():
        raise HTTPException(404, "Script not found")
    p.unlink()
    return {"ok": True, "note": _NOTE}
