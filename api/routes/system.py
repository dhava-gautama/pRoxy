"""System control endpoints (restart, etc.)."""
from __future__ import annotations

import os
import sys
import threading

from fastapi import APIRouter

router = APIRouter(prefix="/api/system", tags=["system"])


def _reexec() -> None:
    """Replace the current process with a fresh one (same interpreter + argv).

    Python's listening sockets are CLOEXEC by default, so they close on exec and
    the new process rebinds the same ports. This picks up new addon scripts,
    settings, and code without an external supervisor.
    """
    os.execv(sys.executable, [sys.executable] + sys.argv)


@router.post("/restart")
def restart() -> dict:
    """Restart the whole pRoxy process.

    Responds first, then re-execs ~0.8s later so the client gets this reply
    before the dashboard briefly drops and comes back. NOTE: unsaved captured
    traffic is cleared (it lives in memory) — save a session first if needed.
    """
    t = threading.Timer(0.8, _reexec)
    t.daemon = True  # don't let a pending restart block interpreter exit
    t.start()
    return {
        "restarting": True,
        "message": "Restarting pRoxy — the dashboard will reconnect in a few seconds.",
    }
