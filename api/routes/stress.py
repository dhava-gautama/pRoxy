from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends,  APIRouter, HTTPException

from api.auth import get_current_user, AUTH_DISABLED

router = APIRouter(prefix="/api/stress", tags=["stress"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)

BINARY = Path(__file__).resolve().parent.parent.parent / "stresstest"


def _validate_target_url(url: str) -> None:
    """Reject non-http(s) schemes and private/loopback/link-local hosts (SSRF guard)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "Only http(s) URLs are allowed")

    host = parsed.hostname
    if not host:
        raise HTTPException(400, "URL must include a host")

    # Resolve hostname to all candidate IPs; reject if any is private/reserved.
    candidates = []
    try:
        candidates.append(ipaddress.ip_address(host))
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            raise HTTPException(400, "Could not resolve host")
        for info in infos:
            try:
                candidates.append(ipaddress.ip_address(info[4][0]))
            except ValueError:
                continue

    if not candidates:
        raise HTTPException(400, "Could not resolve host")

    for ip in candidates:
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise HTTPException(400, "Target host is not allowed")


@router.get("/status")
def stress_status():
    """Check if the stress test binary is available."""
    return {"available": BINARY.exists(), "path": str(BINARY)}


@router.post("")
async def run_stress_test(data: dict):
    """Run Go stress test and return results."""
    if not BINARY.exists():
        raise HTTPException(503, "Stress test binary not found. Build with: cd tools/stresstest && go build -o ../../stresstest .")

    url = data.get("url", "")
    if not url:
        raise HTTPException(400, "url is required")

    _validate_target_url(url)

    config = {
        "method": data.get("method", "GET"),
        "url": url,
        "headers": data.get("headers", {}),
        "body": data.get("body", ""),
        "concurrency": min(data.get("concurrency", 100), 4096),
        "total_requests": min(data.get("total_requests", 1000), 100000),
        "timeout_sec": min(data.get("timeout_sec", 10), 60),
        "follow_redirects": data.get("follow_redirects", True),
        "insecure": data.get("insecure", True),
    }

    # Write config to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            str(BINARY),
            "--config", config_path,
            "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=min(
                config["timeout_sec"] * config["total_requests"] / max(config["concurrency"], 1) + 30,
                600,
            ),
        )

        if proc.returncode != 0:
            raise HTTPException(500, f"Stress test failed: {stderr.decode()}")

        result = json.loads(stdout.decode())
        return result

    except asyncio.TimeoutError:
        if proc:
            proc.kill()
        raise HTTPException(504, "Stress test timed out")
    except json.JSONDecodeError:
        raise HTTPException(500, f"Invalid output from stress test binary")
    finally:
        Path(config_path).unlink(missing_ok=True)