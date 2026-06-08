#!/usr/bin/env python3

import time
import httpx
from contextlib import asynccontextmanager


def generate_timestamp_id(prefix: str) -> str:
    """Generate timestamp-based ID with given prefix."""
    return f"{prefix}-{int(time.time() * 1000)}"


def calculate_duration_ms(start_time: float) -> float:
    """Calculate duration in milliseconds from start time."""
    return round((time.time() - start_time) * 1000, 1)


@asynccontextmanager
async def create_http_client(
    timeout: float = 30.0,
    follow_redirects: bool = True,
    verify: bool = False
):
    """Create a configured httpx client with consistent settings."""
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        headers={"User-Agent": "pRoxy/1.0 (MITM Testing)"}
    ) as client:
        yield client