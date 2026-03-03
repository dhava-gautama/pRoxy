#!/usr/bin/env python3
"""pRoxy — Web-based MITM proxy with dashboard."""

from __future__ import annotations

import logging
import socket
import time

import uvicorn

from api.server import create_app
from proxy.engine import start_proxy_thread


def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_free_port(host: str, start: int, max_tries: int = 20) -> int:
    for offset in range(max_tries):
        port = start + offset
        if is_port_free(host, port):
            return port
    raise RuntimeError(f"No free port found in range {start}-{start + max_tries - 1}")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("pRoxy")

    host = "0.0.0.0"

    proxy_port = find_free_port(host, 8080)
    api_port = find_free_port(host, 8081 if proxy_port == 8080 else proxy_port + 1)

    if proxy_port != 8080:
        logger.warning("Port 8080 in use, proxy using :%d", proxy_port)
    if api_port != 8081:
        logger.warning("Port 8081 in use, dashboard using :%d", api_port)

    logger.info("Starting pRoxy...")
    logger.info("  Proxy:     %s:%d", host, proxy_port)
    logger.info("  Dashboard: http://%s:%d", host, api_port)

    # Start mitmproxy in a daemon thread
    start_proxy_thread(listen_host=host, listen_port=proxy_port)

    # Give proxy a moment to initialize its event loop
    time.sleep(1)

    # Remove mitmproxy's log handler from root logger to avoid cross-thread issues
    root = logging.getLogger()
    for handler in root.handlers[:]:
        if type(handler).__module__.startswith("mitmproxy"):
            root.removeHandler(handler)

    # Start FastAPI on the main thread
    app = create_app()
    try:
        uvicorn.run(app, host=host, port=api_port, log_level="info", timeout_graceful_shutdown=2)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down pRoxy")


if __name__ == "__main__":
    main()
