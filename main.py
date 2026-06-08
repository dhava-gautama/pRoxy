#!/usr/bin/env python3
"""pRoxy — Web-based MITM proxy with dashboard."""

from __future__ import annotations

import logging
import socket
import time

import uvicorn

from api.server import create_app
from proxy.ca import ensure_ca
from proxy.engine import start_proxy_thread, start_dual_mode_proxy


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

    # Default port assignments: 8080=proxy, 8082=dashboard, 51820=WireGuard
    proxy_port = find_free_port(host, 8080)
    wireguard_port = find_free_port(host, 51820)
    api_port = find_free_port(host, 8082)

    # Ensure all ports are different from each other
    if wireguard_port == proxy_port:
        wireguard_port = find_free_port(host, wireguard_port + 1)
    if api_port == proxy_port:
        api_port = find_free_port(host, max(8082, proxy_port + 1))
    if api_port == wireguard_port:
        api_port = find_free_port(host, max(8082, wireguard_port + 1))

    if proxy_port != 8080:
        logger.info("Port 8080 in use, proxy using :%d", proxy_port)
    if wireguard_port != 51820:
        logger.info("Port 51820 in use, WireGuard using :%d", wireguard_port)
    if api_port != 8082:
        logger.info("Port 8082 in use, dashboard using :%d", api_port)

    # Generate the CA once up front so both proxy instances load the same one
    # (concurrent instances would otherwise race to create it on first run).
    ensure_ca()

    logger.info("Starting pRoxy with DUAL mitmproxy instances...")
    logger.info("  HTTP Proxy:  %s:%d (browsers, proxy-aware apps)", host, proxy_port)
    logger.info("  WireGuard:   %s:%d (ALL device traffic via VPN)", host, wireguard_port)
    logger.info("  Dashboard:   http://%s:%d", host, api_port)

    # Start both proxy instances simultaneously
    regular_thread, wireguard_thread = start_dual_mode_proxy(proxy_port, wireguard_port)

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
