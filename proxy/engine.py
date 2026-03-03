from __future__ import annotations

import asyncio
import logging
import socket
import threading
from urllib.parse import urlparse

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from proxy.addon import ProxyAddon
from state.shared import ProxyState

logger = logging.getLogger("pRoxy.engine")

# ── SOCKS5 upstream support ────────────────────────────────────
# mitmproxy doesn't natively chain through SOCKS5 upstream proxies.
# We monkeypatch socket.create_connection to route all outbound TCP
# through the SOCKS5 proxy when configured.

_socks_proxy: tuple[str, int] | None = None
_original_create_connection = socket.create_connection


def _socks_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                             source_address=None, **kwargs):
    """Replacement for socket.create_connection that routes through SOCKS5."""
    if _socks_proxy is not None:
        import socks
        host, port = address
        # Don't proxy connections to localhost (dashboard, etc.)
        if host not in ("127.0.0.1", "localhost", "::1"):
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, _socks_proxy[0], _socks_proxy[1])
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                s.settimeout(timeout)
            if source_address:
                s.bind(source_address)
            s.connect((host, port))
            return s
    return _original_create_connection(address, timeout=timeout,
                                       source_address=source_address, **kwargs)


def _enable_socks5_upstream(proxy_url: str) -> None:
    """Parse socks5://host:port and monkeypatch socket."""
    global _socks_proxy
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 1080
    _socks_proxy = (host, port)
    socket.create_connection = _socks_create_connection
    logger.info("SOCKS5 upstream: %s:%d", host, port)


# ── Proxy engine ───────────────────────────────────────────────

async def _run_proxy_async(listen_host: str, listen_port: int) -> None:
    """Coroutine that creates and runs the DumpMaster inside a running event loop."""
    state = ProxyState()
    settings = state.get_settings()

    opts = options.Options(
        listen_host=listen_host,
        listen_port=listen_port,
        ssl_insecure=True,
    )

    # Upstream proxy configuration
    if settings.upstream_proxy:
        proxy_url = settings.upstream_proxy.strip()
        if proxy_url.startswith("socks5://") or proxy_url.startswith("socks://"):
            _enable_socks5_upstream(proxy_url)
        elif proxy_url.startswith("https://"):
            opts.mode = [f"upstream:{proxy_url}"]
            logger.info("HTTPS upstream proxy: %s", proxy_url)
        else:
            # http:// or bare host:port
            if not proxy_url.startswith("http://"):
                proxy_url = f"http://{proxy_url}"
            opts.mode = [f"upstream:{proxy_url}"]
            logger.info("HTTP upstream proxy: %s", proxy_url)

    master = DumpMaster(opts, with_termlog=False)
    addon = ProxyAddon()
    master.addons.add(addon)

    logger.info("mitmproxy listening on %s:%d", listen_host, listen_port)
    await master.run()


def _run_proxy(listen_host: str, listen_port: int) -> None:
    """Target for the proxy daemon thread — runs its own asyncio loop."""
    try:
        asyncio.run(_run_proxy_async(listen_host, listen_port))
    except Exception:
        logger.exception("mitmproxy crashed")


def start_proxy_thread(listen_host: str = "0.0.0.0", listen_port: int = 8080) -> threading.Thread:
    """Launch mitmproxy in a daemon thread and return the thread handle."""
    t = threading.Thread(
        target=_run_proxy,
        args=(listen_host, listen_port),
        daemon=True,
        name="mitmproxy",
    )
    t.start()
    logger.info("Proxy thread started")
    return t
