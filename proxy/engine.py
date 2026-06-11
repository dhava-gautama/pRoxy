from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from proxy.addon import ProxyAddon
from state.shared import ProxyState

logger = logging.getLogger("pRoxy.engine")

# Drop a custom mitmproxy addon (*.py) here and it's auto-loaded at startup.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"


def collect_custom_scripts(settings) -> list[str]:
    """Return absolute paths of custom addon scripts to load.

    Combines every *.py in SCRIPTS_DIR (excluding dunder files) with any explicit
    paths in settings.custom_scripts, keeping only files that actually exist.
    """
    paths: list[str] = []
    try:
        if SCRIPTS_DIR.is_dir():
            for p in sorted(SCRIPTS_DIR.glob("*.py")):
                if not p.name.startswith("_"):
                    paths.append(str(p.resolve()))
    except OSError as e:
        logger.warning("Could not scan scripts dir %s: %s", SCRIPTS_DIR, e)
    for raw in getattr(settings, "custom_scripts", []) or []:
        p = Path(raw).expanduser()
        if p.is_file() and str(p.resolve()) not in paths:
            paths.append(str(p.resolve()))
        elif not p.is_file():
            logger.warning("custom_scripts path not found, skipping: %s", raw)
    return paths

# ── SOCKS5 upstream support ────────────────────────────────────
# mitmproxy doesn't natively chain through SOCKS5 upstream proxies. mitmproxy
# 12.x opens every upstream TCP connection via asyncio.open_connection
# (mitmproxy/proxy/server.py), so we wrap that function: when a SOCKS5 upstream
# is configured we dial the destination through the SOCKS5 proxy (PySocks) and
# hand the connected socket to asyncio. SOCKS5 resolves the destination host at
# the proxy, so DNS does not leak. NOTE: a plain socket.create_connection patch
# does NOT work — mitmproxy never calls it.
#
# LIMITATION: This patch is PROCESS-GLOBAL and is never torn down. It is only
# installed when an upstream socks5:// proxy is configured (regular mode only),
# and is a no-op passthrough whenever `_socks_proxy` is None — so the working
# regular/wireguard paths are unaffected unless a user explicitly configures a
# SOCKS5 upstream. In dual-instance mode a SOCKS5 upstream configured for one
# instance routes outbound TCP for the whole process for the rest of its
# lifetime; there is no per-instance teardown.

_socks_proxy: tuple[str, int] | None = None
_socks_installed: bool = False
_orig_open_connection = asyncio.open_connection


async def _socks_open_connection(host=None, port=None, **kwds):
    """asyncio.open_connection replacement that tunnels non-local TCP via SOCKS5."""
    proxy = _socks_proxy
    if (
        proxy is not None
        and kwds.get("sock") is None
        and host not in (None, "127.0.0.1", "localhost", "::1")
    ):
        import socks  # PySocks

        def _dial():
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, proxy[0], proxy[1])
            s.settimeout(30)
            s.connect((host, port))  # SOCKS5 resolves `host` at the proxy (no DNS leak)
            s.setblocking(False)
            return s

        loop = asyncio.get_running_loop()
        sock = await loop.run_in_executor(None, _dial)
        kwds.pop("local_addr", None)  # meaningless for a pre-connected tunnel socket
        return await _orig_open_connection(sock=sock, **kwds)
    return await _orig_open_connection(host, port, **kwds)


def _enable_socks5_upstream(proxy_url: str) -> None:
    """Parse socks5://host:port and route upstream TCP through it.

    Patches asyncio.open_connection (mitmproxy's actual upstream dialer) at most
    once per process (guarded by _socks_installed); subsequent calls only update
    the target. See the module header for the process-global limitation.
    """
    global _socks_proxy, _socks_installed
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 1080
    _socks_proxy = (host, port)
    if not _socks_installed:
        asyncio.open_connection = _socks_open_connection
        _socks_installed = True
    logger.info("SOCKS5 upstream: %s:%d", host, port)


# ── Proxy engine ───────────────────────────────────────────────

async def _run_proxy_async(listen_host: str, listen_port: int, mode: str = "regular", target: str = None) -> None:
    """Coroutine that creates and runs the DumpMaster inside a running event loop."""
    state = ProxyState()
    settings = state.get_settings()

    opts = options.Options(
        listen_host=listen_host,
        listen_port=listen_port,
        ssl_insecure=True,
    )

    # Proxy mode configuration
    if mode == "reverse" and target:
        # Reverse proxy mode - act as the server
        opts.mode = [f"reverse:{target}"]
        logger.info("Reverse proxy mode: %s -> %s", f"{listen_host}:{listen_port}", target)
    elif mode == "transparent":
        # Transparent mode - capture without client config
        opts.mode = ["transparent"]
        logger.info("Transparent proxy mode on %s:%d", listen_host, listen_port)
    elif mode == "socks":
        # SOCKS proxy mode
        opts.mode = ["socks5"]
        logger.info("SOCKS5 proxy mode on %s:%d", listen_host, listen_port)
    elif mode == "wireguard":
        # WireGuard VPN mode - uses mitmproxy's WireGuard support
        opts.mode = ["wireguard"]
        logger.info("WireGuard VPN mode on %s:%d", listen_host, listen_port)
    else:
        # Regular proxy mode (default)
        logger.info("Regular proxy mode on %s:%d", listen_host, listen_port)

    # Upstream proxy configuration (only for regular mode)
    if mode == "regular" and settings.upstream_proxy:
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

    # mitmproxy attaches a handler to the ROOT logger that forwards every log
    # record through THIS master's event loop. In dual-instance mode, once one
    # loop closes, that handler turns every later logger call into
    # "RuntimeError: Event loop is closed" — the cascade that intermittently took
    # down startup. pRoxy logs to stdout itself, so strip them here, per instance.
    _root = logging.getLogger()
    for _h in _root.handlers[:]:
        if type(_h).__module__.startswith("mitmproxy"):
            _root.removeHandler(_h)

    master.addons.add(ProxyAddon())
    logger.info("Enhanced proxy addon loaded with HTTP/2, WebSocket, and protocol support")

    # Load user-supplied mitmproxy addon scripts via mitmproxy's ScriptLoader
    # (full request/response/websocket hooks + hot-reload on file change).
    custom_scripts = collect_custom_scripts(settings)
    if custom_scripts:
        master.options.update(scripts=custom_scripts)
        logger.info("Loaded %d custom addon script(s): %s",
                    len(custom_scripts), ", ".join(custom_scripts))

    logger.info("mitmproxy listening on %s:%d", listen_host, listen_port)
    await master.run()


def _wait_until_listening(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll a TCP port until something is accepting connections, up to `timeout`s."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            if s.connect_ex((host, port)) == 0:
                return True
        finally:
            s.close()
        time.sleep(0.2)
    return False


# Bind-retry tuning for the proxy daemon thread. A successful bind reaches
# `await master.run()` and runs indefinitely, so a return/raise within
# _FAST_FAIL_SECONDS means the master failed to bind during startup (e.g. a
# transient "address already in use" race when launching dual instances) and is
# worth retrying. A run that lasted longer was a real shutdown/crash — don't
# tight-loop on it.
_MAX_BIND_ATTEMPTS = 3
_FAST_FAIL_SECONDS = 3.0
_BIND_RETRY_BACKOFF = 0.75


def _run_proxy(listen_host: str, listen_port: int, mode: str = "regular", target: str = None) -> None:
    """Target for the proxy daemon thread — runs its own asyncio loop.

    Retries on fast startup/bind failures (up to `_MAX_BIND_ATTEMPTS`), since the
    WireGuard UDP bind intermittently races with the regular instance on launch.
    Retries happen inside this daemon thread, so the main thread is never blocked.
    """
    for attempt in range(1, _MAX_BIND_ATTEMPTS + 1):
        started = time.monotonic()
        try:
            asyncio.run(_run_proxy_async(listen_host, listen_port, mode, target))
            # A clean return means master.run() exited. If it ran long enough it
            # was a real shutdown; only a fast exit indicates a bind failure.
            elapsed = time.monotonic() - started
        except Exception:
            elapsed = time.monotonic() - started
            if elapsed >= _FAST_FAIL_SECONDS or attempt >= _MAX_BIND_ATTEMPTS:
                logger.exception("mitmproxy crashed (%s mode, %.2fs)", mode, elapsed)
                return
            logger.warning(
                "mitmproxy %s mode failed to start on %s:%d in %.2fs (attempt %d/%d), retrying",
                mode, listen_host, listen_port, elapsed, attempt, _MAX_BIND_ATTEMPTS,
            )
            time.sleep(_BIND_RETRY_BACKOFF)
            continue

        if elapsed >= _FAST_FAIL_SECONDS or attempt >= _MAX_BIND_ATTEMPTS:
            # Ran for a while then exited normally — a genuine shutdown.
            return
        logger.warning(
            "mitmproxy %s mode exited after %.2fs on %s:%d without binding "
            "(attempt %d/%d), retrying",
            mode, elapsed, listen_host, listen_port, attempt, _MAX_BIND_ATTEMPTS,
        )
        time.sleep(_BIND_RETRY_BACKOFF)


def start_proxy_thread(listen_host: str = "0.0.0.0", listen_port: int = 8080,
                       mode: str = "regular", target: str = None) -> threading.Thread:
    """Launch mitmproxy in a daemon thread and return the thread handle."""
    t = threading.Thread(
        target=_run_proxy,
        args=(listen_host, listen_port, mode, target),
        daemon=True,
        name=f"mitmproxy-{mode}",
    )
    t.start()
    logger.info("Proxy thread started in %s mode", mode)
    return t


# Convenience functions for different proxy modes
def start_reverse_proxy(target_url: str, listen_port: int = 8443) -> threading.Thread:
    """Start reverse proxy mode - act as the target server."""
    return start_proxy_thread("0.0.0.0", listen_port, "reverse", target_url)


def start_transparent_proxy(listen_port: int = 8080) -> threading.Thread:
    """Start transparent proxy mode - capture without client config."""
    return start_proxy_thread("0.0.0.0", listen_port, "transparent")


def start_socks_proxy(listen_port: int = 1080) -> threading.Thread:
    """Start SOCKS5 proxy mode."""
    return start_proxy_thread("0.0.0.0", listen_port, "socks")


def start_wireguard_proxy(listen_port: int = 51820) -> threading.Thread:
    """Start WireGuard VPN proxy mode."""
    return start_proxy_thread("0.0.0.0", listen_port, "wireguard")


def start_dual_mode_proxy(regular_port: int = 8082, wireguard_port: int = 51820) -> tuple[threading.Thread, threading.Thread]:
    """
    Start both regular HTTP/HTTPS proxy and WireGuard VPN simultaneously.

    This runs TWO separate mitmproxy instances:
    1. Regular HTTP/HTTPS proxy instance
    2. WireGuard VPN proxy instance

    Both instances share the same ProxyState, so all traffic from both
    modes appears in the unified dashboard.

    Returns:
        tuple[threading.Thread, threading.Thread]: (regular_thread, wireguard_thread)
    """
    logger.info("Starting DUAL mitmproxy instances:")
    logger.info("  Instance 1 - Regular proxy: 0.0.0.0:%d (HTTP/HTTPS)", regular_port)
    logger.info("  Instance 2 - WireGuard VPN: 0.0.0.0:%d (All traffic)", wireguard_port)

    # Start the regular proxy first and wait until it is actually accepting
    # connections before starting WireGuard. Launching both at once races their
    # asyncio startup and intermittently leaves one instance unable to bind.
    regular_thread = start_proxy_thread("0.0.0.0", regular_port, "regular")
    if _wait_until_listening("127.0.0.1", regular_port, timeout=10.0):
        logger.info("Regular proxy is up on :%d", regular_port)
    else:
        logger.warning("Regular proxy did not come up on :%d within timeout", regular_port)

    # Start WireGuard proxy instance (after the regular one is settled).
    wireguard_thread = start_proxy_thread("0.0.0.0", wireguard_port, "wireguard")

    logger.info("Dual mitmproxy instances started - both feeding into unified dashboard")
    return regular_thread, wireguard_thread
