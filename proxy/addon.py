from __future__ import annotations

import fnmatch
import mimetypes
import re
import time
import logging
import base64
from pathlib import Path
from urllib.parse import urlparse

import httpx
from mitmproxy import http, ctx, websocket

from state.models import FlowRecord, InterceptedFlow, WSMessage
from state.shared import ProxyState

logger = logging.getLogger("pRoxy.addon")


class ProxyAddon:
    """mitmproxy addon that bridges flows into ProxyState."""

    def __init__(self) -> None:
        self.state = ProxyState()
        self._dns_cache: dict[str, tuple[str, float]] = {}  # host → (ip, expiry)
        self._doh_client: httpx.Client | None = None

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _headers_dict(headers) -> dict[str, str]:
        return {k: v for k, v in headers.items()}

    @staticmethod
    def _safe_body(content: bytes | None, content_type: str = "", max_size: int = 512_000) -> str:
        if content is None or len(content) == 0:
            return ""
        ct = content_type.lower()
        if any(t in ct for t in ("text", "json", "xml", "javascript", "html", "css", "form")):
            try:
                return content[:max_size].decode("utf-8", errors="replace")
            except Exception:
                return f"<binary {len(content)} bytes>"
        # gRPC / Protobuf: base64-encode binary for frontend wire-format decoding.
        # But if the bytes are actually valid UTF-8 text (e.g. from a mock rule),
        # return both: the text prefixed so frontend can still show it.
        if any(t in ct for t in ("grpc", "protobuf", "x-protobuf")):
            chunk = content[:max_size]
            try:
                text = chunk.decode("utf-8")
                # If it's all printable ASCII, it's not real protobuf — just return text
                if text.isprintable():
                    return text
            except (UnicodeDecodeError, ValueError):
                pass
            return "base64:" + base64.b64encode(chunk).decode("ascii")
        return f"<binary {len(content)} bytes>"

    @staticmethod
    def _url_matches(url: str, pattern: str, is_regex: bool) -> bool:
        if is_regex:
            try:
                return bool(re.search(pattern, url))
            except re.error:
                return False
        return fnmatch.fnmatch(url, pattern)

    def _build_record(self, flow: http.HTTPFlow) -> FlowRecord:
        req = flow.request
        ct_req = req.headers.get("content-type", "")
        display_host = getattr(flow, '_original_host', None) or req.host
        dns_method = getattr(flow, '_dns_method', "")
        display_url = req.pretty_url
        if hasattr(flow, '_original_host'):
            display_url = display_url.replace(req.host, flow._original_host, 1)
        rec = FlowRecord(
            id=flow.id,
            timestamp=time.time(),
            method=req.method,
            scheme=req.scheme,
            host=display_host,
            port=req.port,
            path=req.path,
            url=display_url,
            request_headers=self._headers_dict(req.headers),
            request_body=self._safe_body(req.get_content(), ct_req),
            request_content_type=ct_req,
            dns_method=dns_method,
        )
        if flow.response is not None:
            resp = flow.response
            ct_resp = resp.headers.get("content-type", "")
            rec.status_code = resp.status_code
            rec.reason = resp.reason or ""
            rec.response_headers = self._headers_dict(resp.headers)
            rec.response_body = self._safe_body(resp.get_content(), ct_resp)
            rec.response_content_type = ct_resp
            rec.completed = True
            if hasattr(flow, '_start_time'):
                rec.duration_ms = round((time.time() - flow._start_time) * 1000, 1)
        return rec

    def _matches_breakpoint(self, flow: http.HTTPFlow) -> bool:
        """Check if flow matches any enabled breakpoint rule."""
        settings = self.state.get_settings()
        rules = settings.breakpoint_rules
        if not rules:
            return True  # no rules = intercept all (when intercept is on)
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.method and rule.method.upper() != flow.request.method:
                continue
            if rule.host_pattern and not fnmatch.fnmatch(flow.request.host, rule.host_pattern):
                continue
            if rule.path_pattern:
                try:
                    if not re.search(rule.path_pattern, flow.request.path):
                        continue
                except re.error:
                    continue
            return True
        return False

    def _apply_replace_rules(self, body: str, phase: str) -> str:
        """Apply auto-replace rules to body text."""
        settings = self.state.get_settings()
        for rule in settings.replace_rules:
            if not rule.enabled or rule.phase != phase:
                continue
            try:
                if rule.is_regex:
                    body = re.sub(rule.pattern, rule.replacement, body)
                else:
                    body = body.replace(rule.pattern, rule.replacement)
            except re.error:
                pass
        return body

    def _resolve_doh(self, hostname: str, doh_url: str) -> str | None:
        """Resolve hostname via DNS-over-HTTPS (JSON API). Returns IP or None."""
        now = time.time()
        cached = self._dns_cache.get(hostname)
        if cached and cached[1] > now:
            return cached[0]

        try:
            if self._doh_client is None:
                self._doh_client = httpx.Client(timeout=5.0)
            resp = self._doh_client.get(
                doh_url,
                params={"name": hostname, "type": "A"},
                headers={"Accept": "application/dns-json"},
            )
            resp.raise_for_status()
            data = resp.json()
            for answer in data.get("Answer", []):
                if answer.get("type") == 1:  # A record
                    ip = answer["data"]
                    ttl = max(answer.get("TTL", 300), 60)
                    self._dns_cache[hostname] = (ip, now + ttl)
                    logger.info("DoH: %s → %s (TTL %ds)", hostname, ip, ttl)
                    return ip
        except Exception as e:
            logger.debug("DoH resolution failed for %s: %s", hostname, e)
        return None

    # ── Request hooks ─────────────────────────────────────────

    def request(self, flow: http.HTTPFlow) -> None:
        flow._start_time = time.time()
        settings = self.state.get_settings()

        # Scope filtering — skip out-of-scope flows
        if not self.state.is_in_scope(flow.request.host):
            flow._out_of_scope = True
            return

        # Force SSL
        if settings.force_ssl and flow.request.scheme == "http":
            flow.request.scheme = "https"
            if flow.request.port == 80:
                flow.request.port = 443

        # Custom User-Agent
        if settings.custom_user_agent:
            flow.request.headers["user-agent"] = settings.custom_user_agent

        # Header injection/removal — request phase
        for rule in settings.header_rules:
            if not rule.enabled or rule.phase != "request":
                continue
            if rule.action == "set":
                flow.request.headers[rule.name] = rule.value
            elif rule.action == "remove":
                flow.request.headers.pop(rule.name, None)

        # Auto-replace on request body
        if flow.request.content:
            ct = flow.request.headers.get("content-type", "").lower()
            if any(t in ct for t in ("text", "json", "xml", "javascript", "html", "form")):
                try:
                    original = flow.request.content.decode("utf-8", errors="replace")
                    replaced = self._apply_replace_rules(original, "request")
                    if replaced != original:
                        flow.request.set_content(replaced.encode("utf-8"))
                except Exception:
                    pass

        # DNS blocklist check
        dns = self.state.get_dns()
        if flow.request.host in dns.blocklist:
            flow.response = http.Response.make(
                403,
                b"Blocked by pRoxy DNS blocklist",
                {"Content-Type": "text/plain"},
            )
            logger.info("Blocked: %s", flow.request.host)
            return

        # Custom DNS mappings — rewrite host to mapped IP
        dns_mapped = False
        for mapping in dns.custom_mappings:
            if mapping.enabled and mapping.hostname == flow.request.host:
                original_host = flow.request.host
                flow.request.host = mapping.ip
                flow.request.headers["Host"] = original_host  # restore after host rewrite
                flow._original_host = original_host
                flow._dns_method = "mapping"
                logger.info("DNS mapping: %s → %s", original_host, mapping.ip)
                dns_mapped = True
                break

        # DoH resolution — only if no custom mapping matched
        if not dns_mapped and dns.doh_enabled and dns.doh_url:
            original_host = flow.request.host
            resolved = self._resolve_doh(original_host, dns.doh_url)
            if resolved:
                flow.request.host = resolved
                flow.request.headers["Host"] = original_host  # restore after host rewrite
                flow._original_host = original_host
                flow._dns_method = "doh"

        url = flow.request.pretty_url

        # Mock rules — return fake response, skip server
        for rule in settings.mock_rules:
            if not rule.enabled:
                continue
            if self._url_matches(url, rule.match_pattern, rule.is_regex):
                flow.response = http.Response.make(
                    rule.status_code,
                    rule.body.encode("utf-8"),
                    rule.headers,
                )
                logger.info("Mock matched: %s → %d", rule.match_pattern, rule.status_code)
                record = self._build_record(flow)
                self.state.store_flow(record)
                self.state.traffic_queue.put(record)
                return

        # Map Local — return file content, skip server
        for rule in settings.map_rules:
            if not rule.enabled or rule.rule_type != "local":
                continue
            if self._url_matches(url, rule.match_pattern, rule.is_regex):
                try:
                    file_path = Path(rule.target)
                    content = file_path.read_bytes()
                    ct = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
                    flow.response = http.Response.make(200, content, {"Content-Type": ct})
                    logger.info("Map Local: %s → %s", rule.match_pattern, rule.target)
                except Exception as e:
                    flow.response = http.Response.make(
                        502, f"Map Local error: {e}".encode(), {"Content-Type": "text/plain"}
                    )
                record = self._build_record(flow)
                self.state.store_flow(record)
                self.state.traffic_queue.put(record)
                return

        # Map Remote — rewrite URL, continue to server
        for rule in settings.map_rules:
            if not rule.enabled or rule.rule_type != "remote":
                continue
            if self._url_matches(url, rule.match_pattern, rule.is_regex):
                parsed = urlparse(rule.target)
                flow.request.scheme = parsed.scheme or "https"
                flow.request.host = parsed.hostname or flow.request.host
                flow.request.port = parsed.port or (443 if parsed.scheme == "https" else 80)
                flow.request.path = parsed.path + ("?" + parsed.query if parsed.query else "")
                logger.info("Map Remote: %s → %s", rule.match_pattern, rule.target)
                break

        # Store initial request record + push to WS
        record = self._build_record(flow)
        self.state.store_flow(record)
        self.state.traffic_queue.put(record)

        # Intercept mode — request phase
        if settings.intercept_enabled and self._matches_breakpoint(flow):
            record.intercepted = True
            intercepted = InterceptedFlow(id=flow.id, flow_record=record, phase="request")
            event = self.state.enqueue_intercept(intercepted)
            event.wait(timeout=300)
            resolved = self.state.pop_resolved(flow.id + ":request")
            if resolved is None:
                return
            if resolved.action == "drop":
                flow.response = http.Response.make(
                    502,
                    b"Dropped by pRoxy intercept",
                    {"Content-Type": "text/plain"},
                )
                return
            if resolved.modified_headers:
                for k, v in resolved.modified_headers.items():
                    flow.request.headers[k] = v
            if resolved.modified_body is not None:
                flow.request.set_content(resolved.modified_body.encode("utf-8"))

    # ── Response hooks ────────────────────────────────────────

    def response(self, flow: http.HTTPFlow) -> None:
        # Skip out-of-scope
        if getattr(flow, '_out_of_scope', False):
            return

        settings = self.state.get_settings()

        # HSTS stripping
        if settings.hsts_strip:
            flow.response.headers.pop("strict-transport-security", None)

        # HPKP & Expect-CT stripping
        if settings.hpkp_strip:
            flow.response.headers.pop("public-key-pins", None)
            flow.response.headers.pop("public-key-pins-report-only", None)
            flow.response.headers.pop("expect-ct", None)

        # CSP stripping
        if settings.csp_strip:
            flow.response.headers.pop("content-security-policy", None)
            flow.response.headers.pop("content-security-policy-report-only", None)

        # CORS bypass
        if settings.cors_bypass:
            flow.response.headers["access-control-allow-origin"] = "*"
            flow.response.headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
            flow.response.headers["access-control-allow-headers"] = "*"
            flow.response.headers["access-control-allow-credentials"] = "true"
            flow.response.headers.pop("access-control-max-age", None)

        # Header injection/removal — response phase
        for rule in settings.header_rules:
            if not rule.enabled or rule.phase != "response":
                continue
            if rule.action == "set":
                flow.response.headers[rule.name] = rule.value
            elif rule.action == "remove":
                flow.response.headers.pop(rule.name, None)

        # Auto-replace on response body
        if flow.response.content:
            ct = flow.response.headers.get("content-type", "").lower()
            if any(t in ct for t in ("text", "json", "xml", "javascript", "html", "css", "form")):
                try:
                    original = flow.response.content.decode("utf-8", errors="replace")
                    replaced = self._apply_replace_rules(original, "response")
                    if replaced != original:
                        flow.response.set_content(replaced.encode("utf-8"))
                except Exception:
                    pass

        # Response intercept
        if settings.intercept_enabled and settings.intercept_responses and self._matches_breakpoint(flow):
            record = self._build_record(flow)
            record.intercepted = True
            intercepted = InterceptedFlow(id=flow.id, flow_record=record, phase="response")
            event = self.state.enqueue_intercept(intercepted)
            event.wait(timeout=300)
            resolved = self.state.pop_resolved(flow.id + ":response")
            if resolved is not None:
                if resolved.action == "drop":
                    flow.response = http.Response.make(
                        502,
                        b"Dropped by pRoxy intercept",
                        {"Content-Type": "text/plain"},
                    )
                    # Still store the record
                    record2 = self._build_record(flow)
                    self.state.store_flow(record2)
                    self.state.traffic_queue.put(record2)
                    return
                if resolved.modified_headers:
                    for k, v in resolved.modified_headers.items():
                        flow.response.headers[k] = v
                if resolved.modified_body is not None:
                    flow.response.set_content(resolved.modified_body.encode("utf-8"))

        # Tag WebSocket upgrades
        is_ws_upgrade = (
            flow.response.status_code == 101
            and "websocket" in flow.response.headers.get("upgrade", "").lower()
        )

        # Store completed flow + push to WS
        record = self._build_record(flow)
        if is_ws_upgrade:
            record.flow_type = "websocket"
        self.state.store_flow(record)
        self.state.traffic_queue.put(record)

    # ── WebSocket hooks ───────────────────────────────────────

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if getattr(flow, '_out_of_scope', False):
            return
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        direction = "client" if msg.from_client else "server"
        is_text = msg.is_text
        try:
            content = msg.text if is_text else f"<binary {len(msg.content)} bytes>"
        except Exception:
            content = f"<binary {len(msg.content)} bytes>"
            is_text = False

        ws_msg = WSMessage(
            direction=direction,
            content=content[:50000],
            timestamp=time.time(),
            is_text=is_text,
        )

        # Update or create the flow record
        existing = self.state.get_flow(flow.id)
        if existing is not None:
            existing.flow_type = "websocket"
            existing.ws_messages.append(ws_msg)
            self.state.store_flow(existing)
            self.state.traffic_queue.put(existing)
        else:
            record = self._build_record(flow)
            record.flow_type = "websocket"
            record.ws_messages = [ws_msg]
            self.state.store_flow(record)
            self.state.traffic_queue.put(record)
