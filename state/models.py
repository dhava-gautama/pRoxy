from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    id: str
    timestamp: float
    method: str = ""
    scheme: str = ""
    host: str = ""
    port: int = 0
    path: str = ""
    url: str = ""
    request_headers: dict[str, str] = {}
    request_body: str = ""
    request_content_type: str = ""
    status_code: int = 0
    reason: str = ""
    response_headers: dict[str, str] = {}
    response_body: str = ""
    response_content_type: str = ""
    completed: bool = False
    intercepted: bool = False
    duration_ms: float = 0
    dns_method: str = ""  # "", "mapping", "doh"
    flow_type: str = "http"  # "http" or "websocket"
    ws_messages: list[WSMessage] = []


class WSMessage(BaseModel):
    direction: str = ""  # "client" or "server"
    content: str = ""
    timestamp: float = 0
    is_text: bool = True

# Fix forward ref
FlowRecord.model_rebuild()


class HeaderRule(BaseModel):
    name: str
    value: str
    phase: str = "request"  # "request" or "response"
    action: str = "set"     # "set" or "remove"
    enabled: bool = True


class ReplaceRule(BaseModel):
    pattern: str          # search string or regex
    replacement: str
    phase: str = "response"  # "request" or "response"
    is_regex: bool = False
    enabled: bool = True


class BreakpointRule(BaseModel):
    host_pattern: str = ""     # glob-like match on host
    path_pattern: str = ""     # regex match on path
    method: str = ""           # exact match, empty = any
    enabled: bool = True


class MapRule(BaseModel):
    enabled: bool = True
    match_pattern: str          # glob or regex on full URL
    is_regex: bool = False
    rule_type: str = "remote"   # "local" or "remote"
    target: str = ""            # file path (local) or URL (remote)


class MockRule(BaseModel):
    enabled: bool = True
    match_pattern: str
    is_regex: bool = False
    status_code: int = 200
    headers: dict[str, str] = {"Content-Type": "application/json"}
    body: str = ""


class HighlightRule(BaseModel):
    enabled: bool = True
    match_type: str = "content-type"  # host/path/method/status/content-type
    pattern: str = ""
    color: str = "#1e3a5f"            # background hex


class ProxySettings(BaseModel):
    hsts_strip: bool = False
    hpkp_strip: bool = False       # strip Public-Key-Pins + Expect-CT
    csp_strip: bool = False
    cors_bypass: bool = False
    force_ssl: bool = False
    custom_user_agent: str = ""
    intercept_enabled: bool = False
    intercept_responses: bool = False
    upstream_proxy: str = ""        # e.g. "http://user:pass@host:port" or "socks5://host:port"
    header_rules: list[HeaderRule] = []
    replace_rules: list[ReplaceRule] = []
    breakpoint_rules: list[BreakpointRule] = []
    scope_patterns: list[str] = []  # domain patterns, empty = capture all
    map_rules: list[MapRule] = []
    mock_rules: list[MockRule] = []
    highlight_rules: list[HighlightRule] = []


class DNSMapping(BaseModel):
    hostname: str
    ip: str
    enabled: bool = True


class DNSSettings(BaseModel):
    doh_enabled: bool = False
    doh_url: str = "https://cloudflare-dns.com/dns-query"
    blocklist: list[str] = []
    custom_mappings: list[DNSMapping] = []


class InterceptedFlow(BaseModel):
    id: str
    flow_record: FlowRecord
    phase: str = "request"  # "request" or "response"
    action: Optional[str] = None
    modified_body: Optional[str] = None
    modified_headers: Optional[dict[str, str]] = None


class ReplayRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""
