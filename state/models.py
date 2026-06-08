from __future__ import annotations

import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, unquote
from enum import IntEnum

from pydantic import BaseModel, Field, field_validator, model_validator, ValidationError


class ContentSizePolicy(IntEnum):
    """Content size thresholds for different handling strategies."""
    TINY = 1_024        # 1KB - show full content always
    SMALL = 50_000      # 50KB - show full content
    MEDIUM = 512_000    # 512KB - truncate display (current default)
    LARGE = 5_000_000   # 5MB - stream or save to disk
    HUGE = 50_000_000   # 50MB - force streaming


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
    response_size: int = 0
    completed: bool = False
    intercepted: bool = False
    duration_ms: float = 0
    dns_method: str = ""  # "", "mapping", "doh"
    flow_type: str = "http"  # "http", "websocket", "grpc", "graphql", "sse"
    ws_messages: list[WSMessage] = []

    # Enhanced streaming and protocol support
    stream_mode: bool = False
    http_version: str = ""  # "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"
    request_trailers: dict[str, str] = {}
    response_trailers: dict[str, str] = {}
    error_message: str = ""
    error_timestamp: float = 0
    has_error: bool = False
    content_file_path: str = ""  # Path to large content stored on disk
    content_summary: str = ""    # Summary for large content
    actual_response_size: int = 0  # Actual size if different from response_size

    # Modern protocol support
    http3_features: HTTP3Features | None = None
    grpc_messages: list[GRPCMessage] = []
    graphql_operations: list[GraphQLOperation] = []
    sse_messages: list[SSEMessage] = []

    # Enhanced Flow API support
    client_connection: ConnectionInfo | None = None
    server_connection: ConnectionInfo | None = None
    detailed_error: DetailedErrorInfo | None = None
    lifecycle_info: FlowLifecycleInfo | None = None
    tls_analysis: TLSAnalysis | None = None
    flow_control_actions: list[FlowControlAction] = []


class WSMessage(BaseModel):
    direction: str = ""  # "client" or "server"
    content: str = ""
    timestamp: float = 0
    is_text: bool = True
    size: int = 0  # payload size in bytes


class HeaderRule(BaseModel):
    name: str
    value: str
    phase: str = "request"  # "request" or "response"
    action: str = "set"     # "set" or "remove"
    enabled: bool = True

    @field_validator('phase')
    @classmethod
    def validate_phase(cls, v: str) -> str:
        if v not in ("request", "response"):
            raise ValueError("Phase must be 'request' or 'response'")
        return v

    @field_validator('action')
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ("set", "remove"):
            raise ValueError("Action must be 'set' or 'remove'")
        return v

    @field_validator('name', 'value')
    @classmethod
    def reject_crlf(cls, v: str) -> str:
        # Prevent header (CRLF) injection
        if "\r" in v or "\n" in v:
            raise ValueError("Header name/value must not contain CR or LF characters")
        return v


def _reject_redos(pattern: str) -> None:
    """Reject regex patterns prone to catastrophic backtracking (ReDoS)."""
    # Excessive bounded repetition, e.g. a{100000}
    for m in re.finditer(r"\{(\d+)(?:,(\d*))?\}", pattern):
        if any(int(g) > 1000 for g in m.groups() if g):
            raise ValueError("Quantifier repetition too large (possible ReDoS)")
    # Quantifier applied to a group that itself contains a quantifier or
    # alternation, e.g. (a+)+, ([a-z]+)*, (a|a)*
    if re.search(r"\([^()]*[*+|][^()]*\)[*+]", pattern):
        raise ValueError("Nested quantifier may cause catastrophic backtracking (ReDoS)")


class ReplaceRule(BaseModel):
    pattern: str = Field(min_length=1, max_length=10_000)  # search string or regex
    replacement: str
    phase: str = "response"  # "request" or "response"
    is_regex: bool = False
    enabled: bool = True

    @model_validator(mode='after')
    def validate_regex_pattern(self) -> 'ReplaceRule':
        # If is_regex is True, validate the regex pattern
        if self.is_regex:
            try:
                re.compile(self.pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
            _reject_redos(self.pattern)
        return self

    @field_validator('phase')
    @classmethod
    def validate_phase(cls, v: str) -> str:
        if v not in ("request", "response"):
            raise ValueError("Phase must be 'request' or 'response'")
        return v


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

    @model_validator(mode='after')
    def validate_match_pattern(self) -> 'MapRule':
        if self.is_regex:
            try:
                re.compile(self.match_pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        return self

    @field_validator('rule_type')
    @classmethod
    def validate_rule_type(cls, v: str) -> str:
        if v not in ("local", "remote"):
            raise ValueError("Rule type must be 'local' or 'remote'")
        return v

    @model_validator(mode='after')
    def validate_target(self) -> 'MapRule':
        if not self.target:
            return self

        if self.rule_type == "local":
            # Validate file path and prevent path traversal
            try:
                # Decode first so URL-encoded traversal (e.g. %2e%2e%2f) is caught
                decoded = unquote(self.target)
                if ".." in decoded or decoded.startswith("/"):
                    raise ValueError("Path traversal not allowed. Use relative paths only.")
                # Ensure path is within reasonable bounds. Use is_relative_to so
                # sibling dirs (e.g. cwd /home/app vs /home/app-secrets) are not
                # accepted by a naive string-prefix match.
                path = Path(self.target).resolve()
                if not path.is_relative_to(Path.cwd().resolve()):
                    raise ValueError("File path must be within current directory")
            except (OSError, ValueError) as e:
                raise ValueError(f"Invalid file path: {e}")
        elif self.rule_type == "remote":
            # Validate URL
            try:
                parsed = urlparse(self.target)
                if not parsed.scheme in ("http", "https"):
                    raise ValueError("URL must use http or https scheme")
                if not parsed.netloc:
                    raise ValueError("URL must include hostname")
            except Exception as e:
                raise ValueError(f"Invalid URL: {e}")

        return self


class MockRule(BaseModel):
    enabled: bool = True
    match_pattern: str
    is_regex: bool = False
    status_code: int = 200
    headers: dict[str, str] = {"Content-Type": "application/json"}
    body: str = ""

    @field_validator('status_code')
    @classmethod
    def validate_status_code(cls, v: int) -> int:
        if not (100 <= v <= 599):
            raise ValueError("Status code must be between 100 and 599")
        return v


class HighlightRule(BaseModel):
    enabled: bool = True
    match_type: str = "content-type"  # host/path/method/status/content-type
    pattern: str = ""
    color: str = "#1e3a5f"            # background hex

    @field_validator('match_type')
    @classmethod
    def validate_match_type(cls, v: str) -> str:
        valid = ("host", "path", "method", "status", "content-type")
        if v not in valid:
            raise ValueError(f"Match type must be one of: {', '.join(valid)}")
        return v

    @field_validator('color')
    @classmethod
    def validate_color(cls, v: str) -> str:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", v):
            raise ValueError("Color must be a 6-digit hex value like #1e3a5f")
        return v


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

    # Enhanced content and streaming management
    max_memory_content_size: int = 5_000_000    # 5MB - content larger than this goes to disk
    auto_stream_threshold: int = 10_000_000     # 10MB - auto-enable streaming above this size
    save_large_content: bool = True             # Save large content to disk instead of memory
    content_storage_dir: str = "./flow_content" # Directory for large content storage
    enable_smart_streaming: bool = True         # Enable intelligent streaming decisions

    # Protocol and debugging enhancements
    capture_trailers: bool = True               # Capture HTTP trailers
    log_connection_errors: bool = True          # Log connection and protocol errors
    enhanced_websocket_logging: bool = True     # Enhanced WebSocket connection tracking
    detect_http_version: bool = True            # Detect and log HTTP version
    streaming_rules: list[StreamingRule] = []   # Custom streaming control rules

    # Modern protocol support
    enable_http3_support: bool = True           # Enable HTTP/3 over QUIC features
    enable_grpc_analysis: bool = True           # Enable gRPC message analysis
    enable_graphql_analysis: bool = True        # Enable GraphQL operation analysis
    enable_sse_streaming: bool = True           # Enable Server-Sent Events streaming
    grpc_protobuf_decoding: bool = False        # Attempt protobuf decoding (requires protobuf libs)
    max_grpc_message_size: int = 1_000_000     # 1MB max for gRPC message analysis
    grpc_compression_support: bool = True       # Handle gRPC compression
    grpc_stream_tracking: bool = True           # Track gRPC streaming connections
    grpc_metadata_capture: bool = True          # Capture gRPC metadata
    max_grpc_streams_per_connection: int = 100  # Max tracked streams per connection

    # Enhanced SSE and GraphQL settings
    sse_message_buffer_size: int = 1000         # Max SSE messages to buffer per stream
    sse_reconnect_tracking: bool = True         # Track SSE reconnection attempts
    graphql_complexity_analysis: bool = True    # Perform detailed query complexity analysis
    graphql_query_depth_limit: int = 15        # Max query depth to analyze
    graphql_field_limit: int = 100             # Max fields to analyze per query
    graphql_introspection_detection: bool = True # Detect GraphQL introspection queries

    # Performance and async processing settings
    enable_async_processing: bool = True        # Enable background async processing
    max_async_workers: int = 4                  # Number of background worker threads
    async_task_queue_size: int = 1000          # Max queued background tasks
    connection_pool_size: int = 20              # Max connections in pool per host
    connection_pool_timeout: float = 30.0      # Connection pool timeout in seconds
    enable_request_prioritization: bool = True  # Enable request priority queuing
    background_processing_interval: float = 0.1 # Background processing interval in seconds

    # Performance monitoring and optimization settings
    enable_performance_monitoring: bool = True  # Enable system performance monitoring
    performance_sample_interval: float = 5.0   # Performance sampling interval in seconds
    performance_history_size: int = 1000       # Max performance samples to keep
    enable_resource_alerts: bool = True        # Enable resource usage alerts
    memory_warning_threshold: float = 80.0     # Memory usage warning threshold (%)
    cpu_warning_threshold: float = 80.0        # CPU usage warning threshold (%)
    disk_warning_threshold: float = 90.0       # Disk usage warning threshold (%)
    enable_performance_optimization: bool = True # Enable automatic performance optimizations
    gc_threshold_mb: float = 100.0             # Trigger garbage collection above this memory usage (MB)

    # Enhanced Flow API settings
    enable_connection_analysis: bool = True     # Enable detailed connection analysis
    enable_tls_analysis: bool = True            # Enable TLS/cipher analysis
    enable_flow_lifecycle_tracking: bool = True # Track complete flow lifecycle
    enable_advanced_flow_control: bool = True   # Enable async flow control features
    flow_intercept_timeout: float = 300.0      # Flow intercept timeout in seconds
    enable_flow_backup: bool = True             # Enable flow backup/revert functionality
    max_flow_control_actions: int = 100        # Max flow control actions to track per flow
    enable_connection_fingerprinting: bool = True # Enable client fingerprinting
    tls_vulnerability_scanning: bool = True     # Scan for TLS vulnerabilities


class DNSMapping(BaseModel):
    hostname: str
    ip: str
    enabled: bool = True

    @field_validator('hostname')
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        # Basic hostname validation
        if not v or len(v) > 253:
            raise ValueError("Invalid hostname length")
        if not re.match(r'^[a-zA-Z0-9.-]+$', v):
            raise ValueError("Hostname contains invalid characters")
        # Check for invalid patterns like double dots, leading/trailing dots
        if ".." in v or v.startswith(".") or v.endswith("."):
            raise ValueError("Invalid hostname format")
        return v.lower()

    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address format")
        return v


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

    @field_validator('method')
    @classmethod
    def validate_method(cls, v: str) -> str:
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}
        if v.upper() not in valid_methods:
            raise ValueError(f"Invalid HTTP method. Must be one of: {', '.join(valid_methods)}")
        return v.upper()

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        try:
            parsed = urlparse(v)
            if not parsed.scheme in ("http", "https"):
                raise ValueError("URL must use http or https scheme")
            if not parsed.netloc:
                raise ValueError("URL must include hostname")
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")
        return v

    @field_validator('body')
    @classmethod
    def validate_body_size(cls, v: str) -> str:
        # Limit body size to prevent memory exhaustion
        if len(v.encode('utf-8')) > 1024 * 1024:  # 1MB limit
            raise ValueError("Request body too large (max 1MB)")
        return v


class SavedCollection(BaseModel):
    id: str = ""
    name: str = ""
    requests: list[SavedRequest] = []


class SavedRequest(BaseModel):
    name: str = ""
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = {}
    body: str = ""
    pre_script: str = ""



class FuzzConfig(BaseModel):
    iterations: int = 10
    variables: dict[str, str] = {}  # name -> "range:1,100" | "wordlist:a,b,c" | "random:8"
    delay_ms: int = 0

    @field_validator('iterations')
    @classmethod
    def validate_iterations(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Iterations must be at least 1")
        if v > 10000:
            raise ValueError("Iterations limited to 10,000 to prevent abuse")
        return v

    @field_validator('delay_ms')
    @classmethod
    def validate_delay(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Delay cannot be negative")
        if v > 300000:  # 5 minutes max
            raise ValueError("Delay limited to 5 minutes maximum")
        return v


class SequenceStep(BaseModel):
    name: str = ""
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = {}
    body: str = ""
    pre_script: str = ""
    extract: dict[str, str] = {}  # var_name -> "json:path.to.field" | "header:Name" | "regex:pattern"


class SavedSequence(BaseModel):
    id: str = ""
    name: str = ""
    steps: list[SequenceStep] = []



class SSLBypassProfile(BaseModel):
    name: str = ""
    description: str = ""
    settings: dict[str, bool] = {}
    frida_script: str = ""


class StreamingRule(BaseModel):
    """Rule to control streaming behavior for specific patterns."""
    enabled: bool = True
    name: str = ""
    match_pattern: str = ""         # URL pattern to match
    is_regex: bool = False
    force_streaming: bool = False   # Force streaming regardless of size
    force_buffering: bool = False   # Force buffering regardless of size
    max_content_size: int = 0       # 0 = use default, >0 = custom limit

    @model_validator(mode='after')
    def validate_streaming_rule(self) -> 'StreamingRule':
        if self.force_streaming and self.force_buffering:
            raise ValueError("Cannot force both streaming and buffering")

        if self.is_regex:
            try:
                re.compile(self.match_pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        return self


class ConnectionStats(BaseModel):
    """Statistics for active connections."""
    flow_id: str = ""
    connection_type: str = ""  # "http", "websocket", "tcp", "quic"
    start_time: float = 0
    message_count: int = 0
    total_bytes: int = 0
    last_activity: float = 0
    is_active: bool = True


class HTTP3Features(BaseModel):
    """HTTP/3 and QUIC specific features."""
    is_quic: bool = False
    quic_version: str = ""
    supports_0rtt: bool = False
    server_push_enabled: bool = False
    priority_streams: list[int] = []
    connection_migration: bool = False
    stream_multiplexing_factor: int = 0


class GRPCMessage(BaseModel):
    """gRPC message representation."""
    service_name: str = ""
    method_name: str = ""
    message_type: str = ""  # "unary", "client_stream", "server_stream", "bidirectional"
    direction: str = ""     # "request", "response"
    content: str = ""
    content_type: str = "application/grpc"
    is_compressed: bool = False
    compression_type: str = ""  # "gzip", "deflate", etc.
    metadata: dict[str, str] = {}
    protobuf_fields: dict[str, str] = {}  # Decoded protobuf fields
    message_size: int = 0
    stream_id: int = 0
    timestamp: float = 0


class GRPCStreamInfo(BaseModel):
    """gRPC streaming connection information."""
    service_name: str = ""
    method_name: str = ""
    stream_type: str = ""  # "unary", "client_stream", "server_stream", "bidirectional"
    is_active: bool = True
    message_count: int = 0
    start_time: float = 0
    last_message_time: float = 0
    client_messages: int = 0
    server_messages: int = 0


class GraphQLOperation(BaseModel):
    """GraphQL operation analysis."""
    operation_type: str = ""  # "query", "mutation", "subscription"
    operation_name: str = ""
    query: str = ""
    variables: dict = {}
    complexity_score: int = 0
    execution_time: float = 0
    timestamp: float = 0
    complexity_analysis: GraphQLComplexityAnalysis | None = None
    response_size: int = 0
    errors: list[str] = []
    warnings: list[str] = []


class SSEMessage(BaseModel):
    """Server-Sent Events message."""
    event_type: str = ""
    data: str = ""
    event_id: str = ""
    retry_time: int = 0
    timestamp: float = 0
    message_size: int = 0
    raw_message: str = ""


class SSEStreamInfo(BaseModel):
    """SSE streaming connection information."""
    is_active: bool = True
    start_time: float = 0
    last_message_time: float = 0
    message_count: int = 0
    total_bytes: int = 0
    event_types: list[str] = []
    reconnect_attempts: int = 0


class GraphQLComplexityAnalysis(BaseModel):
    """Advanced GraphQL query complexity analysis."""
    depth_score: int = 0
    field_count: int = 0
    directive_count: int = 0
    fragment_count: int = 0
    variable_count: int = 0
    estimated_cost: int = 0
    potential_n_plus_one: bool = False
    uses_deprecated_fields: bool = False


class AsyncProcessingTask(BaseModel):
    """Async processing task for background operations."""
    task_id: str = ""
    task_type: str = ""  # "content_analysis", "protobuf_decode", "large_content_save"
    priority: int = 1    # 1=low, 2=medium, 3=high, 4=critical
    flow_id: str = ""
    data: dict = {}
    created_time: float = 0
    started_time: float = 0
    completed_time: float = 0
    status: str = "pending"  # "pending", "processing", "completed", "failed"
    error_message: str = ""
    result: dict = {}


class ConnectionPoolStats(BaseModel):
    """Connection pool statistics."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    created_connections: int = 0
    closed_connections: int = 0
    connection_reuse_count: int = 0
    avg_connection_lifetime: float = 0
    pool_hit_rate: float = 0


class ProcessingQueueStats(BaseModel):
    """Processing queue statistics."""
    pending_tasks: int = 0
    processing_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    queue_depth_by_priority: dict[int, int] = {}
    avg_processing_time: float = 0
    throughput_per_second: float = 0


class SystemResourceMetrics(BaseModel):
    """System resource usage metrics."""
    timestamp: float = 0
    cpu_percent: float = 0
    memory_percent: float = 0
    memory_used_mb: float = 0
    memory_available_mb: float = 0
    disk_usage_percent: float = 0
    disk_used_gb: float = 0
    disk_available_gb: float = 0
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    open_file_descriptors: int = 0
    thread_count: int = 0


class PerformanceMetrics(BaseModel):
    """Application performance metrics."""
    timestamp: float = 0
    requests_per_second: float = 0
    avg_request_duration_ms: float = 0
    total_requests: int = 0
    active_flows: int = 0
    error_rate: float = 0
    cache_hit_rate: float = 0
    memory_cache_size_mb: float = 0
    disk_cache_size_mb: float = 0


class AlertRule(BaseModel):
    """Performance alert rule."""
    name: str = ""
    metric_name: str = ""
    threshold: float = 0
    comparison: str = ">"  # ">", "<", ">=", "<=", "=="
    duration_seconds: int = 60
    enabled: bool = True
    last_triggered: float = 0
    trigger_count: int = 0


class PerformanceAlert(BaseModel):
    """Performance alert instance."""
    alert_id: str = ""
    rule_name: str = ""
    message: str = ""
    severity: str = "warning"  # "info", "warning", "error", "critical"
    metric_value: float = 0
    threshold: float = 0
    timestamp: float = 0
    acknowledged: bool = False


class ConnectionInfo(BaseModel):
    """Detailed connection information from mitmproxy Flow."""
    ip: str = ""
    port: int = 0
    tls_version: str = ""
    cipher_name: str = ""
    cipher_list: list[str] = []
    alpn_proto: str = ""
    sni: str = ""
    timestamp_start: float = 0
    timestamp_tls_setup: float | None = None
    timestamp_end: float | None = None
    via: str = ""  # Proxy chain info
    peername: tuple[str, int] | None = None
    sockname: tuple[str, int] | None = None


class DetailedErrorInfo(BaseModel):
    """Enhanced error analysis from Flow.error."""
    message: str = ""
    timestamp: float = 0
    error_type: str = ""  # "killed", "connection", "timeout", "tls", "unknown"
    category: str = ""
    duration_before_error: float = 0
    connection_phase: str = ""  # "handshake", "request", "response", "unknown"
    is_timeout: bool = False
    is_killed: bool = False
    is_tls_error: bool = False
    retry_count: int = 0


class FlowLifecycleInfo(BaseModel):
    """Complete flow lifecycle tracking."""
    created: float = 0
    started: float = 0
    completed: float = 0
    is_live: bool = False
    is_intercepted: bool = False
    is_marked: bool = False
    marker: str = ""
    is_replay: str | None = None  # None, "request", "response"
    replay_type: str = ""
    is_killable: bool = False
    is_modified: bool = False
    creation_to_start_ms: float = 0
    total_duration_ms: float = 0
    backup_count: int = 0
    intercept_count: int = 0


class FlowControlAction(BaseModel):
    """Flow control action tracking (intercept, kill, backup, etc.)."""
    action_id: str = ""
    flow_id: str = ""
    action_type: str = ""  # "intercept", "kill", "backup", "revert", "resume"
    reason: str = ""
    timestamp: float = 0
    phase: str = ""  # "request", "response"
    user: str = ""
    success: bool = False
    timeout_seconds: float = 0
    auto_action: bool = False  # True if automatic, False if user-initiated


class TLSAnalysis(BaseModel):
    """TLS/SSL connection analysis."""
    tls_version: str = ""
    cipher_suite: str = ""
    key_exchange: str = ""
    signature_algorithm: str = ""
    encryption_algorithm: str = ""
    mac_algorithm: str = ""
    certificate_chain_length: int = 0
    has_sni: bool = False
    sni_hostname: str = ""
    alpn_protocols: list[str] = []
    is_forward_secret: bool = False
    vulnerability_score: int = 0  # 0-100, lower is better
    security_level: str = ""  # "secure", "weak", "vulnerable"


class ConnectionPatternAnalysis(BaseModel):
    """Analysis of connection patterns and behavior."""
    unique_client_ips: int = 0
    top_client_ips: list[tuple[str, int]] = []
    connection_reuse_rate: float = 0
    avg_connection_duration: float = 0
    tls_version_distribution: dict[str, int] = {}
    cipher_suite_distribution: dict[str, int] = {}
    protocol_distribution: dict[str, int] = {}
    geographic_distribution: dict[str, int] = {}  # Country codes
    suspicious_patterns: list[str] = []


# ── Fix forward references after all classes are defined ──

# Core models with forward references
FlowRecord.model_rebuild()
SavedCollection.model_rebuild()
SavedSequence.model_rebuild()
