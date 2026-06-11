from __future__ import annotations

import fnmatch
import mimetypes
import re
import time
import logging
import base64
import asyncio
import threading
import gc
import psutil
import os
from pathlib import Path
from urllib.parse import urlparse
from queue import Queue, PriorityQueue
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from collections import deque

import httpx
from mitmproxy import http, ctx, websocket, tls, dns

from state.models import (
    FlowRecord, InterceptedFlow, WSMessage, ContentSizePolicy, ConnectionStats,
    HTTP3Features, GRPCMessage, GRPCStreamInfo, GraphQLOperation, GraphQLComplexityAnalysis,
    SSEMessage, SSEStreamInfo, AsyncProcessingTask, ConnectionPoolStats, ProcessingQueueStats,
    SystemResourceMetrics, PerformanceMetrics, AlertRule, PerformanceAlert,
    ConnectionInfo, DetailedErrorInfo, FlowLifecycleInfo, FlowControlAction, TLSAnalysis,
    ConnectionPatternAnalysis
)
from state.shared import ProxyState

logger = logging.getLogger("pRoxy.addon")


class ProxyAddon:
    """mitmproxy addon that bridges flows into ProxyState."""

    def __init__(self) -> None:
        self.state = ProxyState()
        self.state.proxy_addon = self
        self._dns_cache: dict[str, tuple[str, float]] = {}  # host → (ip, expiry)
        self._doh_client: httpx.Client | None = None
        self._active_ws_flows: dict[str, http.HTTPFlow] = {}  # flow_id → flow
        self._dns_flows: dict[str, dns.DNSFlow] = {}  # track active DNS flows

        # New features
        self._server_replay_rules: dict = {}
        self._content_injection_rules: dict = {}
        self._content_processors: dict = {}
        self._tcp_servers: dict = {}  # rule_id → server task
        self._wireguard_mode: bool = False
        self._reverse_proxy_mode: bool = False

        # Enhanced streaming and connection tracking
        self._connection_stats: dict[str, ConnectionStats] = {}
        self._content_storage_dir: Path | None = None
        self._last_cleanup: float = time.time()
        self._cleanup_interval: float = 3600  # 1 hour

        # gRPC streaming support
        self._grpc_streams: dict[str, GRPCStreamInfo] = {}  # flow_id -> stream_info
        self._grpc_stream_counter: int = 0

        # SSE and GraphQL tracking
        self._sse_streams: dict[str, SSEStreamInfo] = {}    # flow_id -> sse_stream_info
        self._graphql_operations: dict[str, list[GraphQLOperation]] = {}  # flow_id -> operations

        # Async processing and performance optimization
        self._async_task_queue: PriorityQueue = PriorityQueue()
        self._processing_executor: Optional[ThreadPoolExecutor] = None
        self._background_thread: Optional[threading.Thread] = None
        self._shutdown_event: threading.Event = threading.Event()
        self._task_counter: int = 0
        self._connection_pools: dict[str, httpx.AsyncClient] = {}  # host -> client pool
        self._processing_stats: dict[str, float] = {}  # task_type -> avg_processing_time
        self._queue_stats: ProcessingQueueStats = ProcessingQueueStats()

        # Performance monitoring
        self._system_metrics_history: deque = deque(maxlen=1000)
        self._performance_metrics_history: deque = deque(maxlen=1000)
        self._alert_rules: dict[str, AlertRule] = {}
        self._active_alerts: dict[str, PerformanceAlert] = {}
        self._performance_monitor_thread: Optional[threading.Thread] = None
        self._last_performance_sample: float = 0
        self._request_timestamps: deque = deque(maxlen=10000)  # Track request times
        self._process = psutil.Process()

        # Enhanced Flow API tracking
        self._flow_control_actions: dict[str, list[FlowControlAction]] = {}  # flow_id -> actions
        self._intercepted_flows: dict[str, float] = {}  # flow_id -> intercept_timestamp
        self._backed_up_flows: set[str] = set()  # flow_ids that have backups
        self._connection_patterns: dict[str, dict] = {}  # client_ip -> connection_info
        self._tls_vulnerabilities: dict[str, list[str]] = {}  # cipher -> vulnerabilities

        # Initialize performance monitoring and async processing
        self._init_performance_monitoring()
        self._init_async_processing()

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _headers_dict(headers) -> dict[str, str]:
        return {k: v for k, v in headers.items()}

    def _smart_body_handling(self, content: bytes | None, content_type: str, flow_id: str) -> tuple[str, str, int]:
        """
        Smart content handling based on size and type.
        Returns: (body_for_display, content_file_path, actual_size)
        """
        if content is None or len(content) == 0:
            return "", "", 0

        size = len(content)
        ct = content_type.lower()
        settings = self.state.get_settings()

        # Small content - return full content
        if size <= ContentSizePolicy.SMALL:
            return self._safe_body_legacy(content, content_type), "", size

        # Medium content - truncate for display but keep in memory
        elif size <= ContentSizePolicy.MEDIUM:
            return self._safe_body_legacy(content, content_type, ContentSizePolicy.MEDIUM), "", size

        # Large content - save to disk if enabled, show summary
        elif size <= ContentSizePolicy.LARGE:
            if settings.save_large_content:
                # Use async processing for large content saving
                if settings.enable_async_processing and size > 100_000:  # 100KB threshold
                    task_id = self._submit_async_task(
                        "large_content_save",
                        flow_id,
                        {"content": content, "content_type": content_type},
                        priority=2
                    )
                    summary = f"<large content: {size:,} bytes - saving in background (task: {task_id[:8]})>"
                    return summary, "", size
                else:
                    file_path = self._save_large_content(content, flow_id, content_type)
                    summary = f"<large content: {size:,} bytes"
                    if file_path:
                        summary += f" saved to {Path(file_path).name}"
                    summary += ">"
                    return summary, file_path, size
            else:
                # Truncate heavily for display only
                return self._safe_body_legacy(content, content_type, 10000), "", size

        # Huge content - should have been streamed
        else:
            if settings.save_large_content:
                # Always use async processing for huge content
                if settings.enable_async_processing:
                    task_id = self._submit_async_task(
                        "large_content_save",
                        flow_id,
                        {"content": content, "content_type": content_type},
                        priority=3
                    )
                    summary = f"<huge content: {size:,} bytes - saving in background (task: {task_id[:8]})"
                    summary += " - consider enabling streaming>"
                    return summary, "", size
                else:
                    file_path = self._save_large_content(content, flow_id, content_type)
                    summary = f"<huge content: {size:,} bytes - consider enabling streaming"
                    if file_path:
                        summary += f" - saved to {Path(file_path).name}"
                    summary += ">"
                    return summary, file_path, size
            else:
                return f"<huge content: {size:,} bytes - not saved (enable save_large_content)>", "", size

    @staticmethod
    def _safe_body_legacy(content: bytes | None, content_type: str = "", max_size: int = 512_000) -> str:
        """Legacy _safe_body method for backward compatibility."""
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

    # ── Streaming Detection and Management ────────────────────────

    def _should_enable_streaming(self, flow: http.HTTPFlow) -> bool:
        """Decide if this request should use streaming based on multiple factors."""
        settings = self.state.get_settings()

        # Check if smart streaming is enabled
        if not settings.enable_smart_streaming:
            return False

        # Check custom streaming rules first
        url = flow.request.pretty_url
        for rule in settings.streaming_rules:
            if not rule.enabled:
                continue

            if self._url_matches(url, rule.match_pattern, rule.is_regex):
                if rule.force_streaming:
                    logger.info("Streaming forced by rule: %s", rule.name)
                    return True
                elif rule.force_buffering:
                    logger.info("Buffering forced by rule: %s", rule.name)
                    return False

        # 1. Large file indicators by extension
        path_lower = flow.request.path.lower()
        large_file_extensions = [
            '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
            '.iso', '.dmg', '.img', '.exe', '.msi', '.deb', '.rpm',
            '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm',
            '.mp3', '.wav', '.flac', '.aac', '.ogg',
            '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx'
        ]

        if any(ext in path_lower for ext in large_file_extensions):
            logger.debug("Large file extension detected: %s", flow.request.path)
            return True

        # 2. Streaming content types in Accept header
        accept = flow.request.headers.get("accept", "").lower()
        streaming_content_types = [
            "video/", "audio/", "application/octet-stream",
            "text/event-stream",  # Server-Sent Events
            "application/pdf", "application/zip",
            "multipart/x-mixed-replace",  # Streaming multipart
            "application/grpc",  # gRPC streaming
            "application/grpc+proto",
            "application/grpc-web",
            "application/grpc-web+proto"
        ]

        if any(ct in accept for ct in streaming_content_types):
            logger.debug("Streaming content type in Accept header: %s", accept)
            return True

        # 2.5. Modern protocol indicators that benefit from streaming
        if self._detect_grpc_traffic(flow):
            logger.debug("gRPC traffic detected - enabling streaming")
            return True

        if self._detect_sse_traffic(flow):
            logger.debug("SSE traffic detected - enabling streaming")
            return True

        # 3. Expected large responses from Content-Length
        content_length = flow.request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > settings.auto_stream_threshold:
                    logger.info("Large content-length detected: %d bytes", size)
                    return True
            except ValueError:
                pass

        # 4. CDN and file hosting domains
        cdn_indicators = [
            'cdn', 'download', 'files', 'static', 'assets', 'media',
            's3.amazonaws.com', 'blob.core.windows.net', 'storage.googleapis.com',
            'cloudfront.net', 'fastly.com', 'jsdelivr.net'
        ]

        if any(indicator in flow.request.host.lower() for indicator in cdn_indicators):
            # Only for paths that look like files
            if '.' in flow.request.path.split('/')[-1]:
                logger.debug("CDN domain with file path detected: %s%s", flow.request.host, flow.request.path)
                return True

        # 5. Streaming URL patterns
        streaming_patterns = [
            '/stream', '/live', '/video', '/audio', '/download',
            '/api/v1/download', '/blob/', '/attachment'
        ]

        if any(pattern in flow.request.path.lower() for pattern in streaming_patterns):
            logger.debug("Streaming URL pattern detected: %s", flow.request.path)
            return True

        return False

    def _should_override_streaming(self, flow: http.HTTPFlow) -> bool:
        """Smart override: disable streaming for analyzable content based on actual response."""
        if not flow.response:
            return False

        # 1. Check actual response content type - prioritize analysis over streaming
        content_type = flow.response.headers.get("content-type", "").lower()
        analyzable_types = [
            "application/json",
            "application/xml",
            "text/xml",
            "text/html",
            "text/plain",
            "text/css",
            "text/javascript",
            "application/javascript",
            "application/x-javascript",
            "application/ld+json",
            "application/hal+json",
            "application/vnd.api+json",
            "application/problem+json",
            "application/soap+xml",
            "application/graphql"
        ]

        if any(atype in content_type for atype in analyzable_types):
            logger.debug("Override streaming: analyzable content-type %s", content_type)
            return True

        # 2. Check actual response size - if small enough, always capture for analysis
        try:
            content_length = flow.response.headers.get("content-length")
            if content_length:
                size = int(content_length)
                # If less than 1MB, always capture for analysis regardless of initial streaming decision
                if size < 1_000_000:
                    logger.debug("Override streaming: small response size %d bytes", size)
                    return True
        except (ValueError, TypeError):
            pass

        # 3. Check for API endpoint patterns - APIs should be analyzed, not streamed
        path_lower = flow.request.path.lower()
        api_patterns = [
            '/api/', '/v1/', '/v2/', '/v3/', '/rest/',
            '/graphql', '/query', '/mutation',
            '.json', '.xml'
        ]

        if any(pattern in path_lower for pattern in api_patterns):
            logger.debug("Override streaming: API endpoint pattern detected: %s", flow.request.path)
            return True

        # 4. Check for development/testing domains - usually need full analysis
        dev_patterns = ['localhost', '127.0.0.1', 'httpbin', 'jsonplaceholder', 'reqres']
        if any(pattern in flow.request.host.lower() for pattern in dev_patterns):
            logger.debug("Override streaming: development/testing domain: %s", flow.request.host)
            return True

        return False

    def _capture_streaming_preview(self, flow: http.HTTPFlow) -> dict | None:
        """Capture content preview from streamed responses for analysis."""
        if not flow.response:
            return None

        try:
            # Get response metadata
            content_type = flow.response.headers.get("content-type", "unknown")
            content_length = flow.response.headers.get("content-length")
            actual_size = len(flow.response.content) if flow.response.content else 0

            # Settings for preview capture
            settings = self.state.get_settings()
            preview_head_size = 1024  # First 1KB
            preview_tail_size = 512   # Last 512 bytes
            max_preview_size = 2048   # Max total preview size

            preview_parts = []
            summary_parts = []
            is_binary = False  # Initialize to prevent UnboundLocalError

            # Content metadata summary
            summary_parts.append(f"Content-Type: {content_type}")
            if content_length:
                summary_parts.append(f"Declared Size: {content_length}")
            if actual_size > 0:
                summary_parts.append(f"Actual Size: {actual_size:,} bytes")

            # Capture content preview if available
            if flow.response.content and actual_size > 0:
                content = flow.response.content

                # Determine content encoding for preview
                encoding = "utf-8"
                is_binary = False

                # Check if content is binary or protobuf
                if b'\x00' in content[:100] or content_type.startswith(('image/', 'video/', 'audio/', 'application/octet-stream')):
                    is_binary = True
                    encoding = "latin-1"  # Fallback for binary display

                # Special handling for gRPC/Protobuf content
                if content_type.startswith('application/grpc'):
                    try:
                        # Extract protobuf payload from gRPC frame header first
                        protobuf_fields = {}
                        if len(content) >= 5:
                            # gRPC frame: compression_flag (1 byte) + message_length (4 bytes) + payload
                            compression_flag = content[0]
                            message_length = int.from_bytes(content[1:5], byteorder='big')
                            if len(content) >= 5 + message_length:
                                protobuf_payload = content[5:5+message_length]
                                if len(protobuf_payload) > 0:
                                    _, protobuf_fields = self._enhanced_protobuf_decode(protobuf_payload)
                                else:
                                    protobuf_fields = {}  # Empty message

                        if protobuf_fields:
                            # Show only decoded fields in clean format
                            for field_name, field_value in list(protobuf_fields.items())[:10]:
                                field_num = field_name.split('_')[1]
                                preview_parts.append(f"Field {field_num}: {field_value}")
                        else:
                            preview_parts.append(f"=== PROTOBUF MESSAGE ===")
                            preview_parts.append(f"Size: {len(content)} bytes")
                            preview_parts.append("No readable fields found")
                    except Exception as e:
                        # Fall back to binary display if protobuf decoding fails
                        logger.debug("Protobuf decoding failed, using binary display: %s", e)
                        is_binary = True

                elif is_binary:
                    # Binary content preview
                    preview_parts.append("=== BINARY CONTENT PREVIEW ===")
                    preview_parts.append(f"Size: {actual_size:,} bytes")
                    preview_parts.append(f"Content-Type: {content_type}")

                    # Show hex dump of first bytes
                    if actual_size > 0:
                        hex_preview = content[:min(64, actual_size)].hex(' ')
                        preview_parts.append(f"Hex (first 64 bytes): {hex_preview}")

                    # Try to identify file type by magic bytes
                    file_type = self._identify_file_type(content)
                    if file_type:
                        preview_parts.append(f"Detected Type: {file_type}")

                else:
                    # Text content preview
                    try:
                        if actual_size <= max_preview_size:
                            # Small enough to show full content
                            text_content = content.decode(encoding, errors='replace')
                            preview_parts.append("=== FULL CONTENT ===")
                            preview_parts.append(text_content)
                        else:
                            # Show head and tail
                            head = content[:preview_head_size].decode(encoding, errors='replace')
                            tail = content[-preview_tail_size:].decode(encoding, errors='replace')

                            preview_parts.append("=== CONTENT PREVIEW ===")
                            preview_parts.append(f"[First {preview_head_size} bytes]")
                            preview_parts.append(head)
                            preview_parts.append(f"\n... [{actual_size - preview_head_size - preview_tail_size:,} bytes omitted] ...\n")
                            preview_parts.append(f"[Last {preview_tail_size} bytes]")
                            preview_parts.append(tail)

                    except UnicodeDecodeError:
                        # Fallback to binary display
                        hex_preview = content[:64].hex(' ')
                        preview_parts.append(f"=== BINARY CONTENT (decode failed) ===")
                        preview_parts.append(f"Hex preview: {hex_preview}")

            else:
                # No content available (truly streamed)
                preview_parts.append("=== STREAMING RESPONSE ===")
                preview_parts.append("Content was streamed - no buffer available")
                if content_length:
                    preview_parts.append(f"Expected size: {content_length}")

            # Skip response headers for streaming content - they're shown elsewhere

            # Combine everything
            preview_content = "\n".join(preview_parts)
            summary = " | ".join(summary_parts)

            return {
                "preview_content": preview_content,
                "summary": summary,
                "metadata": {
                    "content_type": content_type,
                    "actual_size": actual_size,
                    "is_binary": is_binary,
                    "preview_length": len(preview_content)
                }
            }

        except Exception as e:
            logger.error("Failed to capture streaming preview: %s", e)
            return {
                "preview_content": f"<preview capture failed: {str(e)}>",
                "summary": "Preview capture error",
                "metadata": {"error": str(e)}
            }

    def _identify_file_type(self, content: bytes) -> str | None:
        """Identify file type from magic bytes."""
        if len(content) < 8:
            return None

        # Common file type magic bytes
        magic_bytes = {
            b'\x89PNG\r\n\x1a\n': 'PNG Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'GIF8': 'GIF Image',
            b'RIFF': 'RIFF (possibly AVI/WAV)',
            b'\x00\x00\x00\x18ftypmp4': 'MP4 Video',
            b'\x00\x00\x00\x20ftypM4V': 'M4V Video',
            b'PK\x03\x04': 'ZIP Archive',
            b'Rar!\x1a\x07\x00': 'RAR Archive',
            b'\x1f\x8b\x08': 'GZIP Archive',
            b'%PDF': 'PDF Document',
            b'\xd0\xcf\x11\xe0': 'Microsoft Office Document'
        }

        for magic, file_type in magic_bytes.items():
            if content.startswith(magic):
                return file_type

        return None

    def _create_streaming_processor(self, flow: http.HTTPFlow):
        """Create a transformation function for streaming content."""
        settings = self.state.get_settings()

        def stream_processor(chunk: bytes) -> bytes:
            """Process streaming chunks with limited modifications."""
            try:
                # Only apply simple text replacements for streaming
                if flow.response and "text/" in flow.response.headers.get("content-type", ""):
                    try:
                        text = chunk.decode("utf-8", errors="ignore")
                        for rule in settings.replace_rules:
                            if rule.enabled and rule.phase == "response" and not rule.is_regex:
                                # Only simple string replacement for streaming
                                text = text.replace(rule.pattern, rule.replacement)
                        return text.encode("utf-8")
                    except Exception:
                        pass

                return chunk
            except Exception as e:
                logger.debug("Stream processor error: %s", e)
                return chunk

        return stream_processor

    def _ensure_content_storage_dir(self) -> Path:
        """Ensure content storage directory exists and return path."""
        if self._content_storage_dir is None:
            settings = self.state.get_settings()
            self._content_storage_dir = Path(settings.content_storage_dir)
            self._content_storage_dir.mkdir(parents=True, exist_ok=True)
        return self._content_storage_dir

    def _save_large_content(self, content: bytes, flow_id: str, content_type: str = "") -> str:
        """Save large content to disk and return file path."""
        try:
            storage_dir = self._ensure_content_storage_dir()

            # Determine file extension from content type
            ext = ""
            if "json" in content_type:
                ext = ".json"
            elif "html" in content_type:
                ext = ".html"
            elif "xml" in content_type:
                ext = ".xml"
            elif "text" in content_type:
                ext = ".txt"
            else:
                ext = ".bin"

            file_path = storage_dir / f"{flow_id}_content{ext}"

            with open(file_path, "wb") as f:
                f.write(content)

            logger.info("Large content saved: %s (%d bytes)", file_path, len(content))
            return str(file_path)

        except Exception as e:
            logger.error("Failed to save large content: %s", e)
            return ""

    def _should_process_content(self, flow: http.HTTPFlow) -> bool:
        """Decide if content needs full processing based on type and size."""
        if not flow.response:
            return True  # Always process requests

        settings = self.state.get_settings()
        ct = flow.response.headers.get("content-type", "").lower()

        # Never process large media files
        if any(t in ct for t in ["video/", "audio/", "image/", "application/zip", "application/octet-stream"]):
            return False

        # Skip if no processing rules apply
        if not (settings.replace_rules or settings.header_rules or
                settings.hsts_strip or settings.csp_strip or settings.cors_bypass):
            return False

        # Check content size
        content_length = flow.response.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > ContentSizePolicy.LARGE:
                    logger.debug("Skipping content processing for large response: %d bytes", size)
                    return False
            except ValueError:
                pass

        return True

    def _cleanup_old_content_files(self) -> None:
        """Clean up old content files to prevent disk space issues."""
        try:
            settings = self.state.get_settings()
            if not settings.save_large_content:
                return

            storage_dir = Path(settings.content_storage_dir)
            if not storage_dir.exists():
                return

            # Remove files older than 24 hours
            cutoff_time = time.time() - (24 * 60 * 60)
            removed_count = 0
            total_size = 0

            for file_path in storage_dir.glob("*_content.*"):
                try:
                    if file_path.stat().st_mtime < cutoff_time:
                        file_size = file_path.stat().st_size
                        file_path.unlink()
                        removed_count += 1
                        total_size += file_size
                except OSError:
                    pass

            if removed_count > 0:
                logger.info("Cleaned up %d old content files (%d MB freed)",
                          removed_count, total_size // (1024 * 1024))

        except Exception as e:
            logger.error("Content cleanup failed: %s", e)

    def _get_content_storage_stats(self) -> dict:
        """Get statistics about content storage usage."""
        try:
            settings = self.state.get_settings()
            storage_dir = Path(settings.content_storage_dir)

            if not storage_dir.exists():
                return {"files": 0, "total_size": 0, "directory": str(storage_dir)}

            files = list(storage_dir.glob("*_content.*"))
            total_size = sum(f.stat().st_size for f in files if f.is_file())

            return {
                "files": len(files),
                "total_size": total_size,
                "total_size_mb": total_size // (1024 * 1024),
                "directory": str(storage_dir),
                "oldest_file": min((f.stat().st_mtime for f in files), default=0) if files else 0
            }

        except Exception as e:
            logger.error("Failed to get storage stats: %s", e)
            return {"error": str(e)}

    def _periodic_maintenance(self) -> None:
        """Perform periodic maintenance tasks."""
        current_time = time.time()

        # Only run cleanup every hour
        if current_time - self._last_cleanup > self._cleanup_interval:
            self._cleanup_old_content_files()
            self._cleanup_old_connection_stats()
            self._cleanup_old_grpc_streams()
            self._cleanup_old_sse_streams()
            self._cleanup_connection_pools()
            self._cleanup_flow_control_actions()
            self._last_cleanup = current_time

    def _cleanup_old_connection_stats(self) -> None:
        """Clean up old connection statistics."""
        current_time = time.time()
        cutoff_time = current_time - (3600 * 6)  # 6 hours

        old_connections = [
            flow_id for flow_id, stats in self._connection_stats.items()
            if not stats.is_active and stats.last_activity < cutoff_time
        ]

        for flow_id in old_connections:
            self._connection_stats.pop(flow_id, None)

        if old_connections:
            logger.debug("Cleaned up %d old connection stats", len(old_connections))

    def _cleanup_old_grpc_streams(self) -> None:
        """Clean up old gRPC stream tracking."""
        current_time = time.time()
        cutoff_time = current_time - (3600 * 2)  # 2 hours

        old_streams = [
            flow_id for flow_id, stream_info in self._grpc_streams.items()
            if not stream_info.is_active and stream_info.last_message_time < cutoff_time
        ]

        for flow_id in old_streams:
            self._grpc_streams.pop(flow_id, None)

        if old_streams:
            logger.debug("Cleaned up %d old gRPC streams", len(old_streams))

    def get_grpc_stream_stats(self) -> dict:
        """Get gRPC streaming statistics."""
        active_streams = sum(1 for s in self._grpc_streams.values() if s.is_active)
        total_messages = sum(s.message_count for s in self._grpc_streams.values())

        stream_types = {}
        for stream_info in self._grpc_streams.values():
            stream_types[stream_info.stream_type] = stream_types.get(stream_info.stream_type, 0) + 1

        return {
            "total_streams": len(self._grpc_streams),
            "active_streams": active_streams,
            "total_messages": total_messages,
            "stream_types": stream_types,
            "services": list(set(s.service_name for s in self._grpc_streams.values()))
        }

    def _detect_http_version(self, flow: http.HTTPFlow) -> str:
        """Enhanced HTTP version detection."""
        settings = self.state.get_settings()
        if not settings.detect_http_version:
            return ""

        # Check HTTP version directly from request
        if hasattr(flow.request, 'http_version'):
            version = flow.request.http_version
            if version in ("HTTP/2.0", "h2"):
                return "HTTP/2"
            elif version == "HTTP/3.0" or version == "h3":
                return "HTTP/3"
            elif version in ("HTTP/1.1", "HTTP/1.0"):
                return version

        # Check for HTTP/2 pseudo-headers (mitmproxy converts them)
        if any(header.startswith(":") for header in flow.request.headers.keys()):
            return "HTTP/2"

        # Check version from flow attributes
        if hasattr(flow, 'request') and hasattr(flow.request, 'is_http2') and flow.request.is_http2:
            return "HTTP/2"
        elif hasattr(flow, 'request') and hasattr(flow.request, 'is_http3') and flow.request.is_http3:
            return "HTTP/3"

        return "HTTP/1.1"  # Default assumption

    def _detect_http3_features(self, flow: http.HTTPFlow) -> HTTP3Features | None:
        """Detect HTTP/3 and QUIC specific features."""
        settings = self.state.get_settings()
        if not settings.enable_http3_support:
            return None

        # Check for HTTP/3 indicators
        alt_svc = flow.response.headers.get("alt-svc", "") if flow.response else ""
        http_version = self._detect_http_version(flow)

        if http_version == "HTTP/3" or "h3" in alt_svc:
            features = HTTP3Features(
                is_quic=True,
                quic_version="draft-29" if "h3-29" in alt_svc else "v1",
                supports_0rtt=False,  # Would need deeper QUIC inspection
                server_push_enabled="push" in alt_svc,
                connection_migration="migration" in alt_svc
            )

            # Analyze Alt-Svc header for additional features
            if alt_svc:
                if "h3" in alt_svc:
                    features.is_quic = True
                if "quic" in alt_svc.lower():
                    # Extract QUIC version if present
                    import re
                    version_match = re.search(r'quic=([^;,]+)', alt_svc)
                    if version_match:
                        features.quic_version = version_match.group(1).strip('"')

            logger.debug("HTTP/3 features detected: %s", features)
            return features

        return None

    def _detect_grpc_traffic(self, flow: http.HTTPFlow) -> bool:
        """Detect if this is gRPC traffic."""
        if not flow.request:
            return False

        content_type = flow.request.headers.get("content-type", "").lower()
        user_agent = flow.request.headers.get("user-agent", "").lower()

        # gRPC indicators
        grpc_indicators = [
            "application/grpc",
            "grpc" in content_type,
            "grpc" in user_agent,
            flow.request.headers.get("grpc-encoding") is not None,
            flow.request.headers.get("grpc-timeout") is not None,
            "te: trailers" in str(flow.request.headers).lower()
        ]

        return any(grpc_indicators)

    def _detect_graphql_operation(self, flow: http.HTTPFlow) -> GraphQLOperation | None:
        """Detect and parse GraphQL operations."""
        settings = self.state.get_settings()
        if not settings.enable_graphql_analysis:
            return None

        # Check for GraphQL indicators
        if not flow.request:
            return None

        content_type = flow.request.headers.get("content-type", "").lower()
        url_path = flow.request.path.lower()

        # GraphQL indicators
        is_graphql = (
            "/graphql" in url_path or
            "/graph" in url_path or
            "application/graphql" in content_type or
            flow.request.method == "POST" and "graph" in str(flow.request.get_content() or b"").lower()
        )

        if not is_graphql:
            return None

        try:
            # Try to parse GraphQL query from request body
            if flow.request.get_content():
                body = flow.request.get_content().decode("utf-8", errors="ignore")
                operation = self._parse_graphql_query(body)
                if operation:
                    operation.timestamp = time.time()
                    return operation
        except Exception as e:
            logger.debug("GraphQL parsing error: %s", e)

        # Fallback - create minimal operation info
        return GraphQLOperation(
            operation_type="unknown",
            query="<GraphQL query detected>",
            timestamp=time.time()
        )

    def _parse_graphql_query(self, body: str) -> GraphQLOperation | None:
        """Enhanced GraphQL query parsing with complexity analysis."""
        import json
        import re

        settings = self.state.get_settings()

        try:
            query = ""
            variables = {}
            operation_name = ""

            # Try JSON format first
            if body.strip().startswith('{'):
                data = json.loads(body)
                query = data.get("query", "")
                variables = data.get("variables", {})
                operation_name = data.get("operationName", "")
            else:
                # Try plain GraphQL format
                if any(keyword in body.lower() for keyword in ["query", "mutation", "subscription"]):
                    query = body.strip()

            if not query:
                return None

            # Determine operation type
            query_lower = query.lower().strip()
            if query_lower.startswith("query") or "{" in query_lower and not any(
                keyword in query_lower for keyword in ["mutation", "subscription"]
            ):
                op_type = "query"
            elif query_lower.startswith("mutation"):
                op_type = "mutation"
            elif query_lower.startswith("subscription"):
                op_type = "subscription"
            else:
                op_type = "query"  # Default

            # Basic complexity scoring
            basic_complexity = len(re.findall(r'\{', query)) * 2

            # Advanced complexity analysis
            complexity_analysis = None
            if settings.graphql_complexity_analysis:
                # Use async processing for complex queries
                if settings.enable_async_processing and len(query) > 1000:  # 1KB threshold
                    task_id = self._submit_async_task(
                        "graphql_complexity",
                        "",  # No specific flow ID for this analysis
                        {"query": query},
                        priority=1
                    )
                    logger.debug("GraphQL complexity analysis queued: %s", task_id[:8])
                    # Create basic analysis for immediate use
                    complexity_analysis = GraphQLComplexityAnalysis(
                        depth_score=len(re.findall(r'\{', query)),
                        field_count=len(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', query)),
                        estimated_cost=len(query) // 10  # Rough estimate
                    )
                else:
                    complexity_analysis = self._analyze_graphql_complexity(query)

            # Detect introspection queries
            warnings = []
            if settings.graphql_introspection_detection:
                if self._is_graphql_introspection_query(query):
                    warnings.append("Introspection query detected")

            # Check for potentially expensive patterns
            if "edges" in query and "nodes" in query:
                warnings.append("Relay-style pagination detected - monitor for N+1 queries")

            return GraphQLOperation(
                operation_type=op_type,
                operation_name=operation_name,
                query=query[:2000],  # Store more of the query for analysis
                variables=variables,
                complexity_score=complexity_analysis.estimated_cost if complexity_analysis else basic_complexity,
                complexity_analysis=complexity_analysis,
                warnings=warnings
            )

        except Exception as e:
            logger.debug("GraphQL parsing error: %s", e)
            return None

    def _analyze_graphql_complexity(self, query: str) -> GraphQLComplexityAnalysis:
        """Perform detailed GraphQL query complexity analysis."""
        import re

        settings = self.state.get_settings()

        # Count braces for depth estimation
        brace_depth = 0
        max_depth = 0
        for char in query:
            if char == '{':
                brace_depth += 1
                max_depth = max(max_depth, brace_depth)
            elif char == '}':
                brace_depth -= 1

        # Count fields (simplified - looks for word patterns in selections)
        field_pattern = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b')
        potential_fields = field_pattern.findall(query)

        # Filter out GraphQL keywords
        graphql_keywords = {
            'query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false',
            'null', 'if', 'skip', 'include', '__typename', '__schema', '__type'
        }
        field_count = len([f for f in potential_fields if f.lower() not in graphql_keywords])

        # Count directives
        directive_count = len(re.findall(r'@\w+', query))

        # Count fragments
        fragment_count = len(re.findall(r'\.\.\.', query))

        # Count variables
        variable_count = len(re.findall(r'\$\w+', query))

        # Detect potential N+1 patterns
        potential_n_plus_one = bool(re.search(r'\{\s*\w+\s*\{.*\{\s*\w+', query, re.DOTALL))

        # Check for deprecated field usage patterns
        uses_deprecated_fields = bool(re.search(r'@deprecated|_deprecated|deprecated_', query, re.IGNORECASE))

        # Estimate cost (basic algorithm)
        estimated_cost = (
            max_depth * 2 +
            field_count +
            directive_count * 3 +
            fragment_count * 2 +
            (50 if potential_n_plus_one else 0)
        )

        return GraphQLComplexityAnalysis(
            depth_score=max_depth,
            field_count=min(field_count, settings.graphql_field_limit),
            directive_count=directive_count,
            fragment_count=fragment_count,
            variable_count=variable_count,
            estimated_cost=estimated_cost,
            potential_n_plus_one=potential_n_plus_one,
            uses_deprecated_fields=uses_deprecated_fields
        )

    def _is_graphql_introspection_query(self, query: str) -> bool:
        """Detect if this is a GraphQL introspection query."""
        introspection_indicators = [
            '__schema', '__type', '__typename', '__field', '__inputvalue',
            '__enumvalue', '__directive', 'introspectionquery'
        ]
        query_lower = query.lower()
        return any(indicator in query_lower for indicator in introspection_indicators)

    def _detect_sse_traffic(self, flow: http.HTTPFlow) -> bool:
        """Detect Server-Sent Events traffic."""
        if not flow.response:
            return False

        content_type = flow.response.headers.get("content-type", "").lower()
        cache_control = flow.response.headers.get("cache-control", "").lower()

        return (
            "text/event-stream" in content_type or
            "text/plain" in content_type and "no-cache" in cache_control
        )

    def _parse_grpc_message(self, flow: http.HTTPFlow, content: bytes, direction: str = "request") -> GRPCMessage | None:
        """Enhanced gRPC message parsing with streaming support."""
        settings = self.state.get_settings()
        if not settings.enable_grpc_analysis or not content:
            return None

        try:
            # Handle multiple gRPC messages in a single flow (streaming)
            messages = []
            offset = 0

            while offset < len(content):
                # Basic gRPC message structure analysis
                # gRPC messages have a 5-byte header: compression flag (1 byte) + length (4 bytes)
                if len(content) - offset < 5:
                    break

                compression_flag = content[offset]
                message_length = int.from_bytes(content[offset+1:offset+5], byteorder='big')

                if message_length + 5 + offset > len(content):
                    break

                # Extract message payload
                message_payload = content[offset+5:offset+5+message_length]

                # Extract service and method from URL
                path_parts = flow.request.path.strip('/').split('/')
                service_name = path_parts[0] if path_parts else "unknown"
                method_name = path_parts[1] if len(path_parts) > 1 else "unknown"

                # Get or create stream info
                stream_info = self._get_or_create_grpc_stream(flow, service_name, method_name)

                # Determine compression type
                compression_type = ""
                if compression_flag != 0:
                    grpc_encoding = flow.request.headers.get("grpc-encoding", "")
                    if grpc_encoding:
                        compression_type = grpc_encoding
                    elif compression_flag == 1:
                        compression_type = "gzip"

                # Extract metadata (only for first message or if metadata changed)
                metadata = {}
                if settings.grpc_metadata_capture:
                    for name, value in flow.request.headers.items():
                        if name.lower().startswith('grpc-'):
                            metadata[name] = value

                    # Add response metadata if this is a response direction
                    if direction == "response" and flow.response:
                        for name, value in flow.response.headers.items():
                            if name.lower().startswith('grpc-'):
                                metadata[f"resp-{name}"] = value

                # Handle content decoding
                content_str = "<binary gRPC message>"
                protobuf_fields = {}

                if settings.grpc_protobuf_decoding:
                    try:
                        # Decompress if needed
                        payload = message_payload
                        if compression_flag != 0 and settings.grpc_compression_support:
                            payload = self._decompress_grpc_content(message_payload, compression_type)

                        # Use async processing for large protobuf messages
                        if settings.enable_async_processing and len(payload) > 10000:  # 10KB threshold
                            task_id = self._submit_async_task(
                                "protobuf_decode",
                                flow.id,
                                {"content": payload},
                                priority=2
                            )
                            content_str = f"<protobuf {message_length} bytes - decoding in background (task: {task_id[:8]})>"
                            protobuf_fields = {}
                        else:
                            # Try protobuf decoding synchronously
                            content_str, protobuf_fields = self._enhanced_protobuf_decode(payload)
                    except Exception as e:
                        logger.debug("gRPC protobuf decoding error: %s", e)
                        content_str = f"<protobuf {message_length} bytes, decode_error: {str(e)[:50]}>"
                else:
                    content_str = f"<gRPC message: {message_length} bytes>"

                # Update stream statistics
                if direction == "request":
                    stream_info.client_messages += 1
                else:
                    stream_info.server_messages += 1
                stream_info.message_count += 1
                stream_info.last_message_time = time.time()

                # Create message record
                grpc_message = GRPCMessage(
                    service_name=service_name,
                    method_name=method_name,
                    message_type=stream_info.stream_type,
                    direction=direction,
                    content=content_str,
                    content_type=flow.request.headers.get("content-type", "application/grpc"),
                    is_compressed=compression_flag != 0,
                    compression_type=compression_type,
                    metadata=metadata,
                    protobuf_fields=protobuf_fields,
                    message_size=message_length,
                    stream_id=stream_info.message_count,
                    timestamp=time.time()
                )

                # Capture every parsed message in the stream
                messages.append(grpc_message)

                offset += 5 + message_length

            return messages[0] if messages else None

        except Exception as e:
            logger.debug("gRPC parsing error: %s", e)
            return None

    def _get_or_create_grpc_stream(self, flow: http.HTTPFlow, service_name: str, method_name: str) -> GRPCStreamInfo:
        """Get or create gRPC stream tracking info."""
        settings = self.state.get_settings()

        if flow.id in self._grpc_streams:
            return self._grpc_streams[flow.id]

        # Determine stream type from method name and headers
        stream_type = "unary"  # Default
        if "stream" in method_name.lower():
            if flow.request.headers.get("grpc-timeout"):
                stream_type = "server_stream"
            else:
                stream_type = "bidirectional"
        elif "Subscribe" in method_name or "Watch" in method_name:
            stream_type = "server_stream"

        stream_info = GRPCStreamInfo(
            service_name=service_name,
            method_name=method_name,
            stream_type=stream_type,
            is_active=True,
            message_count=0,
            start_time=time.time(),
            last_message_time=time.time(),
            client_messages=0,
            server_messages=0
        )

        # Limit tracked streams
        if len(self._grpc_streams) >= settings.max_grpc_streams_per_connection:
            # Remove oldest inactive stream
            oldest_id = min(
                (k for k, v in self._grpc_streams.items() if not v.is_active),
                key=lambda x: self._grpc_streams[x].last_message_time,
                default=None
            )
            if oldest_id:
                self._grpc_streams.pop(oldest_id, None)

        self._grpc_streams[flow.id] = stream_info
        return stream_info

    def _decompress_grpc_content(self, content: bytes, compression_type: str) -> bytes:
        """Decompress gRPC message content, size-capped to resist decompression bombs."""
        import zlib
        cap = 64 * 1024 * 1024  # bomb guard (gRPC decode is opt-in but attacker-fed)
        ct = compression_type.lower()
        try:
            if ct == "gzip":
                wbits = 16 + zlib.MAX_WBITS  # gzip header
            elif ct == "deflate":
                wbits = zlib.MAX_WBITS
            else:
                logger.debug("Unknown gRPC compression type: %s", compression_type)
                return content
            d = zlib.decompressobj(wbits)
            out = bytearray()
            data = content
            while True:
                chunk = d.decompress(data, cap + 1 - len(out))
                out += chunk
                if len(out) > cap:
                    raise ValueError("gRPC decompressed output exceeds cap")
                data = d.unconsumed_tail
                if not chunk and not data:
                    return bytes(out)
        except Exception as e:
            logger.debug("gRPC decompression error: %s", e)
            return content

    def _enhanced_protobuf_decode(self, data: bytes) -> tuple[str, dict[str, str]]:
        """Enhanced protobuf decoding with field extraction."""
        fields = {}
        content_str = f"<protobuf data: {len(data)} bytes>"

        try:
            # Basic protobuf wire format analysis
            offset = 0
            field_count = 0

            while offset < len(data) and field_count < 10:  # Limit analysis
                try:
                    # Read varint for field number and wire type
                    varint, bytes_read = self._read_varint(data[offset:])
                    if bytes_read == 0:
                        break

                    field_number = varint >> 3
                    wire_type = varint & 0x07

                    offset += bytes_read

                    # Extract field based on wire type
                    field_value = "unknown"
                    if wire_type == 0:  # Varint
                        value, bytes_read = self._read_varint(data[offset:])
                        field_value = str(value)
                        offset += bytes_read
                    elif wire_type == 2:  # Length-delimited
                        length, bytes_read = self._read_varint(data[offset:])
                        offset += bytes_read
                        if offset + length <= len(data):
                            field_data = data[offset:offset + length]
                            # Try to decode as UTF-8 string
                            try:
                                field_value = field_data.decode('utf-8')
                                if not field_value.isprintable():
                                    field_value = f"<binary {length} bytes>"
                            except UnicodeDecodeError:
                                field_value = f"<binary {length} bytes>"
                            offset += length
                    else:
                        # Skip unsupported wire types
                        break

                    fields[f"field_{field_number}"] = field_value
                    field_count += 1

                except Exception:
                    break

            # Create human-readable protobuf content
            if fields:
                readable_parts = [f"=== PROTOBUF MESSAGE ({len(data)} bytes) ==="]
                for field_name, field_value in fields.items():
                    field_num = field_name.split('_')[1]
                    readable_parts.append(f"Field {field_num}: {field_value}")

                # Add field summary
                readable_parts.append(f"\nSummary: {field_count} fields decoded")
                content_str = "\n".join(readable_parts)
            else:
                content_str = f"=== PROTOBUF MESSAGE ({len(data)} bytes) ===\n[No readable fields found - binary protocol buffer]"

        except Exception as e:
            logger.debug("Protobuf analysis error: %s", e)

        return content_str, fields

    def _read_varint(self, data: bytes) -> tuple[int, int]:
        """Read a protobuf varint from bytes."""
        result = 0
        shift = 0
        bytes_read = 0

        for byte in data:
            bytes_read += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
            if shift >= 64:  # Prevent infinite loop
                break

        return result, bytes_read

    def _decode_protobuf_message(self, data: bytes) -> str:
        """Attempt to decode protobuf message (legacy method for compatibility)."""
        content_str, _ = self._enhanced_protobuf_decode(data)
        return content_str

    def _parse_sse_messages(self, flow: http.HTTPFlow, content: str) -> list[SSEMessage]:
        """Enhanced SSE message parsing with stream tracking."""
        settings = self.state.get_settings()
        messages = []
        lines = content.split('\n')
        current_message = SSEMessage(timestamp=time.time())

        # Get or create SSE stream info
        stream_info = self._get_or_create_sse_stream(flow)

        for line in lines:
            original_line = line
            line = line.strip()

            if not line:
                # Empty line indicates end of message
                if current_message.data or current_message.event_type:
                    current_message.message_size = len(current_message.data.encode('utf-8'))
                    current_message.raw_message = self._build_raw_sse_message(current_message)

                    messages.append(current_message)

                    # Update stream statistics
                    stream_info.message_count += 1
                    stream_info.total_bytes += current_message.message_size
                    stream_info.last_message_time = time.time()

                    if current_message.event_type and current_message.event_type not in stream_info.event_types:
                        stream_info.event_types.append(current_message.event_type)

                    # Handle retry instructions
                    if current_message.retry_time > 0:
                        stream_info.reconnect_attempts += 1

                    current_message = SSEMessage(timestamp=time.time())
                continue

            if line.startswith('data: '):
                current_message.data += line[6:] + '\n'
            elif line.startswith('event: '):
                current_message.event_type = line[7:]
            elif line.startswith('id: '):
                current_message.event_id = line[4:]
            elif line.startswith('retry: '):
                try:
                    current_message.retry_time = int(line[7:])
                except ValueError:
                    pass
            elif line.startswith(': '):
                # Comment line - SSE spec allows this
                pass

        # Add final message if exists
        if current_message.data or current_message.event_type:
            current_message.message_size = len(current_message.data.encode('utf-8'))
            current_message.raw_message = self._build_raw_sse_message(current_message)
            messages.append(current_message)

            # Update stream statistics
            stream_info.message_count += 1
            stream_info.total_bytes += current_message.message_size
            stream_info.last_message_time = time.time()

        # Limit message buffer size
        if len(messages) > settings.sse_message_buffer_size:
            messages = messages[-settings.sse_message_buffer_size:]

        return messages

    def _get_or_create_sse_stream(self, flow: http.HTTPFlow) -> SSEStreamInfo:
        """Get or create SSE stream tracking info."""
        if flow.id in self._sse_streams:
            return self._sse_streams[flow.id]

        stream_info = SSEStreamInfo(
            is_active=True,
            start_time=time.time(),
            last_message_time=time.time(),
            message_count=0,
            total_bytes=0,
            event_types=[],
            reconnect_attempts=0
        )

        self._sse_streams[flow.id] = stream_info
        return stream_info

    def _build_raw_sse_message(self, message: SSEMessage) -> str:
        """Build raw SSE message format for debugging."""
        raw_lines = []

        if message.event_type:
            raw_lines.append(f"event: {message.event_type}")
        if message.event_id:
            raw_lines.append(f"id: {message.event_id}")
        if message.retry_time > 0:
            raw_lines.append(f"retry: {message.retry_time}")

        # Add data lines
        for data_line in message.data.rstrip('\n').split('\n'):
            raw_lines.append(f"data: {data_line}")

        raw_lines.append("")  # Empty line to end message

        return '\n'.join(raw_lines)

    # ── Enhanced Flow API - Connection and Error Analysis ────────

    def _analyze_connection_info(self, connection, connection_type: str = "client") -> ConnectionInfo | None:
        """Extract detailed connection information from mitmproxy connection object."""
        if not connection:
            return None

        try:
            conn_info = ConnectionInfo()

            # Basic connection info
            if hasattr(connection, 'peername') and connection.peername:
                conn_info.ip = connection.peername[0]
                conn_info.port = connection.peername[1]
                conn_info.peername = connection.peername
            elif hasattr(connection, 'address') and connection.address:
                conn_info.ip = connection.address[0]
                conn_info.port = connection.address[1]

            if hasattr(connection, 'sockname'):
                conn_info.sockname = connection.sockname

            # TLS information
            if hasattr(connection, 'tls_version') and connection.tls_version:
                conn_info.tls_version = connection.tls_version

            if hasattr(connection, 'cipher_name') and connection.cipher_name:
                conn_info.cipher_name = connection.cipher_name

            if hasattr(connection, 'cipher_list') and connection.cipher_list:
                conn_info.cipher_list = list(connection.cipher_list)

            if hasattr(connection, 'alpn_proto') and connection.alpn_proto:
                conn_info.alpn_proto = connection.alpn_proto

            if hasattr(connection, 'sni') and connection.sni:
                conn_info.sni = connection.sni

            # Timing information
            if hasattr(connection, 'timestamp_start'):
                conn_info.timestamp_start = connection.timestamp_start or 0

            if hasattr(connection, 'timestamp_tls_setup'):
                conn_info.timestamp_tls_setup = connection.timestamp_tls_setup

            if hasattr(connection, 'timestamp_end'):
                conn_info.timestamp_end = connection.timestamp_end

            # Proxy chain info
            if hasattr(connection, 'via') and connection.via:
                conn_info.via = str(connection.via)

            return conn_info

        except Exception as e:
            logger.debug("Connection info extraction error: %s", e)
            return None

    def _analyze_flow_error(self, flow: http.HTTPFlow) -> DetailedErrorInfo | None:
        """Detailed error analysis using Flow.error."""
        if not flow.error:
            return None

        try:
            error_info = DetailedErrorInfo(
                message=flow.error.msg,
                timestamp=flow.error.timestamp
            )

            # Determine error type
            msg_lower = flow.error.msg.lower()

            if flow.error.msg == getattr(flow.error, 'KILLED_MESSAGE', 'Connection killed.'):
                error_info.error_type = "killed"
                error_info.category = "killed"
                error_info.is_killed = True
            elif any(word in msg_lower for word in ["timeout", "timed out"]):
                error_info.error_type = "timeout"
                error_info.category = "timeout"
                error_info.is_timeout = True
            elif any(word in msg_lower for word in ["ssl", "tls", "certificate", "handshake"]):
                error_info.error_type = "tls"
                error_info.category = "tls"
                error_info.is_tls_error = True
            elif any(word in msg_lower for word in ["connection", "connect", "network"]):
                error_info.error_type = "connection"
                error_info.category = "connection"
            else:
                error_info.error_type = "unknown"
                error_info.category = "unknown"

            # Determine connection phase
            if any(word in msg_lower for word in ["handshake", "hello", "certificate"]):
                error_info.connection_phase = "handshake"
            elif any(word in msg_lower for word in ["request", "sending"]):
                error_info.connection_phase = "request"
            elif any(word in msg_lower for word in ["response", "receiving"]):
                error_info.connection_phase = "response"
            else:
                error_info.connection_phase = "unknown"

            # Calculate duration before error
            if flow.timestamp_start and flow.error.timestamp:
                error_info.duration_before_error = flow.error.timestamp - flow.timestamp_start

            return error_info

        except Exception as e:
            logger.debug("Error analysis failed: %s", e)
            return None

    def _analyze_tls_security(self, client_conn, server_conn) -> TLSAnalysis | None:
        """Analyze TLS security configuration."""
        settings = self.state.get_settings()
        if not settings.enable_tls_analysis:
            return None

        try:
            # Prefer client connection for TLS analysis
            conn = client_conn if client_conn else server_conn
            if not conn:
                return None

            tls_analysis = TLSAnalysis()

            if hasattr(conn, 'tls_version') and conn.tls_version:
                tls_analysis.tls_version = conn.tls_version

            if hasattr(conn, 'cipher_name') and conn.cipher_name:
                tls_analysis.cipher_suite = conn.cipher_name

                # Parse cipher components (simplified)
                cipher_parts = conn.cipher_name.split('-')
                if len(cipher_parts) >= 2:
                    tls_analysis.encryption_algorithm = cipher_parts[0]
                    if 'SHA' in cipher_parts[-1]:
                        tls_analysis.mac_algorithm = cipher_parts[-1]

            if hasattr(conn, 'sni'):
                tls_analysis.has_sni = bool(conn.sni)
                tls_analysis.sni_hostname = conn.sni or ""

            if hasattr(conn, 'alpn_proto') and conn.alpn_proto:
                tls_analysis.alpn_protocols = [conn.alpn_proto]

            # Security assessment
            if settings.tls_vulnerability_scanning:
                tls_analysis.security_level, tls_analysis.vulnerability_score = self._assess_tls_security(tls_analysis)

            return tls_analysis

        except Exception as e:
            logger.debug("TLS analysis error: %s", e)
            return None

    def _assess_tls_security(self, tls_analysis: TLSAnalysis) -> tuple[str, int]:
        """Assess TLS configuration security."""
        vulnerability_score = 0

        # TLS version assessment
        if tls_analysis.tls_version:
            if tls_analysis.tls_version in ["TLSv1", "TLSv1.1"]:
                vulnerability_score += 40  # High vulnerability
            elif tls_analysis.tls_version == "TLSv1.2":
                vulnerability_score += 10  # Low vulnerability
            # TLSv1.3 adds 0 (secure)

        # Cipher suite assessment
        if tls_analysis.cipher_suite:
            cipher_lower = tls_analysis.cipher_suite.lower()

            # Vulnerable ciphers
            if any(weak in cipher_lower for weak in ['rc4', 'des', 'md5', 'null']):
                vulnerability_score += 50
            elif any(weak in cipher_lower for weak in ['sha1', 'cbc']):
                vulnerability_score += 20

            # Check for forward secrecy
            if any(fs in cipher_lower for fs in ['ecdhe', 'dhe']):
                tls_analysis.is_forward_secret = True
            else:
                vulnerability_score += 15

        # Determine security level
        if vulnerability_score >= 50:
            security_level = "vulnerable"
        elif vulnerability_score >= 25:
            security_level = "weak"
        else:
            security_level = "secure"

        return security_level, min(vulnerability_score, 100)

    def _track_flow_lifecycle(self, flow: http.HTTPFlow) -> FlowLifecycleInfo:
        """Track complete flow lifecycle."""
        lifecycle = FlowLifecycleInfo()

        try:
            # Basic timestamps
            if hasattr(flow, 'timestamp_created'):
                lifecycle.created = flow.timestamp_created or 0
            if hasattr(flow, 'timestamp_start'):
                lifecycle.started = flow.timestamp_start or 0

            # Flow state
            if hasattr(flow, 'live'):
                lifecycle.is_live = flow.live
            if hasattr(flow, 'intercepted'):
                lifecycle.is_intercepted = flow.intercepted
            if hasattr(flow, 'marked'):
                lifecycle.is_marked = bool(flow.marked)
                lifecycle.marker = str(flow.marked) if flow.marked else ""
            if hasattr(flow, 'is_replay'):
                lifecycle.is_replay = flow.is_replay
                lifecycle.replay_type = flow.is_replay if flow.is_replay else ""
            if hasattr(flow, 'killable'):
                lifecycle.is_killable = flow.killable
            if hasattr(flow, 'modified'):
                try:
                    lifecycle.is_modified = flow.modified()
                except Exception:
                    lifecycle.is_modified = False

            # Calculate durations
            if lifecycle.started and lifecycle.created:
                lifecycle.creation_to_start_ms = (lifecycle.started - lifecycle.created) * 1000

            # Track control actions
            if flow.id in self._flow_control_actions:
                actions = self._flow_control_actions[flow.id]
                lifecycle.intercept_count = len([a for a in actions if a.action_type == "intercept"])
                lifecycle.backup_count = len([a for a in actions if a.action_type == "backup"])

            return lifecycle

        except Exception as e:
            logger.debug("Lifecycle tracking error: %s", e)
            return lifecycle

    # ── Performance Monitoring and Optimization ──────────────────

    def _init_performance_monitoring(self) -> None:
        """Initialize performance monitoring infrastructure."""
        settings = self.state.get_settings()

        if not settings.enable_performance_monitoring:
            return

        # Initialize default alert rules
        self._init_default_alert_rules()

        # Start performance monitoring thread
        self._performance_monitor_thread = threading.Thread(
            target=self._performance_monitoring_loop,
            daemon=True,
            name="PerformanceMonitor"
        )
        self._performance_monitor_thread.start()

        logger.info("Performance monitoring initialized")

    def _init_default_alert_rules(self) -> None:
        """Initialize default performance alert rules."""
        settings = self.state.get_settings()

        default_rules = [
            AlertRule(
                name="high_memory_usage",
                metric_name="memory_percent",
                threshold=settings.memory_warning_threshold,
                comparison=">=",
                duration_seconds=30,
                enabled=settings.enable_resource_alerts
            ),
            AlertRule(
                name="high_cpu_usage",
                metric_name="cpu_percent",
                threshold=settings.cpu_warning_threshold,
                comparison=">=",
                duration_seconds=60,
                enabled=settings.enable_resource_alerts
            ),
            AlertRule(
                name="high_disk_usage",
                metric_name="disk_usage_percent",
                threshold=settings.disk_warning_threshold,
                comparison=">=",
                duration_seconds=300,
                enabled=settings.enable_resource_alerts
            ),
            AlertRule(
                name="high_error_rate",
                metric_name="error_rate",
                threshold=10.0,  # 10% error rate
                comparison=">=",
                duration_seconds=120,
                enabled=True
            )
        ]

        for rule in default_rules:
            self._alert_rules[rule.name] = rule

    def _performance_monitoring_loop(self) -> None:
        """Main performance monitoring loop."""
        settings = self.state.get_settings()

        while not self._shutdown_event.is_set():
            try:
                current_time = time.time()

                # Sample performance metrics
                if current_time - self._last_performance_sample >= settings.performance_sample_interval:
                    system_metrics = self._collect_system_metrics()
                    performance_metrics = self._collect_performance_metrics()

                    self._system_metrics_history.append(system_metrics)
                    self._performance_metrics_history.append(performance_metrics)

                    # Check alert rules
                    self._check_alert_rules(system_metrics, performance_metrics)

                    # Perform automatic optimizations
                    if settings.enable_performance_optimization:
                        self._perform_automatic_optimizations(system_metrics, performance_metrics)

                    self._last_performance_sample = current_time

                time.sleep(1)  # Check every second

            except Exception as e:
                logger.error("Performance monitoring error: %s", e)
                time.sleep(5)

    def _collect_system_metrics(self) -> SystemResourceMetrics:
        """Collect current system resource metrics."""
        try:
            # CPU and memory
            cpu_percent = self._process.cpu_percent()
            memory_info = self._process.memory_info()
            memory_percent = self._process.memory_percent()

            # System memory
            sys_memory = psutil.virtual_memory()

            # Disk usage for current directory
            disk_usage = psutil.disk_usage('.')

            # Network I/O
            net_io = psutil.net_io_counters()

            # Process info
            try:
                open_files = len(self._process.open_files())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                open_files = 0

            return SystemResourceMetrics(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_used_mb=memory_info.rss / 1024 / 1024,
                memory_available_mb=sys_memory.available / 1024 / 1024,
                disk_usage_percent=(disk_usage.used / disk_usage.total) * 100,
                disk_used_gb=disk_usage.used / 1024 / 1024 / 1024,
                disk_available_gb=disk_usage.free / 1024 / 1024 / 1024,
                network_bytes_sent=net_io.bytes_sent,
                network_bytes_recv=net_io.bytes_recv,
                open_file_descriptors=open_files,
                thread_count=self._process.num_threads()
            )

        except Exception as e:
            logger.debug("System metrics collection error: %s", e)
            return SystemResourceMetrics(timestamp=time.time())

    def _collect_performance_metrics(self) -> PerformanceMetrics:
        """Collect current application performance metrics."""
        try:
            current_time = time.time()

            # Calculate requests per second from recent timestamps
            recent_requests = [ts for ts in self._request_timestamps if current_time - ts <= 60]
            requests_per_second = len(recent_requests) / 60.0

            # Calculate average request duration (simplified)
            total_flows = len(self.state._flows)
            avg_duration = 0
            error_count = 0

            if total_flows > 0:
                durations = []
                for flow in self.state.snapshot_flows()[-1000:]:  # Last 1000 flows
                    if flow.duration_ms > 0:
                        durations.append(flow.duration_ms)
                    if flow.has_error or flow.status_code >= 400:
                        error_count += 1

                avg_duration = sum(durations) / len(durations) if durations else 0

            error_rate = (error_count / max(total_flows, 1)) * 100

            # Cache metrics (simplified)
            cache_size = len(self._dns_cache) * 0.1  # Rough estimate in MB

            return PerformanceMetrics(
                timestamp=current_time,
                requests_per_second=requests_per_second,
                avg_request_duration_ms=avg_duration,
                total_requests=total_flows,
                active_flows=len([f for f in self.state.snapshot_flows() if not f.completed]),
                error_rate=error_rate,
                cache_hit_rate=0,  # Would need separate tracking
                memory_cache_size_mb=cache_size,
                disk_cache_size_mb=0  # Would need disk cache implementation
            )

        except Exception as e:
            logger.debug("Performance metrics collection error: %s", e)
            return PerformanceMetrics(timestamp=time.time())

    def _check_alert_rules(self, system_metrics: SystemResourceMetrics, performance_metrics: PerformanceMetrics) -> None:
        """Check alert rules against current metrics."""
        current_time = time.time()

        for rule_name, rule in self._alert_rules.items():
            if not rule.enabled:
                continue

            try:
                # Get metric value
                metric_value = None
                if hasattr(system_metrics, rule.metric_name):
                    metric_value = getattr(system_metrics, rule.metric_name)
                elif hasattr(performance_metrics, rule.metric_name):
                    metric_value = getattr(performance_metrics, rule.metric_name)

                if metric_value is None:
                    continue

                # Check threshold
                threshold_breached = False
                if rule.comparison == ">" and metric_value > rule.threshold:
                    threshold_breached = True
                elif rule.comparison == ">=" and metric_value >= rule.threshold:
                    threshold_breached = True
                elif rule.comparison == "<" and metric_value < rule.threshold:
                    threshold_breached = True
                elif rule.comparison == "<=" and metric_value <= rule.threshold:
                    threshold_breached = True
                elif rule.comparison == "==" and metric_value == rule.threshold:
                    threshold_breached = True

                if threshold_breached:
                    # Check if we should trigger (duration check)
                    if current_time - rule.last_triggered >= rule.duration_seconds:
                        self._trigger_alert(rule, metric_value, current_time)

            except Exception as e:
                logger.debug("Alert rule check error for %s: %s", rule_name, e)

    def _trigger_alert(self, rule: AlertRule, metric_value: float, timestamp: float) -> None:
        """Trigger a performance alert."""
        alert_id = f"{rule.name}_{int(timestamp)}"

        severity = "warning"
        if rule.metric_name in ["cpu_percent", "memory_percent"] and metric_value > 95:
            severity = "critical"
        elif rule.metric_name == "error_rate" and metric_value > 20:
            severity = "error"

        alert = PerformanceAlert(
            alert_id=alert_id,
            rule_name=rule.name,
            message=f"{rule.metric_name} is {metric_value:.1f} (threshold: {rule.threshold})",
            severity=severity,
            metric_value=metric_value,
            threshold=rule.threshold,
            timestamp=timestamp
        )

        self._active_alerts[alert_id] = alert
        rule.last_triggered = timestamp
        rule.trigger_count += 1

        logger.warning("Performance alert: %s - %s", rule.name, alert.message)

    def _perform_automatic_optimizations(self, system_metrics: SystemResourceMetrics, performance_metrics: PerformanceMetrics) -> None:
        """Perform automatic performance optimizations."""
        settings = self.state.get_settings()

        try:
            # Memory optimization
            if system_metrics.memory_used_mb > settings.gc_threshold_mb:
                # Force garbage collection
                collected = gc.collect()
                if collected > 0:
                    logger.info("Automatic garbage collection freed %d objects", collected)

            # Clean up old data if memory is high
            if system_metrics.memory_percent > 85:
                self._emergency_cleanup()

            # Adjust async processing if CPU is high
            if system_metrics.cpu_percent > 90 and self._processing_executor:
                # Reduce async worker threads temporarily
                logger.info("High CPU detected - consider reducing async workers")

        except Exception as e:
            logger.debug("Automatic optimization error: %s", e)

    def _emergency_cleanup(self) -> None:
        """Emergency cleanup when resources are low."""
        try:
            # Clean up old flow records
            if len(self.state._flows) > 5000:
                # Keep only recent 3000 flows (atomically, under the flows lock)
                self.state.trim_flows(3000)
                logger.info("Emergency cleanup: reduced flow history")

            # Clean up DNS cache
            if len(self._dns_cache) > 1000:
                # Keep only recent entries
                current_time = time.time()
                self._dns_cache = {
                    k: v for k, v in self._dns_cache.items()
                    if v[1] > current_time  # Keep non-expired entries
                }
                logger.info("Emergency cleanup: reduced DNS cache")

            # Force garbage collection
            gc.collect()

        except Exception as e:
            logger.error("Emergency cleanup error: %s", e)

    # ── Async Processing and Performance Optimization ────────────

    def _init_async_processing(self) -> None:
        """Initialize async processing infrastructure."""
        settings = self.state.get_settings()

        if not settings.enable_async_processing:
            return

        # Initialize thread pool for background processing
        self._processing_executor = ThreadPoolExecutor(
            max_workers=settings.max_async_workers,
            thread_name_prefix="ProxyAsync"
        )

        # Start background processing thread
        self._background_thread = threading.Thread(
            target=self._background_processing_loop,
            daemon=True,
            name="ProxyAsyncManager"
        )
        self._background_thread.start()

        logger.info("Async processing initialized with %d workers", settings.max_async_workers)

    def _background_processing_loop(self) -> None:
        """Background loop for processing async tasks."""
        settings = self.state.get_settings()

        while not self._shutdown_event.is_set():
            try:
                # Check for tasks with timeout
                try:
                    priority, task_id, task = self._async_task_queue.get(timeout=1.0)
                    self._process_async_task(task)
                except Exception:
                    # Timeout or queue empty, continue
                    pass

                # Update queue statistics
                self._update_queue_stats()

                # Brief sleep to prevent CPU spinning
                time.sleep(settings.background_processing_interval)

            except Exception as e:
                logger.error("Background processing error: %s", e)
                time.sleep(1)

    def _submit_async_task(self, task_type: str, flow_id: str, data: dict, priority: int = 1) -> str:
        """Submit task for background async processing."""
        settings = self.state.get_settings()

        if not settings.enable_async_processing or not self._processing_executor:
            return ""

        # Check queue size limit
        if self._async_task_queue.qsize() >= settings.async_task_queue_size:
            logger.warning("Async task queue full, dropping task: %s", task_type)
            return ""

        # Create task
        self._task_counter += 1
        task_id = f"{task_type}_{self._task_counter}_{int(time.time())}"

        task = AsyncProcessingTask(
            task_id=task_id,
            task_type=task_type,
            priority=priority,
            flow_id=flow_id,
            data=data,
            created_time=time.time(),
            status="pending"
        )

        # Submit with priority (lower number = higher priority)
        priority_value = 5 - priority  # Invert so higher priority = lower number
        self._async_task_queue.put((priority_value, task_id, task))

        logger.debug("Submitted async task: %s (priority: %d)", task_id, priority)
        return task_id

    def _process_async_task(self, task: AsyncProcessingTask) -> None:
        """Process an individual async task."""
        task.status = "processing"
        task.started_time = time.time()

        try:
            # Route to appropriate processor
            if task.task_type == "content_analysis":
                result = self._process_content_analysis_task(task)
            elif task.task_type == "protobuf_decode":
                result = self._process_protobuf_decode_task(task)
            elif task.task_type == "large_content_save":
                result = self._process_large_content_save_task(task)
            elif task.task_type == "graphql_complexity":
                result = self._process_graphql_complexity_task(task)
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")

            task.result = result
            task.status = "completed"

        except Exception as e:
            task.status = "failed"
            task.error_message = str(e)
            logger.error("Async task failed: %s - %s", task.task_id, e)

        finally:
            task.completed_time = time.time()

            # Update processing statistics
            processing_time = task.completed_time - task.started_time
            if task.task_type in self._processing_stats:
                # Simple moving average
                current_avg = self._processing_stats[task.task_type]
                self._processing_stats[task.task_type] = (current_avg * 0.9) + (processing_time * 0.1)
            else:
                self._processing_stats[task.task_type] = processing_time

    def _process_content_analysis_task(self, task: AsyncProcessingTask) -> dict:
        """Process content analysis in background."""
        content = task.data.get("content", b"")
        content_type = task.data.get("content_type", "")

        if isinstance(content, str):
            content = content.encode("utf-8")

        # Perform expensive content analysis
        analysis = {
            "size": len(content),
            "entropy": self._calculate_entropy(content),
            "line_count": content.count(b'\n'),
            "printable_ratio": self._calculate_printable_ratio(content)
        }

        return analysis

    def _process_protobuf_decode_task(self, task: AsyncProcessingTask) -> dict:
        """Process protobuf decoding in background."""
        content = task.data.get("content", b"")

        if isinstance(content, str):
            content = content.encode("utf-8")

        try:
            content_str, fields = self._enhanced_protobuf_decode(content)
            return {
                "decoded_content": content_str,
                "fields": fields,
                "success": True
            }
        except Exception as e:
            return {
                "error": str(e),
                "success": False
            }

    def _process_large_content_save_task(self, task: AsyncProcessingTask) -> dict:
        """Process large content saving in background."""
        content = task.data.get("content", b"")
        flow_id = task.flow_id
        content_type = task.data.get("content_type", "")

        if isinstance(content, str):
            content = content.encode("utf-8")

        try:
            file_path = self._save_large_content(content, flow_id, content_type)
            return {
                "file_path": file_path,
                "size": len(content),
                "success": True
            }
        except Exception as e:
            return {
                "error": str(e),
                "success": False
            }

    def _process_graphql_complexity_task(self, task: AsyncProcessingTask) -> dict:
        """Process GraphQL complexity analysis in background."""
        query = task.data.get("query", "")

        try:
            complexity = self._analyze_graphql_complexity(query)
            return {
                "complexity": complexity.dict(),
                "success": True
            }
        except Exception as e:
            return {
                "error": str(e),
                "success": False
            }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if len(data) == 0:
            return 0

        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1

        # Calculate entropy
        import math
        entropy = 0
        data_len = len(data)

        for count in frequencies.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable characters."""
        if len(data) == 0:
            return 0

        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        return printable_count / len(data)

    def _update_queue_stats(self) -> None:
        """Update processing queue statistics."""
        # This is a simplified version - in practice you'd track more detailed metrics
        self._queue_stats.pending_tasks = self._async_task_queue.qsize()

    async def _get_connection_pool(self, host: str) -> httpx.AsyncClient:
        """Get or create connection pool for host."""
        settings = self.state.get_settings()

        if host not in self._connection_pools:
            # Create new connection pool for this host
            limits = httpx.Limits(
                max_keepalive_connections=settings.connection_pool_size,
                max_connections=settings.connection_pool_size * 2,
                keepalive_expiry=settings.connection_pool_timeout
            )

            timeout = httpx.Timeout(
                connect=10.0,
                read=30.0,
                write=10.0,
                pool=settings.connection_pool_timeout
            )

            self._connection_pools[host] = httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                http2=True,  # Enable HTTP/2 support
                verify=False  # For testing - should be configurable in production
            )

            logger.debug("Created connection pool for host: %s", host)

        return self._connection_pools[host]

    def _cleanup_connection_pools(self) -> None:
        """Clean up connection pools.

        Called from the synchronous periodic-maintenance path, so there is no
        running event loop here. asyncio.create_task() would raise
        "no running event loop"; instead close each AsyncClient by driving its
        aclose() coroutine to completion with asyncio.run().
        """
        for host, client in list(self._connection_pools.items()):
            try:
                asyncio.run(client.aclose())
                logger.debug("Closed connection pool for: %s", host)
            except Exception as e:
                logger.debug("Error closing connection pool for %s: %s", host, e)

        self._connection_pools.clear()

    def get_connection_pool_stats(self) -> dict[str, ConnectionPoolStats]:
        """Get connection pool statistics for all hosts."""
        stats = {}

        for host, client in self._connection_pools.items():
            # Extract stats from httpx client (simplified)
            pool_stats = ConnectionPoolStats(
                total_connections=len(getattr(client._transport, '_pool', [])) if hasattr(client, '_transport') else 0,
                # Note: httpx doesn't expose detailed pool stats easily
                # In a real implementation, you'd need to track these metrics separately
            )
            stats[host] = pool_stats

        return stats

    def get_async_processing_stats(self) -> dict:
        """Get async processing statistics."""
        return {
            "queue_stats": self._queue_stats.dict(),
            "processing_stats": self._processing_stats,
            "active_workers": len(self._processing_executor._threads) if self._processing_executor else 0,
            "connection_pools": len(self._connection_pools)
        }

    def shutdown_async_processing(self) -> None:
        """Shutdown async processing infrastructure."""
        logger.info("Shutting down async processing...")

        # Signal shutdown
        self._shutdown_event.set()

        # Wait for background thread
        if self._background_thread and self._background_thread.is_alive():
            self._background_thread.join(timeout=5)

        # Shutdown executor
        if self._processing_executor:
            self._processing_executor.shutdown(wait=True, timeout=10)

        # Cleanup connection pools
        self._cleanup_connection_pools()

        logger.info("Async processing shutdown complete")

    def get_performance_metrics(self) -> dict:
        """Get current performance metrics summary."""
        if not self._system_metrics_history or not self._performance_metrics_history:
            return {"message": "Performance monitoring not available"}

        latest_system = self._system_metrics_history[-1]
        latest_performance = self._performance_metrics_history[-1]

        return {
            "system": latest_system.dict(),
            "application": latest_performance.dict(),
            "alerts": {
                "active": len(self._active_alerts),
                "total_rules": len(self._alert_rules),
                "recent_alerts": [alert.dict() for alert in list(self._active_alerts.values())[-5:]]
            }
        }

    def get_performance_history(self, hours: int = 1) -> dict:
        """Get performance history for the specified time period."""
        cutoff_time = time.time() - (hours * 3600)

        recent_system = [
            m for m in self._system_metrics_history
            if m.timestamp >= cutoff_time
        ]

        recent_performance = [
            m for m in self._performance_metrics_history
            if m.timestamp >= cutoff_time
        ]

        return {
            "system_metrics": [m.dict() for m in recent_system],
            "performance_metrics": [m.dict() for m in recent_performance],
            "time_range_hours": hours,
            "sample_count": len(recent_system)
        }

    def get_resource_usage_summary(self) -> dict:
        """Get resource usage summary and recommendations."""
        if not self._system_metrics_history:
            return {"message": "No performance data available"}

        # Calculate averages over last hour
        recent_metrics = [
            m for m in self._system_metrics_history
            if time.time() - m.timestamp <= 3600
        ]

        if not recent_metrics:
            recent_metrics = list(self._system_metrics_history)[-10:]  # Last 10 samples

        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        max_memory = max(m.memory_used_mb for m in recent_metrics)

        recommendations = []
        if avg_cpu > 70:
            recommendations.append("Consider enabling streaming for large responses")
        if avg_memory > 80:
            recommendations.append("Consider reducing content storage or enabling async processing")
        if max_memory > 500:  # 500MB
            recommendations.append("Memory usage is high - check for memory leaks")

        return {
            "averages": {
                "cpu_percent": round(avg_cpu, 1),
                "memory_percent": round(avg_memory, 1),
                "max_memory_mb": round(max_memory, 1)
            },
            "recommendations": recommendations,
            "sample_count": len(recent_metrics)
        }

    def shutdown_performance_monitoring(self) -> None:
        """Shutdown performance monitoring."""
        logger.info("Shutting down performance monitoring...")

        # Signal shutdown
        self._shutdown_event.set()

        # Wait for performance monitor thread
        if self._performance_monitor_thread and self._performance_monitor_thread.is_alive():
            self._performance_monitor_thread.join(timeout=5)

        logger.info("Performance monitoring shutdown complete")

    def _analyze_graphql_response(self, operation: GraphQLOperation, flow: http.HTTPFlow) -> None:
        """Analyze GraphQL response for errors and performance data."""
        try:
            if not flow.response or not flow.response.get_content():
                return

            # Calculate execution time
            if hasattr(flow, '_start_time'):
                operation.execution_time = round((time.time() - flow._start_time) * 1000, 1)

            # Analyze response content
            response_content = flow.response.get_content()
            operation.response_size = len(response_content)

            # Try to parse JSON response for errors
            try:
                import json
                response_text = response_content.decode('utf-8', errors='ignore')
                response_data = json.loads(response_text)

                # Extract GraphQL errors
                if isinstance(response_data, dict):
                    errors = response_data.get('errors', [])
                    if errors:
                        operation.errors = [str(error) for error in errors[:5]]  # Limit to 5 errors

                    # Check for data field to determine if query was successful
                    if 'data' not in response_data and errors:
                        operation.warnings.append("Query failed with errors")

                    # Check response size for potential performance issues
                    if operation.response_size > 1_000_000:  # 1MB
                        operation.warnings.append("Large response size - consider pagination")

            except (json.JSONDecodeError, UnicodeDecodeError):
                operation.warnings.append("Non-JSON response received")

        except Exception as e:
            logger.debug("GraphQL response analysis error: %s", e)

    def _cleanup_old_sse_streams(self) -> None:
        """Clean up old SSE stream tracking."""
        current_time = time.time()
        cutoff_time = current_time - (3600 * 4)  # 4 hours

        old_streams = [
            flow_id for flow_id, stream_info in self._sse_streams.items()
            if not stream_info.is_active and stream_info.last_message_time < cutoff_time
        ]

        for flow_id in old_streams:
            self._sse_streams.pop(flow_id, None)

        if old_streams:
            logger.debug("Cleaned up %d old SSE streams", len(old_streams))

    def _cleanup_flow_control_actions(self) -> None:
        """Clean up old flow control actions."""
        current_time = time.time()
        cutoff_time = current_time - (3600 * 24)  # 24 hours

        flows_to_cleanup = []

        for flow_id, actions in self._flow_control_actions.items():
            # Remove old actions
            recent_actions = [
                action for action in actions
                if action.timestamp >= cutoff_time
            ]

            if len(recent_actions) != len(actions):
                self._flow_control_actions[flow_id] = recent_actions

            # Remove empty entries
            if not recent_actions:
                flows_to_cleanup.append(flow_id)

        # Clean up empty entries
        for flow_id in flows_to_cleanup:
            self._flow_control_actions.pop(flow_id, None)
            self._backed_up_flows.discard(flow_id)

        if flows_to_cleanup:
            logger.debug("Cleaned up flow control actions for %d flows", len(flows_to_cleanup))

    def get_sse_stream_stats(self) -> dict:
        """Get SSE streaming statistics."""
        active_streams = sum(1 for s in self._sse_streams.values() if s.is_active)
        total_messages = sum(s.message_count for s in self._sse_streams.values())
        total_bytes = sum(s.total_bytes for s in self._sse_streams.values())

        # Collect unique event types
        all_event_types = set()
        for stream in self._sse_streams.values():
            all_event_types.update(stream.event_types)

        return {
            "total_streams": len(self._sse_streams),
            "active_streams": active_streams,
            "total_messages": total_messages,
            "total_bytes": total_bytes,
            "event_types": list(all_event_types),
            "reconnect_attempts": sum(s.reconnect_attempts for s in self._sse_streams.values())
        }

    def get_graphql_operation_stats(self) -> dict:
        """Get GraphQL operation statistics."""
        all_operations = []
        for ops_list in self._graphql_operations.values():
            all_operations.extend(ops_list)

        if not all_operations:
            return {"message": "No GraphQL operations recorded"}

        # Aggregate statistics
        operation_types = {}
        total_execution_time = 0
        total_response_size = 0
        error_count = 0
        warning_count = 0

        for op in all_operations:
            operation_types[op.operation_type] = operation_types.get(op.operation_type, 0) + 1
            total_execution_time += op.execution_time
            total_response_size += op.response_size
            if op.errors:
                error_count += len(op.errors)
            if op.warnings:
                warning_count += len(op.warnings)

        avg_execution_time = total_execution_time / len(all_operations) if all_operations else 0
        avg_response_size = total_response_size / len(all_operations) if all_operations else 0

        return {
            "total_operations": len(all_operations),
            "operation_types": operation_types,
            "avg_execution_time_ms": round(avg_execution_time, 1),
            "avg_response_size": int(avg_response_size),
            "total_errors": error_count,
            "total_warnings": warning_count
        }

    def _analyze_modern_protocols(self, flow: http.HTTPFlow, record: FlowRecord) -> None:
        """Analyze and add modern protocol information to the flow record."""

        # HTTP/3 detection
        http3_features = self._detect_http3_features(flow)
        if http3_features:
            record.http3_features = http3_features
            record.flow_type = "http3"

        # gRPC detection and analysis
        if self._detect_grpc_traffic(flow):
            record.flow_type = "grpc"

            # Parse gRPC messages with direction awareness
            if flow.request and flow.request.get_content():
                grpc_msg = self._parse_grpc_message(flow, flow.request.get_content(), "request")
                if grpc_msg:
                    record.grpc_messages.append(grpc_msg)

            if flow.response and flow.response.get_content():
                grpc_msg = self._parse_grpc_message(flow, flow.response.get_content(), "response")
                if grpc_msg:
                    record.grpc_messages.append(grpc_msg)

        # GraphQL detection and analysis
        graphql_op = self._detect_graphql_operation(flow)
        if graphql_op:
            record.flow_type = "graphql"

            # Enhance with response analysis
            if flow.response:
                self._analyze_graphql_response(graphql_op, flow)

            record.graphql_operations.append(graphql_op)

        # Server-Sent Events detection
        if self._detect_sse_traffic(flow):
            record.flow_type = "sse"

            # Parse SSE messages from response with enhanced tracking
            if flow.response and flow.response.get_content():
                try:
                    response_text = flow.response.get_content().decode("utf-8", errors="ignore")
                    sse_messages = self._parse_sse_messages(flow, response_text)
                    record.sse_messages.extend(sse_messages)
                except Exception as e:
                    logger.debug("SSE parsing error: %s", e)

    def _analyze_enhanced_flow_info(self, flow: http.HTTPFlow, record: FlowRecord) -> None:
        """Analyze enhanced Flow API information."""
        settings = self.state.get_settings()

        try:
            # Connection information analysis
            if settings.enable_connection_analysis:
                if hasattr(flow, 'client_conn') and flow.client_conn:
                    record.client_connection = self._analyze_connection_info(flow.client_conn, "client")

                if hasattr(flow, 'server_conn') and flow.server_conn:
                    record.server_connection = self._analyze_connection_info(flow.server_conn, "server")

            # Error analysis
            record.detailed_error = self._analyze_flow_error(flow)

            # Lifecycle tracking
            if settings.enable_flow_lifecycle_tracking:
                record.lifecycle_info = self._track_flow_lifecycle(flow)

            # TLS analysis
            if settings.enable_tls_analysis:
                client_conn = getattr(flow, 'client_conn', None)
                server_conn = getattr(flow, 'server_conn', None)
                record.tls_analysis = self._analyze_tls_security(client_conn, server_conn)

            # Flow control actions
            if flow.id in self._flow_control_actions:
                record.flow_control_actions = self._flow_control_actions[flow.id].copy()

            # Update connection patterns
            if settings.enable_connection_fingerprinting and record.client_connection:
                self._update_connection_patterns(record.client_connection)

        except Exception as e:
            logger.debug("Enhanced flow analysis error: %s", e)

    def _update_connection_patterns(self, client_conn: ConnectionInfo) -> None:
        """Update connection pattern analysis."""
        try:
            client_ip = client_conn.ip
            if not client_ip or client_ip == "unknown":
                return

            if client_ip not in self._connection_patterns:
                self._connection_patterns[client_ip] = {
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "connection_count": 0,
                    "tls_versions": set(),
                    "cipher_suites": set(),
                    "protocols": set(),
                    "sni_hostnames": set()
                }

            pattern = self._connection_patterns[client_ip]
            pattern["last_seen"] = time.time()
            pattern["connection_count"] += 1

            if client_conn.tls_version:
                pattern["tls_versions"].add(client_conn.tls_version)
            if client_conn.cipher_name:
                pattern["cipher_suites"].add(client_conn.cipher_name)
            if client_conn.alpn_proto:
                pattern["protocols"].add(client_conn.alpn_proto)
            if client_conn.sni:
                pattern["sni_hostnames"].add(client_conn.sni)

        except Exception as e:
            logger.debug("Connection pattern update error: %s", e)

    # ── Advanced Flow Control and Lifecycle Management ──────────

    async def _enhanced_flow_intercept(self, flow: http.HTTPFlow, reason: str, user: str = "system") -> bool:
        """Enhanced flow interception with async support and tracking."""
        settings = self.state.get_settings()

        if not settings.enable_advanced_flow_control:
            return False

        if not hasattr(flow, 'killable') or not flow.killable:
            logger.debug("Flow not killable: %s", flow.id[:8])
            return False

        try:
            # Create action record
            action = FlowControlAction(
                action_id=f"intercept_{flow.id}_{int(time.time())}",
                flow_id=flow.id,
                action_type="intercept",
                reason=reason,
                timestamp=time.time(),
                phase="request" if not flow.response else "response",
                user=user,
                timeout_seconds=settings.flow_intercept_timeout,
                auto_action=(user == "system")
            )

            # Record the intercept
            if flow.id not in self._flow_control_actions:
                self._flow_control_actions[flow.id] = []

            if len(self._flow_control_actions[flow.id]) >= settings.max_flow_control_actions:
                # Remove oldest action
                self._flow_control_actions[flow.id].pop(0)

            self._flow_control_actions[flow.id].append(action)

            # Intercept the flow
            if hasattr(flow, 'intercept'):
                flow.intercept()
                self._intercepted_flows[flow.id] = time.time()

                logger.info("Flow intercepted: %s - %s (user: %s)", flow.id[:8], reason, user)

                # Wait for user action with timeout
                try:
                    if hasattr(flow, 'wait_for_resume'):
                        await asyncio.wait_for(
                            flow.wait_for_resume(),
                            timeout=settings.flow_intercept_timeout
                        )
                    action.success = True
                    action.timestamp = time.time()  # Update to completion time
                    return True

                except asyncio.TimeoutError:
                    logger.warning("Flow intercept timeout: %s", flow.id[:8])
                    if hasattr(flow, 'resume'):
                        flow.resume()

                    # Record timeout action
                    timeout_action = FlowControlAction(
                        action_id=f"timeout_{flow.id}_{int(time.time())}",
                        flow_id=flow.id,
                        action_type="resume",
                        reason="intercept_timeout",
                        timestamp=time.time(),
                        user="system",
                        auto_action=True,
                        success=True
                    )
                    self._flow_control_actions[flow.id].append(timeout_action)

                    action.success = False
                    return False

            else:
                logger.warning("Flow does not support interception: %s", flow.id[:8])
                action.success = False
                return False

        except Exception as e:
            logger.error("Flow intercept error: %s", e)
            if action:
                action.success = False
                action.reason += f" (error: {str(e)[:50]})"
            return False

        finally:
            # Clean up intercept tracking
            self._intercepted_flows.pop(flow.id, None)

    def _kill_flow_with_reason(self, flow: http.HTTPFlow, reason: str, user: str = "system") -> bool:
        """Kill flow with detailed reason tracking."""
        settings = self.state.get_settings()

        if not settings.enable_advanced_flow_control:
            return False

        if not hasattr(flow, 'killable') or not flow.killable:
            logger.debug("Flow not killable: %s", flow.id[:8])
            return False

        try:
            # Create action record
            action = FlowControlAction(
                action_id=f"kill_{flow.id}_{int(time.time())}",
                flow_id=flow.id,
                action_type="kill",
                reason=reason,
                timestamp=time.time(),
                phase="request" if not flow.response else "response",
                user=user,
                auto_action=(user == "system")
            )

            # Record the kill action
            if flow.id not in self._flow_control_actions:
                self._flow_control_actions[flow.id] = []

            self._flow_control_actions[flow.id].append(action)

            # Kill the flow
            if hasattr(flow, 'kill'):
                flow.kill()
                action.success = True
                logger.info("Flow killed: %s - %s (user: %s)", flow.id[:8], reason, user)
                return True
            else:
                logger.warning("Flow does not support killing: %s", flow.id[:8])
                action.success = False
                return False

        except Exception as e:
            logger.error("Flow kill error: %s", e)
            action.success = False
            action.reason += f" (error: {str(e)[:50]})"
            return False

    def _backup_flow_state(self, flow: http.HTTPFlow, reason: str = "", user: str = "system") -> bool:
        """Backup flow state for potential revert."""
        settings = self.state.get_settings()

        if not settings.enable_flow_backup:
            return False

        try:
            # Create action record
            action = FlowControlAction(
                action_id=f"backup_{flow.id}_{int(time.time())}",
                flow_id=flow.id,
                action_type="backup",
                reason=reason,
                timestamp=time.time(),
                phase="request" if not flow.response else "response",
                user=user,
                auto_action=(user == "system")
            )

            # Record the backup action
            if flow.id not in self._flow_control_actions:
                self._flow_control_actions[flow.id] = []

            self._flow_control_actions[flow.id].append(action)

            # Backup the flow
            if hasattr(flow, 'backup'):
                flow.backup(force=False)
                self._backed_up_flows.add(flow.id)
                action.success = True
                logger.debug("Flow backed up: %s", flow.id[:8])
                return True
            else:
                logger.debug("Flow does not support backup: %s", flow.id[:8])
                action.success = False
                return False

        except Exception as e:
            logger.debug("Flow backup error: %s", e)
            action.success = False
            action.reason += f" (error: {str(e)[:50]})"
            return False

    def _revert_flow_state(self, flow: http.HTTPFlow, reason: str = "", user: str = "user") -> bool:
        """Revert flow to backed up state."""
        settings = self.state.get_settings()

        if not settings.enable_flow_backup:
            return False

        if flow.id not in self._backed_up_flows:
            logger.debug("No backup available for flow: %s", flow.id[:8])
            return False

        try:
            # Create action record
            action = FlowControlAction(
                action_id=f"revert_{flow.id}_{int(time.time())}",
                flow_id=flow.id,
                action_type="revert",
                reason=reason,
                timestamp=time.time(),
                phase="request" if not flow.response else "response",
                user=user,
                auto_action=(user == "system")
            )

            # Record the revert action
            if flow.id not in self._flow_control_actions:
                self._flow_control_actions[flow.id] = []

            self._flow_control_actions[flow.id].append(action)

            # Revert the flow
            if hasattr(flow, 'revert'):
                flow.revert()
                action.success = True
                logger.info("Flow reverted: %s - %s (user: %s)", flow.id[:8], reason, user)
                return True
            else:
                logger.warning("Flow does not support revert: %s", flow.id[:8])
                action.success = False
                return False

        except Exception as e:
            logger.error("Flow revert error: %s", e)
            action.success = False
            action.reason += f" (error: {str(e)[:50]})"
            return False

    def _resume_flow(self, flow: http.HTTPFlow, reason: str = "", user: str = "user") -> bool:
        """Resume an intercepted flow."""
        try:
            # Create action record
            action = FlowControlAction(
                action_id=f"resume_{flow.id}_{int(time.time())}",
                flow_id=flow.id,
                action_type="resume",
                reason=reason,
                timestamp=time.time(),
                phase="request" if not flow.response else "response",
                user=user,
                auto_action=(user == "system")
            )

            # Record the resume action
            if flow.id not in self._flow_control_actions:
                self._flow_control_actions[flow.id] = []

            self._flow_control_actions[flow.id].append(action)

            # Resume the flow
            if hasattr(flow, 'resume'):
                flow.resume()
                action.success = True
                logger.info("Flow resumed: %s - %s (user: %s)", flow.id[:8], reason, user)

                # Clean up intercept tracking
                self._intercepted_flows.pop(flow.id, None)
                return True
            else:
                logger.warning("Flow does not support resume: %s", flow.id[:8])
                action.success = False
                return False

        except Exception as e:
            logger.error("Flow resume error: %s", e)
            action.success = False
            action.reason += f" (error: {str(e)[:50]})"
            return False

    def get_flow_control_stats(self) -> dict:
        """Get flow control operation statistics."""
        total_actions = 0
        action_counts = {}
        success_rates = {}
        user_actions = 0
        auto_actions = 0

        for actions in self._flow_control_actions.values():
            for action in actions:
                total_actions += 1
                action_type = action.action_type
                action_counts[action_type] = action_counts.get(action_type, 0) + 1

                if action.auto_action:
                    auto_actions += 1
                else:
                    user_actions += 1

                # Track success rates
                if action_type not in success_rates:
                    success_rates[action_type] = {"total": 0, "success": 0}
                success_rates[action_type]["total"] += 1
                if action.success:
                    success_rates[action_type]["success"] += 1

        # Calculate success percentages
        for action_type in success_rates:
            stats = success_rates[action_type]
            stats["success_rate"] = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0

        return {
            "total_actions": total_actions,
            "action_counts": action_counts,
            "success_rates": success_rates,
            "user_actions": user_actions,
            "auto_actions": auto_actions,
            "active_intercepts": len(self._intercepted_flows),
            "backed_up_flows": len(self._backed_up_flows)
        }

    def _analyze_traffic_pattern(self, flow: http.HTTPFlow) -> dict:
        """Analyze traffic patterns for enhanced protocol detection."""
        analysis = {
            "protocol": self._detect_http_version(flow),
            "content_encoding": flow.response.headers.get("content-encoding", "") if flow.response else "",
            "transfer_encoding": flow.response.headers.get("transfer-encoding", "") if flow.response else "",
            "connection": flow.request.headers.get("connection", "").lower(),
            "upgrade": flow.request.headers.get("upgrade", "").lower(),
            "has_websocket_upgrade": False,
            "is_streaming": getattr(flow, '_stream_enabled', False),
            "size_category": "unknown"
        }

        # Detect WebSocket upgrade
        if (analysis["connection"] == "upgrade" and
            "websocket" in analysis["upgrade"]):
            analysis["has_websocket_upgrade"] = True

        # Categorize response size
        if flow.response:
            size = len(flow.response.get_content() or b"")
            if size == 0:
                analysis["size_category"] = "empty"
            elif size <= ContentSizePolicy.SMALL:
                analysis["size_category"] = "small"
            elif size <= ContentSizePolicy.MEDIUM:
                analysis["size_category"] = "medium"
            elif size <= ContentSizePolicy.LARGE:
                analysis["size_category"] = "large"
            else:
                analysis["size_category"] = "huge"

        return analysis

    def _estimate_response_size(self, flow: http.HTTPFlow) -> int:
        """Estimate response size for streaming responses."""
        # Try to get size from Content-Length header
        if flow.response and flow.response.headers.get("content-length"):
            try:
                return int(flow.response.headers["content-length"])
            except ValueError:
                pass

        # Fallback estimation methods
        return 0

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

        # Handle request body with smart sizing
        req_body, req_file_path, req_actual_size = self._smart_body_handling(
            req.get_content(), ct_req, f"{flow.id}_req"
        )

        # Enhanced record with streaming and modern protocol support
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
            request_body=req_body,
            request_content_type=ct_req,
            dns_method=dns_method,
            stream_mode=getattr(flow, '_stream_enabled', False),
            http_version=self._detect_http_version(flow),
        )

        # Detect and analyze modern protocols. These parse attacker-controlled
        # bytes and run on the proxy event loop; each inner parser guards itself,
        # but backstop here too so a parser failure never breaks the flow.
        try:
            self._analyze_modern_protocols(flow, rec)
        except Exception as e:
            logger.debug("modern-protocol analysis failed: %s", e)

        # Enhanced Flow API analysis
        try:
            self._analyze_enhanced_flow_info(flow, rec)
        except Exception as e:
            logger.debug("enhanced flow analysis failed: %s", e)

        # Add trailers if available
        settings = self.state.get_settings()
        if settings.capture_trailers:
            if req.trailers:
                rec.request_trailers = self._headers_dict(req.trailers)

        if flow.response is not None:
            resp = flow.response
            ct_resp = resp.headers.get("content-type", "")

            # Handle response body with smart sizing
            if rec.stream_mode:
                # For streamed responses, don't try to get content
                resp_body = "<streamed content - not captured>"
                resp_file_path = ""
                resp_actual_size = getattr(flow, '_estimated_size', 0)
            else:
                resp_body, resp_file_path, resp_actual_size = self._smart_body_handling(
                    resp.get_content(), ct_resp, f"{flow.id}_resp"
                )

            rec.status_code = resp.status_code
            rec.reason = resp.reason or ""
            rec.response_headers = self._headers_dict(resp.headers)
            rec.response_body = resp_body
            rec.response_content_type = ct_resp
            rec.response_size = len(resp.get_content() or b"") if not rec.stream_mode else resp_actual_size
            rec.actual_response_size = resp_actual_size
            rec.content_file_path = resp_file_path or req_file_path
            rec.completed = True

            # Add response trailers
            if settings.capture_trailers and resp.trailers:
                rec.response_trailers = self._headers_dict(resp.trailers)

            if hasattr(flow, '_start_time'):
                rec.duration_ms = round((time.time() - flow._start_time) * 1000, 1)

        return rec

    def _build_minimal_record(self, flow: http.HTTPFlow) -> FlowRecord:
        """Build minimal record for large content that doesn't need processing."""
        req = flow.request
        ct_req = req.headers.get("content-type", "")
        display_host = getattr(flow, '_original_host', None) or req.host
        dns_method = getattr(flow, '_dns_method', "")
        display_url = req.pretty_url
        if hasattr(flow, '_original_host'):
            display_url = display_url.replace(req.host, flow._original_host, 1)

        # Minimal request body handling
        req_content = req.get_content()
        req_size = len(req_content) if req_content else 0
        req_body = f"<content: {req_size:,} bytes>" if req_size > 1000 else self._safe_body_legacy(req_content, ct_req)

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
            request_body=req_body,
            request_content_type=ct_req,
            dns_method=dns_method,
            http_version=self._detect_http_version(flow),
        )

        if flow.response is not None:
            resp = flow.response
            ct_resp = resp.headers.get("content-type", "")
            resp_content = resp.get_content()
            resp_size = len(resp_content) if resp_content else 0

            # Minimal response body handling
            resp_body = f"<content: {resp_size:,} bytes - processing skipped>" if resp_size > 1000 else self._safe_body_legacy(resp_content, ct_resp)

            rec.status_code = resp.status_code
            rec.reason = resp.reason or ""
            rec.response_headers = self._headers_dict(resp.headers)
            rec.response_body = resp_body
            rec.response_content_type = ct_resp
            rec.response_size = resp_size
            rec.actual_response_size = resp_size
            rec.completed = True
            rec.content_summary = f"Large content ({resp_size:,} bytes) - minimal processing"

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

    # ── TLS/Protocol Detection ────────────────────────────────

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Enhanced TLS Client Hello handling for protocol detection."""
        try:
            settings = self.state.get_settings()
            if not settings.detect_http_version:
                return

            alpn_protocols = []

            # Check for ALPN protocols - multiple ways for compatibility
            if hasattr(data, 'extensions') and data.extensions:
                for ext in data.extensions:
                    if hasattr(ext, 'protocols'):
                        alpn_protocols.extend(ext.protocols)

            if hasattr(data, 'alpn_protocols'):
                alpn_protocols.extend(data.alpn_protocols)

            # Log detected protocols
            if alpn_protocols:
                logger.debug("ALPN protocols detected: %s", alpn_protocols)

                # Specific protocol detection
                if 'h2' in alpn_protocols:
                    logger.debug("HTTP/2 ALPN detected via TLS handshake")
                if 'h3' in alpn_protocols or 'h3-29' in alpn_protocols:
                    logger.debug("HTTP/3 ALPN detected via TLS handshake")
                if 'http/1.1' in alpn_protocols:
                    logger.debug("HTTP/1.1 ALPN detected via TLS handshake")

            # Enhanced TLS info logging
            if hasattr(data, 'server_name') and data.server_name:
                logger.debug("SNI: %s, ALPN: %s", data.server_name, alpn_protocols)

        except (AttributeError, Exception) as e:
            # Gracefully handle version compatibility issues
            logger.debug("TLS ClientHello processing error: %s", e)

    # ── Request hooks ─────────────────────────────────────────

    def request(self, flow: http.HTTPFlow) -> None:
        flow._start_time = time.time()
        settings = self.state.get_settings()

        # Track request for performance monitoring
        if settings.enable_performance_monitoring:
            self._request_timestamps.append(flow._start_time)

        # Scope filtering — skip out-of-scope flows
        if not self.state.is_in_scope(flow.request.host):
            flow._out_of_scope = True
            return

        # ── Streaming Decision (must happen BEFORE response) ─────────
        should_stream = self._should_enable_streaming(flow)
        if should_stream:
            # Enable streaming for both request and response
            flow.request.stream = self._create_streaming_processor(flow)
            # Note: response.stream will be set when response object is created
            flow._stream_enabled = True
            flow._estimated_size = self._estimate_response_size(flow)
            logger.info("Streaming enabled for: %s", flow.request.pretty_url)
        else:
            flow._stream_enabled = False

        # HTTP/2 upgrade detection
        upgrade_header = flow.request.headers.get("upgrade", "").lower()
        if "h2c" in upgrade_header:  # HTTP/2 over cleartext
            logger.debug("HTTP/2 cleartext upgrade detected: %s", flow.request.url)

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

        # Auto-replace on request body. Use mitmproxy's charset-aware text
        # accessor (honors the declared charset; raises on non-text bodies, which
        # the except then skips) instead of a lossy utf-8 errors="replace" round
        # trip that corrupted any non-utf-8 body whenever a rule matched.
        if flow.request.content:
            ct = flow.request.headers.get("content-type", "").lower()
            if any(t in ct for t in ("text", "json", "xml", "javascript", "html", "form")):
                try:
                    original = flow.request.text
                    if original is not None:
                        replaced = self._apply_replace_rules(original, "request")
                        if replaced != original:
                            flow.request.set_text(replaced)
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

        # Block tracking/telemetry domains - return fake success & skip logging
        tracking_domains = [
            "sentry.io",
            "amplitude.com",
            "mixpanel.com",
            "segment.io",
            "fullstory.com",
            "hotjar.com",
            "logrocket.com",
            "datadog-logs.com",
            "api.anthropic.com/v1/messages/telemetry",
            "analytics.anthropic.com",
            "telemetry.anthropic.com",
            "a-api.anthropic.com",  # Main Anthropic analytics API
            "appsflyersdk.com",     # AppsFlyer mobile attribution
            "appsflyer.com",        # AppsFlyer analytics
            "adjust.com",           # Mobile attribution
            "branch.io",            # Mobile deep linking & analytics
            "kochava.com",          # Mobile attribution
            "tune.com",             # Mobile marketing analytics
            "firebase.com",         # Google Firebase analytics
            "crashlytics.com",      # Crash reporting
            "bugsnag.com",          # Error monitoring
            "fabric.io",            # Twitter Fabric analytics
            "flurry.com",           # Yahoo Flurry analytics
            "chronosphere.io",      # Observability/monitoring platform
            "grok.com/_data/v1/analytics/",  # Grok analytics tracking (but not app_config)
            "grok.com/_worker/typeahead"     # Grok typeahead suggestions
        ]

        # Domains to ignore completely - pass through but don't log
        ignore_domains = [
            "cloudflare.com",
            "challenges.cloudflare.com",
            "cdnjs.cloudflare.com",
            "cf-assets.www.cloudflare.com"
        ]

        # Check for tracking domains (support both domain and domain+path patterns)
        is_tracking = False
        for domain in tracking_domains:
            if "/" in domain:
                # Domain with path (e.g., "grok.com/_data/v1/analytics/")
                domain_part, path_part = domain.split("/", 1)
                if domain_part in flow.request.host and path_part in flow.request.path:
                    is_tracking = True
                    break
            else:
                # Simple domain (e.g., "sentry.io")
                if domain in flow.request.host:
                    is_tracking = True
                    break

        is_ignored = any(domain in flow.request.host for domain in ignore_domains)

        if is_tracking:
            flow.response = http.Response.make(
                200,
                b'{"status":"ok","message":"success","id":"blocked"}',
                {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "*"
                },
            )
            # Mark as tracking to skip dashboard logging
            flow._is_tracking = True
            logger.debug("Tracking blocked: %s%s", flow.request.host, flow.request.path)
            return

        if is_ignored:
            # Mark as ignored - let request pass through but skip dashboard logging
            flow._is_ignored = True
            logger.debug("Ignored (pass-through): %s%s", flow.request.host, flow.request.path)
            return

        # Replace Grok app_config with custom content
        if "grok.com" in flow.request.host and "_data/v1/app_config" in flow.request.path:
            try:
                # Read the custom app config file
                config_file = Path(__file__).parent.parent / "grok_appConfig.json"
                if config_file.exists():
                    with open(config_file, 'r', encoding='utf-8') as f:
                        custom_config = f.read()

                    flow.response = http.Response.make(
                        200,
                        custom_config.encode('utf-8'),
                        {
                            "Content-Type": "application/json; charset=utf-8",
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                            "Cache-Control": "no-cache, no-store, must-revalidate",
                            "Server": "pRoxy-Custom"
                        },
                    )
                    logger.info("Replaced Grok app_config with custom content (%d bytes)", len(custom_config))
                    return
                else:
                    logger.warning("Custom Grok config file not found: %s", config_file)
            except Exception as e:
                logger.error("Failed to load custom Grok config: %s", e)

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

        # Server Replay — return recorded responses
        matched_replay, replay_data = self._matches_server_replay(flow)
        if matched_replay:
            flow.response = http.Response.make(
                replay_data['status_code'],
                replay_data['body'].encode("utf-8"),
                replay_data['headers'],
            )
            logger.info("Server replay matched: %s → %d", url, replay_data['status_code'])
            record = self._build_record(flow)
            self.state.store_flow(record)
            self.state.traffic_queue.put(record)
            return

        # Content Injection — fetch content from different URL
        matched_injection, injection_rule = self._matches_content_injection(url)
        if matched_injection:
            try:
                # Fetch content from source URL (synchronous: this hook runs
                # inside mitmproxy's event loop thread, so asyncio.run() here
                # would raise "cannot be called from a running event loop").
                status_code, headers, body = self._fetch_content_injection(
                    injection_rule['source_url'], injection_rule['timeout']
                )

                # Preserve or override headers
                if injection_rule['preserve_headers']:
                    headers.update(injection_rule['custom_headers'])
                else:
                    headers = injection_rule['custom_headers']

                flow.response = http.Response.make(status_code, body.encode("utf-8"), headers)
                logger.info("Content injection: %s → %s", url, injection_rule['source_url'])
                record = self._build_record(flow)
                self.state.store_flow(record)
                self.state.traffic_queue.put(record)
                return
            except Exception as e:
                logger.error("Content injection failed: %s", e)
                flow.response = http.Response.make(
                    502,
                    f"Content injection failed: {e}".encode("utf-8"),
                    {"Content-Type": "text/plain"},
                )
                record = self._build_record(flow)
                self.state.store_flow(record)
                self.state.traffic_queue.put(record)
                return

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

        # Record for replay if recording is active
        if self.state.is_recording():
            self.state.record_flow(flow.id, flow.request.host)

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

        # Skip tracking/telemetry requests from dashboard logs
        if getattr(flow, '_is_tracking', False):
            return

        # Skip ignored domains (Cloudflare, etc.) from dashboard logs
        if getattr(flow, '_is_ignored', False):
            return

        settings = self.state.get_settings()

        # Periodic maintenance (only occasionally to avoid performance impact)
        if hasattr(self, '_maintenance_counter'):
            self._maintenance_counter += 1
        else:
            self._maintenance_counter = 1

        # Run maintenance every 100 requests
        if self._maintenance_counter % 100 == 0:
            self._periodic_maintenance()

        # ── Smart Streaming Override (Response Phase) ─────────────────
        # Override streaming decision based on actual response headers
        is_streaming = getattr(flow, '_stream_enabled', False)
        if is_streaming and flow.response:
            should_override = self._should_override_streaming(flow)
            if should_override:
                logger.info("Smart override: disabling streaming for analyzable content: %s", flow.request.pretty_url)
                is_streaming = False
                flow._stream_enabled = False

        # Handle streaming vs non-streaming responses differently
        if is_streaming:
            self._handle_streaming_response(flow)
            return
        else:
            self._handle_buffered_response(flow)

    def _handle_streaming_response(self, flow: http.HTTPFlow) -> None:
        """Handle responses that were streamed with enhanced content preview."""
        logger.debug("Handling streaming response: %s", flow.request.pretty_url)

        # Create partial record for dashboard
        record = self._build_record(flow)

        # ── Smart Streaming Content Preview ─────────────────────────
        preview_data = self._capture_streaming_preview(flow)

        # Set response body to preview instead of generic message
        if preview_data:
            record.response_body = preview_data["preview_content"]
            record.content_summary = preview_data["summary"]
        else:
            # Fallback to enhanced protocol-specific summaries
            if record.flow_type == "sse":
                record.content_summary = f"Server-Sent Events stream - {len(record.sse_messages)} messages"
                record.response_body = f"<SSE stream: {len(record.sse_messages)} messages captured>"
            elif record.flow_type == "grpc":
                record.content_summary = f"gRPC streaming - {len(record.grpc_messages)} messages"
                record.response_body = f"<gRPC stream: {len(record.grpc_messages)} messages captured>"
            elif record.http3_features and record.http3_features.is_quic:
                record.content_summary = f"HTTP/3 QUIC stream - {record.response_size:,} bytes"
                record.response_body = f"<HTTP/3 QUIC stream: {record.response_size:,} bytes>"
            else:
                record.content_summary = f"Streaming response - size: {record.response_size:,} bytes"
                record.response_body = f"<streamed content: {record.response_size:,} bytes>"

        logger.info("Streaming preview captured for: %s (%s)",
                   flow.request.pretty_url, record.content_summary)

        # Store and notify
        self.state.store_flow(record)
        self.state.traffic_queue.put(record)

    def _handle_buffered_response(self, flow: http.HTTPFlow) -> None:
        """Handle normal buffered responses with smart content processing."""
        settings = self.state.get_settings()

        # Skip intensive processing for content that doesn't need it
        if not self._should_process_content(flow):
            # Create minimal record without heavy processing
            record = self._build_minimal_record(flow)
            self.state.store_flow(record)
            self.state.traffic_queue.put(record)
            return

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

        # Auto-replace on response body. Charset-aware (see request side above) so
        # a non-utf-8 page (e.g. windows-1252) is no longer mangled when a rule hits.
        if flow.response.content:
            ct = flow.response.headers.get("content-type", "").lower()
            if any(t in ct for t in ("text", "json", "xml", "javascript", "html", "css", "form")):
                try:
                    original = flow.response.text
                    if original is not None:
                        replaced = self._apply_replace_rules(original, "response")
                        if replaced != original:
                            flow.response.set_text(replaced)
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

        # Store completed flow + push to WS (skip tracking/telemetry and ignored domains)
        if not getattr(flow, '_is_tracking', False) and not getattr(flow, '_is_ignored', False):
            record = self._build_record(flow)
            if is_ws_upgrade:
                record.flow_type = "websocket"
            self.state.store_flow(record)
            self.state.traffic_queue.put(record)

    # ── Error handling hooks ──────────────────────────────────

    def error(self, flow: http.HTTPFlow) -> None:
        """Handle connection and protocol errors."""
        settings = self.state.get_settings()

        if not settings.log_connection_errors or not flow.error:
            return

        # Skip out-of-scope flows
        if getattr(flow, '_out_of_scope', False):
            return

        # Create error record
        error_record = FlowRecord(
            id=f"{flow.id}_error_{int(time.time()*1000)}",
            timestamp=time.time(),
            method=flow.request.method if flow.request else "UNKNOWN",
            scheme=flow.request.scheme if flow.request else "",
            host=flow.request.host if flow.request else "unknown",
            port=flow.request.port if flow.request else 0,
            path=flow.request.path if flow.request else "",
            url=flow.request.pretty_url if flow.request else "unknown",
            request_headers=self._headers_dict(flow.request.headers) if flow.request else {},
            request_content_type=flow.request.headers.get("content-type", "") if flow.request else "",

            # Error information
            error_message=str(flow.error),
            error_timestamp=time.time(),
            has_error=True,
            completed=False,

            # Basic response info if response was partially received
            status_code=flow.response.status_code if flow.response else 0,
            reason=flow.response.reason if flow.response else "Connection Error",
            response_headers=self._headers_dict(flow.response.headers) if flow.response else {},
            response_content_type=flow.response.headers.get("content-type", "") if flow.response else "",

            # Protocol info
            http_version=self._detect_http_version(flow),
            duration_ms=round((time.time() - getattr(flow, '_start_time', time.time())) * 1000, 1)
        )

        # Store error record
        self.state.store_flow(error_record)
        self.state.traffic_queue.put(error_record)

        logger.warning("Connection error: %s - %s",
                      flow.request.pretty_url if flow.request else "unknown",
                      flow.error)

    # ── WebSocket hooks ───────────────────────────────────────

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        """Handle WebSocket connection establishment."""
        settings = self.state.get_settings()

        if not settings.enhanced_websocket_logging:
            return

        logger.info("WebSocket connection established: %s", flow.request.pretty_url)

        # Create connection stats tracking
        self._connection_stats[flow.id] = ConnectionStats(
            flow_id=flow.id,
            connection_type="websocket",
            start_time=time.time(),
            message_count=0,
            total_bytes=0,
            last_activity=time.time(),
            is_active=True
        )

        # Add to active WebSocket flows
        self._active_ws_flows[flow.id] = flow

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if getattr(flow, '_out_of_scope', False):
            return

        # Track active WS flows for injection
        self._active_ws_flows[flow.id] = flow
        assert flow.websocket is not None

        msg = flow.websocket.messages[-1]
        direction = "client" if msg.from_client else "server"
        is_text = msg.is_text
        msg_size = len(msg.content)

        # Update connection stats
        if flow.id in self._connection_stats:
            conn_stats = self._connection_stats[flow.id]
            conn_stats.message_count += 1
            conn_stats.total_bytes += msg_size
            conn_stats.last_activity = time.time()

        # Handle large WebSocket messages efficiently
        if msg_size > 100_000:  # 100KB
            content = f"<large WS message: {msg_size:,} bytes>"
            is_text = False
        else:
            try:
                content = msg.text if is_text else f"<binary {msg_size} bytes>"
            except Exception:
                content = f"<binary {msg_size} bytes>"
                is_text = False

        ws_msg = WSMessage(
            direction=direction,
            content=content[:50000],  # Still limit display content
            timestamp=time.time(),
            is_text=is_text,
            size=msg_size,
        )

        # Update or create the flow record
        existing = self.state.get_flow(flow.id)
        if existing is not None:
            existing.flow_type = "websocket"
            # Guard the shared-list mutation: search_flows / get_flows_lite
            # iterate flows from other threads, so an unlocked append can raise
            # "list changed size during iteration". store_flow() takes the same
            # lock itself, so release before calling it (Lock is non-reentrant).
            with self.state._flows_lock:
                existing.ws_messages.append(ws_msg)
            self.state.store_flow(existing)
            self.state.traffic_queue.put(existing)
        else:
            record = self._build_record(flow)
            record.flow_type = "websocket"
            record.ws_messages = [ws_msg]
            self.state.store_flow(record)
            self.state.traffic_queue.put(record)

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        """Clean up active WS flows when connection closes."""
        settings = self.state.get_settings()

        # Clean up active flows
        self._active_ws_flows.pop(flow.id, None)

        # Log connection stats if enhanced logging is enabled
        if settings.enhanced_websocket_logging and flow.id in self._connection_stats:
            conn_stats = self._connection_stats[flow.id]
            duration = time.time() - conn_stats.start_time
            logger.info("WebSocket connection closed: %s - Duration: %.1fs, Messages: %d, Bytes: %d",
                       flow.request.pretty_url, duration, conn_stats.message_count, conn_stats.total_bytes)

            # Mark as inactive
            conn_stats.is_active = False
            conn_stats.last_activity = time.time()

            # Clean up old connections (keep for 1 hour for stats)
            if duration > 3600:  # 1 hour
                self._connection_stats.pop(flow.id, None)

    def inject_ws_message(self, flow_id: str, content: str, to_client: bool) -> bool:
        """Inject a WebSocket message into an active connection with enhanced tracking."""
        flow = self._active_ws_flows.get(flow_id)
        if flow is None or flow.websocket is None:
            logger.warning("WebSocket flow not found or closed: %s", flow_id)
            return False

        try:
            from mitmproxy import ctx
            ctx.master.commands.call(
                "inject.websocket",
                flow,
                to_client,
                content.encode("utf-8"),
            )

            # Update connection stats for injected messages
            if flow_id in self._connection_stats:
                conn_stats = self._connection_stats[flow_id]
                conn_stats.message_count += 1
                conn_stats.total_bytes += len(content.encode("utf-8"))
                conn_stats.last_activity = time.time()

            logger.info("WebSocket message injected: %s (%d bytes, to_client=%s)",
                       flow_id[:8], len(content), to_client)
            return True

        except Exception as e:
            logger.warning("WS inject failed for %s: %s", flow_id, e)
            return False

    def get_active_ws_ids(self) -> list[str]:
        """Return IDs of active WebSocket connections."""
        return list(self._active_ws_flows.keys())

    def get_active_ws_connections(self) -> list[dict]:
        """Return detailed information about active WebSocket connections."""
        connections = []
        for flow_id, flow in self._active_ws_flows.items():
            conn_info = {
                "flow_id": flow_id,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "path": flow.request.path,
                "start_time": getattr(flow, '_start_time', 0),
            }

            # Add connection stats if available
            if flow_id in self._connection_stats:
                stats = self._connection_stats[flow_id]
                conn_info.update({
                    "message_count": stats.message_count,
                    "total_bytes": stats.total_bytes,
                    "last_activity": stats.last_activity,
                    "duration": time.time() - stats.start_time
                })

            connections.append(conn_info)

        return connections

    # ── New Features ──────────────────────────────────────────

    def update_server_replay_rules(self, rules: dict) -> None:
        """Update server replay rules."""
        self._server_replay_rules = rules

    def update_content_injection_rules(self, rules: dict) -> None:
        """Update content injection rules."""
        self._content_injection_rules = rules

    def update_content_processors(self, processors: dict) -> None:
        """Update content processors."""
        self._content_processors = processors

    def start_tcp_proxy(self, rule) -> None:
        """Start TCP proxy server for rule."""
        # TODO: Implement TCP proxy server
        logger.info(f"TCP proxy for {rule.name} would start on port {rule.listen_port}")

    def stop_tcp_proxy(self, rule_id: str) -> None:
        """Stop TCP proxy server."""
        # TODO: Implement TCP proxy server stop
        logger.info(f"TCP proxy {rule_id} would stop")

    def close_tcp_connection(self, connection_id: str) -> None:
        """Close TCP connection."""
        # TODO: Implement TCP connection close
        logger.info(f"TCP connection {connection_id} would close")

    def _fetch_content_injection(self, source_url: str, timeout: int = 30) -> tuple[int, dict, str]:
        """Fetch content from source URL for injection.

        Synchronous on purpose: the request/response hooks run inside
        mitmproxy's event loop thread, so a blocking httpx.Client call with a
        short timeout is the correct pattern here (an async client driven via
        asyncio.run() would raise "cannot be called from a running event loop").
        """
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                response = client.get(source_url)
                return response.status_code, dict(response.headers), response.text
        except Exception as e:
            logger.warning(f"Content injection failed for {source_url}: {e}")
            return 502, {}, f"Content injection failed: {e}"

    def _matches_server_replay(self, flow: http.HTTPFlow) -> tuple[bool, dict]:
        """Check if flow matches server replay rules and return cached response."""
        for rule in self._server_replay_rules.values():
            if not rule.enabled:
                continue

            # Match criteria
            url = flow.request.pretty_url

            if rule.match_method and rule.match_method.upper() != flow.request.method:
                continue
            if rule.match_host and rule.match_host != flow.request.host:
                continue
            if rule.match_path and rule.match_path not in flow.request.path:
                continue

            # Find recorded response
            for flow_id in rule.flows:
                recorded_flow = self.state.get_flow(flow_id)
                if recorded_flow and recorded_flow.completed:
                    return True, {
                        'status_code': recorded_flow.status_code,
                        'headers': recorded_flow.response_headers,
                        'body': recorded_flow.response_body
                    }

        return False, {}

    def _matches_content_injection(self, url: str) -> tuple[bool, dict]:
        """Check if URL matches content injection rules."""
        for rule in self._content_injection_rules.values():
            if not rule.enabled:
                continue

            if rule.is_regex:
                try:
                    if re.search(rule.match_pattern, url):
                        return True, rule.__dict__
                except re.error:
                    continue
            else:
                if fnmatch.fnmatch(url, rule.match_pattern):
                    return True, rule.__dict__

        return False, {}

    # WireGuard and advanced mode support
    def enable_wireguard_mode(self) -> None:
        """Enable WireGuard VPN mode for mobile device capture."""
        self._wireguard_mode = True
        logger.info("WireGuard mode enabled - capturing mobile device traffic")

    def disable_wireguard_mode(self) -> None:
        """Disable WireGuard VPN mode."""
        self._wireguard_mode = False
        logger.info("WireGuard mode disabled")

    def enable_reverse_proxy_mode(self, target_url: str) -> None:
        """Enable reverse proxy mode - act as the target server."""
        self._reverse_proxy_mode = True
        logger.info("Reverse proxy mode enabled, proxying to: %s", target_url)

    def disable_reverse_proxy_mode(self) -> None:
        """Disable reverse proxy mode."""
        self._reverse_proxy_mode = False
        logger.info("Reverse proxy mode disabled")

    def get_proxy_mode_stats(self) -> dict:
        """Get statistics about current proxy modes."""
        active_connections = sum(1 for stats in self._connection_stats.values() if stats.is_active)
        total_ws_messages = sum(stats.message_count for stats in self._connection_stats.values())
        total_ws_bytes = sum(stats.total_bytes for stats in self._connection_stats.values())

        return {
            "wireguard_enabled": self._wireguard_mode,
            "reverse_proxy_enabled": self._reverse_proxy_mode,
            "total_flows_captured": len(self.state._flows),
            "active_websockets": len(self._active_ws_flows),
            "active_connections": active_connections,
            "total_websocket_messages": total_ws_messages,
            "total_websocket_bytes": total_ws_bytes,
            "content_injection_rules": len(self._content_injection_rules),
            "server_replay_rules": len(self._server_replay_rules),
            "active_dns_flows": len(self._dns_flows),
            "tracked_connections": len(self._connection_stats)
        }

    def get_connection_stats(self) -> list[ConnectionStats]:
        """Get detailed connection statistics."""
        return list(self._connection_stats.values())

    def get_traffic_analytics(self) -> dict:
        """Get comprehensive traffic analytics with enhanced protocol and performance data."""
        total_flows = len(self.state._flows)
        if total_flows == 0:
            return {"message": "No traffic data available"}

        # Analyze protocol distribution
        protocol_counts = {}
        flow_type_counts = {}
        streaming_flows = 0
        error_flows = 0
        websocket_flows = 0
        large_flows = 0
        http3_flows = 0
        grpc_flows = 0
        graphql_flows = 0
        sse_flows = 0

        for flow_record in self.state.snapshot_flows():
            # Protocol distribution
            protocol = flow_record.http_version or "HTTP/1.1"
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            # Flow type distribution
            flow_type = flow_record.flow_type
            flow_type_counts[flow_type] = flow_type_counts.get(flow_type, 0) + 1

            # Feature counts
            if flow_record.stream_mode:
                streaming_flows += 1
            if flow_record.has_error:
                error_flows += 1
            if flow_record.flow_type == "websocket":
                websocket_flows += 1
            elif flow_record.flow_type == "grpc":
                grpc_flows += 1
            elif flow_record.flow_type == "graphql":
                graphql_flows += 1
            elif flow_record.flow_type == "sse":
                sse_flows += 1
            elif flow_record.flow_type == "http3":
                http3_flows += 1

            if flow_record.response_size > ContentSizePolicy.LARGE:
                large_flows += 1

        # Get protocol-specific statistics
        grpc_stats = self.get_grpc_stream_stats()
        sse_stats = self.get_sse_stream_stats()
        graphql_stats = self.get_graphql_operation_stats()
        performance_summary = self.get_resource_usage_summary()

        return {
            "overview": {
                "total_flows": total_flows,
                "streaming_flows": streaming_flows,
                "error_flows": error_flows,
                "large_flows": large_flows
            },
            "protocols": {
                "http_versions": protocol_counts,
                "flow_types": flow_type_counts,
                "modern_protocols": {
                    "http3": http3_flows,
                    "grpc": grpc_flows,
                    "graphql": graphql_flows,
                    "sse": sse_flows,
                    "websocket": websocket_flows
                }
            },
            "protocol_stats": {
                "grpc": grpc_stats,
                "sse": sse_stats,
                "graphql": graphql_stats
            },
            "infrastructure": {
                "active_connections": len(self._connection_stats),
                "connection_pools": len(self._connection_pools),
                "async_processing": self.get_async_processing_stats(),
                "content_storage": self._get_content_storage_stats()
            },
            "performance": performance_summary,
            "enhanced_analysis": {
                "connection_patterns": self.get_connection_analytics(),
                "flow_lifecycle": self.get_flow_lifecycle_stats(),
                "tls_security": self.get_tls_security_analysis(),
                "flow_control": self.get_flow_control_stats()
            }
        }

    # ── Comprehensive Flow and Connection Analytics ──────────────

    def get_connection_analytics(self) -> dict:
        """Analyze connection patterns and performance with enhanced insights."""
        if not self._connection_patterns:
            return {"message": "No connection pattern data available"}

        # Aggregate connection statistics
        total_unique_clients = len(self._connection_patterns)
        total_connections = sum(p["connection_count"] for p in self._connection_patterns.values())

        # TLS analysis across all connections
        all_tls_versions = set()
        all_cipher_suites = set()
        all_protocols = set()
        all_sni_hostnames = set()

        client_stats = []
        for client_ip, pattern in self._connection_patterns.items():
            all_tls_versions.update(pattern["tls_versions"])
            all_cipher_suites.update(pattern["cipher_suites"])
            all_protocols.update(pattern["protocols"])
            all_sni_hostnames.update(pattern["sni_hostnames"])

            client_stats.append({
                "ip": client_ip,
                "connections": pattern["connection_count"],
                "duration": pattern["last_seen"] - pattern["first_seen"],
                "tls_versions": len(pattern["tls_versions"]),
                "cipher_diversity": len(pattern["cipher_suites"])
            })

        # Sort by connection count
        top_clients = sorted(client_stats, key=lambda x: x["connections"], reverse=True)[:10]

        # Calculate connection reuse rate
        reuse_rate = self._calculate_connection_reuse_rate()

        # Detect suspicious patterns
        suspicious_patterns = self._detect_suspicious_connection_patterns()

        return {
            "summary": {
                "unique_clients": total_unique_clients,
                "total_connections": total_connections,
                "avg_connections_per_client": total_connections / total_unique_clients if total_unique_clients > 0 else 0,
                "connection_reuse_rate": reuse_rate
            },
            "top_clients": top_clients,
            "protocol_diversity": {
                "tls_versions": list(all_tls_versions),
                "cipher_suites": list(all_cipher_suites),
                "alpn_protocols": list(all_protocols),
                "unique_sni_hostnames": len(all_sni_hostnames)
            },
            "security_insights": {
                "suspicious_patterns": suspicious_patterns,
                "client_fingerprint_diversity": len(set(str(sorted(p["cipher_suites"])) for p in self._connection_patterns.values()))
            }
        }

    def _calculate_connection_reuse_rate(self) -> float:
        """Calculate connection reuse rate based on flow patterns."""
        try:
            total_flows = len(self.state._flows)
            if total_flows == 0:
                return 0.0

            # Count flows with server connection reuse indicators
            reused_connections = 0
            for flow_record in self.state.snapshot_flows():
                # This is a simplified calculation - in practice you'd need more detailed tracking
                if (flow_record.server_connection and
                    flow_record.server_connection.timestamp_start and
                    flow_record.timestamp > flow_record.server_connection.timestamp_start):
                    reused_connections += 1

            return (reused_connections / total_flows) * 100 if total_flows > 0 else 0.0

        except Exception as e:
            logger.debug("Connection reuse calculation error: %s", e)
            return 0.0

    def _detect_suspicious_connection_patterns(self) -> list[str]:
        """Detect potentially suspicious connection patterns."""
        suspicious_patterns = []

        try:
            current_time = time.time()

            for client_ip, pattern in self._connection_patterns.items():
                # High connection rate
                duration = pattern["last_seen"] - pattern["first_seen"]
                if duration > 0:
                    connection_rate = pattern["connection_count"] / (duration / 60)  # per minute
                    if connection_rate > 100:  # More than 100 connections per minute
                        suspicious_patterns.append(f"High connection rate from {client_ip}: {connection_rate:.1f}/min")

                # Unusual TLS diversity
                if len(pattern["tls_versions"]) > 3:
                    suspicious_patterns.append(f"Unusual TLS version diversity from {client_ip}")

                # Too many different cipher suites
                if len(pattern["cipher_suites"]) > 10:
                    suspicious_patterns.append(f"High cipher suite diversity from {client_ip}")

                # Very recent first connection with high activity
                if (current_time - pattern["first_seen"] < 300 and  # Less than 5 minutes
                    pattern["connection_count"] > 50):
                    suspicious_patterns.append(f"Rapid connection burst from {client_ip}")

        except Exception as e:
            logger.debug("Suspicious pattern detection error: %s", e)

        return suspicious_patterns

    def get_flow_lifecycle_stats(self) -> dict:
        """Analyze flow lifecycle patterns across all flows."""
        if not self.state._flows:
            return {"message": "No flow data available"}

        # Lifecycle metrics
        intercepted_flows = 0
        killed_flows = 0
        replayed_flows = 0
        marked_flows = 0
        modified_flows = 0
        live_flows = 0
        error_flows = 0

        creation_delays = []
        total_durations = []
        intercept_durations = []

        for flow_record in self.state.snapshot_flows():
            # Count different flow states
            if flow_record.lifecycle_info:
                lifecycle = flow_record.lifecycle_info

                if lifecycle.is_intercepted:
                    intercepted_flows += 1

                if lifecycle.is_replay:
                    replayed_flows += 1

                if lifecycle.is_marked:
                    marked_flows += 1

                if lifecycle.is_modified:
                    modified_flows += 1

                if lifecycle.is_live:
                    live_flows += 1

                # Collect timing data
                if lifecycle.creation_to_start_ms > 0:
                    creation_delays.append(lifecycle.creation_to_start_ms)

                if lifecycle.total_duration_ms > 0:
                    total_durations.append(lifecycle.total_duration_ms)

            if flow_record.has_error:
                error_flows += 1

            # Check for intercept durations from flow control actions
            if flow_record.flow_control_actions:
                for action in flow_record.flow_control_actions:
                    if action.action_type == "intercept" and action.timeout_seconds > 0:
                        intercept_durations.append(action.timeout_seconds)

        # Calculate statistics
        avg_creation_delay = sum(creation_delays) / len(creation_delays) if creation_delays else 0
        avg_duration = sum(total_durations) / len(total_durations) if total_durations else 0
        avg_intercept_duration = sum(intercept_durations) / len(intercept_durations) if intercept_durations else 0

        return {
            "flow_states": {
                "total_flows": len(self.state._flows),
                "intercepted_flows": intercepted_flows,
                "replayed_flows": replayed_flows,
                "marked_flows": marked_flows,
                "modified_flows": modified_flows,
                "live_flows": live_flows,
                "error_flows": error_flows
            },
            "timing_analysis": {
                "avg_creation_delay_ms": round(avg_creation_delay, 2),
                "avg_total_duration_ms": round(avg_duration, 2),
                "avg_intercept_duration_s": round(avg_intercept_duration, 2),
                "max_creation_delay_ms": max(creation_delays) if creation_delays else 0,
                "max_total_duration_ms": max(total_durations) if total_durations else 0
            },
            "lifecycle_efficiency": {
                "intercept_rate": (intercepted_flows / len(self.state._flows) * 100) if self.state._flows else 0,
                "error_rate": (error_flows / len(self.state._flows) * 100) if self.state._flows else 0,
                "modification_rate": (modified_flows / len(self.state._flows) * 100) if self.state._flows else 0
            }
        }

    def get_tls_security_analysis(self) -> dict:
        """Comprehensive TLS security analysis across all flows."""
        if not self.state._flows:
            return {"message": "No TLS data available"}

        # TLS security metrics
        tls_flows = 0
        security_levels = {"secure": 0, "weak": 0, "vulnerable": 0}
        vulnerability_scores = []
        tls_versions = {}
        cipher_suites = {}
        forward_secrecy_count = 0
        sni_usage_count = 0

        for flow_record in self.state.snapshot_flows():
            if flow_record.tls_analysis:
                tls_analysis = flow_record.tls_analysis
                tls_flows += 1

                # Security level distribution
                if tls_analysis.security_level in security_levels:
                    security_levels[tls_analysis.security_level] += 1

                # Vulnerability scores
                if tls_analysis.vulnerability_score > 0:
                    vulnerability_scores.append(tls_analysis.vulnerability_score)

                # TLS version distribution
                if tls_analysis.tls_version:
                    tls_versions[tls_analysis.tls_version] = tls_versions.get(tls_analysis.tls_version, 0) + 1

                # Cipher suite distribution
                if tls_analysis.cipher_suite:
                    cipher_suites[tls_analysis.cipher_suite] = cipher_suites.get(tls_analysis.cipher_suite, 0) + 1

                # Forward secrecy usage
                if tls_analysis.is_forward_secret:
                    forward_secrecy_count += 1

                # SNI usage
                if tls_analysis.has_sni:
                    sni_usage_count += 1

        if tls_flows == 0:
            return {"message": "No TLS connections analyzed"}

        # Calculate averages and recommendations
        avg_vulnerability_score = sum(vulnerability_scores) / len(vulnerability_scores) if vulnerability_scores else 0

        # Generate security recommendations
        recommendations = []
        if security_levels["vulnerable"] > 0:
            recommendations.append(f"Found {security_levels['vulnerable']} vulnerable TLS connections")
        if security_levels["weak"] > security_levels["secure"]:
            recommendations.append("More weak than secure TLS connections detected")
        if forward_secrecy_count / tls_flows < 0.9:
            recommendations.append("Forward secrecy usage below 90%")

        # Identify most problematic cipher suites
        problematic_ciphers = []
        for cipher, count in cipher_suites.items():
            if any(weak in cipher.lower() for weak in ['rc4', 'des', 'md5', 'sha1']):
                problematic_ciphers.append(f"{cipher}: {count} connections")

        return {
            "overview": {
                "total_tls_flows": tls_flows,
                "security_distribution": security_levels,
                "avg_vulnerability_score": round(avg_vulnerability_score, 1),
                "forward_secrecy_rate": round((forward_secrecy_count / tls_flows) * 100, 1),
                "sni_usage_rate": round((sni_usage_count / tls_flows) * 100, 1)
            },
            "protocol_analysis": {
                "tls_versions": tls_versions,
                "top_cipher_suites": sorted(cipher_suites.items(), key=lambda x: x[1], reverse=True)[:10]
            },
            "security_assessment": {
                "recommendations": recommendations,
                "problematic_ciphers": problematic_ciphers[:5],  # Top 5 problematic
                "overall_security_score": round(100 - avg_vulnerability_score, 1)
            }
        }

    # ── DNS Flow Interception (mitmproxy 12+) ─────────────────────────

    def dns_request(self, flow: dns.DNSFlow) -> None:
        """Intercept and process DNS queries with enhanced controls."""
        try:
            query = flow.request
            question = query.question if query else None
            if question is None:
                return

            hostname = question.name.rstrip('.')  # Remove trailing dot
            query_type = question.type
            flow_id = f"dns-{id(flow)}"

            # Store flow for tracking
            self._dns_flows[flow_id] = flow

            # Get DNS settings
            dns_settings = self.state.get_dns()

            logger.info("DNS Query: %s (type: %s, id: %s)", hostname, query_type, query.id)

            # DNS Blocklist Check
            if hostname in dns_settings.blocklist:
                flow.response = self._create_blocked_dns_response(query)
                logger.info("DNS Blocked: %s (blocklist)", hostname)
                return

            # Check hardcoded tracking domains
            tracking_domains = [
                "analytics.google.com", "googletagmanager.com", "google-analytics.com",
                "facebook.com", "connect.facebook.net", "analytics.facebook.com",
                "sentry.io", "amplitude.com", "mixpanel.com", "segment.io",
                "fullstory.com", "hotjar.com", "logrocket.com", "bugsnag.com"
            ]

            if any(domain in hostname for domain in tracking_domains):
                flow.response = self._create_blocked_dns_response(query)
                logger.info("DNS Blocked: %s (tracking domain)", hostname)
                return

            # Custom DNS Mappings
            for mapping in dns_settings.custom_mappings:
                if mapping.enabled and (mapping.hostname == hostname or hostname.endswith('.' + mapping.hostname)):
                    response = self._create_custom_dns_response(query, mapping.ip)
                    if response is not None:
                        flow.response = response
                        logger.info("DNS Mapped: %s → %s", hostname, mapping.ip)
                        return
                    break  # mapping matched but couldn't build response; fall through

            # DNS-over-HTTPS Resolution
            from mitmproxy.net.dns import types
            if dns_settings.doh_enabled and dns_settings.doh_url and query_type == types.A:
                resolved_ip = self._resolve_doh(hostname, dns_settings.doh_url)
                if resolved_ip:
                    response = self._create_custom_dns_response(query, resolved_ip)
                    if response is not None:
                        flow.response = response
                        logger.info("DNS DoH: %s → %s via %s", hostname, resolved_ip, dns_settings.doh_url)
                        return

            # If no custom handling, let the query proceed normally
            logger.debug("DNS Query proceeding normally: %s", hostname)

        except Exception as e:
            logger.error("Error in dns_request: %s", e)

    def dns_response(self, flow: dns.DNSFlow) -> None:
        """Log and analyze DNS responses."""
        try:
            if not flow.response or not flow.request:
                return

            question = flow.request.question
            hostname = question.name.rstrip('.') if question else "unknown"
            flow_id = f"dns-{id(flow)}"

            # Create DNS flow record for analytics
            self._create_dns_flow_record(flow)

            # Log response details
            if flow.response.answers:
                answers = [str(record) for record in flow.response.answers]
                logger.info("DNS Response: %s → %s", hostname, ', '.join(answers))
            else:
                logger.info("DNS Response: %s → NXDOMAIN", hostname)

            # Clean up tracking
            self._dns_flows.pop(flow_id, None)

        except Exception as e:
            logger.error("Error in dns_response: %s", e)

    def _create_blocked_dns_response(self, query: dns.DNSMessage) -> dns.DNSMessage:
        """Create a blocked DNS response (NXDOMAIN).

        Uses mitmproxy 12.x's DNSMessage.fail() helper, which builds a complete,
        well-formed response from the query.
        """
        from mitmproxy.net.dns import response_codes
        return query.fail(response_codes.NXDOMAIN)

    def _create_custom_dns_response(self, query: dns.DNSMessage, ip_address: str) -> dns.DNSMessage | None:
        """Create a custom DNS response with the specified IPv4 address.

        Uses DNSMessage.succeed() + ResourceRecord.A (mitmproxy 12.x API).
        Returns None if the answer cannot be built safely (e.g. the query is not
        an A record, has no question, or ip_address is not a valid IPv4) so the
        caller can let the query proceed normally instead of returning a
        malformed response.
        """
        from ipaddress import IPv4Address
        from mitmproxy.net.dns import types

        question = query.question
        if question is None or question.type != types.A:
            return None
        try:
            # AddressValueError is a subclass of ValueError.
            answer = dns.ResourceRecord.A(question.name, IPv4Address(ip_address), ttl=300)
        except ValueError:
            logger.debug("Invalid IPv4 for DNS mapping: %s", ip_address)
            return None
        return query.succeed([answer])

    def _create_dns_flow_record(self, flow: dns.DNSFlow) -> None:
        """Create a flow record for DNS queries to include in analytics."""
        try:
            question = flow.request.question if flow.request else None
            hostname = question.name.rstrip('.') if question else "unknown"
            query_type = question.type if question else 0

            # Determine response
            response_data = "NXDOMAIN"
            if flow.response and flow.response.answers:
                answers = [str(record) for record in flow.response.answers]
                response_data = ', '.join(answers)

            # Create simplified flow record for DNS
            flow_record = FlowRecord(
                id=f"dns-{id(flow)}",
                timestamp=time.time(),
                client_ip="dns-client",
                method="DNS",
                scheme="dns",
                host=hostname,
                port=53,
                path=f"/{query_type}",
                url=f"dns://{hostname}/{query_type}",
                status_code=flow.response.response_code if flow.response else 0,
                reason="DNS Query",
                request_headers={},
                request_body="",
                request_content_type="application/dns",
                response_headers={},
                response_body=response_data,
                response_content_type="application/dns",
                duration=0.0,
                request_size=len(str(flow.request)) if flow.request else 0,
                response_size=len(str(flow.response)) if flow.response else 0,
                completed=True,
                marked=False,
                intercepted=False,
                replay_count=0,
                websocket_messages=[],
                dns_method="native-dns"  # Mark as true DNS interception
            )

            # Add to state
            self.state.store_flow(flow_record)

        except Exception as e:
            logger.error("Error creating DNS flow record: %s", e)
