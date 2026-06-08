"""
Enhanced proxy features for modern web technologies.
HTTP/2, HTTP/3, advanced SSL/TLS, WebSocket enhancements, and custom protocols.
"""
from __future__ import annotations

import json
import logging
import base64
import time
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.auth import get_current_user, AUTH_DISABLED
from state.shared import ProxyState
from proxy.ca import get_ca_info, get_ca_cert_path, regenerate_ca, get_android_cert_path

router = APIRouter(
    prefix="/api/proxy",
    tags=["proxy"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()
logger = logging.getLogger("pRoxy.proxy")


class ProtocolConfig(BaseModel):
    """Configuration for protocol-specific features."""
    http2_enabled: bool = True
    http3_enabled: bool = False
    websocket_compression: bool = True
    grpc_reflection: bool = True
    graphql_introspection: bool = True


class SSLCertificate(BaseModel):
    """SSL certificate information."""
    subject: str
    fingerprint: str
    not_before: str
    not_after: str
    format: str
    path: Optional[str] = None


class RequestModification(BaseModel):
    """Advanced request modification configuration."""
    id: str = ""  # Optional on create; auto-generated when empty
    name: str
    enabled: bool = True
    target_url_pattern: str
    modifications: Dict[str, Any] = Field(default_factory=dict)
    script: Optional[str] = None  # JavaScript for advanced modifications


class WebSocketEnhancement(BaseModel):
    """WebSocket connection enhancement settings."""
    auto_ping: bool = True
    ping_interval: int = 30
    compression: bool = True
    max_frame_size: int = 1024 * 1024  # 1MB
    buffer_messages: bool = True
    message_history_limit: int = 1000


class WebSocketInjection(BaseModel):
    """Payload for injecting a message into an active WebSocket connection."""
    message: str
    to_client: bool = True


# ── HTTP/2 & HTTP/3 Features ───────────────────────────────────────────

@router.get("/protocols")
def get_protocol_config():
    """Get current protocol configuration."""
    # Get from settings or use defaults
    settings = state.get_settings()

    return ProtocolConfig(
        http2_enabled=getattr(settings, 'http2_enabled', True),
        http3_enabled=getattr(settings, 'http3_enabled', False),
        websocket_compression=getattr(settings, 'websocket_compression', True),
        grpc_reflection=getattr(settings, 'grpc_reflection', True),
        graphql_introspection=getattr(settings, 'graphql_introspection', True)
    )


@router.post("/protocols")
def update_protocol_config(config: ProtocolConfig):
    """Update protocol configuration."""
    # Update settings
    current_settings = state.get_settings()
    updates = {
        'http2_enabled': config.http2_enabled,
        'http3_enabled': config.http3_enabled,
        'websocket_compression': config.websocket_compression,
        'grpc_reflection': config.grpc_reflection,
        'graphql_introspection': config.graphql_introspection
    }

    # Merge with current settings
    state.update_settings(updates)

    return {
        "message": "Protocol configuration updated",
        "config": config,
        "restart_required": config.http3_enabled  # HTTP/3 requires restart
    }


@router.get("/http2/info")
def get_http2_info():
    """Get HTTP/2 connection information and statistics."""
    # This would integrate with mitmproxy's HTTP/2 capabilities
    return {
        "enabled": True,
        "connections": {
            "active": 0,
            "total": 0
        },
        "features": {
            "server_push": True,
            "header_compression": True,
            "stream_multiplexing": True,
            "flow_control": True
        },
        "settings": {
            "max_concurrent_streams": 100,
            "initial_window_size": 65535,
            "max_frame_size": 16384
        }
    }


# ── Advanced SSL/TLS Management ────────────────────────────────────────

@router.get("/certificates")
def get_certificates():
    """Get all available certificates and their information."""
    certificates = []

    # Get main CA certificate
    ca_info = get_ca_info()
    if ca_info:
        pem_path = get_ca_cert_path("pem")
        certificates.append(SSLCertificate(
            subject=ca_info["subject"],
            fingerprint=ca_info["fingerprint"],
            not_before=ca_info["not_before"],
            not_after=ca_info["not_after"],
            format="PEM",
            path=str(pem_path) if pem_path else None
        ))

    # Get Android certificate if available
    android_cert = get_android_cert_path()
    if android_cert and ca_info:
        certificates.append(SSLCertificate(
            subject=ca_info["subject"],
            fingerprint=ca_info["fingerprint"],
            not_before=ca_info["not_before"],
            not_after=ca_info["not_after"],
            format="Android",
            path=str(android_cert[0])
        ))

    return {
        "certificates": certificates,
        "total": len(certificates),
        "ca_configured": ca_info is not None
    }


@router.get("/certificates/{format}")
def download_certificate(format: str):
    """Download certificate in specified format."""
    if format not in ["pem", "crt", "p12", "android"]:
        raise HTTPException(400, f"Unsupported format: {format}")

    if format == "android":
        android_cert = get_android_cert_path()
        if not android_cert:
            raise HTTPException(404, "Android certificate not available")

        cert_path, filename = android_cert
        content = cert_path.read_text()

        return {
            "filename": filename,
            "content": content,
            "mime_type": "application/x-x509-ca-cert"
        }

    cert_path = get_ca_cert_path(format)
    if not cert_path or not cert_path.exists():
        raise HTTPException(404, f"Certificate format {format} not available")

    content = cert_path.read_text() if format == "pem" else base64.b64encode(cert_path.read_bytes()).decode()

    return {
        "filename": cert_path.name,
        "content": content,
        "mime_type": "application/x-x509-ca-cert"
    }


@router.post("/certificates/regenerate")
def regenerate_certificates():
    """Regenerate all CA certificates."""
    success = regenerate_ca()

    if not success:
        raise HTTPException(500, "Failed to regenerate certificates")

    return {
        "message": "Certificates regenerated successfully",
        "restart_recommended": True
    }


@router.get("/ssl/info")
def get_ssl_info():
    """Get SSL/TLS configuration and capabilities."""
    return {
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256"
        ],
        "certificate_validation": {
            "enabled": False,
            "custom_ca_store": False
        },
        "features": {
            "sni_support": True,
            "ocsp_stapling": False,
            "certificate_transparency": False,
            "hsts_preload": False
        }
    }


@router.post("/ssl/bypass-profiles/install")
def install_ssl_bypass_profile(profile_name: str):
    """Install SSL bypass profile for specific platforms."""
    profiles = {
        "ios": {
            "steps": [
                "1. Install CA certificate via Safari: http://proxy-ip:port/api/proxy/certificates/pem",
                "2. Go to Settings > General > About > Certificate Trust Settings",
                "3. Enable full trust for pRoxy CA certificate",
                "4. Configure proxy settings: Manual HTTP Proxy"
            ],
            "script": """// iOS SSL Pinning Bypass - Inject via Frida
if (ObjC.available) {
    // Disable SSL validation
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
    var original = NSURLSessionConfiguration['- setSSLPinningMode:'];

    Interceptor.attach(original.implementation, {
        onEnter: function(args) {
            args[2] = ptr(0); // Disable pinning
        }
    });

    console.log('[pRoxy] iOS SSL bypass activated');
}"""
        },
        "android": {
            "steps": [
                "1. Download Android certificate from /api/proxy/certificates/android",
                "2. Push to device: adb push cert.0 /system/etc/security/cacerts/",
                "3. Set permissions: adb shell chmod 644 /system/etc/security/cacerts/cert.0",
                "4. Reboot device or restart certificate store"
            ],
            "script": """// Android SSL Pinning Bypass - Universal
Java.perform(function() {
    // OkHttp Certificate Pinner
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
        console.log('[pRoxy] OkHttp bypass activated');
    } catch(e) {}

    // Network Security Config bypass
    try {
        var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
        NetworkSecurityPolicy.getInstance.implementation = function() {
            var policy = this.getInstance();
            policy.isCertificateTransparencyVerificationRequired.implementation = function() { return false; };
            return policy;
        };
    } catch(e) {}

    console.log('[pRoxy] Android SSL bypass activated');
});"""
        }
    }

    if profile_name not in profiles:
        raise HTTPException(404, f"SSL bypass profile '{profile_name}' not found")

    return {
        "profile": profile_name,
        "installation": profiles[profile_name],
        "message": f"SSL bypass profile for {profile_name} retrieved"
    }


# ── WebSocket Enhancements ─────────────────────────────────────────────

@router.get("/websockets/config")
def get_websocket_config():
    """Get WebSocket enhancement configuration."""
    settings = state.get_settings()

    return WebSocketEnhancement(
        auto_ping=getattr(settings, 'ws_auto_ping', True),
        ping_interval=getattr(settings, 'ws_ping_interval', 30),
        compression=getattr(settings, 'ws_compression', True),
        max_frame_size=getattr(settings, 'ws_max_frame_size', 1024*1024),
        buffer_messages=getattr(settings, 'ws_buffer_messages', True),
        message_history_limit=getattr(settings, 'ws_history_limit', 1000)
    )


@router.post("/websockets/config")
def update_websocket_config(config: WebSocketEnhancement):
    """Update WebSocket enhancement configuration."""
    updates = {
        'ws_auto_ping': config.auto_ping,
        'ws_ping_interval': config.ping_interval,
        'ws_compression': config.compression,
        'ws_max_frame_size': config.max_frame_size,
        'ws_buffer_messages': config.buffer_messages,
        'ws_history_limit': config.message_history_limit
    }

    state.update_settings(updates)

    return {
        "message": "WebSocket configuration updated",
        "config": config
    }


@router.get("/websockets/active")
def get_active_websockets():
    """Get information about active WebSocket connections."""
    # This would integrate with the ProxyAddon to get active WS connections
    addon = getattr(state, 'proxy_addon', None)
    if not addon:
        return {"active_connections": [], "total": 0}

    active_ids = addon.get_active_ws_ids()
    connections = []

    for ws_id in active_ids:
        flow = state.get_flow(ws_id)
        if flow:
            connections.append({
                "id": ws_id,
                "url": flow.url,
                "host": flow.host,
                "connected_at": flow.timestamp,
                "message_count": len(flow.ws_messages),
                "last_activity": flow.ws_messages[-1].timestamp if flow.ws_messages else flow.timestamp
            })

    return {
        "active_connections": connections,
        "total": len(connections)
    }


@router.post("/websockets/{flow_id}/inject")
def inject_websocket_message(flow_id: str, payload: WebSocketInjection):
    """Inject a message into an active WebSocket connection."""
    addon = getattr(state, 'proxy_addon', None)
    if not addon:
        raise HTTPException(503, "Proxy addon not available")

    message = payload.message
    to_client = payload.to_client

    success = addon.inject_ws_message(flow_id, message, to_client)

    if not success:
        raise HTTPException(404, f"WebSocket connection {flow_id} not found or inactive")

    return {
        "message": f"Message injected into WebSocket {flow_id}",
        "direction": "to_client" if to_client else "to_server",
        "content": message[:100] + "..." if len(message) > 100 else message
    }


# ── Custom Protocol Support ────────────────────────────────────────────

@router.get("/protocols/graphql/schemas")
def get_graphql_schemas():
    """Get discovered GraphQL schemas from intercepted traffic."""
    # This would analyze traffic to extract GraphQL schemas
    flows = state.get_flows(limit=1000)
    schemas = []

    for flow in flows:
        if "/graphql" in flow.path or "graphql" in flow.request_content_type:
            # Extract schema if it's an introspection query
            if flow.request_body and "IntrospectionQuery" in flow.request_body:
                try:
                    req_data = json.loads(flow.request_body)
                    if flow.response_body:
                        resp_data = json.loads(flow.response_body)
                        if "data" in resp_data and "__schema" in resp_data["data"]:
                            schema_info = {
                                "url": flow.url,
                                "discovered_at": flow.timestamp,
                                "types_count": len(resp_data["data"]["__schema"].get("types", [])),
                                "queries": [],
                                "mutations": [],
                                "subscriptions": []
                            }

                            # Extract operation types
                            query_type = resp_data["data"]["__schema"].get("queryType", {})
                            if query_type:
                                schema_info["queries"] = ["Query operations available"]

                            mutation_type = resp_data["data"]["__schema"].get("mutationType", {})
                            if mutation_type:
                                schema_info["mutations"] = ["Mutation operations available"]

                            subscription_type = resp_data["data"]["__schema"].get("subscriptionType", {})
                            if subscription_type:
                                schema_info["subscriptions"] = ["Subscription operations available"]

                            schemas.append(schema_info)
                except (json.JSONDecodeError, KeyError):
                    continue

    return {
        "schemas": schemas,
        "total": len(schemas),
        "endpoints": list(set(s["url"] for s in schemas))
    }


@router.get("/protocols/grpc/services")
def get_grpc_services():
    """Get discovered gRPC services from intercepted traffic."""
    flows = state.get_flows(limit=1000)
    services = []

    for flow in flows:
        content_type = flow.request_content_type or flow.response_content_type or ""
        if "grpc" in content_type or "protobuf" in content_type:
            service_info = {
                "url": flow.url,
                "host": flow.host,
                "path": flow.path,
                "discovered_at": flow.timestamp,
                "method": flow.method,
                "content_type": content_type,
                "has_reflection": "grpc.reflection" in flow.path
            }

            # Try to extract service name from path
            path_parts = flow.path.strip("/").split("/")
            if len(path_parts) >= 2:
                service_info["service_name"] = path_parts[0]
                service_info["method_name"] = path_parts[1]

            services.append(service_info)

    return {
        "services": services,
        "total": len(services),
        "unique_services": len(set(s.get("service_name", "") for s in services if s.get("service_name")))
    }


@router.post("/protocols/detect")
def detect_protocols(
    flows_limit: int = Query(500, description="Number of recent flows to analyze")
):
    """Automatically detect protocols used in recent traffic."""
    flows = state.get_flows(limit=flows_limit)
    protocol_stats = {
        "http_1_1": 0,
        "http_2": 0,
        "http_3": 0,
        "websocket": 0,
        "graphql": 0,
        "grpc": 0,
        "rest": 0,
        "soap": 0
    }

    protocol_details = {
        "graphql_endpoints": set(),
        "grpc_services": set(),
        "websocket_urls": set(),
        "rest_apis": set()
    }

    for flow in flows:
        # HTTP version detection (would need to be enhanced with actual HTTP version info)
        if flow.flow_type == "websocket":
            protocol_stats["websocket"] += 1
            protocol_details["websocket_urls"].add(flow.url)

        # GraphQL detection
        if ("/graphql" in flow.path or
            "query" in flow.request_body or
            "application/graphql" in flow.request_content_type):
            protocol_stats["graphql"] += 1
            protocol_details["graphql_endpoints"].add(flow.url)

        # gRPC detection
        elif ("grpc" in flow.request_content_type or
              "protobuf" in flow.request_content_type):
            protocol_stats["grpc"] += 1
            protocol_details["grpc_services"].add(f"{flow.host}{flow.path}")

        # SOAP detection
        elif ("soap" in flow.request_content_type or
              "xml" in flow.request_content_type and "soap" in flow.request_body):
            protocol_stats["soap"] += 1

        # REST API detection
        elif (flow.method in ["GET", "POST", "PUT", "DELETE", "PATCH"] and
              ("/api/" in flow.path or "application/json" in flow.request_content_type)):
            protocol_stats["rest"] += 1
            protocol_details["rest_apis"].add(f"{flow.host}/api")

        # Default to HTTP/1.1 (would be enhanced with actual version detection)
        else:
            protocol_stats["http_1_1"] += 1

    # Convert sets to lists for JSON serialization
    for key in protocol_details:
        protocol_details[key] = list(protocol_details[key])

    return {
        "protocols": protocol_stats,
        "details": protocol_details,
        "flows_analyzed": len(flows),
        "recommendations": _generate_protocol_recommendations(protocol_stats)
    }


def _generate_protocol_recommendations(stats: Dict[str, int]) -> List[str]:
    """Generate recommendations based on protocol usage."""
    recommendations = []

    if stats["http_2"] == 0 and stats["http_1_1"] > 10:
        recommendations.append("Consider enabling HTTP/2 for better performance")

    if stats["websocket"] > 0:
        recommendations.append("WebSocket traffic detected - enable compression for better performance")

    if stats["graphql"] > 0:
        recommendations.append("GraphQL endpoints detected - enable introspection analysis")

    if stats["grpc"] > 0:
        recommendations.append("gRPC services detected - enable reflection for better analysis")

    return recommendations


# ── Advanced Request/Response Modification ─────────────────────────────

@router.get("/modifications")
def get_request_modifications():
    """Get all configured request/response modifications."""
    settings = state.get_settings()
    modifications = getattr(settings, 'advanced_modifications', [])

    return {
        "modifications": modifications,
        "total": len(modifications)
    }


@router.post("/modifications")
def create_request_modification(modification: RequestModification):
    """Create a new advanced request/response modification."""
    settings = state.get_settings()
    current_mods = getattr(settings, 'advanced_modifications', [])

    # Generate ID if not provided
    if not modification.id:
        modification.id = f"mod_{len(current_mods) + 1}_{int(time.time())}"

    current_mods.append(modification.dict())
    state.update_settings({"advanced_modifications": current_mods})

    return {
        "message": "Advanced modification created",
        "modification": modification
    }


@router.get("/modifications/templates")
def get_modification_templates():
    """Get pre-defined modification templates."""
    templates = [
        {
            "name": "JWT Token Manipulation",
            "description": "Modify JWT tokens in Authorization headers",
            "target_url_pattern": "*",
            "modifications": {
                "headers": {
                    "Authorization": {
                        "action": "modify_jwt",
                        "claims": {
                            "role": "admin",
                            "exp": "extend"
                        }
                    }
                }
            },
            "script": """
// JWT Manipulation Script
function modifyRequest(request) {
    const auth = request.headers['Authorization'];
    if (auth && auth.startsWith('Bearer ')) {
        const token = auth.substring(7);
        const decoded = decodeJWT(token);
        decoded.role = 'admin';
        decoded.exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
        request.headers['Authorization'] = 'Bearer ' + encodeJWT(decoded);
    }
    return request;
}
            """
        },
        {
            "name": "API Response Injection",
            "description": "Inject additional data into JSON API responses",
            "target_url_pattern": "*/api/*",
            "modifications": {
                "response": {
                    "action": "inject_json",
                    "path": "$.data",
                    "value": {"injected": True, "timestamp": "now"}
                }
            },
            "script": """
// JSON Response Injection
function modifyResponse(response) {
    if (response.headers['content-type'].includes('application/json')) {
        const data = JSON.parse(response.body);
        if (data.data) {
            data.data.injected = true;
            data.data.timestamp = new Date().toISOString();
        }
        response.body = JSON.stringify(data);
    }
    return response;
}
            """
        },
        {
            "name": "GraphQL Query Rewriter",
            "description": "Modify GraphQL queries for testing",
            "target_url_pattern": "*/graphql",
            "modifications": {
                "query": {
                    "action": "add_fields",
                    "fields": ["__typename", "id"]
                }
            },
            "script": """
// GraphQL Query Modification
function modifyRequest(request) {
    if (request.body.includes('query')) {
        const data = JSON.parse(request.body);
        if (data.query) {
            // Add __typename to all selections
            data.query = data.query.replace(/{([^}]+)}/g, '{ __typename $1 }');
        }
        request.body = JSON.stringify(data);
    }
    return request;
}
            """
        }
    ]

    return {
        "templates": templates,
        "total": len(templates)
    }


@router.delete("/modifications/{modification_id}")
def delete_request_modification(modification_id: str):
    """Delete a request modification."""
    settings = state.get_settings()
    current_mods = getattr(settings, 'advanced_modifications', [])

    updated_mods = [m for m in current_mods if m.get('id') != modification_id]

    if len(updated_mods) == len(current_mods):
        raise HTTPException(404, f"Modification {modification_id} not found")

    state.update_settings({"advanced_modifications": updated_mods})

    return {
        "message": f"Modification {modification_id} deleted"
    }


# ── Advanced Proxy Modes for Real Device Testing ─────────────────────────

@router.post("/modes/reverse")
def start_reverse_proxy_mode(target_url: str, listen_port: int = 8443) -> dict:
    """Start reverse proxy mode for mobile testing without client config."""
    try:
        from proxy.engine import start_reverse_proxy

        # Start reverse proxy thread
        thread = start_reverse_proxy(target_url, listen_port)

        # Update addon
        if hasattr(state, 'proxy_addon'):
            state.proxy_addon.enable_reverse_proxy_mode(target_url)

        return {
            "message": f"Reverse proxy started on port {listen_port}",
            "target": target_url,
            "listen_port": listen_port,
            "thread_id": thread.name,
            "instructions": [
                f"1. Point mobile app to: {state._settings.server_ip or 'YOUR_SERVER_IP'}:{listen_port}",
                "2. App connects directly to pRoxy (no proxy config needed)",
                "3. pRoxy acts as the target server with full traffic control",
                "4. Perfect for API testing and security analysis"
            ]
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to start reverse proxy: {e}")


@router.post("/modes/transparent")
def start_transparent_mode(listen_port: int = 8080) -> dict:
    """Start transparent proxy mode (requires root and iptables rules)."""
    try:
        from proxy.engine import start_transparent_proxy

        # Start transparent proxy thread
        thread = start_transparent_proxy(listen_port)

        return {
            "message": f"Transparent proxy started on port {listen_port}",
            "listen_port": listen_port,
            "thread_id": thread.name,
            "warnings": [
                "Transparent mode requires root privileges",
                "iptables rules must be configured manually",
                "Not supported on non-rooted mobile devices"
            ],
            "setup_commands": [
                "iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080",
                "iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080"
            ]
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to start transparent proxy: {e}")


@router.post("/modes/socks")
def start_socks_mode(listen_port: int = 1080) -> dict:
    """Start SOCKS5 proxy mode."""
    try:
        from proxy.engine import start_socks_proxy

        # Start SOCKS proxy thread
        thread = start_socks_proxy(listen_port)

        return {
            "message": f"SOCKS5 proxy started on port {listen_port}",
            "listen_port": listen_port,
            "thread_id": thread.name,
            "instructions": [
                f"Configure SOCKS5 proxy: localhost:{listen_port}",
                "Supports both SOCKS4 and SOCKS5 protocols",
                "Works with apps that support SOCKS proxy"
            ]
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to start SOCKS proxy: {e}")


@router.get("/modes/status")
def get_proxy_modes_status() -> dict:
    """Get status and capabilities of all proxy modes."""
    stats = {}
    if hasattr(state, 'proxy_addon'):
        stats = state.proxy_addon.get_proxy_mode_stats()

    return {
        "modes": {
            "regular": {
                "status": "running",
                "port": 8080,
                "description": "Standard HTTP/HTTPS proxy mode",
                "mobile_support": "✅ Works on non-rooted devices",
                "setup_required": "Configure proxy in WiFi settings + install cert"
            },
            "reverse": {
                "status": "available",
                "port": None,
                "description": "Act as the target server",
                "mobile_support": "✅ Perfect for mobile - no config needed",
                "setup_required": "Point app to pRoxy IP instead of real server"
            },
            "wireguard": {
                "status": "available",
                "port": 51820,
                "description": "VPN mode for comprehensive capture",
                "mobile_support": "✅ Best for mobile - captures ALL traffic",
                "setup_required": "Install WireGuard profile (QR code)"
            },
            "transparent": {
                "status": "available",
                "port": None,
                "description": "OS-level traffic capture",
                "mobile_support": "❌ Requires rooted device",
                "setup_required": "Root access + iptables rules"
            },
            "socks": {
                "status": "available",
                "port": 1080,
                "description": "SOCKS5 proxy server",
                "mobile_support": "⚠️ App-dependent support",
                "setup_required": "Configure SOCKS proxy in app"
            }
        },
        "recommendations": {
            "non_rooted_mobile": "Use WireGuard VPN mode for best results",
            "api_testing": "Use Reverse Proxy mode - no client config needed",
            "comprehensive_analysis": "Combine Regular + WireGuard modes",
            "development": "Regular proxy mode with easy cert installation"
        },
        "stats": stats
    }


@router.get("/modes/best-for-device")
def get_best_proxy_mode(
    device_type: str = Query(..., description="android, ios, desktop, iot"),
    rooted: bool = Query(False, description="Device has root/jailbreak"),
    use_case: str = Query("testing", description="testing, development, security_analysis")
) -> dict:
    """Get recommended proxy mode for specific device and use case."""

    recommendations = {
        ("android", False, "testing"): {
            "primary": "wireguard",
            "fallback": "regular",
            "reason": "WireGuard captures ALL traffic including apps that bypass proxy settings"
        },
        ("android", True, "testing"): {
            "primary": "transparent",
            "fallback": "wireguard",
            "reason": "Transparent mode with root access provides system-level capture"
        },
        ("ios", False, "testing"): {
            "primary": "wireguard",
            "fallback": "regular",
            "reason": "iOS apps often ignore proxy settings, WireGuard VPN works universally"
        },
        ("ios", True, "testing"): {
            "primary": "wireguard",
            "fallback": "regular",
            "reason": "Even with jailbreak, WireGuard is more stable than transparent mode"
        },
        (device_type, rooted, "security_analysis"): {
            "primary": "reverse",
            "fallback": "wireguard",
            "reason": "Reverse proxy gives full control over API responses for security testing"
        },
        (device_type, rooted, "development"): {
            "primary": "regular",
            "fallback": "reverse",
            "reason": "Regular proxy with easy cert setup is perfect for development workflow"
        }
    }

    # Find best match
    key = (device_type, rooted, use_case)
    if key in recommendations:
        result = recommendations[key]
    else:
        # Fallback to use case specific defaults
        use_case_defaults = {
            "testing": {"primary": "wireguard", "fallback": "regular"},
            "security_analysis": {"primary": "reverse", "fallback": "wireguard"},
            "development": {"primary": "regular", "fallback": "reverse"}
        }
        result = use_case_defaults.get(use_case, {"primary": "regular", "fallback": "wireguard"})
        result["reason"] = f"Default recommendation for {use_case} on {device_type}"

    return {
        "device": device_type,
        "rooted": rooted,
        "use_case": use_case,
        "recommendation": result,
        "setup_guides": {
            "regular": "/api/proxy/setup-guide/regular",
            "wireguard": "/api/proxy/setup-guide/wireguard",
            "reverse": "/api/proxy/setup-guide/reverse",
            "transparent": "/api/proxy/setup-guide/transparent"
        }
    }


@router.get("/setup-guide/{mode}")
def get_setup_guide(mode: str) -> dict:
    """Get detailed setup guide for specific proxy mode."""

    guides = {
        "regular": {
            "title": "Regular Proxy Setup",
            "description": "Standard HTTP/HTTPS proxy configuration",
            "android_steps": [
                "1. Connect to WiFi network",
                "2. Long press network name → Modify network",
                "3. Advanced options → Proxy → Manual",
                f"4. Hostname: {state._settings.server_ip or 'PROXY_SERVER_IP'}",
                "5. Port: 8080",
                "6. Save settings",
                "7. Visit mitm.it to install certificate",
                "8. Install certificate in Settings → Security"
            ],
            "ios_steps": [
                "1. Settings → WiFi → (i) next to network",
                "2. Configure Proxy → Manual",
                f"3. Server: {state._settings.server_ip or 'PROXY_SERVER_IP'}",
                "4. Port: 8080",
                "5. Save settings",
                "6. Safari → mitm.it → Install Profile",
                "7. Settings → General → VPN & Device Management → Install",
                "8. Settings → About → Certificate Trust → Enable mitmproxy"
            ],
            "pros": ["Works on non-rooted devices", "Easy to setup", "Good for browser testing"],
            "cons": ["Some apps bypass proxy", "Certificate installation needed", "Per-network config"]
        },

        "wireguard": {
            "title": "WireGuard VPN Setup",
            "description": "VPN-based traffic capture for comprehensive analysis",
            "android_steps": [
                "1. Install WireGuard app from Google Play",
                "2. Scan QR code from pRoxy dashboard",
                "3. Enable VPN connection",
                "4. All traffic now goes through pRoxy",
                "5. Install pRoxy certificate if needed for HTTPS"
            ],
            "ios_steps": [
                "1. Install WireGuard app from App Store",
                "2. Scan QR code from pRoxy dashboard",
                "3. Add tunnel configuration",
                "4. Enable VPN connection",
                "5. Install pRoxy certificate for HTTPS analysis"
            ],
            "pros": ["Captures ALL traffic", "Works on any device", "Bypass proxy-ignoring apps", "Remote testing"],
            "cons": ["Requires VPN app installation", "May need certificate for HTTPS", "Uses device VPN slot"]
        },

        "reverse": {
            "title": "Reverse Proxy Setup",
            "description": "pRoxy acts as the target server",
            "setup_steps": [
                "1. Start reverse proxy mode in pRoxy",
                f"2. Point mobile app to pRoxy IP: {state._settings.server_ip or 'PROXY_IP'}:8443",
                "3. App connects directly to pRoxy (no proxy config)",
                "4. pRoxy forwards requests to real backend",
                "5. Full control over requests and responses"
            ],
            "use_cases": ["API testing", "Security assessment", "Mock responses", "A/B testing"],
            "pros": ["Zero client configuration", "Perfect for API testing", "Full request/response control"],
            "cons": ["Requires app reconfiguration", "Only works for specific endpoints"]
        },

        "transparent": {
            "title": "Transparent Proxy Setup",
            "description": "OS-level traffic capture (requires root)",
            "setup_steps": [
                "1. Enable root/administrator access",
                "2. Configure iptables rules for traffic redirection",
                "3. Start transparent proxy mode",
                "4. All traffic automatically captured",
                "5. No client configuration needed"
            ],
            "requirements": ["Root access", "iptables/netsh support", "Network configuration"],
            "pros": ["No client configuration", "Captures all traffic", "Invisible to applications"],
            "cons": ["Requires root access", "Complex setup", "Not practical for mobile testing"]
        }
    }

    if mode not in guides:
        raise HTTPException(404, f"Setup guide for mode '{mode}' not found")

    return guides[mode]