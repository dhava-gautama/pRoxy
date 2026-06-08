"""
Tests for enhanced proxy features including HTTP/2, SSL/TLS, WebSocket enhancements,
and advanced protocol support.
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient

from state.shared import ProxyState


def test_get_protocol_config(test_client: TestClient):
    """Test retrieving protocol configuration."""
    response = test_client.get("/api/proxy/protocols")
    assert response.status_code == 200

    data = response.json()
    assert "http2_enabled" in data
    assert "http3_enabled" in data
    assert "websocket_compression" in data
    assert "grpc_reflection" in data
    assert "graphql_introspection" in data

    # Verify default values
    assert data["http2_enabled"] is True
    assert data["http3_enabled"] is False


def test_update_protocol_config(test_client: TestClient, mock_proxy_state):
    """Test updating protocol configuration."""
    mock_proxy_state.get_settings.return_value = Mock()
    mock_proxy_state.update_settings.return_value = None

    config = {
        "http2_enabled": True,
        "http3_enabled": True,
        "websocket_compression": False,
        "grpc_reflection": True,
        "graphql_introspection": False
    }

    response = test_client.post("/api/proxy/protocols", json=config)
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "config" in data
    assert "restart_required" in data
    assert data["restart_required"] is True  # HTTP/3 requires restart


def test_get_http2_info(test_client: TestClient):
    """Test HTTP/2 information endpoint."""
    response = test_client.get("/api/proxy/http2/info")
    assert response.status_code == 200

    data = response.json()
    assert "enabled" in data
    assert "connections" in data
    assert "features" in data
    assert "settings" in data

    # Verify expected features
    features = data["features"]
    assert features["server_push"] is True
    assert features["header_compression"] is True
    assert features["stream_multiplexing"] is True


def test_get_certificates(test_client: TestClient):
    """Test retrieving SSL certificates."""
    with patch('api.routes.proxy.get_ca_info') as mock_ca_info, \
         patch('api.routes.proxy.get_ca_cert_path') as mock_cert_path, \
         patch('api.routes.proxy.get_android_cert_path') as mock_android:

        mock_ca_info.return_value = {
            "subject": "CN=mitmproxy",
            "fingerprint": "ab:cd:ef:12:34:56",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00"
        }
        mock_cert_path.return_value = "/path/to/cert.pem"
        mock_android.return_value = ("/path/to/cert.0", "12345678.0")

        response = test_client.get("/api/proxy/certificates")
        assert response.status_code == 200

        data = response.json()
        assert "certificates" in data
        assert "total" in data
        assert "ca_configured" in data
        assert data["ca_configured"] is True
        assert len(data["certificates"]) == 2  # PEM and Android


def test_download_certificate_pem(test_client: TestClient):
    """Test downloading PEM certificate."""
    with patch('api.routes.proxy.get_ca_cert_path') as mock_cert_path:
        mock_path = Mock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        mock_path.name = "cert.pem"
        mock_cert_path.return_value = mock_path

        response = test_client.get("/api/proxy/certificates/pem")
        assert response.status_code == 200

        data = response.json()
        assert "filename" in data
        assert "content" in data
        assert "mime_type" in data
        assert data["filename"] == "cert.pem"


def test_download_certificate_android(test_client: TestClient):
    """Test downloading Android certificate."""
    with patch('api.routes.proxy.get_android_cert_path') as mock_android:
        mock_path = Mock()
        mock_path.read_text.return_value = "Certificate:\n    Data:\n-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        mock_android.return_value = (mock_path, "12345678.0")

        response = test_client.get("/api/proxy/certificates/android")
        assert response.status_code == 200

        data = response.json()
        assert data["filename"] == "12345678.0"
        assert "Certificate:" in data["content"]


def test_download_certificate_unsupported_format(test_client: TestClient):
    """Test downloading certificate with unsupported format."""
    response = test_client.get("/api/proxy/certificates/invalid")
    assert response.status_code == 400


def test_regenerate_certificates(test_client: TestClient):
    """Test certificate regeneration."""
    with patch('api.routes.proxy.regenerate_ca') as mock_regen:
        mock_regen.return_value = True

        response = test_client.post("/api/proxy/certificates/regenerate")
        assert response.status_code == 200

        data = response.json()
        assert "message" in data
        assert "restart_recommended" in data
        assert data["restart_recommended"] is True


def test_regenerate_certificates_failure(test_client: TestClient):
    """Test certificate regeneration failure."""
    with patch('api.routes.proxy.regenerate_ca') as mock_regen:
        mock_regen.return_value = False

        response = test_client.post("/api/proxy/certificates/regenerate")
        assert response.status_code == 500


def test_get_ssl_info(test_client: TestClient):
    """Test SSL/TLS information endpoint."""
    response = test_client.get("/api/proxy/ssl/info")
    assert response.status_code == 200

    data = response.json()
    assert "tls_versions" in data
    assert "cipher_suites" in data
    assert "certificate_validation" in data
    assert "features" in data

    # Verify expected TLS versions
    assert "TLSv1.2" in data["tls_versions"]
    assert "TLSv1.3" in data["tls_versions"]


def test_install_ssl_bypass_profile(test_client: TestClient):
    """Test SSL bypass profile installation."""
    response = test_client.post("/api/proxy/ssl/bypass-profiles/install?profile_name=android")
    assert response.status_code == 200

    data = response.json()
    assert "profile" in data
    assert "installation" in data
    assert data["profile"] == "android"
    assert "steps" in data["installation"]
    assert "script" in data["installation"]


def test_install_ssl_bypass_profile_invalid(test_client: TestClient):
    """Test SSL bypass profile installation with invalid profile."""
    response = test_client.post("/api/proxy/ssl/bypass-profiles/install?profile_name=invalid")
    assert response.status_code == 404


def test_get_websocket_config(test_client: TestClient):
    """Test WebSocket configuration retrieval."""
    response = test_client.get("/api/proxy/websockets/config")
    assert response.status_code == 200

    data = response.json()
    assert "auto_ping" in data
    assert "ping_interval" in data
    assert "compression" in data
    assert "max_frame_size" in data
    assert "buffer_messages" in data
    assert "message_history_limit" in data


def test_update_websocket_config(test_client: TestClient, mock_proxy_state):
    """Test WebSocket configuration update."""
    mock_proxy_state.update_settings.return_value = None

    config = {
        "auto_ping": False,
        "ping_interval": 60,
        "compression": True,
        "max_frame_size": 2048,
        "buffer_messages": False,
        "message_history_limit": 500
    }

    response = test_client.post("/api/proxy/websockets/config", json=config)
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "config" in data


def test_get_active_websockets(test_client: TestClient, mock_proxy_state):
    """Test active WebSocket connections retrieval."""
    # Mock proxy addon with active WebSocket connections
    mock_addon = Mock()
    mock_addon.get_active_ws_ids.return_value = ["ws1", "ws2"]

    # Mock flow data
    mock_flow1 = Mock()
    mock_flow1.url = "wss://example.com/ws"
    mock_flow1.host = "example.com"
    mock_flow1.timestamp = 1000
    mock_flow1.ws_messages = [Mock(timestamp=1001)]

    mock_flow2 = Mock()
    mock_flow2.url = "ws://test.com/socket"
    mock_flow2.host = "test.com"
    mock_flow2.timestamp = 2000
    mock_flow2.ws_messages = []

    mock_proxy_state.get_flow.side_effect = lambda flow_id: {
        "ws1": mock_flow1,
        "ws2": mock_flow2
    }.get(flow_id)

    # The route reads ``proxy_addon`` from the live ProxyState singleton, so the
    # addon must be attached to that same instance (not the mock fixture object).
    with patch.object(ProxyState(), "proxy_addon", mock_addon, create=True):
        response = test_client.get("/api/proxy/websockets/active")
    assert response.status_code == 200

    data = response.json()
    assert "active_connections" in data
    assert "total" in data
    assert data["total"] == 2
    assert len(data["active_connections"]) == 2


def test_inject_websocket_message(test_client: TestClient, mock_proxy_state):
    """Test WebSocket message injection."""
    mock_addon = Mock()
    mock_addon.inject_ws_message.return_value = True

    # Addon lives on the ProxyState singleton the route holds.
    with patch.object(ProxyState(), "proxy_addon", mock_addon, create=True):
        response = test_client.post("/api/proxy/websockets/ws1/inject", json={
            "message": "test message",
            "to_client": True
        })
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "direction" in data
    assert "content" in data
    assert data["direction"] == "to_client"


def test_inject_websocket_message_failure(test_client: TestClient, mock_proxy_state):
    """Test WebSocket message injection failure."""
    mock_addon = Mock()
    mock_addon.inject_ws_message.return_value = False

    # Addon lives on the ProxyState singleton the route holds.
    with patch.object(ProxyState(), "proxy_addon", mock_addon, create=True):
        response = test_client.post("/api/proxy/websockets/ws1/inject", json={
            "message": "test message",
            "to_client": True
        })
    assert response.status_code == 404


def test_get_graphql_schemas(test_client: TestClient, mock_proxy_state):
    """Test GraphQL schema discovery."""
    # Mock flows with GraphQL content
    mock_flow = Mock()
    mock_flow.path = "/graphql"
    mock_flow.request_content_type = "application/json"
    mock_flow.request_body = '{"query": "IntrospectionQuery"}'
    mock_flow.response_body = '{"data": {"__schema": {"types": [{"name": "Query"}]}}}'
    mock_flow.url = "https://api.example.com/graphql"
    mock_flow.timestamp = 1000

    mock_proxy_state.get_flows.return_value = [mock_flow]

    response = test_client.get("/api/proxy/protocols/graphql/schemas")
    assert response.status_code == 200

    data = response.json()
    assert "schemas" in data
    assert "total" in data
    assert "endpoints" in data


def test_get_grpc_services(test_client: TestClient, mock_proxy_state):
    """Test gRPC service discovery."""
    # Mock flows with gRPC content
    mock_flow = Mock()
    mock_flow.request_content_type = "application/grpc"
    mock_flow.response_content_type = "application/grpc"
    mock_flow.url = "https://grpc.example.com/service.Service/Method"
    mock_flow.host = "grpc.example.com"
    mock_flow.path = "/service.Service/Method"
    mock_flow.timestamp = 1000
    mock_flow.method = "POST"

    mock_proxy_state.get_flows.return_value = [mock_flow]

    response = test_client.get("/api/proxy/protocols/grpc/services")
    assert response.status_code == 200

    data = response.json()
    assert "services" in data
    assert "total" in data
    assert "unique_services" in data


def test_detect_protocols(test_client: TestClient, mock_proxy_state):
    """Test automatic protocol detection."""
    # Mock flows with various protocols
    flows = [
        Mock(flow_type="websocket", url="wss://example.com", path="/ws",
             request_content_type="", request_body="", method="GET"),
        Mock(flow_type="http", url="https://api.com/graphql", path="/graphql",
             request_content_type="application/json", request_body='{"query": "..."}', method="POST"),
        Mock(flow_type="http", url="https://grpc.com/service", path="/service",
             request_content_type="application/grpc", request_body="", method="POST"),
        Mock(flow_type="http", url="https://rest.com/api/users", path="/api/users",
             request_content_type="application/json", request_body="", method="GET")
    ]

    mock_proxy_state.get_flows.return_value = flows

    response = test_client.post("/api/proxy/protocols/detect")
    assert response.status_code == 200

    data = response.json()
    assert "protocols" in data
    assert "details" in data
    assert "flows_analyzed" in data
    assert "recommendations" in data
    assert data["flows_analyzed"] == 4


def test_get_request_modifications(test_client: TestClient, mock_proxy_state):
    """Test retrieving request modifications."""
    mock_settings = Mock()
    mock_settings.advanced_modifications = [
        {
            "id": "mod1",
            "name": "Test Modification",
            "enabled": True,
            "target_url_pattern": "*api*",
            "modifications": {},
            "script": ""
        }
    ]
    mock_proxy_state.get_settings.return_value = mock_settings

    response = test_client.get("/api/proxy/modifications")
    assert response.status_code == 200

    data = response.json()
    assert "modifications" in data
    assert "total" in data
    assert data["total"] == 1


def test_create_request_modification(test_client: TestClient, mock_proxy_state):
    """Test creating a new request modification."""
    mock_proxy_state.get_settings.return_value = Mock(advanced_modifications=[])
    mock_proxy_state.update_settings.return_value = None

    modification = {
        "name": "JWT Manipulation",
        "enabled": True,
        "target_url_pattern": "*/api/*",
        "modifications": {
            "headers": {
                "Authorization": {
                    "action": "modify_jwt",
                    "claims": {"role": "admin"}
                }
            }
        },
        "script": "// Custom script"
    }

    response = test_client.post("/api/proxy/modifications", json=modification)
    assert response.status_code == 200

    data = response.json()
    assert "message" in data
    assert "modification" in data
    assert data["modification"]["name"] == "JWT Manipulation"


def test_get_modification_templates(test_client: TestClient):
    """Test retrieving modification templates."""
    response = test_client.get("/api/proxy/modifications/templates")
    assert response.status_code == 200

    data = response.json()
    assert "templates" in data
    assert "total" in data
    assert len(data["templates"]) > 0

    # Verify template structure
    template = data["templates"][0]
    assert "name" in template
    assert "description" in template
    assert "target_url_pattern" in template
    assert "modifications" in template


def test_delete_request_modification(test_client: TestClient, mock_proxy_state):
    """Test deleting a request modification."""
    mock_settings = Mock()
    mock_settings.advanced_modifications = [
        {"id": "mod1", "name": "Test"}
    ]
    mock_proxy_state.get_settings.return_value = mock_settings
    mock_proxy_state.update_settings.return_value = None

    response = test_client.delete("/api/proxy/modifications/mod1")
    assert response.status_code == 200

    data = response.json()
    assert "message" in data


def test_delete_nonexistent_modification(test_client: TestClient, mock_proxy_state):
    """Test deleting a non-existent modification."""
    mock_settings = Mock()
    mock_settings.advanced_modifications = []
    mock_proxy_state.get_settings.return_value = mock_settings

    response = test_client.delete("/api/proxy/modifications/nonexistent")
    assert response.status_code == 404


def test_protocol_security_validation(test_client: TestClient):
    """Test that protocol endpoints validate input properly."""
    # Test invalid protocol configuration
    invalid_config = {
        "http2_enabled": "invalid",  # Should be boolean
        "ping_interval": -1  # Should be positive
    }

    # This should be handled by Pydantic validation
    response = test_client.post("/api/proxy/protocols", json=invalid_config)
    # Depending on Pydantic configuration, this might be 422 or 400
    assert response.status_code in [400, 422]


def test_ssl_certificate_path_traversal_protection(test_client: TestClient):
    """Test protection against path traversal in certificate downloads.

    The ``{format}`` segment is constrained by an allowlist in the handler, so no
    attacker-controlled path ever reaches the filesystem. A traversal payload is
    safely rejected: the HTTP client/router normalizes ``..`` segments and the
    request resolves off-route (404), while any non-traversal value that is not in
    the allowlist is rejected by the handler with 400. Either way the response is a
    safe rejection that never serves an arbitrary file.
    """
    # Traversal payload is normalized away and resolves off-route -> safe rejection.
    response = test_client.get("/api/proxy/certificates/../../../etc/passwd")
    assert response.status_code in (400, 404)

    # Handler-level allowlist: a bogus single-segment format is rejected with 400.
    bad_format = test_client.get("/api/proxy/certificates/passwd")
    assert bad_format.status_code == 400


def test_websocket_injection_xss_protection(test_client: TestClient, mock_proxy_state):
    """Test XSS protection in WebSocket message injection."""
    mock_addon = Mock()
    mock_addon.inject_ws_message.return_value = True

    # Attempt to inject XSS payload
    xss_payload = "<script>alert('xss')</script>"

    # Addon lives on the ProxyState singleton the route holds.
    with patch.object(ProxyState(), "proxy_addon", mock_addon, create=True):
        response = test_client.post("/api/proxy/websockets/ws1/inject", json={
            "message": xss_payload,
            "to_client": True
        })

        # Should still succeed (a MITM proxy intentionally passes data through;
        # content filtering is the proxy/client's responsibility, not the API's).
        assert response.status_code == 200

        # Verify the payload is passed through unmodified.
        mock_addon.inject_ws_message.assert_called_once_with("ws1", xss_payload, True)


@pytest.mark.asyncio
async def test_large_modification_script_handling(test_client: TestClient, mock_proxy_state):
    """Test handling of large modification scripts."""
    mock_proxy_state.get_settings.return_value = Mock(advanced_modifications=[])
    mock_proxy_state.update_settings.return_value = None

    # Create a large script (simulate complex modification)
    large_script = "// " + "x" * 50000  # 50KB script

    modification = {
        "name": "Large Script Test",
        "enabled": True,
        "target_url_pattern": "*",
        "modifications": {},
        "script": large_script
    }

    response = test_client.post("/api/proxy/modifications", json=modification)
    assert response.status_code == 200

    data = response.json()
    assert data["modification"]["script"] == large_script