"""
Tests for pRoxy settings API endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from state.models import HeaderRule, ReplaceRule


@pytest.mark.api
class TestSettingsAPI:
    """Test settings API endpoints."""

    def test_get_settings(self, test_client: TestClient, mock_proxy_state):
        """Test GET /api/settings endpoint."""
        response = test_client.get("/api/settings")

        assert response.status_code == 200
        data = response.json()

        # Check required fields exist
        required_fields = [
            "hsts_strip", "hpkp_strip", "csp_strip", "cors_bypass",
            "force_ssl", "intercept_enabled", "intercept_responses",
            "upstream_proxy", "custom_user_agent"
        ]
        for field in required_fields:
            assert field in data

        # Check rule arrays exist
        rule_arrays = [
            "header_rules", "replace_rules", "breakpoint_rules",
            "mock_rules", "map_rules", "highlight_rules", "scope_patterns"
        ]
        for rule_array in rule_arrays:
            assert rule_array in data
            assert isinstance(data[rule_array], list)

    def test_update_settings_partial(self, test_client: TestClient):
        """Test POST /api/settings with partial updates.

        Exercises the real ProxyState.update_settings so the response reflects
        the posted values (the mock_proxy_state fixture stubs update_settings to
        return defaults, which is unsuitable for asserting echoed updates).
        """
        update_data = {
            "hsts_strip": True,
            "cors_bypass": True,
            "custom_user_agent": "pRoxy-Test/1.0"
        }

        response = test_client.post("/api/settings", json=update_data)

        assert response.status_code == 200
        data = response.json()

        # Verify updated fields
        assert data["hsts_strip"] == True
        assert data["cors_bypass"] == True
        assert data["custom_user_agent"] == "pRoxy-Test/1.0"

    def test_update_settings_header_rules(self, test_client: TestClient):
        """Test updating header rules via settings.

        Exercises the real ProxyState.update_settings (the mock_proxy_state
        fixture stubs it to return defaults, which would drop the posted rules).
        """
        header_rules = [
            {
                "name": "X-Custom-Header",
                "value": "test-value",
                "phase": "response",
                "action": "set",
                "enabled": True
            },
            {
                "name": "X-Remove-Header",
                "value": "",
                "phase": "request",
                "action": "remove",
                "enabled": True
            }
        ]

        response = test_client.post("/api/settings", json={"header_rules": header_rules})

        assert response.status_code == 200
        data = response.json()
        assert len(data["header_rules"]) == 2

        # Verify first rule
        rule1 = data["header_rules"][0]
        assert rule1["name"] == "X-Custom-Header"
        assert rule1["value"] == "test-value"
        assert rule1["phase"] == "response"
        assert rule1["action"] == "set"
        assert rule1["enabled"] == True

    def test_update_settings_invalid_data(self, test_client: TestClient):
        """Test settings update with invalid data."""
        # Invalid boolean value
        response = test_client.post("/api/settings", json={"hsts_strip": "invalid"})
        assert response.status_code == 422

        # Invalid header rule - missing required field
        invalid_header_rule = [{
            "name": "X-Test",
            # Missing value, phase, action
            "enabled": True
        }]
        response = test_client.post("/api/settings", json={"header_rules": invalid_header_rule})
        assert response.status_code == 422

    @pytest.mark.security
    def test_settings_xss_protection(self, test_client: TestClient, malicious_inputs):
        """Test XSS handling in settings fields.

        The proxy stores config values verbatim; a JSON API response is not an
        XSS sink (the frontend escapes on render). So the contract is safe
        handling, not server-side stripping: the request is either accepted
        (200) or cleanly rejected (422), the response is valid JSON, and no
        unhandled 500 occurs.
        """
        for xss_payload in malicious_inputs["xss_payloads"]:
            response = test_client.post("/api/settings", json={
                "custom_user_agent": xss_payload
            })
            assert response.status_code in [200, 422]

            if response.status_code == 200:
                data = response.json()
                # Value is stored verbatim and round-trips through JSON cleanly.
                assert data["custom_user_agent"] == xss_payload

    @pytest.mark.security
    def test_settings_path_traversal_protection(self, test_client: TestClient, malicious_inputs):
        """Test path traversal protection in settings."""
        for path_payload in malicious_inputs["path_traversal"]:
            # Try path traversal in upstream_proxy field
            response = test_client.post("/api/settings", json={
                "upstream_proxy": f"http://{path_payload}:8080"
            })
            # Should either sanitize or reject
            assert response.status_code in [200, 422]

    def test_settings_large_payload(self, test_client: TestClient, malicious_inputs):
        """Test handling of large payloads."""
        large_string = malicious_inputs["large_payloads"][0]

        response = test_client.post("/api/settings", json={
            "custom_user_agent": large_string
        })

        # Should handle large payload gracefully
        assert response.status_code in [200, 413, 422]  # OK, Payload Too Large, or Validation Error

    def test_concurrent_settings_updates(self, test_client: TestClient):
        """Test concurrent settings updates."""
        import threading
        import time

        results = []

        def update_setting(value):
            response = test_client.post("/api/settings", json={"hsts_strip": value})
            results.append(response.status_code)

        # Create multiple threads updating settings
        threads = []
        for i in range(5):
            thread = threading.Thread(target=update_setting, args=[i % 2 == 0])
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All updates should succeed
        assert all(status == 200 for status in results)

    def test_settings_persistence_mock(self, test_client: TestClient, mock_proxy_state):
        """Test that settings changes are persisted (mocked)."""
        # Update settings
        update_data = {"hsts_strip": True, "csp_strip": False}
        response = test_client.post("/api/settings", json=update_data)
        assert response.status_code == 200

        # Verify update_settings was called on mock
        mock_proxy_state.update_settings.assert_called()

        # Get settings again
        response = test_client.get("/api/settings")
        assert response.status_code == 200

        # Verify get_settings was called
        mock_proxy_state.get_settings.assert_called()

    def test_empty_settings_update(self, test_client: TestClient):
        """Test updating settings with empty data."""
        response = test_client.post("/api/settings", json={})
        assert response.status_code == 200

        # Should return current settings even with empty update
        data = response.json()
        assert "hsts_strip" in data  # Should have default values