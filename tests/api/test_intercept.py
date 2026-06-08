"""
Tests for pRoxy intercept API endpoints.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.mark.api
class TestInterceptAPI:
    """Test intercept API endpoints."""

    def test_get_intercept_queue(self, test_client: TestClient, mock_proxy_state):
        """Test GET /api/intercept/queue endpoint."""
        # Mock empty queue
        mock_proxy_state.get_intercept_queue.return_value = []

        response = test_client.get("/api/intercept/queue")

        assert response.status_code == 200
        assert response.json() == []
        mock_proxy_state.get_intercept_queue.assert_called_once()

    def test_get_intercept_queue_with_items(self, test_client: TestClient, mock_proxy_state):
        """Test intercept queue with pending items."""
        # Mock queue with items
        queue_items = [
            {
                "flow_id": "test-flow-1",
                "phase": "request",
                "method": "POST",
                "url": "https://api.example.com/login",
                "timestamp": 1700000000.0
            },
            {
                "flow_id": "test-flow-2",
                "phase": "response",
                "method": "GET",
                "url": "https://api.example.com/data",
                "timestamp": 1700000001.0
            }
        ]
        mock_proxy_state.get_intercept_queue.return_value = queue_items

        response = test_client.get("/api/intercept/queue")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["flow_id"] == "test-flow-1"
        assert data[0]["phase"] == "request"

    def test_resolve_intercept_forward(self, test_client: TestClient, mock_proxy_state):
        """Test resolving intercept with forward action."""
        mock_proxy_state.resolve_intercept.return_value = True

        resolve_data = {
            "action": "forward",
            "modified_body": None,
            "modified_headers": None
        }

        response = test_client.post(
            "/api/intercept/test-flow-1/request",
            json=resolve_data
        )

        assert response.status_code == 200
        assert response.json() == {"ok": True}

        # Verify resolve_intercept was called with correct parameters
        mock_proxy_state.resolve_intercept.assert_called_once_with(
            "test-flow-1:request",
            "forward",
            modified_body=None,
            modified_headers=None
        )

    def test_resolve_intercept_drop(self, test_client: TestClient, mock_proxy_state):
        """Test resolving intercept with drop action."""
        mock_proxy_state.resolve_intercept.return_value = True

        resolve_data = {
            "action": "drop"
        }

        response = test_client.post(
            "/api/intercept/test-flow-2/response",
            json=resolve_data
        )

        assert response.status_code == 200
        assert response.json() == {"ok": True}

        mock_proxy_state.resolve_intercept.assert_called_once_with(
            "test-flow-2:response",
            "drop",
            modified_body=None,
            modified_headers=None
        )

    def test_resolve_intercept_with_modifications(self, test_client: TestClient, mock_proxy_state):
        """Test resolving intercept with request/response modifications."""
        mock_proxy_state.resolve_intercept.return_value = True

        modified_headers = {
            "X-Modified": "true",
            "Content-Type": "application/json"
        }
        modified_body = '{"modified": true, "original": false}'

        resolve_data = {
            "action": "forward",
            "modified_body": modified_body,
            "modified_headers": modified_headers
        }

        response = test_client.post(
            "/api/intercept/test-flow-3/request",
            json=resolve_data
        )

        assert response.status_code == 200

        # Verify modifications were passed
        mock_proxy_state.resolve_intercept.assert_called_once_with(
            "test-flow-3:request",
            "forward",
            modified_body=modified_body,
            modified_headers=modified_headers
        )

    def test_resolve_intercept_invalid_action(self, test_client: TestClient):
        """Test resolving intercept with invalid action."""
        resolve_data = {
            "action": "invalid_action"
        }

        response = test_client.post(
            "/api/intercept/test-flow/request",
            json=resolve_data
        )

        assert response.status_code == 400
        assert "action must be 'forward' or 'drop'" in response.json()["detail"]

    def test_resolve_intercept_invalid_phase(self, test_client: TestClient):
        """Test resolving intercept with invalid phase."""
        resolve_data = {
            "action": "forward"
        }

        response = test_client.post(
            "/api/intercept/test-flow/invalid_phase",
            json=resolve_data
        )

        assert response.status_code == 400
        assert "phase must be 'request' or 'response'" in response.json()["detail"]

    def test_resolve_intercept_not_found(self, test_client: TestClient, mock_proxy_state):
        """Test resolving non-existent intercept."""
        mock_proxy_state.resolve_intercept.return_value = False

        resolve_data = {
            "action": "forward"
        }

        response = test_client.post(
            "/api/intercept/non-existent-flow/request",
            json=resolve_data
        )

        assert response.status_code == 404
        assert "Flow not in intercept queue" in response.json()["detail"]

    @pytest.mark.security
    def test_intercept_body_size_limits(self, test_client: TestClient, mock_proxy_state, malicious_inputs):
        """Test handling of large modified bodies."""
        mock_proxy_state.resolve_intercept.return_value = True

        large_body = malicious_inputs["large_payloads"][0]  # 1MB string

        resolve_data = {
            "action": "forward",
            "modified_body": large_body
        }

        response = test_client.post(
            "/api/intercept/test-flow/request",
            json=resolve_data
        )

        # Should handle large payloads gracefully
        assert response.status_code in [200, 413, 422]  # OK, Payload Too Large, or Validation Error

    @pytest.mark.security
    def test_intercept_header_injection_protection(self, test_client: TestClient, mock_proxy_state, malicious_inputs):
        """Test protection against header injection in modified headers."""
        mock_proxy_state.resolve_intercept.return_value = True

        for payload in malicious_inputs["xss_payloads"]:
            modified_headers = {
                "X-Test": payload,
                "X-Malicious": f"Header with {payload}"
            }

            resolve_data = {
                "action": "forward",
                "modified_headers": modified_headers
            }

            response = test_client.post(
                "/api/intercept/test-flow/request",
                json=resolve_data
            )

            # Should handle malicious headers safely
            assert response.status_code in [200, 400, 422]

    def test_intercept_json_body_modification(self, test_client: TestClient, mock_proxy_state):
        """Test modifying JSON request/response bodies."""
        mock_proxy_state.resolve_intercept.return_value = True

        original_body = '{"username": "user", "password": "pass"}'
        modified_body = '{"username": "admin", "password": "admin123"}'

        resolve_data = {
            "action": "forward",
            "modified_body": modified_body,
            "modified_headers": {"Content-Type": "application/json"}
        }

        response = test_client.post(
            "/api/intercept/login-flow/request",
            json=resolve_data
        )

        assert response.status_code == 200

        # Verify the modified body was passed correctly
        call_args = mock_proxy_state.resolve_intercept.call_args
        assert call_args[1]["modified_body"] == modified_body

    def test_intercept_concurrent_resolutions(self, test_client: TestClient, mock_proxy_state):
        """Test concurrent intercept resolutions."""
        import threading

        mock_proxy_state.resolve_intercept.return_value = True
        results = []

        def resolve_intercept(flow_id, phase):
            response = test_client.post(
                f"/api/intercept/{flow_id}/{phase}",
                json={"action": "forward"}
            )
            results.append(response.status_code)

        # Create multiple threads resolving different intercepts
        threads = []
        for i in range(5):
            thread = threading.Thread(
                target=resolve_intercept,
                args=[f"flow-{i}", "request"]
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All resolutions should succeed
        assert all(status == 200 for status in results)
        assert len(results) == 5

    def test_intercept_empty_modifications(self, test_client: TestClient, mock_proxy_state):
        """Test intercept resolution with empty/null modifications."""
        mock_proxy_state.resolve_intercept.return_value = True

        test_cases = [
            {"modified_body": "", "modified_headers": {}},
            {"modified_body": None, "modified_headers": None},
            {"modified_body": "", "modified_headers": None},
            {"modified_body": None, "modified_headers": {}},
        ]

        for i, modifications in enumerate(test_cases):
            resolve_data = {
                "action": "forward",
                **modifications
            }

            response = test_client.post(
                f"/api/intercept/test-flow-{i}/request",
                json=resolve_data
            )

            assert response.status_code == 200

    def test_intercept_malformed_json_body(self, test_client: TestClient, mock_proxy_state):
        """Test handling malformed JSON in modified body."""
        mock_proxy_state.resolve_intercept.return_value = True

        malformed_bodies = [
            '{"incomplete": json',  # Incomplete JSON
            '{"duplicate": "key", "duplicate": "value"}',  # Duplicate keys
            '{"trailing": "comma",}',  # Trailing comma
            '{invalid: json}',  # Unquoted keys
        ]

        for malformed_body in malformed_bodies:
            resolve_data = {
                "action": "forward",
                "modified_body": malformed_body,
                "modified_headers": {"Content-Type": "application/json"}
            }

            response = test_client.post(
                "/api/intercept/test-flow/request",
                json=resolve_data
            )

            # Should handle malformed JSON gracefully
            # May accept (pass through as-is) or reject with validation error
            assert response.status_code in [200, 400, 422]