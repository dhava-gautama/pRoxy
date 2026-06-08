"""
Tests for pRoxy replay API endpoints.
"""
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
import httpx


@pytest.mark.api
class TestReplayAPI:
    """Test replay API endpoints."""

    @patch('api.routes.replay._do_request')
    def test_replay_request_success(self, mock_do_request, test_client: TestClient):
        """Test successful request replay."""
        # Mock successful response
        mock_do_request.return_value = {
            "id": "replay-1234567890",
            "status_code": 200,
            "reason": "OK",
            "headers": {"Content-Type": "application/json"},
            "body": '{"success": true}',
            "duration_ms": 150.5
        }

        replay_data = {
            "method": "GET",
            "url": "https://httpbin.org/get",
            "headers": {"User-Agent": "pRoxy-Test"},
            "body": ""
        }

        response = test_client.post("/api/replay", json=replay_data)

        assert response.status_code == 200
        data = response.json()

        # Verify response structure
        assert "id" in data
        assert data["status_code"] == 200
        assert data["reason"] == "OK"
        assert "headers" in data
        assert "body" in data
        assert "duration_ms" in data

        # Verify mock was called with correct parameters
        mock_do_request.assert_called_once()
        call_args = mock_do_request.call_args[0]
        assert call_args[0] == "GET"  # method
        assert call_args[1] == "https://httpbin.org/get"  # url
        assert call_args[2] == {"User-Agent": "pRoxy-Test"}  # headers
        assert call_args[3] == ""  # body

    @patch('api.routes.replay._do_request')
    def test_replay_request_with_body(self, mock_do_request, test_client: TestClient):
        """Test request replay with POST body."""
        mock_do_request.return_value = {
            "id": "replay-1234567890",
            "status_code": 201,
            "reason": "Created",
            "headers": {"Content-Type": "application/json"},
            "body": '{"created": true}',
            "duration_ms": 250.0
        }

        replay_data = {
            "method": "POST",
            "url": "https://httpbin.org/post",
            "headers": {"Content-Type": "application/json"},
            "body": '{"test": "data"}'
        }

        response = test_client.post("/api/replay", json=replay_data)

        assert response.status_code == 200
        data = response.json()
        assert data["status_code"] == 201

        # Verify POST body was passed
        call_args = mock_do_request.call_args[0]
        assert call_args[3] == '{"test": "data"}'

    @patch('api.routes.replay._do_request')
    def test_replay_request_failure(self, mock_do_request, test_client: TestClient):
        """Test replay request failure handling."""
        # Mock request failure
        mock_do_request.side_effect = httpx.RequestError("Connection failed")

        replay_data = {
            "method": "GET",
            "url": "https://invalid-host.example",
            "headers": {},
            "body": ""
        }

        response = test_client.post("/api/replay", json=replay_data)

        assert response.status_code == 502  # Bad Gateway
        data = response.json()
        assert "Request failed" in data["detail"]

    def test_replay_invalid_data(self, test_client: TestClient):
        """Test replay with invalid request data."""
        # Missing required fields
        response = test_client.post("/api/replay", json={})
        assert response.status_code == 422

        # Invalid URL
        invalid_data = {
            "method": "GET",
            "url": "not-a-valid-url",
            "headers": {},
            "body": ""
        }
        response = test_client.post("/api/replay", json=invalid_data)
        # Should be handled by validation or request execution
        assert response.status_code in [422, 502]

    @pytest.mark.security
    def test_replay_ssrf_protection(self, test_client: TestClient):
        """Test SSRF (Server-Side Request Forgery) protection."""
        dangerous_urls = [
            "http://localhost:22",  # SSH port
            "http://127.0.0.1:3306",  # MySQL port
            "http://169.254.169.254/metadata",  # AWS metadata
            "file:///etc/passwd",  # File protocol
            "ftp://internal-server/",  # FTP protocol
        ]

        for url in dangerous_urls:
            replay_data = {
                "method": "GET",
                "url": url,
                "headers": {},
                "body": ""
            }

            response = test_client.post("/api/replay", json=replay_data)
            # Should either block dangerous URLs or fail safely
            assert response.status_code in [400, 422, 502]

    @pytest.mark.security
    def test_replay_header_injection(self, test_client: TestClient, malicious_inputs):
        """Test protection against header injection attacks."""
        for payload in malicious_inputs["xss_payloads"]:
            replay_data = {
                "method": "GET",
                "url": "https://httpbin.org/get",
                "headers": {"X-Test": payload},
                "body": ""
            }

            response = test_client.post("/api/replay", json=replay_data)
            # Should handle malicious headers safely
            assert response.status_code in [200, 400, 422, 502]

    @patch('api.routes.replay._do_request')
    def test_fuzz_request_basic(self, mock_do_request, test_client: TestClient):
        """Test basic fuzzing functionality."""
        # Mock responses for fuzzing iterations
        mock_do_request.return_value = {
            "id": "replay-fuzz-123",
            "status_code": 200,
            "reason": "OK",
            "headers": {},
            "body": "success",
            "duration_ms": 100.0
        }

        fuzz_data = {
            "method": "GET",
            "url": "https://httpbin.org/get?param={{fuzz.i}}",
            "headers": {},
            "body": "",
            "iterations": 3,
            "variables": {},
            "delay_ms": 0
        }

        response = test_client.post("/api/replay/fuzz", json=fuzz_data)

        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert len(data["results"]) == 3

        # Check result structure
        for i, result in enumerate(data["results"]):
            assert result["iteration"] == i
            assert "status_code" in result
            assert "duration_ms" in result
            assert "size" in result

        # Verify _do_request was called 3 times
        assert mock_do_request.call_count == 3

    @patch('api.routes.replay._do_request')
    def test_fuzz_with_variables(self, mock_do_request, test_client: TestClient):
        """Test fuzzing with variable substitution."""
        mock_do_request.return_value = {
            "id": "replay-fuzz-123",
            "status_code": 200,
            "reason": "OK",
            "headers": {},
            "body": "success",
            "duration_ms": 100.0
        }

        fuzz_data = {
            "method": "GET",
            "url": "https://httpbin.org/get?user={{fuzz.username}}",
            "headers": {},
            "body": "",
            "iterations": 2,
            "variables": {
                "username": "wordlist:admin,user,guest,root"
            },
            "delay_ms": 0
        }

        response = test_client.post("/api/replay/fuzz", json=fuzz_data)

        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 2

        # Verify URLs were modified with different usernames
        call_args_list = mock_do_request.call_args_list
        urls = [call[0][1] for call in call_args_list]  # Extract URLs from calls
        assert "user=admin" in urls[0]
        assert "user=user" in urls[1]

    def test_fuzz_iteration_limit(self, test_client: TestClient):
        """Test fuzzing iteration limits."""
        fuzz_data = {
            "method": "GET",
            "url": "https://httpbin.org/get",
            "headers": {},
            "body": "",
            "iterations": 2000,  # Exceeds max limit of 1000
            "variables": {},
            "delay_ms": 0
        }

        with patch('api.routes.replay._do_request') as mock_do_request:
            mock_do_request.return_value = {
                "id": "test", "status_code": 200, "reason": "OK",
                "headers": {}, "body": "", "duration_ms": 100
            }

            response = test_client.post("/api/replay/fuzz", json=fuzz_data)

            assert response.status_code == 200
            data = response.json()

            # Should be limited to 1000 iterations
            assert len(data["results"]) == 1000

    def test_sequence_basic(self, test_client: TestClient, mock_proxy_state):
        """Test basic sequence functionality."""
        sequence_data = {
            "steps": [
                {
                    "name": "Login",
                    "method": "POST",
                    "url": "https://api.example.com/login",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"username": "test", "password": "pass"}',
                    "extract": {"token": "json:token"}
                },
                {
                    "name": "Get Data",
                    "method": "GET",
                    "url": "https://api.example.com/data",
                    "headers": {"Authorization": "Bearer {{var.token}}"},
                    "body": "",
                    "extract": {}
                }
            ]
        }

        with patch('api.routes.replay._do_request') as mock_do_request:
            # Mock responses for each step
            mock_do_request.side_effect = [
                {
                    "id": "seq-step-1",
                    "status_code": 200,
                    "reason": "OK",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"token": "abc123", "user_id": 1}',
                    "duration_ms": 200.0
                },
                {
                    "id": "seq-step-2",
                    "status_code": 200,
                    "reason": "OK",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"data": ["item1", "item2"]}',
                    "duration_ms": 150.0
                }
            ]

            response = test_client.post("/api/replay/sequence", json=sequence_data)

            assert response.status_code == 200
            data = response.json()

            # Check sequence results
            assert "results" in data
            assert "variables" in data
            assert len(data["results"]) == 2

            # Check extracted variables
            assert "token" in data["variables"]
            assert data["variables"]["token"] == "abc123"

            # Check second request used extracted token
            call_args_list = mock_do_request.call_args_list
            second_call_headers = call_args_list[1][0][2]  # headers from second call
            assert second_call_headers["Authorization"] == "Bearer abc123"

    def test_sequence_crud_operations(self, test_client: TestClient, mock_proxy_state):
        """Test sequence CRUD operations."""
        # Test list sequences
        mock_proxy_state.get_sequences.return_value = []
        response = test_client.get("/api/replay/sequences")
        assert response.status_code == 200
        assert response.json() == []

        # Test create sequence
        sequence_data = {
            "name": "Test Sequence",
            "steps": [
                {
                    "name": "Step 1",
                    "method": "GET",
                    "url": "https://example.com",
                    "headers": {},
                    "body": "",
                    "extract": {}
                }
            ]
        }

        response = test_client.post("/api/replay/sequences", json=sequence_data)
        assert response.status_code == 200
        mock_proxy_state.save_sequence.assert_called()

        # Test delete sequence
        mock_proxy_state.delete_sequence.return_value = True
        response = test_client.delete("/api/replay/sequences/test-seq-id")
        assert response.status_code == 200
        assert response.json() == {"ok": True}

        # Test delete non-existent sequence
        mock_proxy_state.delete_sequence.return_value = False
        response = test_client.delete("/api/replay/sequences/non-existent")
        assert response.status_code == 404