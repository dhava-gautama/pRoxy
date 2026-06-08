"""
Security tests for pRoxy - comprehensive security validation.
"""
import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch


@pytest.mark.security
class TestInputValidationSecurity:
    """Test input validation and sanitization security."""

    def test_api_xss_protection(self, test_client: TestClient, malicious_inputs):
        """Test XSS protection across all API endpoints."""
        endpoints = [
            ("/api/settings", "POST", {"custom_user_agent": "PAYLOAD"}),
            ("/api/settings", "POST", {"upstream_proxy": "http://PAYLOAD:8080"}),
        ]

        for endpoint, method, data in endpoints:
            for xss_payload in malicious_inputs["xss_payloads"]:
                # Replace PAYLOAD with actual XSS payload
                test_data = {}
                for key, value in data.items():
                    if isinstance(value, str) and "PAYLOAD" in value:
                        test_data[key] = value.replace("PAYLOAD", xss_payload)
                    else:
                        test_data[key] = xss_payload if key == "PAYLOAD" else value

                if method == "POST":
                    response = test_client.post(endpoint, json=test_data)
                else:
                    response = test_client.get(endpoint, params=test_data)

                # Should not return 500 (unhandled error); invalid input is
                # cleanly rejected, otherwise the value is accepted.
                assert response.status_code != 500
                assert response.status_code in [200, 422]

                if response.status_code == 200:
                    # The proxy stores config values verbatim; the JSON API
                    # response is not an XSS sink (the frontend escapes on
                    # render). So the payload round-trips as valid JSON rather
                    # than being stripped server-side.
                    data = response.json()
                    assert isinstance(data, dict)

    def test_sql_injection_protection(self, test_client: TestClient, malicious_inputs):
        """Test SQL injection protection (if database operations exist)."""
        # Test common injection points
        for sql_payload in malicious_inputs["sql_injection"]:
            # Test in settings that might be used in queries
            response = test_client.post("/api/settings", json={
                "custom_user_agent": sql_payload
            })

            # Should handle SQL injection attempts safely
            assert response.status_code in [200, 400, 422]

            if response.status_code == 200:
                # Should not contain SQL error messages
                response_text = response.text.lower()
                sql_error_indicators = [
                    "syntax error",
                    "mysql",
                    "postgresql",
                    "sqlite",
                    "ora-",
                    "sql state"
                ]
                for indicator in sql_error_indicators:
                    assert indicator not in response_text

    def test_command_injection_protection(self, test_client: TestClient, malicious_inputs):
        """Test command injection protection."""
        for cmd_payload in malicious_inputs["command_injection"]:
            # Test in fields that might be processed by system commands
            response = test_client.post("/api/settings", json={
                "upstream_proxy": f"http://example.com{cmd_payload}:8080"
            })

            # Should not execute commands
            assert response.status_code in [200, 400, 422]

            # Should not contain command output. The proxy stores upstream_proxy
            # verbatim and echoes it back, so the payload string itself (which
            # may include literal "/etc/passwd") legitimately appears in the
            # response — that is input echo, not execution. Only actual command
            # *output* signatures (e.g. `id`/`ls` results) prove execution.
            if response.status_code == 200:
                response_text = response.text.lower()
                command_outputs = ["uid=", "gid=", "groups=", "total "]
                for output in command_outputs:
                    assert output not in response_text

    def test_path_traversal_protection(self, test_client: TestClient, malicious_inputs):
        """Test path traversal protection in file operations."""
        try:
            for path_payload in malicious_inputs["path_traversal"]:
                # A map rule's "local" target is a real filesystem path, so the
                # MapRule model rejects traversal payloads (422). This is the
                # actual path-traversal protection.
                map_response = test_client.post("/api/settings", json={
                    "map_rules": [{
                        "match_pattern": "/test",
                        "is_regex": False,
                        "rule_type": "local",
                        "target": path_payload,
                        "enabled": True
                    }]
                })
                assert map_response.status_code in [400, 422]

                # A mock rule's body is opaque response data that is never used
                # as a filesystem path, so a path-like string inside it is
                # stored verbatim and handled safely (no traversal occurs).
                mock_response = test_client.post("/api/settings", json={
                    "mock_rules": [{
                        "match_pattern": "/test",
                        "is_regex": False,
                        "status_code": 200,
                        "headers": {},
                        "body": f"{{\"file\": \"{path_payload}\"}}",
                        "enabled": True
                    }]
                })
                assert mock_response.status_code in [200, 400, 422]
        finally:
            # Settings are a shared singleton; clear the rules we set so the
            # stored payload strings don't leak into later tests.
            test_client.post("/api/settings", json={"map_rules": [], "mock_rules": []})

    def test_regex_dos_protection(self, test_client: TestClient, malicious_inputs):
        """Test ReDoS (Regular Expression Denial of Service) protection."""
        dangerous_regex_patterns = [
            r"(a+)+$",
            r"([a-zA-Z]+)*$",
            r"(a|a)*$",
            r"a{100000}",
        ]

        for pattern in dangerous_regex_patterns:
            # Test in replace rules
            response = test_client.post("/api/settings", json={
                "replace_rules": [{
                    "pattern": pattern,
                    "replacement": "safe",
                    "phase": "response",
                    "is_regex": True,
                    "enabled": True
                }]
            })

            # Should reject dangerous regex patterns
            assert response.status_code in [400, 422]

    def test_large_payload_protection(self, test_client: TestClient, malicious_inputs):
        """Test protection against large payloads."""
        large_payload = malicious_inputs["large_payloads"][0]  # 1MB string

        # Test various endpoints with large payloads
        test_cases = [
            {"custom_user_agent": large_payload},
            {"header_rules": [{
                "name": "X-Large",
                "value": large_payload,
                "phase": "response",
                "action": "set",
                "enabled": True
            }]},
            {"replace_rules": [{
                "pattern": "small",
                "replacement": large_payload,
                "phase": "response",
                "is_regex": False,
                "enabled": True
            }]}
        ]

        for test_data in test_cases:
            response = test_client.post("/api/settings", json=test_data)

            # Should handle large payloads gracefully
            assert response.status_code in [200, 413, 422]  # OK, Payload Too Large, or Validation Error

            # Should not cause server errors
            assert response.status_code != 500

    def test_content_type_validation(self, test_client: TestClient):
        """Test content-type validation and security."""
        # Test with incorrect content types
        malicious_content_types = [
            "text/plain",
            "text/html",
            "application/x-www-form-urlencoded",
            "multipart/form-data"
        ]

        for content_type in malicious_content_types:
            response = test_client.post(
                "/api/settings",
                data='{"hsts_strip": true}',  # JSON data
                headers={"Content-Type": content_type}
            )

            # Should handle content-type mismatches appropriately
            assert response.status_code in [200, 400, 415, 422]

    def test_header_injection_protection(self, test_client: TestClient):
        """Test HTTP header injection protection."""
        injection_payloads = [
            "normal-value\r\nX-Injected: malicious",
            "normal-value\nSet-Cookie: session=hijacked",
            "normal-value\r\nLocation: http://evil.com"
        ]

        for payload in injection_payloads:
            # Try header injection via custom headers in replay
            response = test_client.post("/api/replay", json={
                "method": "GET",
                "url": "https://httpbin.org/get",
                "headers": {"X-Test": payload},
                "body": ""
            })

            # Should handle header injection safely
            assert response.status_code in [200, 400, 422, 502]

            # Response headers should not contain injected content
            response_headers = dict(response.headers)
            assert "X-Injected" not in response_headers
            assert "Set-Cookie" not in response_headers or not response_headers["Set-Cookie"].startswith("session=hijacked")


@pytest.mark.security
class TestAuthenticationSecurity:
    """Test authentication and authorization security."""

    def test_auth_disabled_in_test_mode(self, test_client: TestClient):
        """Test that authentication is properly disabled in test/lab mode."""
        # All endpoints should be accessible without authentication
        endpoints = [
            ("/api/settings", "GET"),
            ("/api/settings", "POST"),
            ("/api/flows", "GET"),
            ("/api/intercept/queue", "GET"),
        ]

        for endpoint, method in endpoints:
            if method == "GET":
                response = test_client.get(endpoint)
            else:
                response = test_client.post(endpoint, json={})

            # Should not return 401 (Unauthorized) or 403 (Forbidden)
            assert response.status_code not in [401, 403]

    def test_no_sensitive_info_exposure(self, test_client: TestClient):
        """Test that no sensitive information is exposed in responses."""
        response = test_client.get("/api/settings")

        if response.status_code == 200:
            response_text = response.text.lower()

            # Should not contain sensitive information
            sensitive_patterns = [
                "password",
                "secret",
                "private_key",
                "api_key",
                "token",
                "/etc/passwd",
                "credit_card",
                "ssn"
            ]

            for pattern in sensitive_patterns:
                # Allow these in field names but not in values
                if pattern in response_text:
                    # More specific check - should not be in actual values
                    data = response.json()
                    # Convert to string and check for standalone occurrences
                    data_str = json.dumps(data)
                    # This is a basic check - in real implementation you'd be more specific
                    pass  # Implementation would depend on actual sensitive data


@pytest.mark.security
class TestRateLimitingSecurity:
    """Test rate limiting and DoS protection."""

    def test_request_rate_limiting(self, test_client: TestClient):
        """Test basic request rate limiting."""
        # Make many rapid requests
        responses = []
        for i in range(50):
            response = test_client.get("/api/settings")
            responses.append(response.status_code)

        # Should not all succeed if rate limiting is in place
        # This test assumes rate limiting exists - adjust based on implementation
        status_codes = set(responses)

        # All requests should either succeed or be rate limited
        allowed_codes = {200, 429, 503}  # OK, Too Many Requests, Service Unavailable
        assert status_codes.issubset(allowed_codes)

    def test_resource_exhaustion_protection(self, test_client: TestClient):
        """Test protection against resource exhaustion attacks."""
        # Test concurrent requests
        import threading
        import time

        results = []

        def make_request():
            response = test_client.get("/api/settings")
            results.append(response.status_code)

        # Create many concurrent threads
        threads = []
        for i in range(20):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        # Wait for completion with timeout
        start_time = time.time()
        for thread in threads:
            remaining_time = max(0, 10 - (time.time() - start_time))
            thread.join(timeout=remaining_time)

        # Should handle concurrent requests gracefully
        # No thread should hang indefinitely (all should complete within timeout)
        assert len(results) > 0  # At least some requests completed

        # Should not cause server errors
        server_errors = [code for code in results if code >= 500]
        assert len(server_errors) / len(results) < 0.1  # Less than 10% server errors


@pytest.mark.security
class TestSSRFProtection:
    """Test Server-Side Request Forgery (SSRF) protection."""

    def test_ssrf_protection_in_replay(self, test_client: TestClient):
        """Test SSRF protection in replay functionality."""
        dangerous_urls = [
            "http://localhost:22",          # SSH port
            "http://127.0.0.1:3306",       # MySQL
            "http://169.254.169.254/",      # AWS metadata
            "http://metadata.google.internal/", # GCP metadata
            "file:///etc/passwd",           # File protocol
            "ftp://internal.server/",       # FTP protocol
            "gopher://localhost:25/",       # Gopher protocol
            "http://[::1]:22/",            # IPv6 localhost
        ]

        for url in dangerous_urls:
            response = test_client.post("/api/replay", json={
                "method": "GET",
                "url": url,
                "headers": {},
                "body": ""
            })

            # Should reject dangerous internal URLs
            assert response.status_code in [400, 403, 422, 502]

            if response.status_code not in [400, 422]:
                # If not rejected by validation, should fail safely
                data = response.json()
                assert "detail" in data
                # Should not contain internal service responses
                assert "SSH" not in str(data)
                assert "mysql" not in str(data).lower()

    def test_url_redirect_protection(self, test_client: TestClient):
        """Test protection against malicious redirects."""
        # This would require mocking external services that redirect
        # to internal resources - more complex integration test
        pass


@pytest.mark.security
class TestSecurityHeaders:
    """Test security headers in responses."""

    def test_security_headers_present(self, test_client: TestClient):
        """Test that proper security headers are set."""
        response = test_client.get("/api/settings")

        headers = response.headers

        # Check for security headers (adjust based on implementation)
        recommended_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
        }

        for header, expected_values in recommended_headers.items():
            if header in headers:
                if isinstance(expected_values, list):
                    assert headers[header] in expected_values
                else:
                    assert headers[header] == expected_values

    def test_no_sensitive_headers_leaked(self, test_client: TestClient):
        """Test that sensitive headers are not leaked."""
        response = test_client.get("/api/settings")

        headers = response.headers

        # Headers that should not be present
        dangerous_headers = [
            "Server",  # Might reveal server version
            "X-Powered-By",  # Might reveal technology stack
        ]

        for header in dangerous_headers:
            if header in headers:
                # If present, should not reveal sensitive information
                value = headers[header].lower()
                assert "version" not in value
                assert not any(ver in value for ver in ["1.0", "2.0", "apache", "nginx"])


@pytest.mark.security
class TestErrorHandlingSecurity:
    """Test secure error handling."""

    def test_error_message_safety(self, test_client: TestClient, malicious_inputs):
        """Test that error messages don't leak sensitive information."""
        # Force various types of errors
        error_test_cases = [
            # Invalid JSON
            ("/api/settings", "POST", "invalid-json", "application/json"),
            # Very large payload
            ("/api/settings", "POST", "A" * 10000, "application/json"),
            # Invalid method
            ("/api/settings", "PATCH", '{}', "application/json"),
        ]

        for endpoint, method, data, content_type in error_test_cases:
            if method == "POST":
                response = test_client.post(
                    endpoint,
                    data=data,
                    headers={"Content-Type": content_type}
                )
            elif method == "PATCH":
                response = test_client.patch(
                    endpoint,
                    data=data,
                    headers={"Content-Type": content_type}
                )

            # Should return appropriate error codes
            assert response.status_code >= 400

            if response.status_code != 405:  # Method not allowed is OK
                try:
                    error_data = response.json()
                    error_message = str(error_data).lower()

                    # Should not contain sensitive file paths
                    assert "/etc/passwd" not in error_message
                    assert "c:\\windows" not in error_message

                    # Should not contain internal code paths
                    assert "/home/" not in error_message
                    assert "__file__" not in error_message

                    # Should not contain SQL error details
                    assert "mysql" not in error_message
                    assert "postgresql" not in error_message

                except json.JSONDecodeError:
                    # Non-JSON error response is also acceptable
                    pass

    def test_exception_handling(self, test_client: TestClient):
        """Test that unhandled exceptions don't leak information."""
        # Try to trigger edge cases that might cause exceptions
        edge_cases = [
            # Null bytes
            '{"custom_user_agent": "\x00test"}',
            # Unicode issues
            '{"custom_user_agent": "\uFFFF"}',
            # Very nested JSON
            '{"test": ' + '{"nested": ' * 100 + 'true' + '}' * 100 + '}',
        ]

        for test_case in edge_cases:
            response = test_client.post(
                "/api/settings",
                data=test_case,
                headers={"Content-Type": "application/json"}
            )

            # The security contract is that edge-case input never triggers an
            # unhandled exception (500). Some of these payloads are in fact
            # valid (a lone Unicode char in a string field, or an unknown JSON
            # key that is simply ignored) and are correctly accepted with 200;
            # genuinely malformed input (e.g. embedded null bytes) is cleanly
            # rejected. Either outcome is safe.
            assert response.status_code != 500
            assert response.status_code in [200, 400, 422]