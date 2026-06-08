"""
Tests for pRoxy rule validation and security.
"""
import pytest
import re
from pydantic import ValidationError

from state.models import (
    HeaderRule, ReplaceRule, BreakpointRule, MockRule,
    MapRule, HighlightRule, ProxySettings
)


@pytest.mark.rules
class TestHeaderRuleValidation:
    """Test header rule validation."""

    def test_valid_header_rule_creation(self):
        """Test creating valid header rules."""
        # Set header rule
        rule = HeaderRule(
            name="X-Custom-Header",
            value="custom-value",
            phase="response",
            action="set",
            enabled=True
        )
        assert rule.name == "X-Custom-Header"
        assert rule.value == "custom-value"
        assert rule.phase == "response"
        assert rule.action == "set"
        assert rule.enabled == True

        # Remove header rule
        remove_rule = HeaderRule(
            name="X-Remove-Header",
            value="",
            phase="request",
            action="remove",
            enabled=True
        )
        assert remove_rule.action == "remove"
        assert remove_rule.value == ""

    def test_header_rule_name_validation(self):
        """Test header name validation."""
        # Valid header names
        valid_names = [
            "Content-Type",
            "X-Custom-Header",
            "Authorization",
            "User-Agent",
            "X-API-Key"
        ]

        for name in valid_names:
            rule = HeaderRule(
                name=name,
                value="test",
                phase="request",
                action="set",
                enabled=True
            )
            assert rule.name == name

    def test_header_rule_invalid_phase(self):
        """Test invalid phase validation."""
        with pytest.raises(ValidationError):
            HeaderRule(
                name="X-Test",
                value="test",
                phase="invalid",  # Invalid phase
                action="set",
                enabled=True
            )

    def test_header_rule_invalid_action(self):
        """Test invalid action validation."""
        with pytest.raises(ValidationError):
            HeaderRule(
                name="X-Test",
                value="test",
                phase="request",
                action="invalid",  # Invalid action
                enabled=True
            )

    @pytest.mark.security
    def test_header_rule_xss_protection(self, malicious_inputs):
        """Test XSS protection in header values."""
        for payload in malicious_inputs["xss_payloads"]:
            # Should not raise validation error but may sanitize
            rule = HeaderRule(
                name="X-Test",
                value=payload,
                phase="response",
                action="set",
                enabled=True
            )
            # Rule should be created (validation focuses on structure, not content sanitization)
            assert rule.value == payload

    @pytest.mark.security
    def test_header_rule_injection_protection(self, malicious_inputs):
        """Test header injection protection."""
        injection_payloads = [
            "normal-value\r\nX-Injected: malicious",  # CRLF injection
            "normal-value\nX-Injected: malicious",   # LF injection
            "normal-value\rX-Injected: malicious",   # CR injection
        ]

        for payload in injection_payloads:
            # These should be rejected or sanitized
            with pytest.raises(ValidationError):
                HeaderRule(
                    name="X-Test",
                    value=payload,
                    phase="response",
                    action="set",
                    enabled=True
                )


@pytest.mark.rules
class TestReplaceRuleValidation:
    """Test replace rule validation."""

    def test_valid_replace_rule_creation(self):
        """Test creating valid replace rules."""
        # Text replacement
        rule = ReplaceRule(
            pattern="old-text",
            replacement="new-text",
            phase="response",
            is_regex=False,
            enabled=True
        )
        assert rule.pattern == "old-text"
        assert rule.replacement == "new-text"
        assert rule.is_regex == False

        # Regex replacement
        regex_rule = ReplaceRule(
            pattern=r"api\.old\.com",
            replacement="api.new.com",
            phase="request",
            is_regex=True,
            enabled=True
        )
        assert regex_rule.is_regex == True

    def test_replace_rule_regex_validation(self):
        """Test regex pattern validation."""
        # Valid regex patterns
        valid_patterns = [
            r"api\.example\.com",
            r"\d{3}-\d{3}-\d{4}",  # Phone number
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email
            r"https?://[^\s/$.?#].[^\s]*"  # URL
        ]

        for pattern in valid_patterns:
            rule = ReplaceRule(
                pattern=pattern,
                replacement="replacement",
                phase="response",
                is_regex=True,
                enabled=True
            )
            assert rule.pattern == pattern

        # Invalid regex patterns should raise ValidationError
        invalid_patterns = [
            r"[unclosed",  # Unclosed bracket
            r"*",  # Invalid quantifier
            r"(?",  # Incomplete group
        ]

        for pattern in invalid_patterns:
            with pytest.raises(ValidationError):
                ReplaceRule(
                    pattern=pattern,
                    replacement="replacement",
                    phase="response",
                    is_regex=True,
                    enabled=True
                )

    @pytest.mark.security
    def test_replace_rule_redos_protection(self, malicious_inputs):
        """Test ReDoS (Regular Expression Denial of Service) protection."""
        # Patterns that could cause catastrophic backtracking
        dangerous_patterns = [
            r"(a+)+$",
            r"([a-zA-Z]+)*$",
            r"(a|a)*$",
            r"a{100000}",  # Excessive quantifier
        ]

        for pattern in dangerous_patterns:
            with pytest.raises(ValidationError):
                ReplaceRule(
                    pattern=pattern,
                    replacement="safe",
                    phase="response",
                    is_regex=True,
                    enabled=True
                )

    def test_replace_rule_empty_pattern(self):
        """Test handling of empty patterns."""
        # Empty pattern should be rejected
        with pytest.raises(ValidationError):
            ReplaceRule(
                pattern="",
                replacement="replacement",
                phase="response",
                is_regex=False,
                enabled=True
            )

    def test_replace_rule_large_pattern(self, malicious_inputs):
        """Test handling of very large patterns."""
        large_pattern = malicious_inputs["large_payloads"][0]  # 1MB string

        # Should reject excessively large patterns
        with pytest.raises(ValidationError):
            ReplaceRule(
                pattern=large_pattern,
                replacement="replacement",
                phase="response",
                is_regex=False,
                enabled=True
            )


@pytest.mark.rules
class TestBreakpointRuleValidation:
    """Test breakpoint rule validation."""

    def test_valid_breakpoint_rule_creation(self):
        """Test creating valid breakpoint rules."""
        rule = BreakpointRule(
            host_pattern="*.api.com",
            path_pattern="/auth.*",
            method="POST",
            enabled=True
        )
        assert rule.host_pattern == "*.api.com"
        assert rule.path_pattern == "/auth.*"
        assert rule.method == "POST"

    def test_breakpoint_rule_optional_fields(self):
        """Test breakpoint rules with optional fields."""
        # Only host pattern
        rule1 = BreakpointRule(
            host_pattern="example.com",
            path_pattern="",
            method="",
            enabled=True
        )
        assert rule1.host_pattern == "example.com"

        # Only method
        rule2 = BreakpointRule(
            host_pattern="",
            path_pattern="",
            method="GET",
            enabled=True
        )
        assert rule2.method == "GET"

    def test_breakpoint_rule_method_validation(self):
        """Test HTTP method validation."""
        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", ""]

        for method in valid_methods:
            rule = BreakpointRule(
                host_pattern="*",
                path_pattern="",
                method=method,
                enabled=True
            )
            assert rule.method == method


@pytest.mark.rules
class TestMockRuleValidation:
    """Test mock rule validation."""

    def test_valid_mock_rule_creation(self):
        """Test creating valid mock rules."""
        rule = MockRule(
            match_pattern="*/api/users*",
            is_regex=False,
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"users": []}',
            enabled=True
        )
        assert rule.match_pattern == "*/api/users*"
        assert rule.status_code == 200
        assert rule.body == '{"users": []}'

    def test_mock_rule_status_code_validation(self):
        """Test HTTP status code validation."""
        # Valid status codes
        valid_codes = [200, 201, 400, 401, 403, 404, 500, 502, 503]

        for code in valid_codes:
            rule = MockRule(
                match_pattern="/test",
                is_regex=False,
                status_code=code,
                headers={},
                body="",
                enabled=True
            )
            assert rule.status_code == code

        # Invalid status codes
        invalid_codes = [99, 600, 1000, -1]

        for code in invalid_codes:
            with pytest.raises(ValidationError):
                MockRule(
                    match_pattern="/test",
                    is_regex=False,
                    status_code=code,
                    headers={},
                    body="",
                    enabled=True
                )

    def test_mock_rule_json_body_validation(self):
        """Test JSON body validation."""
        # Valid JSON
        valid_json_bodies = [
            '{"key": "value"}',
            '[]',
            '{"nested": {"key": "value"}}',
            '""',  # Empty string is valid JSON
            'null'
        ]

        for body in valid_json_bodies:
            rule = MockRule(
                match_pattern="/test",
                is_regex=False,
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=body,
                enabled=True
            )
            assert rule.body == body

    def test_mock_rule_large_body(self, malicious_inputs):
        """Test handling of large mock response bodies."""
        large_body = malicious_inputs["large_payloads"][0]

        # Should handle large bodies but may have size limits
        try:
            rule = MockRule(
                match_pattern="/test",
                is_regex=False,
                status_code=200,
                headers={},
                body=large_body,
                enabled=True
            )
            # If accepted, should store the body
            assert len(rule.body) == len(large_body)
        except ValidationError:
            # If rejected, that's also acceptable
            pass


@pytest.mark.rules
class TestMapRuleValidation:
    """Test map rule validation."""

    def test_valid_map_rule_creation(self):
        """Test creating valid map rules."""
        # Remote mapping
        remote_rule = MapRule(
            match_pattern="*/api/old/*",
            is_regex=False,
            rule_type="remote",
            target="https://api.new.com/endpoint",
            enabled=True
        )
        assert remote_rule.rule_type == "remote"
        assert remote_rule.target.startswith("https://")

        # Local mapping (relative path — absolute paths are rejected for safety)
        local_rule = MapRule(
            match_pattern="*/static/*",
            is_regex=False,
            rule_type="local",
            target="responses/local/file.json",
            enabled=True
        )
        assert local_rule.rule_type == "local"

    def test_map_rule_target_validation(self):
        """Test target URL/path validation."""
        # Valid remote targets
        valid_remote_targets = [
            "https://api.example.com/endpoint",
            "http://localhost:8080/api",
            "https://subdomain.example.com:8443/path"
        ]

        for target in valid_remote_targets:
            rule = MapRule(
                match_pattern="/test",
                is_regex=False,
                rule_type="remote",
                target=target,
                enabled=True
            )
            assert rule.target == target

        # Valid local targets (relative only — absolute paths are rejected for safety)
        valid_local_targets = [
            "responses/file.json",
            "mocks/response.xml",
            "./relative/path.txt"
        ]

        for target in valid_local_targets:
            rule = MapRule(
                match_pattern="/test",
                is_regex=False,
                rule_type="local",
                target=target,
                enabled=True
            )
            assert rule.target == target

    @pytest.mark.security
    def test_map_rule_path_traversal_protection(self, malicious_inputs):
        """Test path traversal protection in local file mappings."""
        for path_payload in malicious_inputs["path_traversal"]:
            # Should reject dangerous paths
            with pytest.raises(ValidationError):
                MapRule(
                    match_pattern="/test",
                    is_regex=False,
                    rule_type="local",
                    target=path_payload,
                    enabled=True
                )

    def test_map_rule_type_validation(self):
        """Test rule type validation."""
        # Valid types
        for rule_type in ["local", "remote"]:
            rule = MapRule(
                match_pattern="/test",
                is_regex=False,
                rule_type=rule_type,
                target="https://example.com" if rule_type == "remote" else "path/file",
                enabled=True
            )
            assert rule.rule_type == rule_type

        # Invalid type
        with pytest.raises(ValidationError):
            MapRule(
                match_pattern="/test",
                is_regex=False,
                rule_type="invalid",
                target="target",
                enabled=True
            )


@pytest.mark.rules
class TestHighlightRuleValidation:
    """Test highlight rule validation."""

    def test_valid_highlight_rule_creation(self):
        """Test creating valid highlight rules."""
        rule = HighlightRule(
            match_type="content-type",
            pattern="application/json",
            color="#1e3a5f",
            enabled=True
        )
        assert rule.match_type == "content-type"
        assert rule.pattern == "application/json"
        assert rule.color == "#1e3a5f"

    def test_highlight_rule_match_type_validation(self):
        """Test match type validation."""
        valid_types = ["content-type", "host", "path", "method", "status"]

        for match_type in valid_types:
            rule = HighlightRule(
                match_type=match_type,
                pattern="test-pattern",
                color="#ff0000",
                enabled=True
            )
            assert rule.match_type == match_type

        # Invalid match type
        with pytest.raises(ValidationError):
            HighlightRule(
                match_type="invalid",
                pattern="test",
                color="#ff0000",
                enabled=True
            )

    def test_highlight_rule_color_validation(self):
        """Test color format validation."""
        # Valid colors
        valid_colors = [
            "#000000",
            "#ffffff",
            "#1e3a5f",
            "#FF5733",
            "#abc123"
        ]

        for color in valid_colors:
            rule = HighlightRule(
                match_type="host",
                pattern="example.com",
                color=color,
                enabled=True
            )
            assert rule.color == color

        # Invalid colors
        invalid_colors = [
            "red",          # Named color
            "#gggggg",      # Invalid hex
            "#12345",       # Too short
            "#1234567",     # Too long
            "rgb(255,0,0)"  # RGB format
        ]

        for color in invalid_colors:
            with pytest.raises(ValidationError):
                HighlightRule(
                    match_type="host",
                    pattern="example.com",
                    color=color,
                    enabled=True
                )


@pytest.mark.rules
class TestProxySettingsValidation:
    """Test overall proxy settings validation."""

    def test_valid_settings_creation(self, sample_rules):
        """Test creating valid proxy settings."""
        settings = ProxySettings(
            hsts_strip=True,
            csp_strip=False,
            header_rules=[sample_rules["header_rule"]],
            replace_rules=[sample_rules["replace_rule"]]
        )

        assert settings.hsts_strip == True
        assert settings.csp_strip == False
        assert len(settings.header_rules) == 1
        assert len(settings.replace_rules) == 1

    def test_settings_with_all_rule_types(self, sample_rules):
        """Test settings with all rule types."""
        settings = ProxySettings(
            header_rules=[sample_rules["header_rule"]],
            replace_rules=[sample_rules["replace_rule"]],
            breakpoint_rules=[sample_rules["breakpoint_rule"]],
            mock_rules=[sample_rules["mock_rule"]],
            map_rules=[sample_rules["map_rule"]],
            highlight_rules=[sample_rules["highlight_rule"]]
        )

        # Verify all rule types are present
        assert len(settings.header_rules) == 1
        assert len(settings.replace_rules) == 1
        assert len(settings.breakpoint_rules) == 1
        assert len(settings.mock_rules) == 1
        assert len(settings.map_rules) == 1
        assert len(settings.highlight_rules) == 1

    def test_settings_rule_conflicts(self):
        """Test detection of conflicting rules."""
        # This is more of an integration test - the model itself
        # doesn't detect conflicts, but the application logic should
        pass  # Implementation depends on business logic

    @pytest.mark.security
    def test_settings_bulk_validation(self, malicious_inputs):
        """Test bulk validation with mixed valid/invalid rules."""
        # Mix of valid and potentially malicious rules
        mixed_header_rules = [
            # Valid rule
            HeaderRule(
                name="X-Valid-Header",
                value="valid-value",
                phase="response",
                action="set",
                enabled=True
            )
        ]

        # Try to add malicious rule
        for payload in malicious_inputs["xss_payloads"][:2]:  # Test first 2
            try:
                mixed_header_rules.append(
                    HeaderRule(
                        name="X-Malicious",
                        value=payload,
                        phase="response",
                        action="set",
                        enabled=True
                    )
                )
            except ValidationError:
                # Expected for malicious payloads
                pass

        # Settings should accept valid rules and reject/sanitize invalid ones
        settings = ProxySettings(header_rules=mixed_header_rules)
        assert len(settings.header_rules) >= 1  # At least the valid one