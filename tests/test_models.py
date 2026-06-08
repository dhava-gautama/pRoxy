#!/usr/bin/env python3

import pytest
from pydantic import ValidationError

from state.models import (
    ReplaceRule, MapRule, ReplayRequest, DNSMapping, FuzzConfig
)


class TestReplaceRule:
    """Test ReplaceRule validation"""

    def test_valid_regex_pattern(self):
        """Test valid regex pattern validation"""
        rule = ReplaceRule(
            pattern=r"\d+",
            replacement="number",
            is_regex=True
        )
        assert rule.pattern == r"\d+"

    def test_invalid_regex_pattern(self):
        """Test invalid regex pattern rejection"""
        with pytest.raises(ValidationError) as exc_info:
            ReplaceRule(
                pattern="[invalid regex",  # Missing closing bracket
                replacement="test",
                is_regex=True
            )
        assert "Invalid regex pattern" in str(exc_info.value)

    def test_invalid_phase(self):
        """Test invalid phase rejection"""
        with pytest.raises(ValidationError):
            ReplaceRule(
                pattern="test",
                replacement="replaced",
                phase="invalid"
            )


class TestMapRule:
    """Test MapRule validation"""

    def test_valid_local_rule(self):
        """Test valid local file mapping"""
        rule = MapRule(
            match_pattern="*.js",
            rule_type="local",
            target="static/test.js"
        )
        assert rule.target == "static/test.js"

    def test_path_traversal_prevention(self):
        """Test path traversal attack prevention"""
        with pytest.raises(ValidationError) as exc_info:
            MapRule(
                match_pattern="*.js",
                rule_type="local",
                target="../../../etc/passwd"
            )
        assert "Path traversal not allowed" in str(exc_info.value)

    def test_absolute_path_prevention(self):
        """Test absolute path prevention"""
        with pytest.raises(ValidationError):
            MapRule(
                match_pattern="*.js",
                rule_type="local",
                target="/etc/passwd"
            )

    def test_valid_remote_rule(self):
        """Test valid remote URL mapping"""
        rule = MapRule(
            match_pattern="*.js",
            rule_type="remote",
            target="https://example.com/script.js"
        )
        assert rule.target == "https://example.com/script.js"

    def test_invalid_remote_url(self):
        """Test invalid remote URL rejection"""
        with pytest.raises(ValidationError):
            MapRule(
                match_pattern="*.js",
                rule_type="remote",
                target="ftp://invalid.com/file.js"  # Invalid scheme
            )

    def test_invalid_regex_pattern(self):
        """Test invalid regex pattern in match_pattern"""
        with pytest.raises(ValidationError):
            MapRule(
                match_pattern="[invalid",
                is_regex=True,
                rule_type="remote",
                target="https://example.com"
            )


class TestReplayRequest:
    """Test ReplayRequest validation"""

    def test_valid_request(self):
        """Test valid replay request"""
        request = ReplayRequest(
            method="POST",
            url="https://api.example.com/endpoint",
            headers={"Content-Type": "application/json"},
            body='{"test": "data"}'
        )
        assert request.method == "POST"

    def test_invalid_http_method(self):
        """Test invalid HTTP method rejection"""
        with pytest.raises(ValidationError):
            ReplayRequest(
                method="INVALID",
                url="https://example.com"
            )

    def test_invalid_url_scheme(self):
        """Test invalid URL scheme rejection"""
        with pytest.raises(ValidationError):
            ReplayRequest(
                method="GET",
                url="ftp://example.com/file.txt"
            )

    def test_missing_hostname(self):
        """Test missing hostname rejection"""
        with pytest.raises(ValidationError):
            ReplayRequest(
                method="GET",
                url="https://"
            )

    def test_body_size_limit(self):
        """Test body size limit enforcement"""
        large_body = "x" * (1024 * 1024 + 1)  # 1MB + 1 byte
        with pytest.raises(ValidationError) as exc_info:
            ReplayRequest(
                method="POST",
                url="https://example.com",
                body=large_body
            )
        assert "too large" in str(exc_info.value)

    def test_method_normalization(self):
        """Test HTTP method normalization to uppercase"""
        request = ReplayRequest(
            method="get",
            url="https://example.com"
        )
        assert request.method == "GET"


class TestDNSMapping:
    """Test DNSMapping validation"""

    def test_valid_mapping(self):
        """Test valid DNS mapping"""
        mapping = DNSMapping(
            hostname="example.com",
            ip="192.168.1.1"
        )
        assert mapping.hostname == "example.com"

    def test_hostname_normalization(self):
        """Test hostname normalization to lowercase"""
        mapping = DNSMapping(
            hostname="EXAMPLE.COM",
            ip="192.168.1.1"
        )
        assert mapping.hostname == "example.com"

    def test_invalid_hostname(self):
        """Test invalid hostname rejection"""
        with pytest.raises(ValidationError):
            DNSMapping(
                hostname="invalid..hostname",
                ip="192.168.1.1"
            )

    def test_invalid_ipv4(self):
        """Test invalid IPv4 address rejection"""
        with pytest.raises(ValidationError):
            DNSMapping(
                hostname="example.com",
                ip="999.999.999.999"
            )

    def test_valid_ipv6(self):
        """Test valid IPv6 address"""
        mapping = DNSMapping(
            hostname="example.com",
            ip="2001:db8::1"
        )
        assert mapping.ip == "2001:db8::1"

    def test_hostname_too_long(self):
        """Test overly long hostname rejection"""
        long_hostname = "a" * 254
        with pytest.raises(ValidationError):
            DNSMapping(
                hostname=long_hostname,
                ip="192.168.1.1"
            )


class TestFuzzConfig:
    """Test FuzzConfig validation"""

    def test_valid_config(self):
        """Test valid fuzz configuration"""
        config = FuzzConfig(
            iterations=100,
            delay_ms=1000
        )
        assert config.iterations == 100

    def test_minimum_iterations(self):
        """Test minimum iterations validation"""
        with pytest.raises(ValidationError):
            FuzzConfig(iterations=0)

    def test_maximum_iterations(self):
        """Test maximum iterations validation"""
        with pytest.raises(ValidationError):
            FuzzConfig(iterations=20000)

    def test_negative_delay(self):
        """Test negative delay rejection"""
        with pytest.raises(ValidationError):
            FuzzConfig(
                iterations=10,
                delay_ms=-100
            )

    def test_maximum_delay(self):
        """Test maximum delay validation"""
        with pytest.raises(ValidationError):
            FuzzConfig(
                iterations=10,
                delay_ms=400000  # > 5 minutes
            )


if __name__ == "__main__":
    pytest.main([__file__])