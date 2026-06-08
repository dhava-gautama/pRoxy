"""
Shared pytest fixtures and configuration for pRoxy tests.
"""
import asyncio
import contextlib
import json
import os
import sys
import tempfile
from typing import AsyncGenerator, Dict, Any
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path

import pytest
import httpx

# Ensure project root is in Python path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Isolate ProxyState persistence so the suite never writes to the real ~/.pRoxy.
# Must be set BEFORE importing api.server below (route modules instantiate the
# ProxyState singleton at import time, which reads this on first construction).
os.environ.setdefault("PROXY_STATE_DIR", tempfile.mkdtemp(prefix="proxy-test-state-"))

# Try importing pRoxy modules with fallback
try:
    from fastapi.testclient import TestClient
    from api.server import create_app
    from state.shared import ProxyState
    from state.models import (
        ProxySettings, FlowRecord, HeaderRule, ReplaceRule,
        BreakpointRule, MockRule, MapRule, HighlightRule
    )
    IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import pRoxy modules: {e}")
    IMPORTS_AVAILABLE = False


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_client():
    """Create a FastAPI test client."""
    if not IMPORTS_AVAILABLE:
        pytest.skip("pRoxy modules not available")
    app = create_app()
    return TestClient(app)


@pytest.fixture
async def async_client():
    """Create an async HTTP client for testing."""
    if not IMPORTS_AVAILABLE:
        pytest.skip("pRoxy modules not available")
    app = create_app()
    async with httpx.AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def mock_proxy_state():
    """Mock the shared ProxyState singleton.

    Route modules bind ``state = ProxyState()`` at import time, so patching the
    class is too late. Because ProxyState is a singleton, we instead patch the
    public methods on the live instance — the same object the routes hold.
    """
    if not IMPORTS_AVAILABLE:
        pytest.skip("pRoxy modules not available")

    state = ProxyState()  # shared singleton held by the route modules
    mock = MagicMock()

    # Sensible defaults
    mock.get_settings.return_value = ProxySettings()
    mock.update_settings.return_value = ProxySettings()
    mock.store_flow.return_value = None
    mock.get_flow.return_value = None
    mock.get_flows.return_value = []
    mock.get_flows_lite.return_value = []
    mock.search_flows.return_value = []
    mock.delete_flow.return_value = True
    mock.clear_flows.return_value = 0
    mock.get_sequences.return_value = []
    mock.get_sequence.return_value = None
    mock.save_sequence.side_effect = lambda seq: seq
    mock.delete_sequence.return_value = True
    mock.get_intercept_queue.return_value = []
    mock.resolve_intercept.return_value = True
    mock.get_collections.return_value = []
    mock.get_collection.return_value = None
    mock.save_collection.side_effect = lambda col: col
    mock.delete_collection.return_value = True

    patched = [
        "get_settings", "update_settings", "store_flow", "get_flow", "get_flows",
        "get_flows_lite", "search_flows", "delete_flow", "clear_flows",
        "get_sequences", "get_sequence", "save_sequence", "delete_sequence",
        "get_intercept_queue", "resolve_intercept",
        "get_collections", "get_collection", "save_collection", "delete_collection",
    ]
    with contextlib.ExitStack() as stack:
        for name in patched:
            stack.enter_context(patch.object(state, name, getattr(mock, name)))
        yield mock


@pytest.fixture(autouse=True)
def _block_outbound_network():
    """Fail outbound HTTP fast so tests never hang on real network I/O.

    Only ``httpx.AsyncClient`` (used by the replay request executor) is blocked;
    the sync ``httpx.Client`` that backs Starlette's TestClient is untouched.
    """
    async def _blocked(*args, **kwargs):
        raise httpx.ConnectError("outbound network blocked in tests")

    with patch("httpx.AsyncClient.send", _blocked):
        yield


@pytest.fixture
def temp_config_dir():
    """Create a temporary directory for config files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def sample_settings():
    """Sample proxy settings for testing."""
    if not IMPORTS_AVAILABLE:
        pytest.skip("pRoxy modules not available")
    return ProxySettings(
        hsts_strip=True,
        hpkp_strip=False,
        csp_strip=True,
        cors_bypass=False,
        force_ssl=False,
        intercept_enabled=True,
        intercept_responses=False,
        upstream_proxy="",
        custom_user_agent="pRoxy-Test/1.0",
        header_rules=[
            HeaderRule(
                name="X-Test-Header",
                value="test-value",
                phase="response",
                action="set",
                enabled=True
            )
        ],
        replace_rules=[
            ReplaceRule(
                pattern="old-text",
                replacement="new-text",
                phase="response",
                is_regex=False,
                enabled=True
            )
        ]
    )


@pytest.fixture
def sample_flow():
    """Sample flow record for testing."""
    if not IMPORTS_AVAILABLE:
        pytest.skip("pRoxy modules not available")
    return FlowRecord(
        id="test-flow-1",
        timestamp=1700000000.0,
        method="GET",
        scheme="https",
        host="example.com",
        port=443,
        path="/api/test",
        url="https://example.com/api/test",
        request_headers={"User-Agent": "pRoxy-Test"},
        request_body="",
        request_content_type="",
        status_code=200,
        reason="OK",
        response_headers={"Content-Type": "application/json"},
        response_body='{"status": "success"}',
        response_content_type="application/json",
        response_size=25,
        completed=True,
        duration_ms=150.5
    )


@pytest.fixture
def sample_rules():
    """Sample rules for testing rule validation."""
    if not IMPORTS_AVAILABLE:
        pytest.skip("pRoxy modules not available")
    return {
        "header_rule": HeaderRule(
            name="Authorization",
            value="Bearer test-token",
            phase="request",
            action="set",
            enabled=True
        ),
        "replace_rule": ReplaceRule(
            pattern="api\\.example\\.com",
            replacement="api.test.com",
            phase="request",
            is_regex=True,
            enabled=True
        ),
        "breakpoint_rule": BreakpointRule(
            host_pattern="*.api.com",
            path_pattern="/auth.*",
            method="POST",
            enabled=True
        ),
        "mock_rule": MockRule(
            match_pattern="*/api/mock",
            is_regex=False,
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"mocked": true}',
            enabled=True
        ),
        "map_rule": MapRule(
            match_pattern="*/api/old",
            is_regex=False,
            rule_type="remote",
            target="https://api.new.com/endpoint",
            enabled=True
        ),
        "highlight_rule": HighlightRule(
            match_type="content-type",
            pattern="application/json",
            color="#1e3a5f",
            enabled=True
        )
    }


@pytest.fixture
def malicious_inputs():
    """Collection of malicious inputs for security testing."""
    return {
        "xss_payloads": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//';alert('XSS');//\">"
        ],
        "sql_injection": [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; UPDATE users SET password='hacked' WHERE id=1; --",
            "1' UNION SELECT null,username,password FROM users--"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ],
        "command_injection": [
            "; ls -la",
            "| whoami",
            "; cat /etc/passwd",
            "`id`",
            "$(id)"
        ],
        "regex_dos": [
            "a" * 10000,  # Long string
            "(a+)+$",     # Catastrophic backtracking
            "a{100000}",  # Excessive quantifier
        ],
        "large_payloads": [
            "A" * 1000000,  # 1MB string
            {"key": "value" * 50000}  # Large JSON
        ]
    }


@pytest.fixture
def auth_headers():
    """Authentication headers for API testing."""
    # Since auth is disabled in lab mode, return empty headers
    return {}


@pytest.fixture(autouse=True)
def setup_test_env():
    """Set up test environment variables."""
    # Ensure we're in test mode
    os.environ["PROXY_DISABLE_AUTH"] = "true"
    os.environ["TESTING"] = "true"
    yield
    # Cleanup
    os.environ.pop("TESTING", None)