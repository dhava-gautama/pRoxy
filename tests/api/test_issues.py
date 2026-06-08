"""
Hermetic tests for the unified Issues dashboard (api/routes/issues.py).

The issues route performs no outbound I/O: it calls the existing scanner, recon,
and threat_detection finder functions, all of which read flows from the shared
ProxyState singleton and run local analysis. We drive everything through the
``mock_proxy_state`` fixture (which patches the live singleton's ``get_flows``).

The router is not yet registered in api/server.py, so we mount it on a
standalone FastAPI app.

Endpoint under test:
  GET /api/issues?domain="" -> {issues, total, by_severity, by_source}
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import issues
from state.models import FlowRecord


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(issues.router)
    return TestClient(app)


# ── Flow builder ───────────────────────────────────────────────────────────


def _flow(**overrides) -> FlowRecord:
    base = dict(
        id="flow-1",
        timestamp=time.time(),  # recent so threat_detection's time window keeps it
        method="GET",
        scheme="https",
        host="example.com",
        port=443,
        path="/",
        url="https://example.com/",
        request_headers={},
        request_body="",
        request_content_type="",
        status_code=200,
        reason="OK",
        response_headers={"Content-Type": "text/html"},
        response_body="",
        response_content_type="text/html",
        response_size=0,
        completed=True,
    )
    base.update(overrides)
    return FlowRecord(**base)


def _trigger_flows() -> list[FlowRecord]:
    """A set of flows engineered to trigger findings across multiple sources."""
    return [
        # scanner sensitive: AWS key (critical) in response body.
        # scanner headers: HTML response missing every security header.
        # recon fingerprint: nginx Server header -> tech disclosure.
        _flow(
            id="leak",
            host="api.example.com",
            path="/keys",
            response_headers={"Content-Type": "text/html", "Server": "nginx/1.2.3"},
            response_content_type="text/html",
            response_body="aws key AKIAIOSFODNN7EXAMPLE here",
        ),
        # scanner errors: a 500 with a Python stack trace -> info leakage.
        _flow(
            id="err",
            host="api.example.com",
            path="/boom",
            status_code=500,
            reason="Internal Server Error",
            response_headers={"Content-Type": "text/html"},
            response_content_type="text/html",
            response_body='Traceback (most recent call last):\n  File "app.py", line 10',
        ),
        # threat_detection: suspicious user-agent (sqlmap) -> threat alert
        # (threshold 1). Recent timestamp keeps it inside the scan window.
        _flow(
            id="threat",
            host="api.example.com",
            path="/admin",
            url="https://api.example.com/admin",
            request_headers={"User-Agent": "sqlmap/1.5"},
        ),
    ]


# ── Tests ──────────────────────────────────────────────────────────────────


def test_empty_when_no_flows(client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = []

    resp = client.get("/api/issues")
    assert resp.status_code == 200
    data = resp.json()
    assert data == {"issues": [], "total": 0, "by_severity": {}, "by_source": {}}


def test_normalized_shape(client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = _trigger_flows()

    resp = client.get("/api/issues")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] >= 1
    assert data["total"] == len(data["issues"])
    assert isinstance(data["by_severity"], dict) and data["by_severity"]
    assert isinstance(data["by_source"], dict) and data["by_source"]

    for issue in data["issues"]:
        assert set(issue.keys()) == {"source", "severity", "title", "detail", "location"}
        assert issue["source"] in ("scanner", "recon", "threat_detection")
        assert issue["severity"] in ("critical", "high", "medium", "low", "info")
        assert isinstance(issue["title"], str)
        assert isinstance(issue["detail"], str)
        assert isinstance(issue["location"], str)


def test_findings_from_at_least_two_sources(client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = _trigger_flows()

    resp = client.get("/api/issues")
    assert resp.status_code == 200
    data = resp.json()

    sources = {i["source"] for i in data["issues"]}
    assert len(sources) >= 2, f"expected findings from >=2 sources, got {sources}"
    # scanner (sensitive/headers/errors) must contribute.
    assert "scanner" in sources


def test_sorted_highest_severity_first(client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = _trigger_flows()

    resp = client.get("/api/issues")
    assert resp.status_code == 200
    issues_list = resp.json()["issues"]

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    levels = [order[i["severity"]] for i in issues_list]
    assert levels == sorted(levels), "issues must be sorted by severity, critical first"
    # The AWS key is a critical finding and must be present and first-tier.
    assert levels[0] == 0


def test_counts_consistent_with_issues(client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = _trigger_flows()

    resp = client.get("/api/issues")
    assert resp.status_code == 200
    data = resp.json()

    assert sum(data["by_severity"].values()) == data["total"]
    assert sum(data["by_source"].values()) == data["total"]


def test_domain_filter_excludes_other_hosts(client: TestClient, mock_proxy_state):
    flows = _trigger_flows()
    # Add an unrelated host that also leaks a secret; the filter must drop it.
    flows.append(_flow(
        id="other",
        host="other-host.test",
        path="/x",
        response_body="AKIAIOSFODNN7EXAMPLE",
    ))
    mock_proxy_state.get_flows.return_value = flows

    resp = client.get("/api/issues?domain=api.example.com")
    assert resp.status_code == 200
    data = resp.json()

    locations = " ".join(i["location"] for i in data["issues"])
    assert "other-host.test" not in locations
    assert data["total"] >= 1
