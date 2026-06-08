"""
Hermetic tests for the scanner route (api/routes/scanner.py).

The scanner performs no outbound I/O: every endpoint reads flows from the
shared ProxyState singleton and runs local regex analysis. We therefore drive
the routes entirely through the ``mock_proxy_state`` fixture, which patches the
state methods the scanner calls (``get_flow``, ``get_flows``). No network,
subprocess, or socket calls are involved.

Endpoints under test:
  POST /api/scanner/sensitive  -> {findings, total, by_severity, by_pattern}
  POST /api/scanner/headers    -> {domains, count}
  GET  /api/scanner/errors     -> {errors, total, clusters}
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from state.models import FlowRecord


# ── Flow builders ──────────────────────────────────────────────────────────


def _flow(**overrides) -> FlowRecord:
    """Build a FlowRecord with sane defaults, overridable per test."""
    base = dict(
        id="flow-1",
        timestamp=1700000000.0,
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


# ── /sensitive ─────────────────────────────────────────────────────────────


def test_sensitive_empty_when_no_flows(test_client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = []

    resp = test_client.post("/api/scanner/sensitive", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "findings": [],
        "total": 0,
        "by_severity": {},
        "by_pattern": {},
    }


def test_sensitive_detects_and_masks_secret(test_client: TestClient, mock_proxy_state):
    # AWS access key (critical) lives in the response body.
    aws_key = "AKIAIOSFODNN7EXAMPLE"  # AKIA + 16 chars
    flow = _flow(id="f-aws", host="api.example.com", path="/keys",
                 response_body=f"key={aws_key}")
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.post("/api/scanner/sensitive", json={"max_flows": 100})
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] >= 1
    aws_findings = [f for f in data["findings"] if f["pattern_name"] == "AWS Access Key"]
    assert len(aws_findings) == 1
    finding = aws_findings[0]
    assert finding["severity"] == "critical"
    assert finding["flow_id"] == "f-aws"
    assert finding["host"] == "api.example.com"
    assert finding["location"] == "response_body"
    # Value must be masked, never returned in the clear.
    assert aws_key not in finding["matched"]
    assert finding["matched"].startswith("AKIAIO")
    assert finding["matched"].endswith("MPLE")
    assert data["by_severity"]["critical"] >= 1
    assert data["by_pattern"]["AWS Access Key"] >= 1


def test_sensitive_findings_sorted_critical_first(test_client: TestClient, mock_proxy_state):
    # Email (low) + AWS key (critical) in one flow; critical must sort first.
    flow = _flow(
        id="f-mixed",
        response_body="contact me at user@example.com  AKIAIOSFODNN7EXAMPLE",
    )
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.post("/api/scanner/sensitive", json={})
    assert resp.status_code == 200
    findings = resp.json()["findings"]
    severities = [f["severity"] for f in findings]
    # critical must appear before any low finding.
    assert "critical" in severities and "low" in severities
    assert severities.index("critical") < severities.index("low")


def test_sensitive_single_flow_by_id(test_client: TestClient, mock_proxy_state):
    flow = _flow(id="target", response_body="AKIAIOSFODNN7EXAMPLE")
    mock_proxy_state.get_flow.return_value = flow

    resp = test_client.post("/api/scanner/sensitive", json={"flow_id": "target"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    # Scan must have used get_flow, not get_flows.
    mock_proxy_state.get_flow.assert_called_once_with("target")
    mock_proxy_state.get_flows.assert_not_called()


def test_sensitive_unknown_flow_id_returns_empty(test_client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flow.return_value = None

    resp = test_client.post("/api/scanner/sensitive", json={"flow_id": "nope"})
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


def test_sensitive_caps_max_flows_at_2000(test_client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = []

    resp = test_client.post("/api/scanner/sensitive", json={"max_flows": 999999})
    assert resp.status_code == 200
    # The route clamps max_flows to 2000 before querying state.
    mock_proxy_state.get_flows.assert_called_once_with(limit=2000)


def test_sensitive_skips_oversized_text(test_client: TestClient, mock_proxy_state):
    # Body over 1,000,000 chars is skipped entirely (no findings even if it matches).
    huge = "AKIAIOSFODNN7EXAMPLE" + ("x" * 1_000_001)
    flow = _flow(id="f-huge", response_body=huge)
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.post("/api/scanner/sensitive", json={})
    assert resp.status_code == 200
    # The matching key is in the oversized body, so it must be skipped.
    body_findings = [f for f in resp.json()["findings"] if f["location"] == "response_body"]
    assert body_findings == []


# ── /headers ───────────────────────────────────────────────────────────────


def test_headers_empty_when_no_flows(test_client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = []

    resp = test_client.post("/api/scanner/headers", json={})
    assert resp.status_code == 200
    assert resp.json() == {"domains": [], "count": 0}


def test_headers_grades_missing_headers(test_client: TestClient, mock_proxy_state):
    # HTML response with no security headers -> grade F, all headers missing.
    flow = _flow(
        host="insecure.example.com",
        response_headers={"Content-Type": "text/html"},
        response_content_type="text/html",
    )
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.post("/api/scanner/headers", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    domain = data["domains"][0]
    assert domain["domain"] == "insecure.example.com"
    assert domain["grade"] == "F"
    assert domain["score"] == 0
    assert domain["max_score"] > 0
    names = {h["name"] for h in domain["missing_headers"]}
    assert "Content-Security-Policy (CSP)" in names
    # Internal bookkeeping key must be stripped from the response.
    assert "checked" not in domain


def test_headers_grades_present_headers(test_client: TestClient, mock_proxy_state):
    # A response with every security header should grade A and have no missing.
    secure_headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "0",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    flow = _flow(host="secure.example.com", response_headers=secure_headers,
                 response_content_type="text/html")
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.post("/api/scanner/headers", json={})
    assert resp.status_code == 200
    domain = resp.json()["domains"][0]
    assert domain["grade"] == "A"
    assert domain["missing_headers"] == []
    assert len(domain["present_headers"]) == len(secure_headers) - 1  # minus Content-Type


def test_headers_flags_insecure_cookie(test_client: TestClient, mock_proxy_state):
    flow = _flow(
        host="cookie.example.com",
        response_headers={"Content-Type": "text/html", "Set-Cookie": "sid=abc123"},
        response_content_type="text/html",
    )
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.post("/api/scanner/headers", json={})
    assert resp.status_code == 200
    issues = resp.json()["domains"][0]["cookie_issues"]
    assert len(issues) == 1
    assert issues[0]["cookie"] == "sid"
    assert set(issues[0]["missing_flags"]) == {"HttpOnly", "Secure", "SameSite"}


def test_headers_reports_info_disclosure(test_client: TestClient, mock_proxy_state):
    flow = _flow(
        host="leaky.example.com",
        response_headers={
            "Content-Type": "text/html",
            "Server": "nginx/1.2.3",
            "X-Powered-By": "PHP/8.0",
        },
        response_content_type="text/html",
    )
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.post("/api/scanner/headers", json={})
    assert resp.status_code == 200
    disclosure = resp.json()["domains"][0]["info_disclosure"]
    headers = {d["header"]: d["value"] for d in disclosure}
    assert headers["Server"] == "nginx/1.2.3"
    assert headers["X-Powered-By"] == "PHP/8.0"


def test_headers_domain_filter(test_client: TestClient, mock_proxy_state):
    keep = _flow(id="keep", host="keep.example.com", response_content_type="text/html")
    drop = _flow(id="drop", host="other.example.com", response_content_type="text/html")
    mock_proxy_state.get_flows.return_value = [keep, drop]

    resp = test_client.post("/api/scanner/headers", json={"domain": "keep.example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["domains"][0]["domain"] == "keep.example.com"


# ── /errors ────────────────────────────────────────────────────────────────


def test_errors_empty_when_no_flows(test_client: TestClient, mock_proxy_state):
    mock_proxy_state.get_flows.return_value = []

    resp = test_client.get("/api/scanner/errors")
    assert resp.status_code == 200
    assert resp.json() == {"errors": [], "total": 0, "clusters": []}


def test_errors_ignores_success_responses(test_client: TestClient, mock_proxy_state):
    ok = _flow(id="ok", status_code=200, response_body="all good")
    mock_proxy_state.get_flows.return_value = [ok]

    resp = test_client.get("/api/scanner/errors")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


def test_errors_detects_stack_trace_and_clusters(test_client: TestClient, mock_proxy_state):
    body = 'Traceback (most recent call last):\n  File "app.py", line 10'
    f1 = _flow(id="e1", host="app.example.com", path="/a", status_code=500,
               reason="Internal Server Error", response_body=body)
    f2 = _flow(id="e2", host="app.example.com", path="/b", status_code=500,
               reason="Internal Server Error", response_body=body)
    mock_proxy_state.get_flows.return_value = [f1, f2]

    resp = test_client.get("/api/scanner/errors")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 2
    techs = {d["tech"] for e in data["errors"] for d in e["detected"]}
    assert "Python/Django" in techs

    # Both 500s on the same host collapse into a single cluster of count 2.
    assert len(data["clusters"]) == 1
    cluster = data["clusters"][0]
    assert cluster["status_code"] == 500
    assert cluster["host"] == "app.example.com"
    assert cluster["count"] == 2
    assert set(cluster["paths"]) == {"/a", "/b"}
    assert "Python/Django" in cluster["technologies"]


def test_errors_body_preview_truncated(test_client: TestClient, mock_proxy_state):
    long_body = "E" * 1000
    flow = _flow(id="big-err", status_code=502, response_body=long_body)
    mock_proxy_state.get_flows.return_value = [flow]

    resp = test_client.get("/api/scanner/errors")
    assert resp.status_code == 200
    entry = resp.json()["errors"][0]
    assert len(entry["body_preview"]) == 500
    assert entry["response_size"] == 1000


def test_errors_clusters_sorted_by_count_desc(test_client: TestClient, mock_proxy_state):
    flows = [
        _flow(id="a1", host="a.com", path="/1", status_code=500, response_body="err"),
        _flow(id="a2", host="a.com", path="/2", status_code=500, response_body="err"),
        _flow(id="b1", host="b.com", path="/1", status_code=404, response_body="nope"),
    ]
    mock_proxy_state.get_flows.return_value = flows

    resp = test_client.get("/api/scanner/errors")
    assert resp.status_code == 200
    clusters = resp.json()["clusters"]
    counts = [c["count"] for c in clusters]
    assert counts == sorted(counts, reverse=True)
    assert clusters[0]["count"] == 2
