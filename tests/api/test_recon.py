"""
Hermetic tests for the recon API endpoints (api/routes/recon.py).

All external I/O is mocked:
- ProxyState.get_flows is patched via the ``mock_proxy_state`` fixture so the
  fingerprint / subdomains / schema endpoints read synthetic flows, never live
  captured traffic.
- ``httpx.AsyncClient.get`` is patched for the /discover endpoint so no real
  outbound HTTP / DNS happens (the conftest ``_block_outbound_network`` fixture
  already blocks ``httpx.AsyncClient.send`` as a safety net).
"""
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from state.models import FlowRecord


def _flow(**overrides) -> FlowRecord:
    """Build a FlowRecord with sensible defaults, overridable per-test."""
    base = dict(
        id="f-1",
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
        response_headers={},
        response_body="",
        response_content_type="",
        response_size=0,
        completed=True,
    )
    base.update(overrides)
    return FlowRecord(**base)


# ── /api/recon/fingerprint ─────────────────────────────────


@pytest.mark.api
class TestFingerprint:
    def test_fingerprint_detects_tech_from_headers_cookies_body(
        self, test_client: TestClient, mock_proxy_state
    ):
        mock_proxy_state.get_flows.return_value = [
            _flow(
                host="shop.example.com",
                path="/wp-login.php",
                response_headers={
                    "Server": "nginx/1.25",
                    "X-Powered-By": "PHP/8.2",
                    "Set-Cookie": "PHPSESSID=abc; path=/",
                    "X-Vercel-Id": "iad1::abc",
                },
                response_body="<link href='/wp-content/themes/x.css'>",
            ),
        ]

        resp = test_client.post("/api/recon/fingerprint", json={})
        assert resp.status_code == 200
        data = resp.json()

        assert data["count"] == 1
        domains = data["domains"]
        assert "shop.example.com" in domains
        cats = domains["shop.example.com"]

        # Header value signatures
        assert "Nginx" in cats["Server/Infra"]
        assert "PHP" in cats["Server/Infra"]
        # Header-presence signatures
        assert "Vercel" in cats["Infrastructure"]
        # Cookie signatures
        assert "PHP" in cats["Framework"]
        # Body signatures
        assert "WordPress" in cats["Frontend/CMS"]

        # Raw header buckets must be stripped from the public result
        assert not any(k.startswith("_raw_") for k in cats)

    def test_fingerprint_domain_filter(self, test_client: TestClient, mock_proxy_state):
        mock_proxy_state.get_flows.return_value = [
            _flow(host="a.target.com", response_headers={"Server": "nginx"}),
            _flow(host="other.com", response_headers={"Server": "apache"}),
        ]

        resp = test_client.post("/api/recon/fingerprint", json={"domain": "target.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert "a.target.com" in data["domains"]
        assert "other.com" not in data["domains"]

    def test_fingerprint_graphql_from_content_type_and_path(
        self, test_client: TestClient, mock_proxy_state
    ):
        mock_proxy_state.get_flows.return_value = [
            _flow(host="api.example.com", path="/graphql"),
        ]
        resp = test_client.post("/api/recon/fingerprint", json={})
        assert resp.status_code == 200
        cats = resp.json()["domains"]["api.example.com"]
        assert "GraphQL" in cats["API"]

    def test_fingerprint_no_flows_returns_empty(
        self, test_client: TestClient, mock_proxy_state
    ):
        mock_proxy_state.get_flows.return_value = []
        resp = test_client.post("/api/recon/fingerprint", json={})
        assert resp.status_code == 200
        assert resp.json() == {"domains": {}, "count": 0}

    def test_fingerprint_missing_body_is_unprocessable(self, test_client: TestClient):
        # endpoint declares `data: dict` body -> missing body is a 422
        resp = test_client.post("/api/recon/fingerprint")
        assert resp.status_code == 422


# ── /api/recon/subdomains ──────────────────────────────────


@pytest.mark.api
class TestSubdomains:
    def test_subdomains_collected_from_host_headers_body(
        self, test_client: TestClient, mock_proxy_state
    ):
        mock_proxy_state.get_flows.return_value = [
            _flow(
                host="www.example.com:443",
                response_headers={"Location": "https://cdn.example.com/x"},
                response_body='{"api": "https://api.example.com/v1"}',
                request_body="ref=auth.example.com",
            ),
        ]
        resp = test_client.get("/api/recon/subdomains")
        assert resp.status_code == 200
        data = resp.json()
        subs = data["subdomains"]
        # Host port is stripped, all referenced domains are picked up
        assert "www.example.com" in subs
        assert "cdn.example.com" in subs
        assert "api.example.com" in subs
        assert "auth.example.com" in subs
        assert data["count"] == len(subs)
        assert subs == sorted(subs)

    def test_subdomains_domain_filter(self, test_client: TestClient, mock_proxy_state):
        mock_proxy_state.get_flows.return_value = [
            _flow(host="a.target.com", response_body="see also b.target.com and z.other.org"),
        ]
        resp = test_client.get("/api/recon/subdomains", params={"domain": "target.com"})
        assert resp.status_code == 200
        subs = resp.json()["subdomains"]
        assert "a.target.com" in subs
        assert "b.target.com" in subs
        assert "z.other.org" not in subs

    def test_subdomains_empty(self, test_client: TestClient, mock_proxy_state):
        mock_proxy_state.get_flows.return_value = []
        resp = test_client.get("/api/recon/subdomains")
        assert resp.status_code == 200
        assert resp.json() == {"subdomains": [], "count": 0}


# ── /api/recon/discover ────────────────────────────────────


@pytest.mark.api
class TestDiscover:
    def _mock_response(self, status_code=200, content=b"ok", headers=None):
        resp = AsyncMock()
        resp.status_code = status_code
        resp.content = content
        resp.headers = headers or {}
        return resp

    def test_discover_success_marks_interesting(self, test_client: TestClient):
        # 200 -> interesting, 404 -> not interesting
        responses = {
            "https://t.example.com/admin": self._mock_response(200, b"hello"),
            "https://t.example.com/missing": self._mock_response(
                404, b"nope", {"content-type": "text/html"}
            ),
        }

        async def fake_get(self, url, headers=None):
            return responses[url]

        with patch("httpx.AsyncClient.get", new=fake_get):
            resp = test_client.post(
                "/api/recon/discover",
                json={
                    "base_url": "https://t.example.com/",
                    "wordlist": ["admin", "missing"],
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["found"] == 1

        by_path = {r["path"]: r for r in data["results"]}
        assert by_path["admin"]["status_code"] == 200
        assert by_path["admin"]["interesting"] is True
        assert by_path["admin"]["size"] == len(b"hello")
        assert by_path["missing"]["status_code"] == 404
        assert by_path["missing"]["interesting"] is False
        assert by_path["missing"]["content_type"] == "text/html"

        assert len(data["interesting"]) == 1
        assert data["interesting"][0]["path"] == "admin"

    def test_discover_handles_request_errors_per_path(self, test_client: TestClient):
        async def boom(self, url, headers=None):
            raise RuntimeError("connection refused")

        with patch("httpx.AsyncClient.get", new=boom):
            resp = test_client.post(
                "/api/recon/discover",
                json={"base_url": "https://t.example.com/", "wordlist": ["admin"]},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["found"] == 0
        result = data["results"][0]
        assert result["status_code"] == 0
        assert "connection refused" in result["error"]
        assert result["interesting"] is False

    def test_discover_max_probes_caps_wordlist(self, test_client: TestClient):
        calls = []

        async def fake_get(self, url, headers=None):
            calls.append(url)
            return TestDiscover()._mock_response(200, b"x")

        wordlist = [f"p{i}" for i in range(10)]
        with patch("httpx.AsyncClient.get", new=fake_get):
            resp = test_client.post(
                "/api/recon/discover",
                json={
                    "base_url": "https://t.example.com/",
                    "wordlist": wordlist,
                    "max_probes": 3,
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(calls) == 3

    def test_discover_normalizes_base_url(self, test_client: TestClient):
        seen = []

        async def fake_get(self, url, headers=None):
            seen.append(url)
            return TestDiscover()._mock_response(200, b"x")

        with patch("httpx.AsyncClient.get", new=fake_get):
            # base_url without trailing slash and with a path segment
            resp = test_client.post(
                "/api/recon/discover",
                json={"base_url": "https://t.example.com/app/index.html", "wordlist": ["admin"]},
            )

        assert resp.status_code == 200
        assert seen == ["https://t.example.com/app/admin"]

    def test_discover_missing_base_url_is_400(self, test_client: TestClient):
        resp = test_client.post("/api/recon/discover", json={})
        assert resp.status_code == 400
        assert "base_url" in resp.json()["detail"]


# ── /api/recon/schema ──────────────────────────────────────


@pytest.mark.api
class TestSchema:
    def test_schema_groups_and_generalizes_paths(
        self, test_client: TestClient, mock_proxy_state
    ):
        mock_proxy_state.get_flows.return_value = [
            _flow(
                host="api.example.com",
                method="GET",
                path="/users/42?expand=profile",
                status_code=200,
                request_content_type="",
                response_content_type="application/json",
                response_body='{"id": 42}',
            ),
            _flow(
                host="api.example.com",
                method="GET",
                path="/users/7",
                status_code=404,
                response_content_type="application/json",
            ),
            _flow(
                host="api.example.com",
                method="POST",
                path="/users/42",
                status_code=201,
                request_content_type="application/json",
                request_body='{"name": "x"}',
            ),
        ]

        resp = test_client.get("/api/recon/schema")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        ep = data["endpoints"][0]

        assert ep["host"] == "api.example.com"
        assert ep["path"] == "/users/{id}"
        assert "/users/42" in ep["original_paths"]
        assert "/users/7" in ep["original_paths"]

        methods = ep["methods"]
        assert set(methods) == {"GET", "POST"}
        # GET seen twice (200 + 404)
        assert methods["GET"]["count"] == 2
        assert methods["GET"]["status_codes"] == {"200": 1, "404": 1}
        # query params extracted and JSON-serialized as a list
        assert "expand" in methods["GET"]["query_params"]
        assert isinstance(methods["GET"]["query_params"], list)
        # content types serialized as lists
        assert methods["GET"]["response_content_types"] == ["application/json"]
        # sample bodies captured
        assert methods["GET"]["sample_response_body"] == '{"id": 42}'
        assert methods["POST"]["count"] == 1
        assert methods["POST"]["status_codes"] == {"201": 1}
        assert methods["POST"]["sample_request_body"] == '{"name": "x"}'

    def test_schema_uuid_and_objectid_placeholders(
        self, test_client: TestClient, mock_proxy_state
    ):
        mock_proxy_state.get_flows.return_value = [
            _flow(
                host="api.example.com",
                path="/orders/550e8400-e29b-41d4-a716-446655440000",
            ),
            _flow(
                host="api.example.com",
                path="/docs/507f1f77bcf86cd799439011",
            ),
        ]
        resp = test_client.get("/api/recon/schema")
        assert resp.status_code == 200
        paths = {ep["path"] for ep in resp.json()["endpoints"]}
        assert "/orders/{uuid}" in paths
        assert "/docs/{objectId}" in paths

    def test_schema_skips_websocket_flows(
        self, test_client: TestClient, mock_proxy_state
    ):
        mock_proxy_state.get_flows.return_value = [
            _flow(host="api.example.com", path="/ws", flow_type="websocket"),
        ]
        resp = test_client.get("/api/recon/schema")
        assert resp.status_code == 200
        assert resp.json() == {"endpoints": [], "count": 0}

    def test_schema_domain_filter(self, test_client: TestClient, mock_proxy_state):
        mock_proxy_state.get_flows.return_value = [
            _flow(host="api.target.com", path="/a"),
            _flow(host="api.other.com", path="/b"),
        ]
        resp = test_client.get("/api/recon/schema", params={"domain": "target.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["endpoints"][0]["host"] == "api.target.com"

    def test_schema_empty(self, test_client: TestClient, mock_proxy_state):
        mock_proxy_state.get_flows.return_value = []
        resp = test_client.get("/api/recon/schema")
        assert resp.status_code == 200
        assert resp.json() == {"endpoints": [], "count": 0}
