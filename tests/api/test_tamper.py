"""
Hermetic tests for the pRoxy tamper API endpoints.

All outbound HTTP is mocked at ``api.routes.tamper._fire`` (the single helper that
performs network I/O), so these tests never touch the network or subprocesses.
ProxyState flow lookups use the ``mock_proxy_state`` fixture from conftest.

Endpoints under test:
  POST /api/tamper/injection-points  -> map injectable points (no network)
  POST /api/tamper/auto              -> generate/fire tampered variants
  POST /api/tamper/payloads          -> fire a payload list at one point
  POST /api/tamper/mass-assign       -> add hidden fields to a JSON body
"""
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient


# A deterministic stand-in for the network helper _fire().
def _fake_fire_result(status_code=200, size=100, duration_ms=10.0, body="OK"):
    return {
        "status_code": status_code,
        "duration_ms": duration_ms,
        "size": size,
        "body": body,
        "headers": {"Content-Type": "text/plain"},
    }


@pytest.mark.api
class TestInjectionPoints:
    """POST /api/tamper/injection-points — pure analysis, no network."""

    def test_query_and_header_points(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/injection-points", json={
            "method": "GET",
            "url": "https://example.com/api/users/5?id=42&q=hello",
            "headers": {"X-Custom": "abc", "Host": "example.com"},
            "body": "",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == len(data["points"])
        assert data["request"] == {"method": "GET",
                                   "url": "https://example.com/api/users/5?id=42&q=hello"}

        types = {(p["type"], p["name"]) for p in data["points"]}
        # path segments
        assert ("path", "path[0]") in types  # api
        assert ("path", "path[2]") in types  # 5
        # query params
        assert ("query", "id") in types
        assert ("query", "q") in types
        # custom header included, Host skipped
        assert ("header", "X-Custom") in types
        assert ("header", "Host") not in types

    def test_cookie_points_parsed(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/injection-points", json={
            "method": "GET",
            "url": "https://example.com/",
            "headers": {"Cookie": "sid=abc123; theme=dark"},
        })
        assert resp.status_code == 200
        points = resp.json()["points"]
        cookies = {p["name"]: p["value"] for p in points if p["type"] == "cookie"}
        assert cookies == {"sid": "abc123", "theme": "dark"}

    def test_json_body_points_nested(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/injection-points", json={
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"Content-Type": "application/json"},
            "body": '{"user": {"id": 7, "name": "bob"}, "items": [{"sku": "x"}]}',
        })
        assert resp.status_code == 200
        names = {p["name"] for p in resp.json()["points"] if p["type"] == "json"}
        # nested dict fields get dotted paths
        assert "user.id" in names
        assert "user.name" in names
        # scalar fields inside list-of-objects get index + dotted path
        assert "items[0].sku" in names

    def test_malformed_json_body_falls_back_to_raw(self, test_client: TestClient):
        """Invalid JSON must not 500 — it should be recorded as a raw body point."""
        resp = test_client.post("/api/tamper/injection-points", json={
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"Content-Type": "application/json"},
            "body": "{not valid json",
        })
        assert resp.status_code == 200
        types = {p["type"] for p in resp.json()["points"]}
        assert "body_raw" in types

    def test_form_body_points(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/injection-points", json={
            "method": "POST",
            "url": "https://example.com/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "user=alice&pass=secret",
        })
        assert resp.status_code == 200
        form = {p["name"] for p in resp.json()["points"] if p["type"] == "form"}
        assert form == {"user", "pass"}

    def test_empty_url_no_crash(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/injection-points", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["points"] == []
        assert data["count"] == 0

    def test_flow_lookup_not_found_returns_404(self, test_client: TestClient,
                                               mock_proxy_state):
        mock_proxy_state.get_flow.return_value = None
        resp = test_client.post("/api/tamper/injection-points",
                                json={"flow_id": "missing"})
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Flow not found"

    def test_flow_lookup_uses_flow_fields(self, test_client: TestClient,
                                          mock_proxy_state, sample_flow):
        mock_proxy_state.get_flow.return_value = sample_flow
        resp = test_client.post("/api/tamper/injection-points",
                                json={"flow_id": "test-flow-1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["request"]["url"] == sample_flow.url
        assert data["request"]["method"] == sample_flow.method
        mock_proxy_state.get_flow.assert_called_once_with("test-flow-1")


@pytest.mark.api
class TestAutoTamper:
    """POST /api/tamper/auto — variant generation; fires only when fire=True."""

    def test_generate_without_firing(self, test_client: TestClient):
        """fire defaults to False — no network call, variants returned directly."""
        resp = test_client.post("/api/tamper/auto", json={
            "method": "GET",
            "url": "https://example.com/api/item?id=10",
            "strategies": ["idor"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["fired"] is False
        assert data["total"] == len(data["results"])
        assert data["total"] > 0
        v = data["results"][0]
        # un-fired variants carry generation metadata
        assert v["strategy"] == "idor"
        assert "payload" in v
        assert "point_name" in v
        assert "url" in v

    def test_max_requests_caps_results(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/auto", json={
            "method": "GET",
            "url": "https://example.com/a/b/c?x=1&y=2&z=3",
            "strategies": ["idor", "type_juggle", "boundary", "sqli"],
            "max_requests": 5,
        })
        assert resp.status_code == 200
        assert resp.json()["total"] <= 5

    def test_unknown_strategy_ignored(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/auto", json={
            "method": "GET",
            "url": "https://example.com/api?id=1",
            "strategies": ["does_not_exist"],
        })
        assert resp.status_code == 200
        # No valid strategy -> no variants
        assert resp.json()["total"] == 0

    def test_target_points_filter(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/auto", json={
            "method": "GET",
            "url": "https://example.com/api?id=1&other=2",
            "strategies": ["idor"],
            "target_points": ["id"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] > 0
        assert all(r["point_name"] == "id" for r in data["results"])

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_fire_true_calls_fire_and_shapes_results(self, mock_fire,
                                                     test_client: TestClient):
        mock_fire.return_value = _fake_fire_result(status_code=403, size=55,
                                                   body="forbidden")
        resp = test_client.post("/api/tamper/auto", json={
            "method": "GET",
            "url": "https://example.com/api?id=1",
            "strategies": ["idor"],
            "fire": True,
            "max_requests": 3,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["fired"] is True
        assert mock_fire.await_count == data["total"]
        r = data["results"][0]
        assert r["response_status"] == 403
        assert r["response_size"] == 55
        assert "response_body_preview" in r
        # headers stripped from fired result rows
        assert "headers" not in r

    def test_flow_not_found_returns_404(self, test_client: TestClient,
                                        mock_proxy_state):
        mock_proxy_state.get_flow.return_value = None
        resp = test_client.post("/api/tamper/auto", json={"flow_id": "nope"})
        assert resp.status_code == 404

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_cookie_injection_does_not_crash(self, mock_fire,
                                             test_client: TestClient):
        """Regression: the cookie variant branch previously passed a stray
        kwarg to re.sub() and raised TypeError -> 500."""
        mock_fire.return_value = _fake_fire_result()
        resp = test_client.post("/api/tamper/auto", json={
            "method": "GET",
            "url": "https://example.com/",
            "headers": {"Cookie": "sid=abc; csrf=tok"},
            "strategies": ["idor"],
            "fire": True,
            "max_requests": 10,
        })
        assert resp.status_code == 200
        # at least one cookie point was tampered and fired
        assert any(r["point_type"] == "cookie" for r in resp.json()["results"])


@pytest.mark.api
class TestSwapPayloads:
    """POST /api/tamper/payloads — always fires (baseline + per payload)."""

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_success_flags_reflection_and_status_change(self, mock_fire,
                                                        test_client: TestClient):
        # baseline 200/100, then a payload-reflecting 500 response
        mock_fire.side_effect = [
            _fake_fire_result(status_code=200, size=100, body="clean"),
            _fake_fire_result(status_code=500, size=300,
                              body="<script>alert(1)</script> boom"),
        ]
        resp = test_client.post("/api/tamper/payloads", json={
            "method": "GET",
            "url": "https://example.com/api?q=test",
            "point_name": "q",
            "custom_payloads": ["<script>alert(1)</script>"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["baseline"]["status_code"] == 200
        r = data["results"][0]
        assert r["interesting"] is True
        assert any("Status changed" in a for a in r["anomalies"])
        assert "Payload reflected in response" in r["anomalies"]
        assert data["found"] == 1

    def test_missing_point_name_returns_400(self, test_client: TestClient):
        resp = test_client.post("/api/tamper/payloads", json={
            "method": "GET",
            "url": "https://example.com/api?q=test",
        })
        assert resp.status_code == 400
        assert "point_name" in resp.json()["detail"]

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_unknown_point_returns_400(self, mock_fire, test_client: TestClient):
        # baseline _fire happens before point resolution, so mock it
        mock_fire.return_value = _fake_fire_result()
        resp = test_client.post("/api/tamper/payloads", json={
            "method": "GET",
            "url": "https://example.com/api?q=test",
            "point_name": "nonexistent",
            "custom_payloads": ["x"],
        })
        assert resp.status_code == 400
        assert "not found" in resp.json()["detail"]

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_named_payload_type_used_when_no_custom(self, mock_fire,
                                                    test_client: TestClient):
        mock_fire.return_value = _fake_fire_result()
        resp = test_client.post("/api/tamper/payloads", json={
            "method": "GET",
            "url": "https://example.com/api?q=test",
            "point_name": "q",
            "payload_type": "sqli",
        })
        assert resp.status_code == 200
        data = resp.json()
        # sqli list is non-empty -> some results, plus the baseline fire
        assert data["total"] > 0
        assert mock_fire.await_count == data["total"] + 1  # +1 baseline

    def test_flow_not_found_returns_404(self, test_client: TestClient,
                                        mock_proxy_state):
        mock_proxy_state.get_flow.return_value = None
        resp = test_client.post("/api/tamper/payloads", json={
            "flow_id": "nope", "point_name": "q",
        })
        assert resp.status_code == 404


@pytest.mark.api
class TestMassAssignment:
    """POST /api/tamper/mass-assign — JSON-only, always fires."""

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_non_json_content_type_returns_error_shape(self, mock_fire,
                                                       test_client: TestClient):
        mock_fire.return_value = _fake_fire_result()
        resp = test_client.post("/api/tamper/mass-assign", json={
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"Content-Type": "text/plain"},
            "body": "hello",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["results"] == []
        assert "JSON Content-Type" in data["error"]

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_custom_fields_tested_individually(self, mock_fire,
                                               test_client: TestClient):
        mock_fire.return_value = _fake_fire_result(status_code=200, size=100)
        resp = test_client.post("/api/tamper/mass-assign", json={
            "method": "POST",
            "url": "https://example.com/api/profile",
            "headers": {"Content-Type": "application/json"},
            "body": '{"name": "bob"}',
            "custom_fields": {"is_admin": True, "role": "admin"},
        })
        assert resp.status_code == 200
        data = resp.json()
        fields = {r["field"] for r in data["results"]}
        assert fields == {"is_admin", "role"}
        assert data["total"] == 2
        # baseline + one fire per field
        assert mock_fire.await_count == 3

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_existing_field_is_skipped(self, mock_fire, test_client: TestClient):
        mock_fire.return_value = _fake_fire_result()
        resp = test_client.post("/api/tamper/mass-assign", json={
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"Content-Type": "application/json"},
            "body": '{"is_admin": false}',
            "custom_fields": {"is_admin": True, "role": "admin"},
        })
        assert resp.status_code == 200
        fields = {r["field"] for r in resp.json()["results"]}
        # is_admin already present in body -> skipped
        assert "is_admin" not in fields
        assert "role" in fields

    @patch("api.routes.tamper._fire", new_callable=AsyncMock)
    def test_interesting_requires_more_than_acceptance(self, mock_fire,
                                                       test_client: TestClient):
        # baseline 200/100; tampered also 200/100 -> only "accepted" anomaly,
        # which alone must NOT mark the field interesting (needs >1 anomaly).
        mock_fire.return_value = _fake_fire_result(status_code=200, size=100,
                                                   body="")
        resp = test_client.post("/api/tamper/mass-assign", json={
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"Content-Type": "application/json"},
            "body": "{}",
            "custom_fields": {"role": "admin"},
        })
        assert resp.status_code == 200
        data = resp.json()
        r = data["results"][0]
        assert r["interesting"] is False
        assert data["found"] == 0

    def test_flow_not_found_returns_404(self, test_client: TestClient,
                                        mock_proxy_state):
        mock_proxy_state.get_flow.return_value = None
        resp = test_client.post("/api/tamper/mass-assign", json={"flow_id": "nope"})
        assert resp.status_code == 404
