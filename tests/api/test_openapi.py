"""Tests for the OpenAPI spec generation route."""
import pytest
from fastapi.testclient import TestClient

from state.models import FlowRecord


def _flow(method, path, host="api.example.com", req="", rct="", body="",
          sc=200, resp_ct="application/json", flow_type="http"):
    return FlowRecord(
        id=f"{method}-{path}-{sc}-{len(req)}-{len(body)}", timestamp=1.0,
        method=method, scheme="https", host=host, port=443, path=path,
        url=f"https://{host}{path}", request_body=req, request_content_type=rct,
        status_code=sc, reason="OK", response_body=body,
        response_content_type=resp_ct, flow_type=flow_type,
    )


@pytest.fixture
def sample_flows():
    return [
        _flow("GET", "/api/users?page=1", body='[{"id":1,"name":"a"}]'),
        _flow("GET", "/api/users/42", body='{"id":42,"name":"bob","active":true}'),
        _flow("GET", "/api/users/99", body='{"id":99,"name":"sue"}'),  # no 'active'
        _flow("POST", "/api/users", req='{"name":"new","age":30}',
              rct="application/json", body='{"id":100}', sc=201),
        _flow("GET", "/api/users/42/posts/7", body='{"postId":7,"title":"hi"}'),
        _flow("GET", "/other", host="cdn.other.com", body='{"x":1}'),  # different host
        _flow("GET", "/ws", flow_type="websocket"),  # should be skipped
    ]


@pytest.mark.api
class TestOpenAPISpec:
    def test_spec_is_openapi_3(self, test_client: TestClient, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        assert spec["openapi"].startswith("3.0")
        assert "paths" in spec and spec["paths"]
        assert spec["info"]["title"]

    def test_path_templating_numeric_id(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec?domain=api.example.com").json()
        assert "/api/users/{userId}" in spec["paths"]
        params = spec["paths"]["/api/users/{userId}"]["get"]["parameters"]
        path_params = [p for p in params if p["in"] == "path"]
        assert path_params[0]["name"] == "userId"
        assert path_params[0]["schema"]["type"] == "integer"
        assert path_params[0]["required"] is True

    def test_nested_params_are_unique(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        assert "/api/users/{userId}/posts/{postId}" in spec["paths"]
        names = [p["name"] for p in
                 spec["paths"]["/api/users/{userId}/posts/{postId}"]["get"]["parameters"]
                 if p["in"] == "path"]
        assert names == ["userId", "postId"]
        assert len(names) == len(set(names))  # unique

    def test_query_params_extracted(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        q = [p["name"] for p in spec["paths"]["/api/users"]["get"]["parameters"]
             if p["in"] == "query"]
        assert "page" in q

    def test_request_body_schema_inferred(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        schema = spec["paths"]["/api/users"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        assert schema["type"] == "object"
        assert schema["properties"]["name"]["type"] == "string"
        assert schema["properties"]["age"]["type"] == "integer"

    def test_required_merged_across_samples(self, test_client, mock_proxy_state, sample_flows):
        # 'active' appears in only one of the two GET /users/{id} responses -> not required
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        schema = spec["paths"]["/api/users/{userId}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        assert set(schema["required"]) == {"id", "name"}
        assert "active" in schema["properties"]  # present, just not required

    def test_status_codes_preserved(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        assert "201" in spec["paths"]["/api/users"]["post"]["responses"]

    def test_examples_off_by_default(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        media = spec["paths"]["/api/users"]["post"]["requestBody"]["content"]["application/json"]
        assert "example" not in media

    def test_examples_included_when_opted_in(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec?include_examples=true").json()
        media = spec["paths"]["/api/users"]["post"]["requestBody"]["content"]["application/json"]
        assert media["example"] == {"name": "new", "age": 30}

    def test_domain_filter_excludes_other_hosts(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec?domain=api.example.com").json()
        assert "/other" not in spec["paths"]

    def test_websocket_flows_skipped(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec").json()
        assert "/ws" not in spec["paths"]

    def test_servers_derived(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        spec = test_client.get("/api/openapi/spec?domain=api.example.com").json()
        assert {"url": "https://api.example.com"} in spec["servers"]

    def test_yaml_format(self, test_client, mock_proxy_state, sample_flows):
        import yaml
        mock_proxy_state.get_flows.return_value = sample_flows
        resp = test_client.get("/api/openapi/spec?domain=api.example.com&format=yaml")
        assert resp.status_code == 200
        assert "yaml" in resp.headers["content-type"]
        spec = yaml.safe_load(resp.text)  # valid YAML that round-trips to the spec
        assert spec["openapi"] == "3.0.3"
        assert "/api/users/{userId}" in spec["paths"]


@pytest.mark.api
class TestOpenAPIEndpoints:
    def test_endpoints_listing(self, test_client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        data = test_client.get("/api/openapi/endpoints?domain=api.example.com").json()
        assert data["count"] >= 3
        paths = {(e["method"], e["path"]) for e in data["endpoints"]}
        assert ("POST", "/api/users") in paths
        assert ("GET", "/api/users/{userId}") in paths

    def test_endpoints_empty_when_no_flows(self, test_client, mock_proxy_state):
        mock_proxy_state.get_flows.return_value = []
        data = test_client.get("/api/openapi/endpoints").json()
        assert data == {"endpoints": [], "count": 0}
