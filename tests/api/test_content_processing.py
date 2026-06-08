"""
Hermetic tests for the pRoxy content-processing API endpoints.

Standalone app: we build a fresh ``FastAPI()`` and mount only the
content_processing router, so these tests are isolated from the full server.
The ``mock_proxy_state`` fixture (conftest) patches the live ProxyState
singleton the route module holds.

Regression coverage for two fixed bugs:
  1. create/update/delete/toggle previously did
     ``if hasattr(state, 'proxy_addon'):`` which is ALWAYS true (proxy_addon
     is initialised to None) -> None.update_content_processors(...) -> 500.
  2. POST /api/content/analyze took ``content``/``content_type`` as QUERY
     params, so JSON-body callers got 422. It now accepts a Pydantic body.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import content_processing


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(content_processing.router)
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_processor_store():
    """Keep the module-global processor dict isolated per test."""
    content_processing._content_processors.clear()
    yield
    content_processing._content_processors.clear()


class TestProcessorCrudDoesNotCrash:
    """proxy_addon is None in tests; CRUD must NOT call None.update_*()."""

    def _make(self, client):
        resp = client.post("/api/content/processors", json={
            "id": "ignored",
            "name": "JSON beautify",
            "processors": ["parse_json", "beautify_json"],
        })
        return resp

    def test_create_returns_200_not_500(self, client, mock_proxy_state):
        resp = self._make(client)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["name"] == "JSON beautify"
        assert body["id"].startswith("proc_")

    def test_update_returns_200_not_500(self, client, mock_proxy_state):
        pid = self._make(client).json()["id"]
        resp = client.put(f"/api/content/processors/{pid}", json={
            "id": pid,
            "name": "renamed",
            "processors": ["parse_json"],
        })
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "renamed"

    def test_toggle_returns_200_not_500(self, client, mock_proxy_state):
        pid = self._make(client).json()["id"]
        resp = client.post(f"/api/content/processors/{pid}/toggle")
        assert resp.status_code == 200, resp.text
        assert resp.json()["enabled"] is False

    def test_delete_returns_200_not_500(self, client, mock_proxy_state):
        pid = self._make(client).json()["id"]
        resp = client.delete(f"/api/content/processors/{pid}")
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"message": "Processor deleted"}


class TestAnalyzeAcceptsJsonBody:
    """POST /api/content/analyze must accept a JSON body, not query params."""

    def test_json_body_ok(self, client):
        resp = client.post("/api/content/analyze", json={
            "content": '{"a": 1, "b": 2}',
            "content_type": "application/json",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        # Response shape must be unchanged (ContentAnalysis fields).
        assert data["content_type"] == "application/json"
        assert "json" in data["detected_formats"]
        assert set(["encoding", "size", "is_compressed", "compression_type",
                    "detected_formats", "extracted_data", "security_issues",
                    "performance_hints"]).issubset(data.keys())

    def test_default_content_type(self, client):
        resp = client.post("/api/content/analyze", json={"content": "hello"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["content_type"] == "text/plain"

    def test_missing_content_is_422(self, client):
        resp = client.post("/api/content/analyze", json={})
        assert resp.status_code == 422
