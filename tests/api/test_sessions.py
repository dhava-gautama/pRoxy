"""Tests for the save/load capture sessions route."""
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import sessions
from state.models import FlowRecord


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(sessions, "SESSIONS_DIR", tmp_path)
    app = FastAPI()
    app.include_router(sessions.router)
    return TestClient(app)


def _flow(i):
    return FlowRecord(
        id=f"flow-{i}", timestamp=float(i), method="GET", scheme="https",
        host="example.com", port=443, path=f"/api/{i}",
        url=f"https://example.com/api/{i}", status_code=200, reason="OK",
        response_body='{"ok": true}', response_content_type="application/json",
    )


@pytest.fixture
def sample_flows():
    return [_flow(1), _flow(2), _flow(3)]


@pytest.mark.api
class TestSessionsSave:
    def test_save_writes_file_and_returns_count(self, client, tmp_path, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        resp = client.post("/api/sessions/save", json={"name": "snap1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"name": "snap1", "count": 3}

        path = tmp_path / "snap1.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) == 3
        assert data[0]["id"] == "flow-1"

    def test_save_then_list_shows_session(self, client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        client.post("/api/sessions/save", json={"name": "snap1"})

        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        listing = resp.json()
        assert len(listing) == 1
        entry = listing[0]
        assert entry["name"] == "snap1"
        assert entry["count"] == 3
        assert entry["size_bytes"] > 0
        assert "modified" in entry


@pytest.mark.api
class TestSessionsList:
    def test_list_empty_when_none(self, client, mock_proxy_state):
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        assert resp.json() == []


@pytest.mark.api
class TestSessionsLoad:
    def test_load_reads_back_and_stores_each_flow(self, client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        client.post("/api/sessions/save", json={"name": "snap1"})

        resp = client.post("/api/sessions/load", json={"name": "snap1", "clear": True})
        assert resp.status_code == 200
        assert resp.json() == {"loaded": 3}

        mock_proxy_state.clear_flows.assert_called_once()
        assert mock_proxy_state.store_flow.call_count == 3
        stored = [c.args[0] for c in mock_proxy_state.store_flow.call_args_list]
        assert all(isinstance(f, FlowRecord) for f in stored)
        assert {f.id for f in stored} == {"flow-1", "flow-2", "flow-3"}

    def test_load_without_clear_does_not_clear(self, client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        client.post("/api/sessions/save", json={"name": "snap1"})

        resp = client.post("/api/sessions/load", json={"name": "snap1", "clear": False})
        assert resp.status_code == 200
        mock_proxy_state.clear_flows.assert_not_called()
        assert mock_proxy_state.store_flow.call_count == 3

    def test_load_skips_bad_entries(self, client, tmp_path, mock_proxy_state):
        path = tmp_path / "mixed.json"
        path.write_text(json.dumps([
            _flow(1).model_dump(),
            {"not": "a valid flow"},  # missing required id/timestamp
            _flow(2).model_dump(),
        ]))
        resp = client.post("/api/sessions/load", json={"name": "mixed"})
        assert resp.status_code == 200
        assert resp.json() == {"loaded": 2}
        assert mock_proxy_state.store_flow.call_count == 2

    def test_load_missing_returns_404(self, client, mock_proxy_state):
        resp = client.post("/api/sessions/load", json={"name": "nope"})
        assert resp.status_code == 404


@pytest.mark.api
class TestSessionsDelete:
    def test_delete_removes_file(self, client, tmp_path, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        client.post("/api/sessions/save", json={"name": "snap1"})
        assert (tmp_path / "snap1.json").exists()

        resp = client.delete("/api/sessions/snap1")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        assert not (tmp_path / "snap1.json").exists()

    def test_delete_missing_returns_404(self, client, mock_proxy_state):
        resp = client.delete("/api/sessions/nope")
        assert resp.status_code == 404


@pytest.mark.api
class TestSessionsSecurity:
    def test_save_path_traversal_rejected(self, client, mock_proxy_state, sample_flows):
        mock_proxy_state.get_flows.return_value = sample_flows
        resp = client.post("/api/sessions/save", json={"name": "../evil"})
        assert resp.status_code == 400

    def test_load_path_traversal_rejected(self, client, mock_proxy_state):
        resp = client.post("/api/sessions/load", json={"name": "../evil"})
        assert resp.status_code == 400
