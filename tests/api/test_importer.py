"""Tests for the HAR / flow import route (api/routes/importer.py).

The importer router is not yet registered in server.py, so these tests build a
standalone app rather than using the global ``test_client`` fixture. The
``mock_proxy_state`` fixture (from conftest) patches the live ProxyState
singleton, so ``state.store_flow`` is the mock and ``state.traffic_queue`` is the
real queue.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import importer
from state.models import FlowRecord


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(importer.router)
    return TestClient(app)


def _har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def _har_entry(method="GET", url="https://api.example.com/users/42?page=1",
               status=200, status_text="OK", req_body="", req_mime="",
               resp_body='{"id": 42}', resp_mime="application/json",
               started="2024-01-02T03:04:05.000Z"):
    return {
        "startedDateTime": started,
        "request": {
            "method": method,
            "url": url,
            "headers": [{"name": "Accept", "value": "application/json"}],
            "postData": {"mimeType": req_mime, "text": req_body} if req_body or req_mime else {},
        },
        "response": {
            "status": status,
            "statusText": status_text,
            "headers": [{"name": "Content-Type", "value": resp_mime}],
            "content": {"mimeType": resp_mime, "text": resp_body},
        },
    }


def _stored_flows(mock_proxy_state):
    """Return the FlowRecord objects passed to store_flow."""
    return [call.args[0] for call in mock_proxy_state.store_flow.call_args_list]


@pytest.mark.api
class TestHARImport:
    def test_imports_har_entries(self, client, mock_proxy_state):
        body = _har([
            _har_entry(method="GET", url="https://api.example.com/users/42",
                       status=200),
            _har_entry(method="POST", url="https://api.example.com/users",
                       status=201, status_text="Created",
                       req_body='{"name": "new"}', req_mime="application/json",
                       resp_body='{"id": 100}'),
        ])
        resp = client.post("/api/import/har", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported"] == 2
        assert data["errors"] == []

        flows = _stored_flows(mock_proxy_state)
        assert len(flows) == 2
        assert all(isinstance(f, FlowRecord) for f in flows)

        get_flow = flows[0]
        assert get_flow.method == "GET"
        assert get_flow.url == "https://api.example.com/users/42"
        assert get_flow.status_code == 200
        assert get_flow.host == "api.example.com"
        assert get_flow.scheme == "https"
        assert get_flow.port == 443
        assert get_flow.reason == "OK"

        post_flow = flows[1]
        assert post_flow.method == "POST"
        assert post_flow.url == "https://api.example.com/users"
        assert post_flow.status_code == 201
        assert post_flow.request_body == '{"name": "new"}'
        assert post_flow.request_content_type == "application/json"
        assert post_flow.response_body == '{"id": 100}'

    def test_har_parses_timestamp(self, client, mock_proxy_state):
        resp = client.post("/api/import/har", json=_har([_har_entry()]))
        assert resp.status_code == 200
        flow = _stored_flows(mock_proxy_state)[0]
        assert flow.timestamp > 0  # ISO startedDateTime parsed to epoch

    def test_har_pushes_to_traffic_queue(self, client, mock_proxy_state):
        # traffic_queue is the real queue (not mocked); draining it confirms push.
        before = importer.state.traffic_queue.qsize()
        client.post("/api/import/har", json=_har([_har_entry()]))
        assert importer.state.traffic_queue.qsize() == before + 1

    def test_malformed_entry_counted_not_crashing(self, client, mock_proxy_state):
        body = _har([
            _har_entry(method="GET", url="https://api.example.com/ok"),
            "not-an-object",  # malformed entry (not a dict)
            {"request": {"url": "https://api.example.com/bad"},
             "response": {"status": "not-a-number"}},  # status uncoercible -> mapping error
        ])
        resp = client.post("/api/import/har", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported"] == 1
        assert len(data["errors"]) == 2
        assert all(isinstance(e, str) for e in data["errors"])


@pytest.mark.api
class TestFlowListImport:
    def test_imports_bare_flow_list(self, client, mock_proxy_state):
        body = [
            {"id": "f1", "timestamp": 1.0, "method": "GET",
             "url": "https://x.com/a", "status_code": 200},
            {"id": "f2", "timestamp": 2.0, "method": "POST",
             "url": "https://x.com/b", "status_code": 500},
        ]
        resp = client.post("/api/import/har", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported"] == 2
        assert data["errors"] == []
        flows = _stored_flows(mock_proxy_state)
        assert {f.id for f in flows} == {"f1", "f2"}
        assert flows[1].status_code == 500

    def test_imports_flows_key(self, client, mock_proxy_state):
        body = {"flows": [{"id": "g1", "timestamp": 0.0, "method": "GET",
                           "url": "https://y.com/"}]}
        resp = client.post("/api/import/har", json=body)
        assert resp.status_code == 200
        assert resp.json()["imported"] == 1

    def test_flow_defaults_id_and_timestamp(self, client, mock_proxy_state):
        body = [{"method": "GET", "url": "https://z.com/"}]  # no id/timestamp
        resp = client.post("/api/import/har", json=body)
        assert resp.status_code == 200
        assert resp.json()["imported"] == 1
        flow = _stored_flows(mock_proxy_state)[0]
        assert flow.id == "import-0"

    def test_bad_flow_counted_in_errors(self, client, mock_proxy_state):
        body = [
            {"id": "good", "timestamp": 0.0, "method": "GET", "url": "https://ok.com/"},
            {"id": "bad", "timestamp": "not-a-float"},  # invalid type for timestamp
        ]
        resp = client.post("/api/import/har", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["imported"] == 1
        assert len(data["errors"]) == 1


@pytest.mark.api
class TestInvalidInput:
    def test_empty_list_400(self, client, mock_proxy_state):
        resp = client.post("/api/import/har", json=[])
        assert resp.status_code == 400

    def test_unrecognized_dict_400(self, client, mock_proxy_state):
        resp = client.post("/api/import/har", json={"something": "else"})
        assert resp.status_code == 400

    def test_har_entries_not_a_list_400(self, client, mock_proxy_state):
        resp = client.post("/api/import/har", json={"log": {"entries": "nope"}})
        assert resp.status_code == 400
