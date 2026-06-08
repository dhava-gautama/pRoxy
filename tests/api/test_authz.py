"""Tests for the Authorization / IDOR tester route (api/routes/authz.py).

The router is not yet registered in the main app, so these tests mount it on a
standalone FastAPI app. The network (replay's ``_do_request``) is fully mocked.
"""
import pytest
import httpx
from unittest.mock import patch, AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import authz


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(authz.router)
    return TestClient(app)


def _resp(status, body, duration=10.0):
    """Build a canned _do_request return value."""
    return {
        "id": "replay-1",
        "status_code": status,
        "reason": "OK",
        "headers": {"Content-Type": "application/json"},
        "body": body,
        "duration_ms": duration,
    }


def test_identical_success_is_flagged(client):
    # Two profiles get 2xx responses of the same length -> low-priv is flagged.
    side = [
        _resp(200, '{"account": "12345", "secret": "AAAA"}'),  # baseline
        _resp(200, '{"account": "12345", "secret": "BBBB"}'),  # low-priv (same length)
    ]
    with patch("api.routes.authz._do_request", new=AsyncMock(side_effect=side)):
        r = client.post("/api/authz/test", json={
            "method": "GET",
            "url": "https://api.example.com/account",
            "headers": {"Accept": "application/json"},
            "profiles": [
                {"name": "admin", "headers": {"Authorization": "Bearer ADMIN"}},
                {"name": "low", "headers": {"Authorization": "Bearer LOW"}},
            ],
            "baseline": "admin",
        })
    assert r.status_code == 200
    data = r.json()
    assert data["baseline"] == "admin"
    assert data["flagged"] == ["low"]
    assert "broken access control" in data["analysis"].lower()
    assert len(data["results"]) == 2


def test_different_status_not_flagged(client):
    # Low-priv profile is properly denied (403) -> NOT flagged.
    side = [
        _resp(200, '{"account": "12345", "secret": "AAAA"}'),  # baseline 2xx
        _resp(403, '{"error": "forbidden"}'),                  # low-priv denied
    ]
    with patch("api.routes.authz._do_request", new=AsyncMock(side_effect=side)):
        r = client.post("/api/authz/test", json={
            "url": "https://api.example.com/account",
            "profiles": [
                {"name": "admin", "headers": {"Authorization": "Bearer ADMIN"}},
                {"name": "low", "headers": {"Authorization": "Bearer LOW"}},
            ],
            "baseline": "admin",
        })
    assert r.status_code == 200
    data = r.json()
    assert data["flagged"] == []
    assert data["results"][1]["status_code"] == 403


def test_different_length_not_flagged(client):
    # Both 2xx but the bodies differ wildly in size -> NOT flagged.
    side = [
        _resp(200, "x" * 1000),  # baseline
        _resp(200, "x" * 10),    # very different length
    ]
    with patch("api.routes.authz._do_request", new=AsyncMock(side_effect=side)):
        r = client.post("/api/authz/test", json={
            "url": "https://api.example.com/account",
            "profiles": [
                {"name": "admin", "headers": {}},
                {"name": "low", "headers": {}},
            ],
            "baseline": "admin",
        })
    assert r.status_code == 200
    assert r.json()["flagged"] == []


def test_do_request_called_once_per_profile_with_merged_headers(client):
    side = [_resp(200, "same-body"), _resp(200, "same-body")]
    mock = AsyncMock(side_effect=side)
    with patch("api.routes.authz._do_request", new=mock):
        r = client.post("/api/authz/test", json={
            "method": "GET",
            "url": "https://api.example.com/account",
            "headers": {"Accept": "application/json", "Authorization": "Bearer BASE"},
            "body": "payload",
            "profiles": [
                {"name": "admin", "headers": {"Authorization": "Bearer ADMIN"}},
                {"name": "low", "headers": {"X-Extra": "1"}},
            ],
            "baseline": "admin",
        })
    assert r.status_code == 200
    assert mock.await_count == 2

    # First call: admin overrides Authorization, keeps Accept.
    call1 = mock.await_args_list[0].args
    assert call1[0] == "GET"
    assert call1[1] == "https://api.example.com/account"
    assert call1[2] == {"Accept": "application/json", "Authorization": "Bearer ADMIN"}
    assert call1[3] == "payload"

    # Second call: low keeps base Authorization, adds X-Extra.
    call2 = mock.await_args_list[1].args
    assert call2[2] == {"Accept": "application/json", "Authorization": "Bearer BASE", "X-Extra": "1"}


def test_missing_url_and_no_flow_returns_400(client):
    with patch("api.routes.authz._do_request", new=AsyncMock()):
        r = client.post("/api/authz/test", json={
            "profiles": [{"name": "a", "headers": {}}],
        })
    assert r.status_code == 400


def test_empty_profiles_returns_400(client):
    with patch("api.routes.authz._do_request", new=AsyncMock()):
        r = client.post("/api/authz/test", json={
            "url": "https://api.example.com/account",
            "profiles": [],
        })
    assert r.status_code == 400


def test_request_error_recorded_no_500(client):
    # One profile's request raises RequestError -> recorded as error, no 500.
    side = [
        _resp(200, "baseline-body"),
        httpx.RequestError("connection refused"),
    ]
    with patch("api.routes.authz._do_request", new=AsyncMock(side_effect=side)):
        r = client.post("/api/authz/test", json={
            "url": "https://api.example.com/account",
            "profiles": [
                {"name": "admin", "headers": {}},
                {"name": "broken", "headers": {}},
            ],
            "baseline": "admin",
        })
    assert r.status_code == 200
    data = r.json()
    broken = data["results"][1]
    assert broken["name"] == "broken"
    assert broken["status_code"] is None
    assert broken["error"] == "connection refused"
    # An errored profile cannot be flagged.
    assert "broken" not in data["flagged"]


def test_baseline_defaults_to_first_when_unnamed(client):
    side = [_resp(200, "same"), _resp(200, "same")]
    with patch("api.routes.authz._do_request", new=AsyncMock(side_effect=side)):
        r = client.post("/api/authz/test", json={
            "url": "https://api.example.com/account",
            "profiles": [
                {"name": "first", "headers": {}},
                {"name": "second", "headers": {}},
            ],
        })
    assert r.status_code == 200
    data = r.json()
    assert data["baseline"] == "first"
    assert data["flagged"] == ["second"]
