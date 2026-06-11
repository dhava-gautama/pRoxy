"""Tests for system control endpoints."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import system


@pytest.fixture
def client(monkeypatch):
    # Capture the scheduled re-exec instead of actually replacing the process.
    calls = {}

    class FakeTimer:
        def __init__(self, delay, fn):
            calls["delay"], calls["fn"] = delay, fn

        def start(self):
            calls["started"] = True

    monkeypatch.setattr(system.threading, "Timer", FakeTimer)
    app = FastAPI()
    app.include_router(system.router)
    c = TestClient(app)
    c.calls = calls
    return c


@pytest.mark.api
class TestSystemRestart:
    def test_restart_schedules_reexec_without_executing(self, client):
        r = client.post("/api/system/restart")
        assert r.status_code == 200
        assert r.json()["restarting"] is True
        # The re-exec was scheduled (and would have replaced the process) but not run.
        assert client.calls.get("started") is True
        assert client.calls.get("fn") is system._reexec
        assert client.calls.get("delay") > 0
