"""Hermetic tests for the parallel-proxy manager route (api/routes/proxy_manager.py).

The route's only real side effect is ``_start_proxy_thread``, which imports
``proxy.engine`` and spawns OS threads / binds ports. Every test patches that
function with a fake thread, so nothing real is started, no port is bound, and
no network is touched. Module-level instance state is reset per test.
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import api.routes.proxy_manager as pm


@pytest.fixture(autouse=True)
def _reset_pm_state():
    """Isolate module-level instance/thread registries between tests."""
    pm._proxy_instances.clear()
    pm._proxy_threads.clear()
    pm._next_instance_id = 1
    yield
    pm._proxy_instances.clear()
    pm._proxy_threads.clear()
    pm._next_instance_id = 1


@pytest.fixture
def mock_thread():
    """Patch _start_proxy_thread so no real proxy thread is created."""
    fake = MagicMock()
    fake.name = "fake-proxy-thread"
    with patch.object(pm, "_start_proxy_thread", return_value=fake) as m:
        yield m


@pytest.mark.api
class TestProxyManagerStatus:
    def test_status_empty(self, test_client: TestClient):
        resp = test_client.get("/api/proxy-manager/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_instances"] == 0
        assert data["running_instances"] == 0
        assert data["stopped_instances"] == 0
        assert data["error_instances"] == 0
        assert data["instances"] == []
        assert data["dashboard_url"] == "http://localhost:8081"
        assert data["unified_logging"] is True

    def test_status_counts_by_state(self, test_client: TestClient, mock_thread):
        test_client.post("/api/proxy-manager/instances", json={"mode": "regular", "listen_port": 18080})
        test_client.post("/api/proxy-manager/instances", json={"mode": "socks", "listen_port": 11080})
        # Stop one so we get a mix of running/stopped.
        test_client.delete("/api/proxy-manager/instances/regular_1")

        resp = test_client.get("/api/proxy-manager/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_instances"] == 2
        assert data["running_instances"] == 1
        assert data["stopped_instances"] == 1


@pytest.mark.api
class TestProxyManagerInstances:
    def test_list_empty(self, test_client: TestClient):
        resp = test_client.get("/api/proxy-manager/instances")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_start_instance(self, test_client: TestClient, mock_thread):
        resp = test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "regular", "listen_port": 18080},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "regular_1"
        assert data["mode"] == "regular"
        assert data["status"] == "running"
        assert data["listen_port"] == 18080
        assert data["thread_id"] == "fake-proxy-thread"
        # The real thread starter was used (mocked), not a real one.
        mock_thread.assert_called_once()

    def test_start_instance_auto_port(self, test_client: TestClient, mock_thread):
        resp = test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "socks"},  # no listen_port -> auto-assign default 1080
        )
        assert resp.status_code == 200
        assert resp.json()["listen_port"] == 1080

    def test_start_instance_no_auto_start(self, test_client: TestClient, mock_thread):
        resp = test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "regular", "listen_port": 18081, "auto_start": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "starting"
        # Without auto_start, no thread is created at all.
        mock_thread.assert_not_called()

    def test_start_reverse_requires_target_url_422(self, test_client: TestClient):
        resp = test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "reverse", "listen_port": 18443},
        )
        assert resp.status_code == 422

    def test_start_reverse_with_target_url(self, test_client: TestClient, mock_thread):
        resp = test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "reverse", "listen_port": 18443, "target_url": "https://example.com"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "reverse"
        assert data["target_url"] == "https://example.com"
        assert data["status"] == "running"

    def test_start_port_conflict_400(self, test_client: TestClient, mock_thread):
        first = test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "regular", "listen_port": 18080},
        )
        assert first.status_code == 200
        dup = test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "socks", "listen_port": 18080},
        )
        assert dup.status_code == 400
        assert "already in use" in dup.json()["detail"]

    def test_start_thread_failure_500(self, test_client: TestClient):
        with patch.object(pm, "_start_proxy_thread", side_effect=RuntimeError("boom")):
            resp = test_client.post(
                "/api/proxy-manager/instances",
                json={"mode": "regular", "listen_port": 18082},
            )
        assert resp.status_code == 500
        assert "Failed to start" in resp.json()["detail"]
        # Instance was recorded with error status before raising.
        instance = pm._proxy_instances["regular_1"]
        assert instance.status == "error"
        assert instance.config["error"] == "boom"

    def test_stop_instance(self, test_client: TestClient, mock_thread):
        test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "regular", "listen_port": 18080},
        )
        resp = test_client.delete("/api/proxy-manager/instances/regular_1")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Proxy instance regular_1 stopped"}
        assert pm._proxy_instances["regular_1"].status == "stopped"
        assert "regular_1" not in pm._proxy_threads

    def test_stop_missing_instance_404(self, test_client: TestClient):
        resp = test_client.delete("/api/proxy-manager/instances/nope")
        assert resp.status_code == 404

    def test_restart_instance(self, test_client: TestClient, mock_thread):
        test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "regular", "listen_port": 18080},
        )
        resp = test_client.post("/api/proxy-manager/instances/regular_1/restart")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "regular_1"
        assert data["status"] == "running"

    def test_restart_missing_instance_404(self, test_client: TestClient):
        resp = test_client.post("/api/proxy-manager/instances/nope/restart")
        assert resp.status_code == 404

    def test_restart_thread_failure_500(self, test_client: TestClient, mock_thread):
        test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "regular", "listen_port": 18080},
        )
        with patch.object(pm, "_start_proxy_thread", side_effect=RuntimeError("restart-boom")):
            resp = test_client.post("/api/proxy-manager/instances/regular_1/restart")
        assert resp.status_code == 500
        assert "Failed to restart" in resp.json()["detail"]
        assert pm._proxy_instances["regular_1"].status == "error"


@pytest.mark.api
class TestProxyManagerStats:
    def test_stats_regular_mode(self, test_client: TestClient, mock_thread, mock_proxy_state):
        test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "regular", "listen_port": 18080},
        )
        resp = test_client.get("/api/proxy-manager/instances/regular_1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["instance_id"] == "regular_1"
        assert data["mode"] == "regular"
        assert data["status"] == "running"
        assert data["port"] == 18080
        # mock_proxy_state.get_flows returns [] -> zero counts, no crash.
        assert data["total_flows"] == 0
        assert data["https_flows"] == 0
        assert data["unique_hosts"] == 0

    def test_stats_reverse_mode(self, test_client: TestClient, mock_thread):
        test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "reverse", "listen_port": 18443, "target_url": "https://example.com"},
        )
        resp = test_client.get("/api/proxy-manager/instances/reverse_1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "reverse"
        assert data["target_url"] == "https://example.com"
        assert data["ssl_bypass_active"] is True

    def test_stats_missing_instance_404(self, test_client: TestClient):
        resp = test_client.get("/api/proxy-manager/instances/nope/stats")
        assert resp.status_code == 404


@pytest.mark.api
class TestProxyManagerRecommendations:
    def test_recommended_default(self, test_client: TestClient):
        resp = test_client.get("/api/proxy-manager/recommended-setup")
        assert resp.status_code == 200
        data = resp.json()
        assert data["setup"] == "parallel_comprehensive"
        assert len(data["recommended_instances"]) == 3

    def test_recommended_ssl_pinning(self, test_client: TestClient):
        resp = test_client.get(
            "/api/proxy-manager/recommended-setup",
            params={"use_case": "ssl_pinning_bypass"},
        )
        assert resp.status_code == 200
        assert resp.json()["setup"] == "ssl_focused"

    def test_recommended_unknown_use_case(self, test_client: TestClient):
        resp = test_client.get(
            "/api/proxy-manager/recommended-setup",
            params={"use_case": "made_up"},
        )
        assert resp.status_code == 200
        assert "error" in resp.json()


@pytest.mark.api
class TestProxyManagerQuickSetup:
    def test_quick_setup_ssl_bypass(self, test_client: TestClient, mock_thread):
        resp = test_client.post(
            "/api/proxy-manager/quick-setup/ssl-bypass",
            json=["example.com", "api.example.com"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["message"] == "SSL bypass setup completed"
        # Two reverse instances + one wireguard backup = 3.
        assert data["instances_created"] == 3
        assert len(data["dns_redirections"]) == 2

    def test_quick_setup_continues_when_wireguard_fails(self, test_client: TestClient):
        # Reverse proxies succeed, WireGuard backup raises -> swallowed.
        def selective(instance):
            if instance.mode == "wireguard":
                raise RuntimeError("wg down")
            fake = MagicMock()
            fake.name = "t"
            return fake

        with patch.object(pm, "_start_proxy_thread", side_effect=selective):
            resp = test_client.post(
                "/api/proxy-manager/quick-setup/ssl-bypass",
                json=["example.com"],
            )
        assert resp.status_code == 200
        data = resp.json()
        # Only the reverse instance was created; wireguard was skipped.
        assert data["instances_created"] == 1


@pytest.mark.api
class TestProxyManagerUnifiedDashboard:
    def test_unified_dashboard_empty(self, test_client: TestClient, mock_proxy_state):
        resp = test_client.get("/api/proxy-manager/dashboard/unified")
        assert resp.status_code == 200
        data = resp.json()
        assert data["proxy_instances"] == []
        assert data["total_flows"] == 0
        assert data["ssl_bypass_active"] is False
        assert data["vpn_capture_active"] is False
        assert data["comprehensive_coverage"] is False
        assert data["recent_activity"] == []

    def test_unified_dashboard_with_reverse_instance(self, test_client: TestClient, mock_thread, mock_proxy_state):
        test_client.post(
            "/api/proxy-manager/instances",
            json={"mode": "reverse", "listen_port": 18443, "target_url": "https://example.com"},
        )
        resp = test_client.get("/api/proxy-manager/dashboard/unified")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["proxy_instances"]) == 1
        assert data["ssl_bypass_active"] is True
        assert "reverse" in data["mode_statistics"]
        assert data["ssl_pinning_status"]["bypass_active"] is True
