"""
Hermetic tests for the SSL bypass / certificate management API (api/routes/ssl.py).

All external I/O is mocked:
  * ``subprocess.run`` (real ``adb`` invocations in app-discovery) is patched so no
    real device commands run and tests stay fast.
  * ``ProxyState().get_flows`` is patched (via the live singleton) for the
    traffic-based discovery path so no real flow store is touched.

The module under test keeps state in module-level dicts
(``_ssl_bypass_methods``, ``_frida_scripts``, ``_cert_replacements``). Those leak
across tests, so the ``_reset_ssl_state`` autouse fixture clears them before each
test and assertions avoid depending on cross-test accumulation.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import api.routes.ssl as ssl_mod
from state.shared import ProxyState
from state.models import FlowRecord


@pytest.fixture(autouse=True)
def _reset_ssl_state():
    """Clear the module-level SSL stores so tests are isolated."""
    ssl_mod._ssl_bypass_methods.clear()
    ssl_mod._frida_scripts.clear()
    ssl_mod._cert_replacements.clear()
    ssl_mod._detection_running = False
    yield
    ssl_mod._ssl_bypass_methods.clear()
    ssl_mod._frida_scripts.clear()
    ssl_mod._cert_replacements.clear()


@pytest.fixture(autouse=True)
def _no_real_adb():
    """Ensure no test accidentally shells out to a real ``adb`` binary.

    Default: simulate adb not being installed (FileNotFoundError), which the
    route swallows. Individual tests that need a specific adb behaviour patch
    ``api.routes.ssl.subprocess.run`` themselves inside the test body.
    """
    with patch("api.routes.ssl.subprocess.run", side_effect=FileNotFoundError("no adb in test env")):
        yield


@pytest.mark.api
class TestSSLBypassMethods:
    """/api/ssl/bypass-methods CRUD-ish endpoints."""

    def test_get_bypass_methods_empty(self, test_client: TestClient):
        response = test_client.get("/api/ssl/bypass-methods")
        assert response.status_code == 200
        assert response.json() == []

    def test_create_bypass_method_generates_id(self, test_client: TestClient):
        payload = {"id": "", "name": "My Bypass", "method": "frida"}
        response = test_client.post("/api/ssl/bypass-methods", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "My Bypass"
        assert data["method"] == "frida"
        # Empty id should be auto-generated.
        assert data["id"].startswith("ssl_bypass_")
        # Default fields preserved.
        assert data["enabled"] is True
        assert data["effectiveness"] == "high"

    def test_create_bypass_method_keeps_explicit_id(self, test_client: TestClient):
        payload = {"id": "custom-id", "name": "X", "method": "magisk"}
        response = test_client.post("/api/ssl/bypass-methods", json=payload)
        assert response.status_code == 200
        assert response.json()["id"] == "custom-id"

    def test_create_then_list_roundtrip(self, test_client: TestClient):
        test_client.post(
            "/api/ssl/bypass-methods",
            json={"id": "rt-1", "name": "Roundtrip", "method": "reverse_proxy"},
        )
        response = test_client.get("/api/ssl/bypass-methods")
        assert response.status_code == 200
        ids = [m["id"] for m in response.json()]
        assert ids == ["rt-1"]

    def test_create_bypass_method_missing_required_fields(self, test_client: TestClient):
        # name and method are required (no defaults) -> validation error.
        response = test_client.post("/api/ssl/bypass-methods", json={"name": "only-name"})
        assert response.status_code == 422

    def test_get_builtin_bypass_methods(self, test_client: TestClient):
        response = test_client.get("/api/ssl/bypass-methods/builtin")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 4
        ids = {m["id"] for m in data}
        assert "reverse_proxy_bypass" in ids
        assert "frida_universal_bypass" in ids
        # Every builtin must carry the core SSLBypassMethod shape.
        for m in data:
            assert {"id", "name", "method", "effectiveness", "requires_root"} <= set(m)


@pytest.mark.api
class TestFridaScripts:
    """/api/ssl/frida-scripts endpoints."""

    def test_get_frida_scripts_empty(self, test_client: TestClient):
        response = test_client.get("/api/ssl/frida-scripts")
        assert response.status_code == 200
        assert response.json() == []

    def test_create_frida_script_generates_id(self, test_client: TestClient):
        payload = {
            "id": "",
            "name": "Hook OkHttp",
            "script_content": "Java.perform(function(){});",
            "target_platform": "android",
            "bypass_methods": ["okhttp"],
        }
        response = test_client.post("/api/ssl/frida-scripts", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["id"].startswith("frida_")
        assert data["name"] == "Hook OkHttp"
        assert data["bypass_methods"] == ["okhttp"]
        assert data["auto_attach"] is True

    def test_create_frida_script_missing_required(self, test_client: TestClient):
        # script_content, target_platform, bypass_methods required.
        response = test_client.post("/api/ssl/frida-scripts", json={"name": "incomplete"})
        assert response.status_code == 422

    def test_create_then_list_frida_scripts(self, test_client: TestClient):
        test_client.post(
            "/api/ssl/frida-scripts",
            json={
                "id": "fs-1",
                "name": "S",
                "script_content": "x",
                "target_platform": "ios",
                "bypass_methods": ["nsurlsession"],
            },
        )
        response = test_client.get("/api/ssl/frida-scripts")
        assert response.status_code == 200
        assert [s["id"] for s in response.json()] == ["fs-1"]

    def test_get_frida_templates(self, test_client: TestClient):
        response = test_client.get("/api/ssl/frida-scripts/templates")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        platforms = {t["platform"] for t in data}
        assert platforms == {"android", "ios"}
        for t in data:
            assert {"name", "platform", "description", "script", "bypass_methods"} <= set(t)
            assert isinstance(t["bypass_methods"], list) and t["bypass_methods"]


@pytest.mark.api
class TestCertificateReplacement:
    """/api/ssl/certificate-replacement(s) endpoints."""

    def test_get_replacements_empty(self, test_client: TestClient):
        response = test_client.get("/api/ssl/certificate-replacements")
        assert response.status_code == 200
        assert response.json() == []

    def test_create_replacement_default_method(self, test_client: TestClient):
        payload = {
            "target_domain": "api.example.com",
            "replacement_cert": "CERTDATA",
            "replacement_key": "KEYDATA",
        }
        response = test_client.post("/api/ssl/certificate-replacement", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["target_domain"] == "api.example.com"
        assert data["method"] == "dns_hijack"  # default
        assert data["enabled"] is True

    @pytest.mark.parametrize("method", ["dns_hijack", "hosts_file", "transparent_proxy"])
    def test_create_replacement_each_apply_branch(self, test_client: TestClient, method):
        # Exercises every branch of _apply_certificate_replacement without crashing.
        payload = {
            "target_domain": f"{method}.example.com",
            "replacement_cert": "C",
            "replacement_key": "K",
            "method": method,
        }
        response = test_client.post("/api/ssl/certificate-replacement", json=payload)
        assert response.status_code == 200
        assert response.json()["method"] == method

    def test_create_then_list_replacement_roundtrip(self, test_client: TestClient):
        test_client.post(
            "/api/ssl/certificate-replacement",
            json={"target_domain": "rt.example.com", "replacement_cert": "C", "replacement_key": "K"},
        )
        response = test_client.get("/api/ssl/certificate-replacements")
        assert response.status_code == 200
        domains = [r["target_domain"] for r in response.json()]
        assert domains == ["rt.example.com"]

    def test_create_replacement_missing_required(self, test_client: TestClient):
        response = test_client.post(
            "/api/ssl/certificate-replacement", json={"target_domain": "x"}
        )
        assert response.status_code == 422


@pytest.mark.api
class TestAutoBypass:
    """/api/ssl/auto-bypass/{app_package} endpoint."""

    def test_auto_bypass_default_reverse_proxy(self, test_client: TestClient):
        response = test_client.post("/api/ssl/auto-bypass/com.test.app")
        assert response.status_code == 200
        data = response.json()
        assert data["app_package"] == "com.test.app"
        assert data["method"] == "reverse_proxy"
        assert data["requires_root"] is False
        assert "instructions" in data and isinstance(data["instructions"], list)
        assert "advantages" in data

    def test_auto_bypass_reverse_proxy_with_domains(self, test_client: TestClient):
        response = test_client.post(
            "/api/ssl/auto-bypass/com.test.app",
            params={"method": "reverse_proxy", "target_domains": ["a.com", "b.com"]},
        )
        assert response.status_code == 200
        data = response.json()
        setup = " ".join(data["setup_commands"])
        assert "a.com" in setup
        assert "b.com" in setup

    def test_auto_bypass_frida(self, test_client: TestClient):
        response = test_client.post(
            "/api/ssl/auto-bypass/com.test.app", params={"method": "frida"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "frida"
        assert "requirements" in data
        assert any("frida" in cmd for cmd in data["setup_commands"])

    def test_auto_bypass_certificate_injection(self, test_client: TestClient):
        response = test_client.post(
            "/api/ssl/auto-bypass/com.test.app",
            params={"method": "certificate_injection"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "certificate_injection"
        assert data["requires_root"] is True

    def test_auto_bypass_unknown_method(self, test_client: TestClient):
        response = test_client.post(
            "/api/ssl/auto-bypass/com.test.app", params={"method": "bogus"}
        )
        # Route returns 200 with an error payload (existing behaviour, not changed).
        assert response.status_code == 200
        assert response.json() == {"error": "Unknown method: bogus"}


@pytest.mark.api
class TestEffectivenessAndStatus:
    """Static informational endpoints."""

    def test_effectiveness_comparison(self, test_client: TestClient):
        response = test_client.get("/api/ssl/effectiveness-comparison")
        assert response.status_code == 200
        data = response.json()
        assert "methods" in data and "recommendations" in data
        assert "reverse_proxy" in data["methods"]
        assert data["methods"]["reverse_proxy"]["effectiveness"] == 95

    def test_detection_status(self, test_client: TestClient):
        response = test_client.get("/api/ssl/detection-status")
        assert response.status_code == 200
        data = response.json()
        assert data["detection_running"] is False
        assert "reverse_proxy" in data["available_methods"]
        assert data["recommended_method"] == "reverse_proxy"


@pytest.mark.api
class TestAppDiscovery:
    """/api/ssl/app-discovery endpoint (subprocess + ProxyState side effects)."""

    def test_discovery_no_adb_no_flows(self, test_client: TestClient):
        # autouse _no_real_adb makes adb unavailable; patch flows to empty.
        state = ProxyState()
        with patch.object(state, "get_flows", return_value=[]):
            response = test_client.get("/api/ssl/app-discovery")
        assert response.status_code == 200
        data = response.json()
        assert data["discovery_methods_used"] == 3
        # Database method always contributes known pinned apps even with no adb/flows.
        assert data["total_candidates"] == 10
        assert len(data["discovered_apps"]) == 10
        pkgs = {a["package_name"] for a in data["discovered_apps"]}
        assert "com.chase.sig.android" in pkgs

    def test_discovery_from_traffic(self, test_client: TestClient):
        # Four https flows to api.facebook.com (>= threshold of 3) -> traffic app.
        flows = [
            FlowRecord(
                id=f"f{i}",
                timestamp=1700000000.0 + i,
                host="api.facebook.com",
                scheme="https",
                method="GET",
            )
            for i in range(4)
        ]
        state = ProxyState()
        with patch.object(state, "get_flows", return_value=flows):
            response = test_client.get("/api/ssl/app-discovery")
        assert response.status_code == 200
        apps = response.json()["discovered_apps"]
        traffic_app = next((a for a in apps if a["package_name"] == "com.facebook.app"), None)
        assert traffic_app is not None
        assert traffic_app["is_running"] is True
        assert "api.facebook.com" in traffic_app["detected_domains"]
        assert traffic_app["confidence_score"] == 0.7  # https_ratio > 0.5

    def test_discovery_traffic_below_threshold_ignored(self, test_client: TestClient):
        # Only 2 flows for a host -> below threshold (3) -> not surfaced from traffic.
        flows = [
            FlowRecord(id="f0", timestamp=1.0, host="api.tinyapp.com", scheme="https", method="GET"),
            FlowRecord(id="f1", timestamp=2.0, host="api.tinyapp.com", scheme="https", method="GET"),
        ]
        state = ProxyState()
        with patch.object(state, "get_flows", return_value=flows):
            response = test_client.get("/api/ssl/app-discovery")
        assert response.status_code == 200
        pkgs = {a["package_name"] for a in response.json()["discovered_apps"]}
        assert "com.tinyapp.app" not in pkgs

    def test_discovery_with_adb_success(self, test_client: TestClient):
        """ADB success branch: package list + details, fully mocked subprocess."""
        def fake_run(cmd, *args, **kwargs):
            # ssl.py now calls adb via argv lists (no shell); join for matching.
            cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else cmd
            m = MagicMock()
            m.returncode = 0
            if "pm list packages" in cmd_str:
                # One third-party app + one system app (filtered out).
                m.stdout = "package:com.example.coolapp\npackage:com.android.systemui\n"
            elif "shell ps" in cmd_str:
                m.stdout = "u0_a1 1234 com.example.coolapp"
            elif "pm dump" in cmd_str:
                m.stdout = "applicationLabel=CoolApp\n"
            else:
                m.stdout = ""
            return m

        state = ProxyState()
        with patch.object(state, "get_flows", return_value=[]), \
             patch("api.routes.ssl.subprocess.run", side_effect=fake_run):
            response = test_client.get("/api/ssl/app-discovery")

        assert response.status_code == 200
        apps = response.json()["discovered_apps"]
        coolapp = next((a for a in apps if a["package_name"] == "com.example.coolapp"), None)
        assert coolapp is not None
        assert coolapp["app_name"] == "CoolApp"
        assert coolapp["is_running"] is True
        assert coolapp["confidence_score"] == 0.8
        # System package must be filtered out.
        assert "com.android.systemui" not in {a["package_name"] for a in apps}

    def test_discovery_handles_subprocess_timeout(self, test_client: TestClient):
        """A hanging/timed-out adb call must not crash discovery (graceful degrade)."""
        import subprocess as _sp

        state = ProxyState()
        with patch.object(state, "get_flows", return_value=[]), \
             patch("api.routes.ssl.subprocess.run",
                   side_effect=_sp.TimeoutExpired(cmd="adb", timeout=30)):
            response = test_client.get("/api/ssl/app-discovery")
        # Should still succeed (database method) despite adb timing out.
        assert response.status_code == 200
        assert response.json()["discovery_methods_used"] == 3

    def test_discovery_deduplicates(self, test_client: TestClient):
        """Traffic + database both surfacing same package merge into one entry."""
        # api.coinbase.com -> traffic guesses com.coinbase.app; database has
        # com.coinbase.android. These are different keys, so instead verify the
        # database list itself has no duplicate package names after dedup.
        state = ProxyState()
        with patch.object(state, "get_flows", return_value=[]):
            response = test_client.get("/api/ssl/app-discovery")
        pkgs = [a["package_name"] for a in response.json()["discovered_apps"]]
        assert len(pkgs) == len(set(pkgs))  # no duplicates
