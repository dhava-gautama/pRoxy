"""Hermetic tests for the WireGuard API route.

All external I/O is mocked: subprocess (wg/ip/iptables/wg-quick), the socket
used for server-endpoint detection, and QR-code generation. No real processes,
files, or network are touched. The module-level ``_wg_config`` / ``_wg_clients``
globals are reset around every test so cases stay isolated.
"""
import pytest
from fastapi.testclient import TestClient

import api.routes.wireguard as wg


@pytest.fixture
def fake_keypair(monkeypatch):
    """Stub keypair generation so no ``wg genkey`` subprocess ever runs."""
    counter = {"n": 0}

    def _gen():
        counter["n"] += 1
        n = counter["n"]
        return (f"priv-key-{n}", f"pub-key-{n}")

    monkeypatch.setattr(wg, "_generate_keypair", _gen)
    return _gen


@pytest.fixture
def no_interface(monkeypatch):
    """Pretend no WireGuard interface exists on the host."""
    monkeypatch.setattr(wg, "_is_wireguard_running", lambda: False)


@pytest.fixture
def running_interface(monkeypatch):
    """Pretend a WireGuard interface is up; capture config-sync side effects."""
    calls = {"update": 0}
    monkeypatch.setattr(wg, "_is_wireguard_running", lambda: True)
    monkeypatch.setattr(
        wg, "_update_wireguard_config",
        lambda: calls.__setitem__("update", calls["update"] + 1),
    )
    return calls


@pytest.fixture
def fake_endpoint(monkeypatch):
    """Stub server-endpoint detection so no real socket connect happens."""
    monkeypatch.setattr(wg, "_get_server_endpoint", lambda: "192.0.2.10")


@pytest.fixture(autouse=True)
def reset_wg_globals(monkeypatch):
    """Isolate the module-level config/client stores around each test."""
    monkeypatch.setattr(wg, "_wg_config", wg.WireGuardConfig())
    monkeypatch.setattr(wg, "_wg_clients", {})
    yield


@pytest.mark.api
class TestWireGuardConfig:
    def test_get_config_defaults(self, test_client: TestClient):
        resp = test_client.get("/api/wireguard/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["interface_name"] == "wg-prxy"
        assert data["listen_port"] == 51820
        assert data["server_ip"] == "10.0.0.1"
        assert data["client_ip_range"] == "10.0.0.0/24"
        # Keys are empty until generated.
        assert data["server_private_key"] == ""
        assert data["server_public_key"] == ""

    def test_update_config_generates_keys_when_missing(
        self, test_client: TestClient, fake_keypair
    ):
        payload = {
            "interface_name": "wg-test",
            "listen_port": 51821,
            "server_ip": "10.0.0.1",
            "client_ip_range": "10.0.0.0/24",
        }
        resp = test_client.post("/api/wireguard/config", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["interface_name"] == "wg-test"
        assert data["listen_port"] == 51821
        # Keys auto-generated because none were supplied.
        assert data["server_private_key"].startswith("priv-key-")
        assert data["server_public_key"].startswith("pub-key-")

    def test_update_config_preserves_supplied_keys(
        self, test_client: TestClient, fake_keypair
    ):
        payload = {
            "server_private_key": "my-priv",
            "server_public_key": "my-pub",
        }
        resp = test_client.post("/api/wireguard/config", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        # Supplied keys must not be regenerated.
        assert data["server_private_key"] == "my-priv"
        assert data["server_public_key"] == "my-pub"

    def test_update_config_invalid_ip_rejected(self, test_client: TestClient):
        resp = test_client.post(
            "/api/wireguard/config",
            json={"server_ip": "not-an-ip"},
        )
        # model_validator raises ValueError -> 422 unprocessable entity.
        assert resp.status_code == 422

    def test_update_config_invalid_cidr_rejected(self, test_client: TestClient):
        resp = test_client.post(
            "/api/wireguard/config",
            json={"client_ip_range": "999.999.0.0/24"},
        )
        assert resp.status_code == 422


@pytest.mark.api
class TestWireGuardStartStop:
    def test_start_when_not_running_returns_500(
        self, test_client: TestClient, no_interface
    ):
        resp = test_client.post("/api/wireguard/start")
        assert resp.status_code == 500
        assert "not available" in resp.json()["detail"]

    def test_start_when_running_initializes_keys(
        self, test_client: TestClient, fake_keypair, monkeypatch
    ):
        monkeypatch.setattr(wg, "_is_wireguard_running", lambda: True)
        resp = test_client.post("/api/wireguard/start")
        assert resp.status_code == 200
        data = resp.json()
        assert data["message"] == "WireGuard VPN is running"
        assert data["listen_port"] == 51820
        # Server keys should have been auto-generated.
        assert wg._wg_config.server_private_key.startswith("priv-key-")

    def test_stop_always_rejected(self, test_client: TestClient):
        resp = test_client.post("/api/wireguard/stop")
        assert resp.status_code == 400
        assert "cannot be stopped" in resp.json()["detail"]


@pytest.mark.api
class TestWireGuardStatus:
    def test_status_down(self, test_client: TestClient, no_interface):
        resp = test_client.get("/api/wireguard/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is False
        assert data["interface"] == "wg-prxy"
        assert data["listen_port"] == 51820
        assert data["server_ip"] == "10.0.0.1"
        assert data["connected_clients"] == 0

    def test_status_up(self, test_client: TestClient, monkeypatch):
        monkeypatch.setattr(wg, "_is_wireguard_running", lambda: True)
        resp = test_client.get("/api/wireguard/status")
        assert resp.status_code == 200
        assert resp.json()["running"] is True

    def test_status_counts_active_clients(
        self, test_client: TestClient, no_interface
    ):
        wg._wg_clients["c1"] = wg.WireGuardClient(
            id="c1", name="a", ip_address="10.0.0.2",
            private_key="p", public_key="P", created_at=0.0, status="active",
        )
        wg._wg_clients["c2"] = wg.WireGuardClient(
            id="c2", name="b", ip_address="10.0.0.3",
            private_key="p", public_key="P", created_at=0.0, status="inactive",
        )
        resp = test_client.get("/api/wireguard/status")
        assert resp.status_code == 200
        # Only the "active" client is counted as connected.
        assert resp.json()["connected_clients"] == 1


@pytest.mark.api
class TestWireGuardClients:
    def test_list_empty(self, test_client: TestClient):
        resp = test_client.get("/api/wireguard/clients")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_client_assigns_ip_and_keys(
        self, test_client: TestClient, fake_keypair, no_interface
    ):
        resp = test_client.post(
            "/api/wireguard/clients", json={"name": "phone"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "phone"
        assert data["status"] == "inactive"
        assert data["private_key"].startswith("priv-key-")
        assert data["public_key"].startswith("pub-key-")
        # First free host address (server is 10.0.0.1, so client gets .2).
        assert data["ip_address"] == "10.0.0.2"
        assert data["id"].startswith("client_")

    def test_create_client_skips_used_ips(
        self, test_client: TestClient, fake_keypair, no_interface
    ):
        wg._wg_clients["existing"] = wg.WireGuardClient(
            id="existing", name="x", ip_address="10.0.0.2",
            private_key="p", public_key="P", created_at=0.0,
        )
        resp = test_client.post(
            "/api/wireguard/clients", json={"name": "second"}
        )
        assert resp.status_code == 200
        # .1 is server, .2 is taken -> next free is .3.
        assert resp.json()["ip_address"] == "10.0.0.3"

    def test_create_client_persists_in_store(
        self, test_client: TestClient, fake_keypair, no_interface
    ):
        resp = test_client.post(
            "/api/wireguard/clients", json={"name": "phone"}
        )
        cid = resp.json()["id"]
        assert cid in wg._wg_clients
        listing = test_client.get("/api/wireguard/clients").json()
        assert len(listing) == 1
        assert listing[0]["id"] == cid

    def test_create_client_syncs_running_interface(
        self, test_client: TestClient, fake_keypair, running_interface
    ):
        resp = test_client.post(
            "/api/wireguard/clients", json={"name": "phone"}
        )
        assert resp.status_code == 200
        # Config sync invoked because the interface is "up".
        assert running_interface["update"] == 1

    def test_create_client_max_limit(
        self, test_client: TestClient, no_interface
    ):
        for i in range(50):
            wg._wg_clients[f"c{i}"] = wg.WireGuardClient(
                id=f"c{i}", name=f"n{i}", ip_address=f"10.0.0.{i+2}",
                private_key="p", public_key="P", created_at=0.0,
            )
        resp = test_client.post(
            "/api/wireguard/clients", json={"name": "overflow"}
        )
        assert resp.status_code == 400
        assert "Maximum number" in resp.json()["detail"]

    def test_create_client_missing_name_422(self, test_client: TestClient):
        resp = test_client.post("/api/wireguard/clients", json={})
        assert resp.status_code == 422

    def test_create_client_exhausted_ip_pool(
        self, test_client: TestClient, fake_keypair, no_interface, monkeypatch
    ):
        # Tiny /30 range: hosts are .1 and .2; server takes .1, fill .2.
        cfg = wg.WireGuardConfig(client_ip_range="10.0.0.0/30", server_ip="10.0.0.1")
        monkeypatch.setattr(wg, "_wg_config", cfg)
        wg._wg_clients["used"] = wg.WireGuardClient(
            id="used", name="x", ip_address="10.0.0.2",
            private_key="p", public_key="P", created_at=0.0,
        )
        resp = test_client.post(
            "/api/wireguard/clients", json={"name": "nope"}
        )
        assert resp.status_code == 400
        assert "No available IP" in resp.json()["detail"]

    def test_delete_client(
        self, test_client: TestClient, no_interface
    ):
        wg._wg_clients["c1"] = wg.WireGuardClient(
            id="c1", name="a", ip_address="10.0.0.2",
            private_key="p", public_key="P", created_at=0.0,
        )
        resp = test_client.delete("/api/wireguard/clients/c1")
        assert resp.status_code == 200
        assert resp.json()["message"] == "Client deleted"
        assert "c1" not in wg._wg_clients

    def test_delete_client_syncs_running_interface(
        self, test_client: TestClient, running_interface
    ):
        wg._wg_clients["c1"] = wg.WireGuardClient(
            id="c1", name="a", ip_address="10.0.0.2",
            private_key="p", public_key="P", created_at=0.0,
        )
        resp = test_client.delete("/api/wireguard/clients/c1")
        assert resp.status_code == 200
        assert running_interface["update"] == 1

    def test_delete_missing_client_404(self, test_client: TestClient):
        resp = test_client.delete("/api/wireguard/clients/does-not-exist")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Client not found"


@pytest.mark.api
class TestClientConfig:
    def _make_client(self):
        client = wg.WireGuardClient(
            id="c1", name="phone", ip_address="10.0.0.2",
            private_key="client-priv", public_key="client-pub", created_at=0.0,
        )
        wg._wg_clients["c1"] = client
        return client

    def test_get_client_config_qr(
        self, test_client: TestClient, fake_keypair, fake_endpoint, monkeypatch
    ):
        self._make_client()
        monkeypatch.setattr(
            wg, "_generate_qr_code", lambda text: "data:image/png;base64,FAKE"
        )
        resp = test_client.get("/api/wireguard/clients/c1/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["client_ip"] == "10.0.0.2"
        assert data["client_name"] == "phone"
        assert data["server_endpoint"] == "192.0.2.10:51820"
        assert data["qr_code"] == "data:image/png;base64,FAKE"
        assert isinstance(data["instructions"], list) and data["instructions"]
        # Generated config embeds the client private key and server endpoint.
        assert "client-priv" in data["config_text"]
        assert "192.0.2.10:51820" in data["config_text"]

    def test_get_client_config_text_format(
        self, test_client: TestClient, fake_keypair, fake_endpoint
    ):
        self._make_client()
        resp = test_client.get(
            "/api/wireguard/clients/c1/config", params={"format": "text"}
        )
        assert resp.status_code == 200
        data = resp.json()
        # Non-qr format omits qr_code/instructions.
        assert "qr_code" not in data
        assert "instructions" not in data
        assert data["config_text"].startswith("[Interface]")

    def test_get_client_config_auto_inits_server_keys(
        self, test_client: TestClient, fake_keypair, fake_endpoint, monkeypatch
    ):
        client = self._make_client()
        monkeypatch.setattr(wg, "_generate_qr_code", lambda text: None)
        assert wg._wg_config.server_public_key == ""
        resp = test_client.get("/api/wireguard/clients/c1/config")
        assert resp.status_code == 200
        # Server keys auto-generated during config build.
        assert wg._wg_config.server_public_key.startswith("pub-key-")

    def test_get_client_config_missing_qr_lib_returns_none(
        self, test_client: TestClient, fake_keypair, fake_endpoint, monkeypatch
    ):
        self._make_client()
        monkeypatch.setattr(wg, "_generate_qr_code", lambda text: None)
        resp = test_client.get("/api/wireguard/clients/c1/config")
        assert resp.status_code == 200
        # When qrcode is unavailable the field is present but null.
        assert resp.json()["qr_code"] is None

    def test_get_config_missing_client_404(
        self, test_client: TestClient, fake_endpoint
    ):
        resp = test_client.get("/api/wireguard/clients/ghost/config")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Client not found"


@pytest.mark.api
class TestWireGuardStats:
    def test_stats_when_down(self, test_client: TestClient, no_interface):
        wg._wg_clients["c1"] = wg.WireGuardClient(
            id="c1", name="a", ip_address="10.0.0.2",
            private_key="p", public_key="P", created_at=0.0,
        )
        resp = test_client.get("/api/wireguard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["interface_status"] == "down"
        assert data["connected_clients"] == 0
        assert data["total_clients"] == 1
        assert data["bytes_sent"] == 0
        assert data["bytes_received"] == 0
        assert data["uptime"] == 0

    def test_stats_when_up_parses_wg_output(
        self, test_client: TestClient, monkeypatch
    ):
        monkeypatch.setattr(wg, "_is_wireguard_running", lambda: True)
        monkeypatch.setattr(
            wg, "_parse_wireguard_stats",
            lambda: {
                "connected_clients": 2,
                "bytes_sent": 1000,
                "bytes_received": 2000,
                "uptime": 0,
            },
        )
        resp = test_client.get("/api/wireguard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["interface_status"] == "up"
        assert data["connected_clients"] == 2
        assert data["bytes_sent"] == 1000
        assert data["bytes_received"] == 2000
