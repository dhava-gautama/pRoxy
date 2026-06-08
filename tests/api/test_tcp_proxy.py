"""Hermetic tests for the TCP/UDP proxy route (api/routes/tcp_proxy.py).

These tests never bind a real port, spawn a thread, or touch the network.
The route only reaches external I/O through ``state.proxy_addon`` (which is
``None`` in tests), so no socket/thread patching is required — the route's
``proxy_addon is not None`` guard short-circuits all side effects.
"""
import pytest
from fastapi.testclient import TestClient

import api.routes.tcp_proxy as tcp


@pytest.fixture(autouse=True)
def _reset_tcp_state():
    """Isolate the module-level in-memory stores between tests."""
    tcp._tcp_rules.clear()
    tcp._active_connections.clear()
    tcp._traffic_logs.clear()
    yield
    tcp._tcp_rules.clear()
    tcp._active_connections.clear()
    tcp._traffic_logs.clear()


def _valid_rule(**overrides):
    rule = {
        "id": "placeholder",          # server overwrites this
        "name": "ssh-tunnel",
        "enabled": True,
        "protocol": "tcp",
        "listen_port": 2222,
        "target_host": "10.0.0.5",
        "target_port": 22,
        "description": "test rule",
    }
    rule.update(overrides)
    return rule


@pytest.mark.api
class TestTCPRulesCRUD:
    def test_list_empty(self, test_client: TestClient):
        resp = test_client.get("/api/tcp/rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_rule(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/rules", json=_valid_rule())
        assert resp.status_code == 200
        data = resp.json()
        # Server assigns its own id (ignores the client-supplied one).
        assert data["id"].startswith("tcp_rule_")
        assert data["name"] == "ssh-tunnel"
        assert data["protocol"] == "tcp"
        assert data["listen_port"] == 2222
        assert data["target_host"] == "10.0.0.5"
        assert data["target_port"] == 22

    def test_create_then_list(self, test_client: TestClient):
        test_client.post("/api/tcp/rules", json=_valid_rule())
        resp = test_client.get("/api/tcp/rules")
        assert resp.status_code == 200
        rules = resp.json()
        assert len(rules) == 1
        assert rules[0]["name"] == "ssh-tunnel"

    def test_create_port_conflict(self, test_client: TestClient):
        first = test_client.post("/api/tcp/rules", json=_valid_rule())
        assert first.status_code == 200
        # Same enabled listen_port -> 400 conflict.
        dup = test_client.post(
            "/api/tcp/rules",
            json=_valid_rule(name="other", target_port=23),
        )
        assert dup.status_code == 400
        assert "already in use" in dup.json()["detail"]

    def test_create_port_conflict_allowed_when_existing_disabled(self, test_client: TestClient):
        test_client.post("/api/tcp/rules", json=_valid_rule(enabled=False))
        # Disabled rules don't reserve the port.
        resp = test_client.post("/api/tcp/rules", json=_valid_rule(name="other"))
        assert resp.status_code == 200

    def test_update_rule(self, test_client: TestClient):
        created = test_client.post("/api/tcp/rules", json=_valid_rule()).json()
        rule_id = created["id"]
        updated = _valid_rule(id=rule_id, name="renamed", target_port=2200)
        resp = test_client.put(f"/api/tcp/rules/{rule_id}", json=updated)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == rule_id
        assert data["name"] == "renamed"
        assert data["target_port"] == 2200

    def test_update_missing_rule_404(self, test_client: TestClient):
        resp = test_client.put("/api/tcp/rules/nope", json=_valid_rule())
        assert resp.status_code == 404

    def test_delete_rule(self, test_client: TestClient):
        created = test_client.post("/api/tcp/rules", json=_valid_rule()).json()
        rule_id = created["id"]
        resp = test_client.delete(f"/api/tcp/rules/{rule_id}")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Rule deleted"}
        # Confirm it's gone.
        assert test_client.get("/api/tcp/rules").json() == []

    def test_delete_missing_rule_404(self, test_client: TestClient):
        resp = test_client.delete("/api/tcp/rules/nope")
        assert resp.status_code == 404

    def test_toggle_rule(self, test_client: TestClient):
        created = test_client.post("/api/tcp/rules", json=_valid_rule(enabled=True)).json()
        rule_id = created["id"]
        resp = test_client.post(f"/api/tcp/rules/{rule_id}/toggle")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        # Toggle back.
        resp2 = test_client.post(f"/api/tcp/rules/{rule_id}/toggle")
        assert resp2.json()["enabled"] is True

    def test_toggle_missing_rule_404(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/rules/nope/toggle")
        assert resp.status_code == 404


@pytest.mark.api
class TestTCPRuleValidation:
    def test_invalid_protocol_422(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/rules", json=_valid_rule(protocol="icmp"))
        assert resp.status_code == 422

    def test_empty_name_422(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/rules", json=_valid_rule(name="   "))
        assert resp.status_code == 422

    def test_listen_port_out_of_range_422(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/rules", json=_valid_rule(listen_port=70000))
        assert resp.status_code == 422

    def test_target_port_out_of_range_422(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/rules", json=_valid_rule(target_port=0))
        assert resp.status_code == 422

    def test_empty_target_host_422(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/rules", json=_valid_rule(target_host="  "))
        assert resp.status_code == 422

    def test_missing_required_field_422(self, test_client: TestClient):
        # Drop required target_host entirely.
        bad = _valid_rule()
        del bad["target_host"]
        resp = test_client.post("/api/tcp/rules", json=bad)
        assert resp.status_code == 422


@pytest.mark.api
class TestTCPConnections:
    def test_list_connections_empty(self, test_client: TestClient):
        resp = test_client.get("/api/tcp/connections")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_connections_with_entry(self, test_client: TestClient):
        conn = tcp.TCPConnection(
            id="conn-1",
            rule_id="tcp_rule_1",
            client_addr="192.168.1.10",
            client_port=51000,
            target_host="10.0.0.5",
            target_port=22,
            protocol="tcp",
            started_at=1700000000.0,
        )
        tcp.add_tcp_connection(conn)
        resp = test_client.get("/api/tcp/connections")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["id"] == "conn-1"
        assert data[0]["status"] == "active"

    def test_close_connection(self, test_client: TestClient):
        conn = tcp.TCPConnection(
            id="conn-2",
            rule_id="tcp_rule_1",
            client_addr="192.168.1.11",
            client_port=51001,
            target_host="10.0.0.5",
            target_port=22,
            protocol="tcp",
            started_at=1700000000.0,
        )
        tcp.add_tcp_connection(conn)
        resp = test_client.post("/api/tcp/connections/conn-2/close")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Connection closed"}

    def test_close_missing_connection_404(self, test_client: TestClient):
        resp = test_client.post("/api/tcp/connections/nope/close")
        assert resp.status_code == 404


@pytest.mark.api
class TestTCPTraffic:
    def test_get_traffic_empty(self, test_client: TestClient):
        resp = test_client.get("/api/tcp/traffic")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_traffic_filtered_by_connection(self, test_client: TestClient):
        tcp.log_tcp_traffic(tcp.TCPTrafficLog(
            id="log-1", connection_id="conn-A", timestamp=1.0,
            direction="client_to_server", data_size=10, data_preview="aa",
        ))
        tcp.log_tcp_traffic(tcp.TCPTrafficLog(
            id="log-2", connection_id="conn-B", timestamp=2.0,
            direction="server_to_client", data_size=20, data_preview="bb",
        ))
        resp = test_client.get("/api/tcp/traffic", params={"connection_id": "conn-A"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["connection_id"] == "conn-A"

    def test_get_traffic_limit(self, test_client: TestClient):
        for i in range(5):
            tcp.log_tcp_traffic(tcp.TCPTrafficLog(
                id=f"log-{i}", connection_id="conn-A", timestamp=float(i),
                direction="client_to_server", data_size=i, data_preview="x",
            ))
        resp = test_client.get("/api/tcp/traffic", params={"limit": 2})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        # Returns the most recent (tail).
        assert data[-1]["id"] == "log-4"

    def test_clear_traffic(self, test_client: TestClient):
        tcp.log_tcp_traffic(tcp.TCPTrafficLog(
            id="log-1", connection_id="conn-A", timestamp=1.0,
            direction="client_to_server", data_size=10, data_preview="aa",
        ))
        resp = test_client.delete("/api/tcp/traffic")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Traffic logs cleared"}
        assert test_client.get("/api/tcp/traffic").json() == []


@pytest.mark.api
class TestTCPStats:
    def test_stats_empty(self, test_client: TestClient):
        resp = test_client.get("/api/tcp/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_rules"] == 0
        assert data["active_rules"] == 0
        assert data["active_connections"] == 0
        assert data["protocols"] == {}
        assert data["ports"] == []

    def test_stats_with_rules(self, test_client: TestClient):
        test_client.post("/api/tcp/rules", json=_valid_rule(listen_port=2222))
        test_client.post("/api/tcp/rules", json=_valid_rule(name="udp-rule", protocol="udp", listen_port=5353))
        resp = test_client.get("/api/tcp/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_rules"] == 2
        assert data["active_rules"] == 2
        assert data["protocols"] == {"tcp": 1, "udp": 1}
        assert len(data["ports"]) == 2
        ports = {p["port"] for p in data["ports"]}
        assert ports == {2222, 5353}
