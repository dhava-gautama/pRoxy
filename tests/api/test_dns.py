"""
Hermetic tests for the pRoxy DNS API endpoints.

Standalone app mounting only the dns router. Regression coverage for the fix
where ``state.update_dns(body)`` raised a pydantic ValidationError on bad
input and surfaced as HTTP 500; it now returns 422.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import dns


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(dns.router)
    return TestClient(app)


class TestUpdateDns:
    def test_valid_patch_returns_200(self, client):
        resp = client.post("/api/dns", json={"doh_enabled": True})
        assert resp.status_code == 200, resp.text
        assert resp.json()["doh_enabled"] is True

    def test_valid_custom_mapping(self, client):
        resp = client.post("/api/dns", json={
            "custom_mappings": [{"hostname": "example.com", "ip": "1.2.3.4"}]
        })
        assert resp.status_code == 200, resp.text

    def test_invalid_mapping_returns_422_not_500(self, client):
        # Bad hostname triggers DNSMapping validation -> pydantic ValidationError.
        resp = client.post("/api/dns", json={
            "custom_mappings": [{"hostname": "bad host!!", "ip": "1.2.3.4"}]
        })
        assert resp.status_code == 422, resp.text

    def test_invalid_ip_returns_422_not_500(self, client):
        resp = client.post("/api/dns", json={
            "custom_mappings": [{"hostname": "example.com", "ip": "not-an-ip"}]
        })
        assert resp.status_code == 422, resp.text

    def test_get_returns_200(self, client):
        resp = client.get("/api/dns")
        assert resp.status_code == 200, resp.text
        assert "doh_enabled" in resp.json()
