"""
Hermetic tests for the pRoxy threat-detection API endpoints.

Standalone app mounting only the threat_detection router. The
``mock_proxy_state`` fixture patches the ProxyState singleton (get_flows).

Regression coverage for the fixed add_custom_pattern bug: user regexes were
appended to the process-global ATTACK_PATTERNS with no ReDoS check and no
length cap (each pattern is re.search'd against every flow on every scan).
The fix rejects ReDoS-prone patterns (400) and caps the custom list.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import threat_detection


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(threat_detection.router)
    return TestClient(app)


@pytest.fixture(autouse=True)
def _restore_patterns():
    """Snapshot/restore the module-global ATTACK_PATTERNS list per test."""
    original = list(threat_detection.ATTACK_PATTERNS)
    yield
    threat_detection.ATTACK_PATTERNS[:] = original


def _pattern(patterns):
    return {
        "name": "custom",
        "category": "injection",
        "patterns": patterns,
        "threshold": 1,
        "timeframe": 60,
        "severity": "low",
    }


class TestAddCustomPattern:
    def test_valid_pattern_accepted(self, client):
        resp = client.post("/api/threat-detection/custom-pattern",
                            json=_pattern([r"(?i)foo\d+"]))
        assert resp.status_code == 200, resp.text
        assert resp.json()["message"] == "Custom pattern added successfully"

    def test_uncompilable_regex_rejected(self, client):
        resp = client.post("/api/threat-detection/custom-pattern",
                            json=_pattern([r"(unclosed"]))
        assert resp.status_code == 400

    def test_redos_nested_quantifier_rejected(self, client):
        # (a+)+ is catastrophic backtracking; _reject_redos must flag it.
        resp = client.post("/api/threat-detection/custom-pattern",
                            json=_pattern([r"(a+)+"]))
        assert resp.status_code == 400, resp.text
        assert "Dangerous regex" in resp.json()["detail"]

    def test_redos_excessive_quantifier_rejected(self, client):
        resp = client.post("/api/threat-detection/custom-pattern",
                            json=_pattern([r"a{100000}"]))
        assert resp.status_code == 400, resp.text

    def test_redos_pattern_not_appended(self, client):
        before = len(threat_detection.ATTACK_PATTERNS)
        client.post("/api/threat-detection/custom-pattern",
                    json=_pattern([r"(a+)+"]))
        assert len(threat_detection.ATTACK_PATTERNS) == before

    def test_custom_pattern_count_capped(self, client):
        # Fill to the cap, then expect the next add to be rejected.
        max_custom = threat_detection.MAX_CUSTOM_PATTERNS
        for i in range(max_custom):
            resp = client.post("/api/threat-detection/custom-pattern",
                               json=_pattern([rf"safe{i}"]))
            assert resp.status_code == 200, resp.text
        resp = client.post("/api/threat-detection/custom-pattern",
                           json=_pattern([r"safe_over"]))
        assert resp.status_code == 400, resp.text
        assert "Too many custom patterns" in resp.json()["detail"]


class TestScanWithMockState:
    def test_scan_empty_flows(self, client, mock_proxy_state):
        mock_proxy_state.get_flows.return_value = []
        resp = client.get("/api/threat-detection/scan")
        assert resp.status_code == 200, resp.text
        assert resp.json()["alerts"] == []
