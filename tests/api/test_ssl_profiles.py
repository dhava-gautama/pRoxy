"""
Tests for the SSL pinning bypass profile endpoints consumed by the Tools tab:

    GET  /api/settings/ssl-profiles
    POST /api/settings/ssl-profiles/apply
"""
import pytest
from fastapi.testclient import TestClient

REQUIRED_KEYS = {"name", "description", "settings", "frida_script"}
SETTINGS_FLAGS = {"hsts_strip", "hpkp_strip", "csp_strip", "cors_bypass"}


@pytest.mark.api
class TestSSLProfilesAPI:
    """SSL bypass profile listing and application."""

    def test_list_ssl_profiles(self, test_client: TestClient):
        """GET returns a non-empty list; each item matches the tools.js shape."""
        response = test_client.get("/api/settings/ssl-profiles")

        assert response.status_code == 200
        profiles = response.json()
        assert isinstance(profiles, list)
        assert len(profiles) > 0

        for profile in profiles:
            # Exactly the four keys tools.js reads.
            assert REQUIRED_KEYS.issubset(profile.keys())
            assert isinstance(profile["name"], str) and profile["name"]
            assert isinstance(profile["description"], str)
            assert isinstance(profile["frida_script"], str)  # may be ""

            settings = profile["settings"]
            assert isinstance(settings, dict)
            # The four bool flags _renderSSLProfiles iterates over.
            assert SETTINGS_FLAGS.issubset(settings.keys())
            for flag in SETTINGS_FLAGS:
                assert isinstance(settings[flag], bool)

    def test_list_includes_expected_profiles(self, test_client: TestClient):
        """The four documented presets are present, Generic has no script."""
        profiles = test_client.get("/api/settings/ssl-profiles").json()
        names = [p["name"] for p in profiles]
        for expected in [
            "Android (Full Bypass)",
            "iOS (Full Bypass)",
            "Flutter/Dart Bypass",
            "Generic (Headers Only)",
        ]:
            assert expected in names

        generic = next(p for p in profiles if p["name"] == "Generic (Headers Only)")
        assert generic["frida_script"] == ""

        # Non-generic presets ship a real Frida script.
        for p in profiles:
            if p["name"] != "Generic (Headers Only)":
                assert p["frida_script"].strip()

    def test_apply_ssl_profile_valid_index(self, test_client: TestClient, mock_proxy_state):
        """POST apply with a valid index calls update_settings with the profile's settings."""
        # Discover the real profile settings for index 0 first.
        profiles = test_client.get("/api/settings/ssl-profiles").json()
        expected_settings = profiles[0]["settings"]

        response = test_client.post("/api/settings/ssl-profiles/apply", json={"index": 0})

        assert response.status_code == 200
        mock_proxy_state.update_settings.assert_called_once_with(expected_settings)

    def test_apply_ssl_profile_returns_settings(self, test_client: TestClient):
        """Applying a profile (real state) returns settings with the toggles set."""
        response = test_client.post("/api/settings/ssl-profiles/apply", json={"index": 0})

        assert response.status_code == 200
        data = response.json()
        for flag in SETTINGS_FLAGS:
            assert flag in data
            assert data[flag] is True

    def test_apply_ssl_profile_out_of_range(self, test_client: TestClient):
        """An out-of-range index is rejected with 400 or 404."""
        response = test_client.post("/api/settings/ssl-profiles/apply", json={"index": 9999})
        assert response.status_code in (400, 404)

    def test_apply_ssl_profile_negative_index(self, test_client: TestClient):
        """A negative index is rejected with 400 or 404."""
        response = test_client.post("/api/settings/ssl-profiles/apply", json={"index": -1})
        assert response.status_code in (400, 404)
