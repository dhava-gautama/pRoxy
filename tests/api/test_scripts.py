"""Tests for the custom-addon-scripts management route."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from api.routes import scripts as scr
    from proxy import engine
    # Redirect both the route's and the engine's scripts dir to a temp dir.
    monkeypatch.setattr(scr, "SCRIPTS_DIR", tmp_path)
    monkeypatch.setattr(engine, "SCRIPTS_DIR", tmp_path)
    app = FastAPI()
    app.include_router(scr.router)
    return TestClient(app)


VALID = b"class A:\n    def request(self, flow):\n        pass\naddons = [A()]\n"


@pytest.mark.api
class TestScriptsRoute:
    def test_list_empty(self, client):
        data = client.get("/api/scripts").json()
        assert data["scripts"] == []
        assert "scripts_dir" in data and "note" in data

    def test_upload_and_list(self, client, tmp_path):
        r = client.post("/api/scripts/upload",
                        files={"file": ("my_addon.py", VALID, "text/x-python")})
        assert r.status_code == 200
        assert (tmp_path / "my_addon.py").is_file()
        scripts = client.get("/api/scripts").json()["scripts"]
        entry = next(s for s in scripts if s["name"] == "my_addon.py")
        assert entry["loaded"] is True and entry["ignored"] is False

    def test_underscore_script_ignored(self, client):
        client.post("/api/scripts/upload",
                    files={"file": ("_helper.py", VALID, "text/x-python")})
        entry = next(s for s in client.get("/api/scripts").json()["scripts"]
                     if s["name"] == "_helper.py")
        assert entry["ignored"] is True and entry["loaded"] is False

    def test_upload_syntax_error_rejected(self, client):
        r = client.post("/api/scripts/upload",
                        files={"file": ("bad.py", b"def (:\n", "text/x-python")})
        assert r.status_code == 400
        assert "syntax" in r.json()["detail"].lower()

    def test_upload_bad_name_rejected(self, client):
        for bad in ("notpy.txt", "../evil.py", "a/b.py"):
            r = client.post("/api/scripts/upload",
                            files={"file": (bad, VALID, "text/x-python")})
            assert r.status_code == 400, bad

    def test_delete(self, client, tmp_path):
        (tmp_path / "gone.py").write_bytes(VALID)
        assert client.delete("/api/scripts/gone.py").status_code == 200
        assert not (tmp_path / "gone.py").exists()
        assert client.delete("/api/scripts/missing.py").status_code == 404

    def test_delete_traversal_rejected(self, client):
        assert client.delete("/api/scripts/..%2f..%2fetc%2fpasswd").status_code in (400, 404)

    def test_sample(self, client):
        data = client.get("/api/scripts/sample").json()
        assert data["filename"].endswith(".py")
        assert "addons" in data["content"]
