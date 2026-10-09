"""The favicon: served without a login (so no 404 or redirect in the log), and linked from pages."""

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app

PASSWORD = "test-password"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    return create_app(db_path=tmp_path / "qlure.db", logs_dir=tmp_path / "logs")


def test_favicon_served_without_login(app):
    r = TestClient(app).get("/favicon.ico", follow_redirects=False)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in r.text
    assert "script" not in r.text.lower()


def test_base_page_links_the_icon(app):
    c = TestClient(app)
    c.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    r = c.get("/config")
    assert r.status_code == 200
    assert '<link rel="icon" href="/favicon.ico"' in r.text


def test_csp_unchanged(app):
    r = TestClient(app).get("/favicon.ico")
    assert "img-src 'self'" in r.headers["content-security-policy"]
    assert "default-src 'none'" in r.headers["content-security-policy"]
