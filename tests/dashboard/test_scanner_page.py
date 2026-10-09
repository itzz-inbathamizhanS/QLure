"""The domain scanner page: login required, and the Q-CAPS guardrails hold through the page."""

import pytest
from fastapi.testclient import TestClient

from dashboard import scanning
from dashboard.app import create_app

PASSWORD = "test-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    monkeypatch.delenv("QLURE_DASHBOARD_SECRET", raising=False)
    monkeypatch.setattr(scanning, "_recent", scanning._recent.__class__())
    app = create_app(db_path=tmp_path / "qlure.db", logs_dir=tmp_path / "logs")
    c = TestClient(app)
    c.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    return c


def test_scanner_needs_login(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    app = create_app(db_path=tmp_path / "qlure.db", logs_dir=tmp_path / "logs")
    anon = TestClient(app)
    r = anon.get("/scanner", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_page_renders_and_shows_full_scans_off(client):
    r = client.get("/scanner")
    assert r.status_code == 200
    assert "Domain scanner" in r.text
    assert "Full scans are off" in r.text


@pytest.mark.parametrize(
    "target, message",
    [
        ("localhost", "restricted address"),
        ("https://example.com:8443", "Ports are not accepted"),
        ("10.0.0.1", "Enter a hostname"),
    ],
)
def test_refused_targets_are_not_scanned(client, target, message):
    r = client.post("/scanner", data={"target": target, "mode": "standard", "action": "scan"})
    assert r.status_code == 200
    assert message in r.text
    assert "Findings" not in r.text


def test_full_scan_is_refused_without_a_secret(client):
    r = client.post("/scanner", data={"target": "example.com", "mode": "full", "action": "scan"})
    assert "Full scans are off" in r.text
    assert "Findings" not in r.text


def test_full_scan_needs_the_ownership_record(client, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_SECRET", "test-secret")
    monkeypatch.setattr(scanning.ownership, "_lookup_txt", lambda name: [])
    r = client.post("/scanner", data={"target": "example.com", "mode": "full", "action": "scan"})
    assert "Full scans need proof" in r.text
    assert "_qcaps-verify.example.com" in r.text


def test_ownership_record_is_bound_to_the_domain(monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_SECRET", "test-secret")
    info = scanning.verification_info("test-secret", "example.com")
    other = scanning.verification_info("test-secret", "example.org")
    assert info["record_value"] != other["record_value"]
    assert info["record_name"] == "_qcaps-verify.example.com"


def test_one_scan_at_a_time_and_rate_limited(monkeypatch):
    monkeypatch.setattr(scanning, "_recent", scanning._recent.__class__())
    monkeypatch.setattr(scanning, "_busy", False)
    assert scanning._start() is None
    assert "already running" in scanning._start()
    scanning._finish()
    for _ in range(scanning.RATE_COUNT - 1):
        assert scanning._start() is None
        scanning._finish()
    assert "Rate limit" in scanning._start()
