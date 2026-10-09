"""A blank rule weight in the settings form removes the override, through the audited path."""

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from qlure import settings as cfg
from qlure.store import db

PASSWORD = "test-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_CONTENT", str(tmp_path / "content.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    app = create_app(tmp_path / "q.db", tmp_path / "logs")
    c = TestClient(app, base_url="http://testserver")
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return c


def test_blank_weight_removes_the_override_and_is_audited(client, tmp_path):
    r = client.post("/config", data={"rules.weights.R2": "40"}, follow_redirects=False)
    assert "ok=1" in r.headers["location"]
    assert cfg.load_settings()["rules"]["weights"] == {"R2": 40}

    r = client.post("/config", data={"rules.weights.R2": "  "}, follow_redirects=False)
    assert "ok=1" in r.headers["location"]
    assert "saved" in r.headers["location"]
    assert cfg.load_settings()["rules"]["weights"] == {}

    conn = db.connect(tmp_path / "q.db")
    rows = conn.execute(
        "SELECT old_value, new_value, outcome FROM config_audit WHERE key='rules.weights'"
        " ORDER BY audit_id"
    ).fetchall()
    assert [r["outcome"] for r in rows] == ["applied", "applied"]
    assert rows[1]["old_value"] == '{"R2": 40}' and rows[1]["new_value"] == "{}"


def test_blank_weight_with_no_override_changes_nothing(client, tmp_path):
    r = client.post("/config", data={"rules.weights.R5": ""}, follow_redirects=False)
    assert "Nothing+changed" in r.headers["location"]
    assert cfg.load_settings()["rules"]["weights"] == {}
