"""alerts.* settings: validated, audited, and the webhook URL is masked everywhere."""

import pytest

from qlure import settings
from qlure.store import db

URL = "https://hooks.example.test/services/SECRETPATH123"


def _conn(tmp_path):
    return db.connect(tmp_path / "qlure.db")


def test_defaults_are_off():
    assert settings.defaults()["alerts"] == {"webhook_url": "", "min_verdict": "noteworthy"}


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://x/y",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:pw@hooks.example.test/x",
        "https://@hooks.example.test/x",
        "https:///nohost",
        "https://hooks.example.test/" + "a" * 600,
        "https://hooks.example.test/a b",
    ],
)
def test_bad_urls_refused_and_audited_without_the_url(tmp_path, bad):
    conn, path = _conn(tmp_path), tmp_path / "s.json"
    ok, msg = settings.apply_change(conn, "t", {"alerts.webhook_url": bad}, path)
    assert not ok
    row = conn.execute("SELECT outcome, old_value, new_value, reason FROM config_audit").fetchone()
    assert row["outcome"] == "refused"
    assert "user:pw" not in " ".join(str(v) for v in tuple(row))
    assert "user:pw" not in msg


def test_valid_url_applies_and_audit_is_masked(tmp_path):
    conn, path = _conn(tmp_path), tmp_path / "s.json"
    ok, _ = settings.apply_change(conn, "t", {"alerts.webhook_url": URL}, path)
    assert ok and settings.load_settings(path)["alerts"]["webhook_url"] == URL
    ok, _ = settings.apply_change(conn, "t", {"alerts.webhook_url": URL + "2"}, path)
    assert ok
    rows = conn.execute("SELECT old_value, new_value FROM config_audit").fetchall()
    text = " ".join(" ".join(r) for r in rows)
    assert "SECRETPATH123" not in text and "https://hooks.example.test/" in text


def test_rollback_of_the_secret_is_refused(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "s.json"))
    monkeypatch.setenv("QLURE_CONTENT", str(tmp_path / "c.json"))
    assert settings.apply_change(conn, "t", {"alerts.webhook_url": URL})[0]
    audit_id = conn.execute("SELECT audit_id FROM config_audit").fetchone()[0]
    ok, msg = settings.rollback(conn, "t", audit_id)
    assert not ok and "masked" in msg


def test_min_verdict_validated(tmp_path):
    conn, path = _conn(tmp_path), tmp_path / "s.json"
    assert settings.apply_change(conn, "t", {"alerts.min_verdict": "suspicious"}, path)[0]
    assert not settings.apply_change(conn, "t", {"alerts.min_verdict": "benign"}, path)[0]


def test_judge_mode_blocks_alert_changes(tmp_path):
    conn, path = _conn(tmp_path), tmp_path / "s.json"
    assert settings.apply_change(conn, "t", {"judge_mode": True}, path)[0]
    assert not settings.apply_change(conn, "t", {"alerts.webhook_url": URL}, path)[0]


def test_masked_export_hides_the_url():
    data = settings.defaults()
    data["alerts"]["webhook_url"] = URL
    out = settings.masked(data)
    assert "SECRETPATH123" not in str(out) and out["alerts"]["webhook_url"].startswith(
        "https://hooks"
    )
    assert data["alerts"]["webhook_url"] == URL
    assert settings.mask_url("") == ""
