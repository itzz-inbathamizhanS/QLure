"""QLURE_JUDGE_LOCK: the host can pin judge mode on so a logged-in user cannot switch it off."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from dashboard.app import create_app
from qlure import settings
from qlure.store import db
from qlure.store.verify import verify_config

ROOT = Path(__file__).resolve().parents[1]
REASON = "judge mode is locked by the host (QLURE_JUDGE_LOCK)"


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "q.db")
    yield c
    c.close()


def _write(path, **values):
    path.write_text(json.dumps(values), encoding="utf-8")


def _audit(conn):
    return [
        (r["key"], r["outcome"], r["reason"]) for r in conn.execute("SELECT * FROM config_audit")
    ]


@pytest.mark.parametrize("flag", ["1", "true", "TRUE", "Yes"])
def test_lock_refuses_turning_judge_mode_off(conn, tmp_path, monkeypatch, flag):
    monkeypatch.setenv("QLURE_JUDGE_LOCK", flag)
    path = tmp_path / "settings.json"
    _write(path, judge_mode=True)
    ok, message = settings.apply_change(conn, "admin", {"judge_mode": False}, path)
    assert not ok and REASON in message
    assert settings.load_settings(path)["judge_mode"] is True
    assert _audit(conn) == [("judge_mode", "refused", REASON)]
    assert verify_config(conn)[2] is None


def test_lock_refuses_turning_judge_mode_on_and_rollback(conn, tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    monkeypatch.setenv("QLURE_SETTINGS", str(path))
    assert settings.apply_change(conn, "admin", {"judge_mode": True}, path)[0]  # lock off
    monkeypatch.setenv("QLURE_JUDGE_LOCK", "1")
    audit_id = conn.execute("SELECT audit_id FROM config_audit").fetchone()[0]
    ok, message = settings.rollback(conn, "admin", audit_id)
    assert not ok and REASON in message
    assert settings.load_settings(path)["judge_mode"] is True
    assert verify_config(conn)[2] is None
    _write(path, judge_mode=False)
    ok, message = settings.apply_change(conn, "admin", {"judge_mode": True}, path)
    assert not ok and REASON in message


def test_lock_with_stored_judge_mode_off_still_refuses_changes(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_JUDGE_LOCK", "1")
    path = tmp_path / "settings.json"
    _write(path, judge_mode=False)
    assert settings.judge_active(settings.load_settings(path))
    ok, message = settings.apply_change(conn, "admin", {"decoys.ssh.port": 2200}, path)
    assert not ok and "judge mode is on" in message
    assert verify_config(conn)[2] is None


@pytest.mark.parametrize("flag", [None, "0", "no", "", "false"])
def test_lock_off_keeps_existing_behaviour(conn, tmp_path, monkeypatch, flag):
    if flag is None:
        monkeypatch.delenv("QLURE_JUDGE_LOCK", raising=False)
    else:
        monkeypatch.setenv("QLURE_JUDGE_LOCK", flag)
    path = tmp_path / "settings.json"
    assert not settings.judge_active({"judge_mode": False})
    assert settings.apply_change(conn, "a", {"judge_mode": True}, path)[0]
    assert settings.judge_active(settings.load_settings(path))
    assert not settings.apply_change(conn, "a", {"decoys.ssh.port": 2200}, path)[0]
    assert settings.apply_change(conn, "a", {"judge_mode": False}, path)[0]
    assert settings.apply_change(conn, "a", {"decoys.ssh.port": 2200}, path)[0]


def test_clear_all_is_403_when_locked_and_judge_mode_stored_off(log_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", "pw")
    monkeypatch.setenv("QLURE_JUDGE_LOCK", "1")
    _write(tmp_path / "settings.json", judge_mode=False)
    db.connect(tmp_path / "q.db").close()
    client = TestClient(create_app(tmp_path / "q.db", log_dir), base_url="http://testserver")
    assert client.post("/login", data={"password": "pw"}).status_code in (200, 303)
    assert client.post("/clear", data={"confirm": "yes"}).status_code == 403
    page = client.get("/config").text
    assert "locked by the host" in page
    client.post("/config", data={"judge_mode": "false"})
    assert settings.judge_active(settings.load_settings())
    monkeypatch.delenv("QLURE_JUDGE_LOCK")
    assert "locked by the host" not in client.get("/config").text


def test_prepare_hosted_demo_works_with_lock_env(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("prep", ROOT / "tools" / "prepare_hosted_demo.py")
    prep = importlib.util.module_from_spec(spec)
    sys.modules["prep"] = prep
    spec.loader.exec_module(prep)
    monkeypatch.setenv("QLURE_JUDGE_LOCK", "1")
    db.connect(tmp_path / "d.db").close()
    path = tmp_path / "data" / "settings.json"
    assert prep.prepare(tmp_path / "d.db", path) == "enabled"
    assert json.loads(path.read_text())["judge_mode"] is True
    c = db.connect(tmp_path / "d.db")
    assert verify_config(c)[2] is None
    c.close()


def test_render_yaml_sets_the_lock_without_secrets():
    text = (ROOT / "render.yaml").read_text(encoding="utf-8")
    env = {i["key"]: i for i in yaml.safe_load(text)["services"][0]["envVars"]}
    assert env["QLURE_JUDGE_LOCK"]["value"] == "1"
    assert env["QLURE_DASHBOARD_PASSWORD"] == {
        "key": "QLURE_DASHBOARD_PASSWORD",
        "generateValue": True,
    }
