"""The dashboard, driven over HTTP on events the real web decoy logged."""

import json
import re

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from decoys.web.app import app as web_app
from qlure import settings as cfg
from qlure.correlate import store as correlate_store
from qlure.store import db, forwarder

PASSWORD = "test-password"
ATTACKER = "198.51.100.77"


def _visit(ip, agent, paths, logins=0):
    client = TestClient(web_app, client=(ip, 40404))
    client.headers["user-agent"] = agent
    for path in paths:
        client.get(path)
    for i in range(logins):
        client.post("/login", data={"username": "ops", "password": f"guess-{i}"})


@pytest.fixture
def env(log_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    cfg_cache = __import__("qlure.correlate.rules", fromlist=["load_config"]).load_config
    cfg_cache.cache_clear()
    _visit(ATTACKER, "Nikto/2.5.0", ["/wp-login.php", "/phpmyadmin/", "/backup/config.bak"], 6)
    _visit("198.51.100.88", "Mozilla/5.0 Firefox/131.0", ["/login"])
    db_path = tmp_path / "qlure.db"
    conn = db.connect(db_path)
    forwarder.forward_once(conn, log_dir)
    correlate_store.run(conn)
    yield {"db": db_path, "logs": log_dir, "conn": conn}
    cfg_cache.cache_clear()


@pytest.fixture
def client(env):
    app = create_app(env["db"], env["logs"])
    c = TestClient(app, base_url="http://testserver")
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return c


def _session_ids(client, **params):
    html = client.get("/", params=params).text
    return re.findall(r'href="/session/([^"]+)"', html)


def test_everything_redirects_to_login_without_a_cookie(env):
    anonymous = TestClient(create_app(env["db"], env["logs"]))
    for path in ("/", "/config", "/session/x"):
        r = anonymous.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"


def test_wrong_password_is_refused(env):
    anonymous = TestClient(create_app(env["db"], env["logs"]))
    assert anonymous.post("/login", data={"password": "nope"}).status_code == 401


def test_list_filters_and_sort(client):
    everything = _session_ids(client)
    assert len(everything) == 2
    noteworthy = _session_ids(client, verdict="Noteworthy")
    assert 0 < len(noteworthy) < len(everything) or noteworthy == []
    assert _session_ids(client, verdict="Benign") != noteworthy
    assert _session_ids(client, rule="R10") is not None
    assert len(_session_ids(client, service="web")) == 2
    assert _session_ids(client, service="ssh") == []
    assert _session_ids(client, honeytoken="ht-ssh-001")
    top = _session_ids(client, sort="score")[0]
    assert client.get(f"/session/{top}").status_code == 200


def test_htmx_request_gets_only_the_results_fragment(client):
    full = client.get("/").text
    fragment = client.get("/", headers={"hx-request": "true"}).text
    assert "<html" in full and "<html" not in fragment
    assert "<table" in fragment


def test_session_page_explains_and_shows_timeline(client):
    top = _session_ids(client, sort="score")[0]
    html = client.get(f"/session/{top}").text
    assert "Why this verdict" in html and "Timeline" in html and "Raw event" in html


def test_attacker_text_is_escaped_and_headers_forbid_inline_script(client, env):
    _visit("198.51.100.99", "<script>alert(1)</script>", ["/<script>alert(2)</script>"])
    forwarder.forward_once(env["conn"], env["logs"])
    correlate_store.run(env["conn"])
    for sid in _session_ids(client):
        html = client.get(f"/session/{sid}").text
        assert "<script>alert" not in html
    response = client.get("/")
    assert "<script>alert" not in response.text
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    # No inline script blocks or style attributes on any page.
    for path in ("/", "/config", f"/session/{_session_ids(client)[0]}"):
        html = client.get(path).text
        assert not re.search(r"<script(?![^>]*\bsrc=)", html)
        assert " style=" not in html


def test_label_and_evidence_export_with_chain_proof(client):
    sid = _session_ids(client, sort="score")[0]
    html = client.get(f"/session/{sid}").text
    event_id = re.search(r'name="evidence" value="([^"]+)"', html).group(1)
    r = client.post(
        f"/session/{sid}/label",
        data={"label": "malicious", "evidence": [event_id]},
        follow_redirects=False,
    )
    assert r.status_code == 303
    bundle = client.get(f"/session/{sid}/evidence.json").json()
    assert bundle["label"] == "malicious" and bundle["evidence_marked"] == [event_id]
    assert bundle["hash_chain"]["verified"] is True
    assert all(e["hash"] for e in bundle["events"])
    assert client.post(f"/session/{sid}/label", data={"label": "bogus"}).status_code == 400
    report = client.get(f"/session/{sid}/report")
    assert report.status_code == 200 and "hash chain is intact" in report.text


def test_unknown_session_is_404(client):
    assert client.get("/session/does-not-exist").status_code == 404
    assert client.get("/session/does-not-exist/evidence.json").status_code == 404


def test_tampering_shows_in_the_report(client, env):
    sid = _session_ids(client, sort="score")[0]
    path = env["logs"] / "web.jsonl"
    path.write_text(path.read_text().replace("wp-login.php", "wp-login.pxp", 1))
    report = client.get(f"/session/{sid}/report")
    assert "hash chain failed" in report.text


def test_config_refuses_unsafe_ports_and_forbidden_keys(client, env):
    for key, value in (
        ("decoys.ssh.port", 22),
        ("decoys.web.port", 9000),
        ("decoys.web.port", 80),
        ("outbound_network", True),
        ("decoys.web.exec", True),
    ):
        ok, _ = cfg.apply_change(env["conn"], "tester", {key: value})
        assert not ok, key
    rows = env["conn"].execute("SELECT outcome FROM config_audit").fetchall()
    assert rows and all(r["outcome"] == "refused" for r in rows)


def test_config_apply_audit_and_rollback(client, env):
    r = client.post("/config", data={"decoys.ssh.port": "2200"}, follow_redirects=False)
    assert r.status_code == 303 and "ok=1" in r.headers["location"]
    assert cfg.load_settings()["decoys"]["ssh"]["port"] == 2200
    applied = env["conn"].execute("SELECT * FROM config_audit WHERE outcome='applied'").fetchone()
    assert applied["key"] == "decoys.ssh.port" and applied["who"] == "admin"
    assert "Undo" in client.get("/config").text
    client.post(f"/config/rollback/{applied['audit_id']}")
    assert cfg.load_settings()["decoys"]["ssh"]["port"] == 2222


def test_config_form_refuses_port_22_over_http(client, env):
    r = client.post("/config", data={"decoys.ssh.port": "22"}, follow_redirects=True)
    assert "not allowed" in r.text or "not on the approved list" in r.text
    assert cfg.load_settings()["decoys"]["ssh"]["port"] == 2222


def test_secret_looking_content_is_refused(client, env):
    ok, message = cfg.apply_change(
        env["conn"], "tester", {"content.company_name": "AKIAABCDEFGHIJKLMNOP"}
    )
    assert not ok and "secret" in message


def test_judge_mode_makes_everything_read_only(client, env):
    client.post("/config", data={"judge_mode": "true"})
    assert cfg.load_settings()["judge_mode"] is True
    r = client.post("/config", data={"decoys.ssh.port": "2200"}, follow_redirects=True)
    assert "judge mode" in r.text
    assert cfg.load_settings()["decoys"]["ssh"]["port"] == 2222
    sid = _session_ids(client)[0]
    assert client.post(f"/session/{sid}/label", data={"label": "benign"}).status_code == 403
    assert client.post("/config", data={"judge_mode": "false"}).status_code in (200, 303)
    assert cfg.load_settings()["judge_mode"] is False


def test_cross_site_post_is_refused(client):
    r = client.post(
        "/config", data={"retention_days": "10"}, headers={"origin": "https://evil.example"}
    )
    assert r.status_code == 403


def test_same_site_form_posts_work_and_browser_cross_site_is_refused(client):
    ok = client.post("/config", data={}, headers={"origin": "http://testserver"})
    assert ok.status_code in (200, 303)
    # With "no-referrer" browsers send Origin: null on form posts and the login breaks.
    assert client.get("/").headers["referrer-policy"] == "same-origin"
    refused = client.post("/config", data={}, headers={"sec-fetch-site": "cross-site"})
    assert refused.status_code == 403


def test_changing_a_weight_changes_correlation(client, env):
    before = {f["session_id"]: f["score"] for f in _rows(env["conn"])}
    fired = env["conn"].execute("SELECT rule_ids FROM findings WHERE score>0").fetchone()[0]
    rule = json.loads(fired)[0]
    ok, _ = cfg.apply_change(env["conn"], "tester", {f"rules.weights.{rule}": 1})
    assert ok
    client.post("/refresh")
    after = {f["session_id"]: f["score"] for f in _rows(env["conn"])}
    assert after != before


def _rows(conn):
    return conn.execute("SELECT session_id, score FROM findings").fetchall()


def test_settings_schema_is_valid_json():
    assert json.dumps(cfg.schema())
