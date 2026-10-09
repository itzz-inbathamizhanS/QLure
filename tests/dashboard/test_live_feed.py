"""P3.1 live feed: the background correlation pass, its lock, judge mode, the env switches, and the
overview's poll."""

import asyncio
import logging
import re
import time

import pytest
from fastapi.testclient import TestClient

from dashboard import app as app_module
from dashboard import data
from dashboard.app import LiveFeed, create_app, live_interval, live_loop, live_tick
from decoys.web.app import app as web_app
from qlure import settings as cfg
from qlure.correlate import store as correlate_store
from qlure.store import db, forwarder

PASSWORD = "test-password"


def _visit(ip, agent, paths):
    client = TestClient(web_app, client=(ip, 40404))
    client.headers["user-agent"] = agent
    for path in paths:
        client.get(path)


@pytest.fixture(autouse=True)
def _clear_rule_config(monkeypatch):
    load_config = __import__("qlure.correlate.rules", fromlist=["load_config"]).load_config
    load_config.cache_clear()
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    yield
    load_config.cache_clear()


@pytest.fixture
def store(tmp_path, log_dir, monkeypatch):
    """A store with one scanner session, forwarded and correlated, and the paths to it."""
    monkeypatch.delenv("QLURE_LIVE", raising=False)
    _visit("198.51.100.77", "Nikto/2.5.0", ["/wp-login.php", "/phpmyadmin/", "/.env"])
    db_path = tmp_path / "qlure.db"
    conn = db.connect(db_path)
    forwarder.forward_once(conn, log_dir)
    correlate_store.run(conn)
    conn.close()
    return {"db": db_path, "logs": log_dir}


def _login(app):
    client = TestClient(app, base_url="http://testserver")
    response = client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert response.status_code == 303
    return client


def _session_ids(conn):
    return {r["session_id"] for r in data.list_findings(conn, {})}


# ---------- the interval: env switches ----------


def test_interval_defaults_to_ten_seconds(monkeypatch):
    monkeypatch.delenv("QLURE_LIVE", raising=False)
    monkeypatch.delenv("QLURE_LIVE_INTERVAL", raising=False)
    assert live_interval() == 10


def test_interval_has_a_floor_of_two_seconds(monkeypatch):
    monkeypatch.setenv("QLURE_LIVE_INTERVAL", "1")
    assert live_interval() == 2
    monkeypatch.setenv("QLURE_LIVE_INTERVAL", "30")
    assert live_interval() == 30


def test_a_bad_interval_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("QLURE_LIVE_INTERVAL", "soon")
    assert live_interval() == 10


def test_live_zero_turns_the_loop_off(monkeypatch):
    monkeypatch.setenv("QLURE_LIVE", "0")
    assert live_interval() is None


# ---------- one pass ----------


def test_one_pass_shows_a_new_attack_once_the_forwarder_has_stored_it(store, log_dir):
    conn = db.connect(store["db"])
    before = _session_ids(conn)
    _visit("203.0.113.40", "sqlmap/1.8", ["/?id=1' union select 1,2--", "/.git/config"])
    forwarder.forward_once(conn, log_dir)  # the forwarder service's job, not the loop's
    feed = LiveFeed(interval=10)
    assert asyncio.run(live_tick(store["db"], feed)) is True
    assert _session_ids(conn) > before
    assert feed.updated is not None and feed.failed is False
    conn.close()


def test_the_loop_reuses_the_refresh_pass(store, monkeypatch):
    calls = []
    monkeypatch.setattr(app_module, "correlate_db", lambda path: calls.append(path))
    asyncio.run(live_tick(store["db"], LiveFeed(interval=10)))
    assert calls == [store["db"]]


# ---------- the lock: passes never overlap ----------


def test_a_running_refresh_makes_the_loop_skip_not_overlap(store, monkeypatch):
    calls = []
    monkeypatch.setattr(app_module, "correlate_db", lambda path: calls.append(path))

    async def scenario():
        feed = LiveFeed(interval=10)
        await feed.lock.acquire()  # a manual Re-run, or an earlier pass, is in progress
        try:
            return await live_tick(store["db"], feed), feed.updated
        finally:
            feed.lock.release()

    ran, updated = asyncio.run(scenario())
    assert ran is False and updated is None
    assert calls == []


# ---------- judge mode: the pass writes, so it does not run ----------


def test_judge_mode_pauses_the_loop(store, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(app_module, "correlate_db", lambda path: calls.append(path))
    (tmp_path / "settings.json").write_text('{"judge_mode": true}', encoding="utf-8")
    assert cfg.load_settings()["judge_mode"] is True
    assert asyncio.run(live_tick(store["db"], LiveFeed(interval=10))) is False
    assert calls == []


# ---------- errors are logged and the loop carries on ----------


def test_a_failing_pass_is_logged_and_the_loop_keeps_running(store, monkeypatch, caplog):
    def broken(path):
        raise RuntimeError("store is busy")

    monkeypatch.setattr(app_module, "correlate_db", broken)

    async def scenario():
        feed = LiveFeed(interval=2)
        task = asyncio.create_task(live_loop(store["db"], feed, 2))
        await asyncio.sleep(0.05)  # the first pass runs at once and fails
        alive = not task.done()
        task.cancel()
        return feed, alive

    with caplog.at_level(logging.ERROR, logger="dashboard.app"):
        feed, alive = asyncio.run(scenario())
    assert alive is True
    assert feed.failed is True
    assert "live correlation pass failed" in caplog.text


# ---------- the app: the loop, the switch and the poll ----------


def test_env_zero_starts_no_loop_and_says_so(store, monkeypatch):
    monkeypatch.setenv("QLURE_LIVE", "0")
    app = create_app(store["db"], store["logs"])
    with TestClient(app) as _:
        assert app.state.live.task is None
    html = _login(create_app(store["db"], store["logs"])).get("/").text
    assert "Auto-update is off" in html
    assert 'hx-trigger="every' not in html


def test_the_loop_runs_while_the_app_is_up_and_stops_on_shutdown(store, monkeypatch):
    monkeypatch.delenv("QLURE_LIVE", raising=False)
    monkeypatch.setenv("QLURE_LIVE_INTERVAL", "2")
    app = create_app(store["db"], store["logs"])
    with TestClient(app):
        deadline = time.monotonic() + 10
        while app.state.live.updated is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert app.state.live.updated is not None
        task = app.state.live.task
    assert task is not None and task.done()


def test_overview_polls_the_list_with_htmx_when_live(store):
    html = _login(create_app(store["db"], store["logs"])).get("/").text
    assert 'id="results" hx-get="/?live=1" hx-trigger="every 5s"' in html
    assert "Live" in html and "first pass not run yet" in html


def test_poll_returns_the_rows_of_the_list_the_browser_shows(store):
    client = _login(create_app(store["db"], store["logs"]))
    shown = client.get(
        "/",
        params={"verdict": "Benign"},
        headers={"hx-request": "true", "hx-current-url": "http://testserver/?verdict=Benign"},
    ).text
    poll = client.get(
        "/",
        params={"live": "1"},
        headers={"hx-request": "true", "hx-current-url": "http://testserver/?verdict=Benign"},
    ).text
    assert poll == shown
    assert "<html" not in poll  # the fragment only, not the whole page
    assert 'class="live-status small"' in poll


def test_poll_without_a_browser_url_shows_everything(store):
    client = _login(create_app(store["db"], store["logs"]))
    poll = client.get("/", params={"live": "1"}, headers={"hx-request": "true"}).text
    assert set(re.findall(r'href="/session/([^"]+)"', poll)) == _session_ids(
        db.connect(store["db"])
    )
