"""P3.3 SSH terminal replay: the transcript in order, escaping, long output, the old cap."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from dashboard import data
from dashboard.app import create_app
from decoys.web.app import app as web_app
from qlure.correlate import store as correlate_store
from qlure.correlate.rules import load_config
from qlure.events import Event
from qlure.events.emit import emit
from qlure.store import db, forwarder

PASSWORD = "test-password"
IP = "198.51.100.61"
IDLE_IP = "198.51.100.63"  # a second SSH visitor, so its session is not merged with the first
WEB_IP = "198.51.100.62"
CREDS = {"username": "deploy", "password": "decoy-password"}


def _ssh(session, action, ip=IP, **fields):
    emit({"service": "ssh", "src_ip": ip, "session_id": session, "action": action, **fields})


def _command(session, command, output):
    _ssh(session, "command", request={"command": command}, response={"output_preview": output})


@pytest.fixture(autouse=True)
def _rule_config(monkeypatch):
    load_config.cache_clear()
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    yield
    load_config.cache_clear()


@pytest.fixture
def store(tmp_path, log_dir):
    """One SSH session that logs in as `deploy` and runs commands, one web session."""
    _ssh("conn-1", "login_attempt", credential=CREDS)
    _ssh("conn-1", "login_success", credential=CREDS)
    _command("conn-1", "whoami", "deploy\n")
    _command("conn-1", 'echo "<script>alert(1)</script>"', "<script>alert(1)</script>\n")
    _command("conn-1", "echo <img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>\n")
    # Stored previews, newline included: 3000 characters, and exactly the old 256-character cap.
    _command("conn-1", "cat /var/log/big", "x" * 2999 + "\n")
    _command("conn-1", "ls -la /srv", "y" * 255 + "\n")
    _command("conn-1", "uname -a", "z" * 2048)
    _ssh("conn-2", "login_success", ip=IDLE_IP, credential={"username": "ops", "password": "p"})
    web = TestClient(web_app, client=(WEB_IP, 40404))
    web.get("/wp-login.php")
    db_path = tmp_path / "qlure.db"
    conn = db.connect(db_path)
    forwarder.forward_once(conn, log_dir)
    correlate_store.run(conn)
    conn.close()
    return db_path


@pytest.fixture
def client(store, log_dir):
    app = create_app(store, log_dir)
    c = TestClient(app, base_url="http://testserver")
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return c


def _ssh_session_id(store, src_ip=IP):
    conn = db.connect(store)
    try:
        return next(r["session_id"] for r in data.list_findings(conn, {}) if r["src_ip"] == src_ip)
    finally:
        conn.close()


def _panel(html):
    start = html.index('id="term-h"')
    return html[start : html.index("</section>", start)]


# ---------- the transcript: unit level, on hand-built events ----------


def _event(i, action, **fields):
    base = datetime(2026, 10, 9, 12, 0, 0, tzinfo=UTC)
    return Event(
        event_id=f"e{i}",
        ts=base + timedelta(seconds=i),
        service="ssh",
        src_ip=IP,
        session_id="s",
        action=action,
        **fields,
    )


def test_replay_lists_the_commands_in_order_with_the_login_user():
    events = [
        _event(1, "login_success", credential={"username": "root", "password": "p"}),
        _event(2, "command", request={"command": "id"}, response={"output_preview": "uid=0\n"}),
        _event(3, "command", request={"command": "uname -a"}, response={"output_preview": "Linux"}),
    ]
    steps = data.terminal_replay(events)
    assert [s["command"] for s in steps] == ["id", "uname -a"]
    assert steps[0]["prompt"] == "root@srv:~$"
    assert steps[0]["output"] == "uid=0"  # the trailing newline is not shown as a blank line
    assert steps[0]["note"] == ""


def test_replay_falls_back_to_the_decoy_default_user():
    steps = data.terminal_replay([_event(1, "command", request={"command": "whoami"})])
    assert steps[0]["prompt"] == "deploy@srv:~$"
    assert steps[0]["output"] == ""


def test_replay_names_a_cut_at_the_display_limit():
    steps = data.terminal_replay(
        [
            _event(
                1, "command", request={"command": "cat x"}, response={"output_preview": "a" * 3000}
            )
        ]
    )
    assert len(steps[0]["output"]) == data.TERMINAL_SHOWN_CHARS
    assert steps[0]["note"] == "output cut for display: 2048 of 3000 characters shown"


def test_replay_notes_an_old_256_character_preview():
    steps = data.terminal_replay(
        [_event(1, "command", request={"command": "ls"}, response={"output_preview": "a" * 256})]
    )
    assert "at most 256 characters" in steps[0]["note"]


def test_replay_keeps_a_full_2048_character_preview_without_a_note():
    steps = data.terminal_replay(
        [_event(1, "command", request={"command": "ls"}, response={"output_preview": "a" * 2048})]
    )
    assert steps[0]["note"] == ""
    assert len(steps[0]["output"]) == 2048


def test_replay_ignores_events_that_are_not_commands():
    events = [_event(1, "connect"), _event(2, "login_attempt", credential=CREDS)]
    assert data.terminal_replay(events) == []


# ---------- the session page ----------


def test_session_page_shows_the_replay_in_order(client, store):
    html = client.get(f"/session/{_ssh_session_id(store)}").text
    panel = _panel(html)
    assert "Terminal replay" in html
    assert panel.index("whoami") < panel.index("uname -a")
    assert "deploy@srv:~$" in panel
    assert 'class="term-prompt"' in panel and 'class="term-out"' in panel


def test_command_text_is_escaped(client, store):
    html = client.get(f"/session/{_ssh_session_id(store)}").text
    assert "echo &#34;&lt;script&gt;alert(1)&lt;/script&gt;&#34;" in html
    assert "<script>alert(1)" not in html


def test_output_is_escaped_too(client, store):
    html = client.get(f"/session/{_ssh_session_id(store)}").text
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<img src=x" not in html


def test_long_output_is_cut_and_the_cut_is_named(client, store):
    # Scoped to the panel: the timeline's raw-event view still holds the whole output, as before.
    panel = _panel(client.get(f"/session/{_ssh_session_id(store)}").text)
    assert "output cut for display: 2048 of 3000 characters shown" in panel
    assert "x" * 2048 in panel and "x" * 2049 not in panel


def test_an_old_256_preview_says_it_may_be_short(client, store):
    html = client.get(f"/session/{_ssh_session_id(store)}").text
    assert "the decoy keeps at most 256 characters; more may be missing" in html


def test_a_full_2048_preview_has_no_note(client, store):
    html = client.get(f"/session/{_ssh_session_id(store)}").text
    assert "z" * 2048 in html
    assert html.count("output cut for display") == 1


def test_ssh_session_without_commands_says_so(client, store):
    html = client.get(f"/session/{_ssh_session_id(store, src_ip=IDLE_IP)}").text
    assert "No commands ran in this session." in _panel(html)


def test_web_session_has_no_replay_panel(client, store):
    conn = db.connect(store)
    web_sid = next(r["session_id"] for r in data.list_findings(conn, {}) if r["service"] == "web")
    conn.close()
    html = client.get(f"/session/{web_sid}").text
    assert "Terminal replay" not in html


def test_replay_panel_has_no_inline_style(client, store):
    html = client.get(f"/session/{_ssh_session_id(store)}").text
    assert 'style="' not in _panel(html)
