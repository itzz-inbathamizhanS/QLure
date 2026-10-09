import json

import pytest

from qlure.cli import main as cli
from qlure.events import Action, Service, emit
from qlure.store import db, forwarder
from qlure.store.verify import verify


def _emit(action, service=Service.WEB, **extra):
    return emit(
        {
            "service": service,
            "src_ip": "192.0.2.10",
            "session_id": "s1",
            "action": action,
            **extra,
        }
    )


@pytest.fixture
def conn(tmp_path):
    return db.connect(tmp_path / "store" / "qlure.db")


def _fill(log_dir):
    for i in range(3):
        _emit(Action.HTTP_REQUEST, request={"path": f"/p{i}"})
    _emit(Action.CONNECT, Service.SSH)
    _emit(Action.COMMAND, Service.SSH, request={"command": "whoami"})


def test_forwarder_stores_every_event_in_wal_mode(log_dir, conn):
    _fill(log_dir)
    assert forwarder.forward_once(conn, log_dir) == (5, 0)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 5
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_forwarder_resumes_without_duplicates(log_dir, conn):
    _emit(Action.CONNECT)
    forwarder.forward_once(conn, log_dir)
    assert forwarder.forward_once(conn, log_dir) == (0, 0)
    _emit(Action.DISCONNECT)
    assert forwarder.forward_once(conn, log_dir) == (1, 0)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2


def test_forwarder_skips_a_half_written_line_and_picks_it_up_later(log_dir, conn):
    path = log_dir / "web.jsonl"
    _emit(Action.CONNECT)
    full = path.read_text()
    path.write_text(full + full.splitlines()[0][:40])  # no newline yet
    assert forwarder.forward_once(conn, log_dir) == (1, 0)


def test_forwarder_rejects_invalid_lines_but_keeps_going(log_dir, conn):
    _emit(Action.CONNECT)
    with (log_dir / "web.jsonl").open("a") as fh:
        fh.write(json.dumps({"action": "connect"}) + "\n")
    _emit(Action.DISCONNECT)
    assert forwarder.forward_once(conn, log_dir) == (2, 1)


def test_untouched_archive_verifies(log_dir, conn):
    _fill(log_dir)
    forwarder.forward_once(conn, log_dir)
    assert verify(conn, log_dir) == (5, None)


def test_editing_one_jsonl_line_fails_verify_at_that_event(log_dir, conn):
    _fill(log_dir)
    forwarder.forward_once(conn, log_dir)
    path = log_dir / "web.jsonl"
    lines = path.read_text().splitlines()
    victim = json.loads(lines[1])
    victim["request"]["path"] = "/innocent"
    lines[1] = json.dumps(victim)
    path.write_text("\n".join(lines) + "\n")

    checked, problem = verify(conn, log_dir)
    assert problem is not None
    assert problem.event_id == victim["event_id"]
    assert "edited" in problem.reason
    assert checked == 3  # the two ssh events and the first web event come before it


def test_deleting_one_jsonl_line_fails_verify_at_that_event(log_dir, conn):
    _fill(log_dir)
    forwarder.forward_once(conn, log_dir)
    path = log_dir / "web.jsonl"
    lines = path.read_text().splitlines()
    gone = json.loads(lines[0])["event_id"]
    path.write_text("\n".join(lines[1:]) + "\n")

    _, problem = verify(conn, log_dir)
    assert problem is not None
    assert problem.event_id == gone
    assert "missing" in problem.reason


def test_tampering_with_the_store_breaks_the_chain(log_dir, conn):
    _fill(log_dir)
    forwarder.forward_once(conn, log_dir)
    conn.execute("DELETE FROM events WHERE seq=2")
    conn.commit()
    _, problem = verify(conn, log_dir)
    assert problem is not None
    assert problem.seq == 3
    assert "chain link broken" in problem.reason


def test_cli_forward_then_verify(log_dir, tmp_path, capsys):
    _fill(log_dir)
    db_path = str(tmp_path / "cli.db")
    assert cli(["forward", "--logs", str(log_dir), "--db", db_path]) == 0
    assert "stored 5" in capsys.readouterr().out
    assert cli(["verify", "--logs", str(log_dir), "--db", db_path]) == 0
    assert "5 events intact" in capsys.readouterr().out

    path = log_dir / "ssh.jsonl"
    path.write_text(path.read_text().replace("whoami", "ls"))
    assert cli(["verify", "--logs", str(log_dir), "--db", db_path]) == 1
    assert "VERIFY FAILED" in capsys.readouterr().err
