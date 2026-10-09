"""The sample-data seed: a database that verifies, tells the story, and never overwrites."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from qlure.cli import main as cli
from qlure.store import db

ROOT = Path(__file__).resolve().parents[2]
KILL_CHAIN_IP = "198.51.100.77"


def _load_seed():
    spec = importlib.util.spec_from_file_location("seed_demo", ROOT / "tools" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed_demo = _load_seed()


def _rows(db_path: Path, sql: str, args: tuple = ()) -> list:
    conn = db.connect(db_path)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def _shape(db_path: Path) -> tuple:
    """Everything the counts depend on, without the random ids the decoys assign."""
    events = _rows(db_path, "SELECT COUNT(*) FROM events")[0][0]
    actors = _rows(db_path, "SELECT COUNT(*) FROM actors")[0][0]
    sessions = sorted(
        tuple(row)
        for row in _rows(
            db_path,
            "SELECT s.src_ip, s.service, f.verdict, f.score, f.rule_ids"
            " FROM sessions s JOIN findings f USING (session_id)",
        )
    )
    return events, actors, sessions


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    root = tmp_path_factory.mktemp("seed")
    db_path, logs = root / "demo.db", root / "logs"
    assert seed_demo.main(["--db", str(db_path), "--logs", str(logs)]) == 0
    return db_path, logs


def test_verify_passes_on_the_seeded_database(seeded, capsys):
    db_path, logs = seeded
    assert cli(["verify", "--logs", str(logs), "--db", str(db_path)]) == 0
    assert "chain verified" in capsys.readouterr().out


def test_at_least_three_actors_three_noteworthy_and_one_benign(seeded):
    db_path, _ = seeded
    actors = _rows(db_path, "SELECT COUNT(*) FROM actors")[0][0]
    verdicts = {
        verdict: count
        for verdict, count in _rows(db_path, "SELECT verdict, COUNT(*) FROM findings GROUP BY 1")
    }
    assert actors >= 3
    assert verdicts.get("Noteworthy", 0) >= 3
    assert verdicts.get("Benign", 0) >= 1


def test_kill_chain_actor_has_honeytoken_and_discovery_hits(seeded):
    db_path, _ = seeded
    [(actor_id,)] = _rows(
        db_path,
        "SELECT actor_id FROM sessions WHERE src_ip = ? AND service = 'ssh'",
        (KILL_CHAIN_IP,),
    )
    hits = set()
    for (rule_ids,) in _rows(
        db_path,
        "SELECT f.rule_ids FROM sessions s JOIN findings f USING (session_id) WHERE s.actor_id = ?",
        (actor_id,),
    ):
        hits |= set(json.loads(rule_ids))
    assert {"R7", "R8", "R9"} <= hits


def test_refuses_to_overwrite_without_force(seeded, capsys):
    db_path, logs = seeded
    before = _shape(db_path)
    lines = sorted(path.read_bytes() for path in logs.glob("*.jsonl"))
    assert seed_demo.main(["--db", str(db_path), "--logs", str(logs)]) == 1
    assert "--force" in capsys.readouterr().err
    assert _shape(db_path) == before
    assert sorted(path.read_bytes() for path in logs.glob("*.jsonl")) == lines


def test_force_replaces_the_database_with_the_same_counts(seeded):
    db_path, logs = seeded
    before = _shape(db_path)
    assert seed_demo.main(["--db", str(db_path), "--logs", str(logs), "--force"]) == 0
    assert _shape(db_path) == before


def test_two_fresh_runs_have_the_same_counts(tmp_path):
    shapes = []
    for name in ("first", "second"):
        target = tmp_path / name
        assert (
            seed_demo.main(["--db", str(target / "demo.db"), "--logs", str(target / "logs")]) == 0
        )
        shapes.append(_shape(target / "demo.db"))
    assert shapes[0] == shapes[1]


def test_prints_chain_line_and_dashboard_command(tmp_path, capsys):
    target = tmp_path / "out"
    assert seed_demo.main(["--db", str(target / "demo.db"), "--logs", str(target / "logs")]) == 0
    out = capsys.readouterr().out
    assert "chain verified:" in out
    assert "QLURE_DB=" in out and "QLURE_LOGS=" in out
    assert "QLURE_DASHBOARD_PASSWORD=choose-a-strong-password" in out


def test_refuses_when_logs_already_hold_events(tmp_path, capsys):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "web.jsonl").write_text("", encoding="utf-8")
    (logs / "old.jsonl").write_text('{"keep": true}\n', encoding="utf-8")
    assert seed_demo.main(["--db", str(tmp_path / "demo.db"), "--logs", str(logs)]) == 1
    assert (logs / "old.jsonl").read_text(encoding="utf-8") == '{"keep": true}\n'
