"""`qlure prune`: old events leave the store and the archive, and `verify` keeps working."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from qlure import settings as cfg
from qlure.cli import main as cli
from qlure.events import Action, Service, emit
from qlure.store import db, forwarder, retention
from qlure.store.verify import verify, verify_config

NOW = datetime(2026, 6, 1, tzinfo=UTC)
CLEARED = ("events", "sessions", "actors", "findings", "forwarder_state", "labels", "checkpoints")


def _emit(i, age_days, service=Service.WEB):
    return emit(
        {
            "service": service,
            "src_ip": "192.0.2.10",
            "session_id": f"s{i % 7}",
            "action": Action.HTTP_REQUEST,
            "request": {"method": "GET", "path": f"/p{i}"},
            "ts": NOW - timedelta(days=age_days, seconds=-i),
        }
    )


@pytest.fixture
def store(log_dir, tmp_path):
    """60 events 40 days old, then 120 from the last 3 days, over two services."""
    conn = db.connect(tmp_path / "store" / "q.db")
    for batch in (range(60), range(60, 180)):  # the chain follows forwarding order, not ts
        for i in batch:
            _emit(i, 40 if i < 60 else 3, Service.WEB if i % 2 else Service.API)
        forwarder.forward_once(conn, log_dir)
    assert verify(conn, log_dir) == (180, None)
    return conn


def _prune(conn, log_dir, age="30d", **kw):
    return retention.prune(conn, log_dir, retention.parse_age(age), now=NOW, **kw)


def _lines(log_dir):
    return sum(len(p.read_text().splitlines()) for p in log_dir.glob("*.jsonl"))


def test_prune_removes_old_events_everywhere_and_verify_passes(store, log_dir):
    before = {p.name: p.read_text().splitlines() for p in log_dir.glob("*.jsonl")}
    result = _prune(store, log_dir)
    assert (result.pruned, result.kept) == (60, 120)
    assert store.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 120
    assert _lines(log_dir) == 120
    assert verify(store, log_dir) == (120, None)
    # retained lines are byte-for-byte the originals, in order
    for name, old in before.items():
        new = (log_dir / name).read_text().splitlines()
        assert new == [x for x in old if x in set(new)]
    assert store.execute("SELECT COUNT(*) FROM retention_anchors").fetchone()[0] == 1
    assert verify_config(store) == (1, 0, None)
    assert store.execute("SELECT key FROM config_audit").fetchone()[0] == "data.prune"


def test_forwarder_keeps_working_and_offsets_match_file_sizes(store, log_dir):
    _prune(store, log_dir)
    for row in store.execute("SELECT file, offset FROM forwarder_state"):
        assert row["offset"] == (log_dir / row["file"]).stat().st_size
    assert forwarder.forward_once(store, log_dir) == (0, 0)
    _emit(500, 0)
    assert forwarder.forward_once(store, log_dir) == (1, 0)
    assert verify(store, log_dir) == (121, None)


def test_second_prune_and_anchor_history(store, log_dir):
    _prune(store, log_dir)
    # nothing more is old enough
    assert _prune(store, log_dir).pruned == 0
    later = retention.prune(store, log_dir, timedelta(days=1), now=NOW + timedelta(days=30))
    assert later.pruned == 20  # the last 100 events are never pruned
    assert verify(store, log_dir) == (100, None)
    rows = store.execute("SELECT total_pruned FROM retention_anchors ORDER BY anchor_id").fetchall()
    assert [r[0] for r in rows] == [60, 80]


def test_never_prunes_the_last_hundred_or_young_events(store, log_dir):
    result = retention.prune(store, log_dir, timedelta(days=1), now=NOW + timedelta(days=999))
    assert (result.pruned, result.kept) == (80, 100)
    assert verify(store, log_dir) == (100, None)


def test_dry_run_changes_nothing(store, log_dir):
    snapshot = {p.name: p.read_bytes() for p in log_dir.glob("*.jsonl")}
    result = _prune(store, log_dir, dry_run=True)
    assert result.pruned == 60 and result.anchor_hash
    assert store.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 180
    assert {p.name: p.read_bytes() for p in log_dir.glob("*.jsonl")} == snapshot
    assert store.execute("SELECT COUNT(*) FROM retention_anchors").fetchone()[0] == 0
    assert not store.in_transaction


def test_orphaned_sessions_findings_and_actors_go(store, log_dir):
    old = [r[0] for r in store.execute("SELECT event_id FROM events ORDER BY seq LIMIT 60")]
    recent = [
        r[0] for r in store.execute("SELECT event_id FROM events ORDER BY seq LIMIT 1 OFFSET 100")
    ]
    store.executemany(
        "INSERT INTO sessions (session_id, event_ids) VALUES (?,?)",
        [("dead", json.dumps(old)), ("live", json.dumps(old + recent))],
    )
    store.execute(
        "INSERT INTO findings (session_id, verdict, score, explanation)"
        " VALUES ('dead','Benign',0,'x')"
    )
    store.execute("INSERT INTO actors (actor_id, session_ids) VALUES ('a1', '[\"dead\"]')")
    store.commit()
    _prune(store, log_dir)
    assert [r[0] for r in store.execute("SELECT session_id FROM sessions")] == ["live"]
    assert store.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert store.execute("SELECT COUNT(*) FROM actors").fetchone()[0] == 0


# ---- tamper detection -------------------------------------------------------------------


@pytest.fixture
def pruned(store, log_dir):
    _prune(store, log_dir)
    return store


def test_tamper_modified_retained_event_fails(pruned, log_dir):
    pruned.execute(
        "UPDATE events SET raw = replace(raw, '/p100', '/pXXX') WHERE raw LIKE '%/p100\"%'"
    )
    pruned.commit()
    assert verify(pruned, log_dir)[1] is not None


def test_tamper_deleted_retained_event_fails(pruned, log_dir):
    pruned.execute(
        "DELETE FROM events WHERE seq=(SELECT seq FROM events ORDER BY seq LIMIT 1 OFFSET 40)"
    )
    pruned.commit()
    assert verify(pruned, log_dir)[1] is not None


def test_tamper_deleting_first_retained_event_fails(pruned, log_dir):
    pruned.execute("DELETE FROM events WHERE seq=(SELECT MIN(seq) FROM events)")
    pruned.commit()
    assert "link" in verify(pruned, log_dir)[1].reason


def test_tamper_altered_anchor_hash_fails(pruned, log_dir):
    pruned.execute("UPDATE retention_anchors SET upto_hash = ?", ("f" * 64,))
    pruned.commit()
    problem = verify(pruned, log_dir)[1]
    assert problem is not None and "anchor" in problem.reason


def test_tamper_rehashed_anchor_still_fails_against_the_chain(pruned, log_dir):
    from qlure.store.chain import anchor_hash

    row = dict(pruned.execute("SELECT * FROM retention_anchors").fetchone())
    row["upto_hash"] = "f" * 64
    pruned.execute(
        "UPDATE retention_anchors SET upto_hash=?, hash=?", (row["upto_hash"], anchor_hash(row))
    )
    pruned.commit()
    assert "link" in verify(pruned, log_dir)[1].reason


def test_tamper_removed_anchor_fails(store, log_dir):
    _prune(store, log_dir)
    retention.prune(store, log_dir, timedelta(days=1), now=NOW + timedelta(days=30))
    store.execute(
        "DELETE FROM retention_anchors"
        " WHERE anchor_id=(SELECT MAX(anchor_id) FROM retention_anchors)"
    )
    store.commit()
    assert verify(store, log_dir)[1] is not None
    store.execute("DELETE FROM retention_anchors")
    store.commit()
    assert verify(store, log_dir)[1] is not None


def test_tamper_events_removed_without_anchor_fails(store, log_dir):
    store.execute("DELETE FROM events WHERE seq<=60")
    store.commit()
    assert "link" in verify(store, log_dir)[1].reason


def test_tamper_truncated_archive_fails(pruned, log_dir):
    path = log_dir / "web.jsonl"
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:-5]))
    assert verify(pruned, log_dir)[1] is not None


def test_prune_refuses_a_store_that_already_fails_verify(store, log_dir):
    store.execute("UPDATE events SET raw = raw || ' ' WHERE seq=100")
    store.commit()
    with pytest.raises(retention.PruneError, match="verify fails"):
        _prune(store, log_dir)
    assert store.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 180


# ---- other lifecycle --------------------------------------------------------------------


def test_prune_then_clear_all_then_new_events_verifies(pruned, log_dir):
    for table in CLEARED:
        pruned.execute(f"DELETE FROM {table}")  # noqa: S608
    for path in log_dir.glob("*.jsonl"):
        path.write_text("")
    pruned.commit()
    assert verify(pruned, log_dir) == (0, None)
    _emit(900, 0)
    _emit(901, 0)
    assert forwarder.forward_once(pruned, log_dir) == (2, 0)
    assert verify(pruned, log_dir) == (2, None)


def test_signed_checkpoints_before_the_cut_stay_valid(store, log_dir, tmp_path):
    from qlure.pqc import signing

    try:
        signing._oqs()
    except signing.SigningUnavailable:
        pytest.skip("liboqs is not installed")
    private, public = signing.keygen(tmp_path / "signing")
    signing.sign(store, private, public, every=30)
    assert signing.verify_checkpoints(store, public).problem is None
    _prune(store, log_dir)
    result = signing.verify_checkpoints(store, public)
    assert result.problem is None and result.checked == 6
    store.execute("UPDATE retention_anchors SET upto_hash=?", ("a" * 64,))  # anchor at seq 60
    store.commit()
    assert "anchor" in signing.verify_checkpoints(store, public).problem


def test_cli_requires_yes_and_enforces_floor(store, log_dir, tmp_path, capsys):
    db_path = str(tmp_path / "store" / "q.db")
    base = ["prune", "--db", db_path, "--logs", str(log_dir)]
    assert cli([*base, "--older-than", "30d"]) == 1
    assert "--yes" in capsys.readouterr().err
    assert cli([*base, "--older-than", "0d", "--yes"]) == 1
    assert cli([*base, "--older-than", "12h", "--yes"]) == 1
    assert store.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 180
    # real clock: every seeded event is ~2026-04..06, so a 1d cut keeps only the last 100
    assert cli([*base, "--older-than", "1d", "--dry-run"]) == 0
    assert cli([*base, "--older-than", "1d", "--yes"]) == 0
    assert cli(["verify", "--db", db_path, "--logs", str(log_dir)]) == 0
    out = capsys.readouterr().out
    assert "80 pruned before" in out and "(anchor ok)" in out


def test_retention_days_zero_is_a_valid_audited_setting(tmp_path):
    conn = db.connect(tmp_path / "q.db")
    path = tmp_path / "settings.json"
    assert cfg.apply_change(conn, "admin", {"retention_days": 0}, path)[0]
    assert not cfg.apply_change(conn, "admin", {"retention_days": 366}, path)[0]
    assert verify_config(conn)[2] is None
