"""Verify the store against itself and against the JSONL archive."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from qlure.events import Event
from qlure.store.chain import GENESIS, anchor_hash, canonical, config_hash, link_hash


@dataclass(frozen=True)
class Problem:
    seq: int
    event_id: str
    reason: str


def check_anchors(conn: sqlite3.Connection) -> tuple[list[sqlite3.Row], Problem | None]:
    """The retention anchors must form one hash-linked, non-decreasing history."""
    rows = conn.execute("SELECT * FROM retention_anchors ORDER BY anchor_id").fetchall()
    prev, last_seq, total = GENESIS, 0, 0
    for row in rows:
        where = f"retention anchor #{row['anchor_id']}"
        problem = None
        if row["prev_anchor"] != prev:
            problem = "anchor history broken: an earlier anchor was removed"
        elif anchor_hash(dict(row)) != row["hash"]:
            problem = "anchor was edited after it was written"
        elif row["upto_seq"] <= last_seq:
            problem = "anchor does not move forward"
        elif row["pruned"] < 1 or row["total_pruned"] != total + row["pruned"]:
            problem = "anchor counts are inconsistent"
        if problem:
            return rows, Problem(row["upto_seq"], where, problem)
        prev, last_seq, total = row["hash"], row["upto_seq"], row["total_pruned"]
    return rows, None


def retention_summary(conn: sqlite3.Connection) -> tuple[int, str] | None:
    """(events pruned in total, newest cutoff) or None if nothing was ever pruned."""
    row = conn.execute(
        "SELECT total_pruned, cutoff FROM retention_anchors ORDER BY anchor_id DESC LIMIT 1"
    ).fetchone()
    return (row["total_pruned"], row["cutoff"]) if row else None


def _archive(log_dir: Path) -> dict[str, str]:
    """event_id -> canonical JSON of what the JSONL files say today."""
    found: dict[str, str] = {}
    for path in sorted(log_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = Event.model_validate_json(line)
            except ValidationError:
                continue
            found[event.event_id] = canonical(event)
    return found


def verify(conn: sqlite3.Connection, log_dir: Path) -> tuple[int, Problem | None]:
    """Walk the chain in order. Returns (events checked, first problem or None).

    Checks each link's hash, that the stored event still matches the archived line,
    and that the line has not been deleted.
    """
    archive = _archive(log_dir)
    anchors, anchor_problem = check_anchors(conn)
    if anchor_problem is not None:
        return 0, anchor_problem
    prev = anchors[-1]["upto_hash"] if anchors else GENESIS
    anchor_seq = anchors[-1]["upto_seq"] if anchors else 0
    checked = 0
    for row in conn.execute("SELECT seq, event_id, raw, prev_hash, hash FROM events ORDER BY seq"):
        seq, event_id = row["seq"], row["event_id"]
        if seq <= anchor_seq:
            return checked, Problem(seq, event_id, "event is older than the retention anchor")
        if row["prev_hash"] != prev:
            return checked, Problem(
                seq, event_id, "chain link broken: an earlier event was removed"
            )
        if link_hash(prev, row["raw"]) != row["hash"]:
            return checked, Problem(seq, event_id, "stored event does not match its hash")
        archived = archive.get(event_id)
        if archived is None:
            return checked, Problem(seq, event_id, "event is missing from the JSONL archive")
        if archived != row["raw"]:
            return checked, Problem(seq, event_id, "JSONL line was edited after it was stored")
        prev = row["hash"]
        checked += 1
    removed = _removed_from_store(conn, log_dir)
    if removed is not None:
        if removed.endswith("archive file is missing") or "shorter than" in removed:
            return checked, Problem(0, removed, "JSONL archive file was deleted or truncated")
        return checked, Problem(0, removed, "event was removed from the store")
    return checked, None


def _removed_from_store(conn: sqlite3.Connection, log_dir: Path) -> str | None:
    """An archived event the forwarder already read that the store no longer holds.

    The chain alone cannot show that the newest rows were deleted: what is left still links up.
    The forwarder's offsets say how far each file was ingested, so every valid line before that
    point must still be in `events`.
    """
    stored = {row["event_id"] for row in conn.execute("SELECT event_id FROM events")}
    for row in conn.execute("SELECT file, offset FROM forwarder_state ORDER BY file"):
        path = log_dir / row["file"]
        if not path.is_file():
            return f"{row['file']}: archive file is missing"
        if path.stat().st_size < row["offset"]:
            return f"{row['file']}: archive file is shorter than what was ingested"
        with path.open("rb") as fh:
            ingested = fh.read(row["offset"])
        for line in ingested.splitlines():
            if not line.strip():
                continue
            try:
                event = Event.model_validate_json(line)
            except ValidationError:
                continue  # the forwarder rejected it too
            if event.event_id not in stored:
                return event.event_id
    return None


@dataclass(frozen=True)
class ConfigProblem:
    audit_id: int
    reason: str


def verify_config(conn: sqlite3.Connection) -> tuple[int, int, ConfigProblem | None]:
    """Walk config_audit in order. Returns (chained rows checked, legacy rows, first problem).

    Rows written before chaining (empty hash) may only come first. Editing a row, or removing
    a row from the middle, breaks the chain at that point. Removing the newest row cannot be
    seen from the chain alone; signed checkpoints are the place to pin the head.
    """
    prev = GENESIS
    chained = False
    checked = 0
    legacy = 0
    for row in conn.execute("SELECT * FROM config_audit ORDER BY audit_id"):
        if not row["hash"]:
            if chained:
                return (
                    checked,
                    legacy,
                    ConfigProblem(row["audit_id"], "unchained row after chained rows"),
                )
            legacy += 1
            continue
        chained = True
        if row["prev_hash"] != prev:
            return (
                checked,
                legacy,
                ConfigProblem(row["audit_id"], "chain link broken: an earlier change was removed"),
            )
        if config_hash(prev, dict(row)) != row["hash"]:
            return (
                checked,
                legacy,
                ConfigProblem(row["audit_id"], "row was edited after it was written"),
            )
        prev = row["hash"]
        checked += 1
    return checked, legacy, None
