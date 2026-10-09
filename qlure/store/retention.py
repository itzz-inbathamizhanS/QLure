"""Retention: remove the oldest events from the store and the archive, keeping `verify` valid.

Only a contiguous prefix of the chain is ever removed. A retention anchor records the last
removed event's seq and hash, so the retained chain (which keeps its original prev_hash values)
still starts at a pinned point. See docs/RETENTION.md.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from qlure import settings as cfg
from qlure.events import Event
from qlure.store.chain import GENESIS, anchor_hash
from qlure.store.verify import verify

KEEP_LAST = 100
MIN_AGE = timedelta(days=1)
_AGE = re.compile(r"^(\d+)([dw])$")


class PruneError(RuntimeError):
    """The prune was refused; nothing was changed."""


def parse_age(text: str) -> timedelta:
    """`30d` or `4w`. Anything under one day is refused."""
    match = _AGE.match(text.strip().lower())
    if not match:
        raise PruneError(f"--older-than must look like 30d or 4w, not {text!r}")
    age = timedelta(days=int(match[1]) * (7 if match[2] == "w" else 1))
    if age < MIN_AGE:
        raise PruneError("--older-than must be at least 1d")
    return age


@dataclass
class PruneResult:
    pruned: int = 0
    kept: int = 0
    cutoff: str = ""
    anchor_seq: int | None = None
    anchor_hash: str | None = None
    oldest_kept: str | None = None
    newest_kept: str | None = None
    dry_run: bool = False
    files: dict[str, int] = field(default_factory=dict)  # file -> lines removed


def _when(ts: str) -> datetime:
    value = datetime.fromisoformat(ts)
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def prune(
    conn: sqlite3.Connection,
    log_dir: Path,
    older_than: timedelta,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
    who: str = "cli",
) -> PruneResult:
    if older_than < MIN_AGE:
        raise PruneError("--older-than must be at least 1d")
    cutoff = (now or datetime.now(UTC)) - older_than
    # The write lock first, like the forwarder, so no forwarder pass can interleave.
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        raise PruneError(f"store is busy: {exc}") from exc
    try:
        result = _prune_locked(conn, log_dir, cutoff, dry_run, who)
    except BaseException:
        conn.rollback()
        raise
    if dry_run or result.pruned == 0:
        conn.rollback()  # a real prune was committed by the audit row
    return result


def _prune_locked(
    conn: sqlite3.Connection, log_dir: Path, cutoff: datetime, dry_run: bool, who: str
) -> PruneResult:
    # Never bless a store that is already damaged: the anchor would hide the damage.
    _, problem = verify(conn, log_dir)
    if problem is not None:
        raise PruneError(f"refusing to prune: verify fails ({problem.reason}); run `qlure verify`")
    rows = conn.execute("SELECT seq, event_id, ts, hash FROM events ORDER BY seq").fetchall()
    eligible = max(len(rows) - KEEP_LAST, 0)
    n = 0
    while n < eligible and _when(rows[n]["ts"]) < cutoff:  # a prefix: stop at the first newer one
        n += 1
    result = PruneResult(pruned=n, kept=len(rows) - n, cutoff=cutoff.isoformat(), dry_run=dry_run)
    if n == 0:
        return result
    last = rows[n - 1]
    result.anchor_seq, result.anchor_hash = last["seq"], last["hash"]
    result.oldest_kept, result.newest_kept = rows[n]["ts"], rows[-1]["ts"]
    gone = {row["event_id"] for row in rows[:n]}
    if dry_run:
        result.files = _rewrite_archive(log_dir, gone, conn, write=False)
        return result

    conn.execute("DELETE FROM events WHERE seq<=?", (last["seq"],))
    _drop_orphans(conn, gone)
    prev = conn.execute(
        "SELECT hash, total_pruned FROM retention_anchors ORDER BY anchor_id DESC LIMIT 1"
    ).fetchone()
    anchor = {
        "prev_anchor": prev["hash"] if prev else GENESIS,
        "upto_seq": last["seq"],
        "upto_hash": last["hash"],
        "ts": datetime.now(UTC).isoformat(),
        "cutoff": cutoff.isoformat(),
        "pruned": n,
        "total_pruned": (prev["total_pruned"] if prev else 0) + n,
    }
    conn.execute(
        "INSERT INTO retention_anchors (prev_anchor, upto_seq, upto_hash, ts, cutoff, pruned,"
        " total_pruned, hash) VALUES (?,?,?,?,?,?,?,?)",
        (*(anchor[k] for k in anchor), anchor_hash(anchor)),
    )
    result.files = _rewrite_archive(log_dir, gone, conn, write=True)
    # audit() commits, which also commits the deletes and the anchor above.
    cfg.audit(
        conn,
        who,
        "data.prune",
        {"events": len(rows)},
        {"events": len(rows) - n, "pruned": n, "anchor_seq": last["seq"], "anchor": last["hash"]},
        "applied",
        f"older than {cutoff.isoformat()}",
    )
    return result


def _drop_orphans(conn: sqlite3.Connection, gone: set[str]) -> None:
    """Sessions (and their findings and actors) made only of removed events. Rebuildable."""
    dead_sessions: set[str] = set()
    for row in conn.execute("SELECT session_id, event_ids FROM sessions").fetchall():
        ids = json.loads(row["event_ids"] or "[]")
        if ids and all(i in gone for i in ids):
            dead_sessions.add(row["session_id"])
    for sid in dead_sessions:
        conn.execute("DELETE FROM sessions WHERE session_id=?", (sid,))
        conn.execute("DELETE FROM findings WHERE session_id=?", (sid,))
    for row in conn.execute("SELECT actor_id, session_ids FROM actors").fetchall():
        ids = json.loads(row["session_ids"] or "[]")
        if ids and all(i in dead_sessions for i in ids):
            conn.execute("DELETE FROM actors WHERE actor_id=?", (row["actor_id"],))


def _rewrite_archive(
    log_dir: Path, gone: set[str], conn: sqlite3.Connection, *, write: bool
) -> dict[str, int]:
    """Drop the removed events' lines from each JSONL file; every other byte stays as it was."""
    removed: dict[str, int] = {}
    pending: list[tuple[Path, Path, int, int]] = []
    try:
        for path in sorted(log_dir.glob("*.jsonl")):
            data = path.read_bytes()
            state = conn.execute(
                "SELECT offset FROM forwarder_state WHERE file=?", (path.name,)
            ).fetchone()
            offset = state["offset"] if state else 0
            kept: list[bytes] = []
            dropped = dropped_in_offset = pos = 0
            for line in data.splitlines(keepends=True):
                pos += len(line)
                if line.endswith(b"\n") and _event_id(line) in gone:
                    dropped += 1
                    if pos <= offset:
                        dropped_in_offset += len(line)
                    continue
                kept.append(line)
            if not dropped:
                continue
            removed[path.name] = dropped
            if write:
                tmp = path.with_name(f".{path.name}.prune")
                tmp.write_bytes(b"".join(kept))
                shutil.copymode(path, tmp)
                pending.append((path, tmp, len(data), dropped_in_offset))
        for path, tmp, size, shrink in pending:
            with path.open("rb") as fh:  # a decoy may have appended meanwhile: carry it over
                fh.seek(size)
                tail = fh.read()
            with tmp.open("ab") as out:
                out.write(tail)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, path)
            conn.execute(
                "UPDATE forwarder_state SET offset=offset-? WHERE file=?", (shrink, path.name)
            )
    finally:
        for _, tmp, _, _ in pending:
            tmp.unlink(missing_ok=True)
    return removed


def _event_id(line: bytes) -> str | None:
    try:
        return Event.model_validate_json(line).event_id
    except ValidationError:
        return None
