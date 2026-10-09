"""Forwarder: tails the decoys' JSONL files and is the only writer to the store."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from pydantic import ValidationError

from qlure.events import Event
from qlure.store.chain import GENESIS, canonical, link_hash


def _last_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    return row["hash"] if row else GENESIS


def forward_once(conn: sqlite3.Connection, log_dir: Path) -> tuple[int, int]:
    """Ingest every new complete line. Returns (events stored, lines rejected)."""
    stored = rejected = 0
    prev = _last_hash(conn)
    for path in sorted(log_dir.glob("*.jsonl")):
        row = conn.execute(
            "SELECT offset FROM forwarder_state WHERE file=?", (path.name,)
        ).fetchone()
        offset = row["offset"] if row else 0
        with path.open("rb") as fh:
            fh.seek(offset)
            while True:
                line = fh.readline()
                if not line.endswith(b"\n"):
                    break  # empty, or a line the decoy is still writing
                offset += len(line)
                if not line.strip():
                    continue
                try:
                    event = Event.model_validate_json(line)
                except ValidationError:
                    rejected += 1
                    continue
                raw = canonical(event)
                digest = link_hash(prev, raw)
                cur = conn.execute(
                    "INSERT OR IGNORE INTO events (event_id, ts, replay_ts, service, src_ip,"
                    " session_id, actor_id, action, honeytoken_id, raw, prev_hash, hash)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.event_id,
                        event.ts.isoformat(),
                        event.replay_ts.isoformat() if event.replay_ts else None,
                        event.service.value,
                        event.src_ip,
                        event.session_id,
                        event.actor_id,
                        event.action.value,
                        event.honeytoken_id,
                        raw,
                        prev,
                        digest,
                    ),
                )
                if cur.rowcount:
                    prev = digest
                    stored += 1
        conn.execute(
            "INSERT INTO forwarder_state (file, offset) VALUES (?, ?)"
            " ON CONFLICT(file) DO UPDATE SET offset=excluded.offset",
            (path.name, offset),
        )
    conn.commit()
    return stored, rejected


def follow(conn: sqlite3.Connection, log_dir: Path, interval: float = 1.0) -> None:
    while True:
        forward_once(conn, log_dir)
        time.sleep(interval)
