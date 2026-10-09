"""SQLite store (WAL mode). The JSONL files are the archive; this is the query index."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    ts           TEXT NOT NULL,
    replay_ts    TEXT,
    service      TEXT NOT NULL,
    src_ip       TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    actor_id     TEXT,
    action       TEXT NOT NULL,
    honeytoken_id TEXT,
    raw          TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS events_honeytoken ON events(honeytoken_id);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS forwarder_state (
    file   TEXT PRIMARY KEY,
    offset INTEGER NOT NULL
);

-- Written by `qlure correlate`; everything here can be rebuilt from `events`.
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY, actor_id TEXT, service TEXT, src_ip TEXT, client_fp TEXT,
    first_seen TEXT, last_seen TEXT, event_ids TEXT
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, session_ids TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    session_id TEXT PRIMARY KEY, actor_id TEXT, verdict TEXT NOT NULL, score INTEGER NOT NULL,
    families TEXT, rule_ids TEXT, hits TEXT, suppressors TEXT, explanation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS honeytokens (
    honeytoken_id TEXT PRIMARY KEY, kind TEXT, planted_in TEXT
);
CREATE TABLE IF NOT EXISTS config_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, who TEXT NOT NULL,
    key TEXT NOT NULL, old_value TEXT, new_value TEXT
);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _migrate(conn)
    conn.executescript(SCHEMA)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Phase 2 created empty placeholder tables; replace them with the Phase 3 layout."""
    for table, marker in (
        ("sessions", "event_ids"),
        ("actors", "session_ids"),
        ("findings", "hits"),
    ):
        columns = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]
        if columns and marker not in columns:
            conn.execute(f"DROP TABLE {table}")
