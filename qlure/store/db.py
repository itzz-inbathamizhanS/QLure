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

-- Filled in by later phases; created now so the layout is fixed.
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY, service TEXT, src_ip TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
    verdict TEXT NOT NULL, score INTEGER NOT NULL, explanation TEXT NOT NULL
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
    conn.executescript(SCHEMA)
    return conn
