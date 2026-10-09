"""Read events from the store and write correlation results back."""

from __future__ import annotations

import json
import sqlite3

from qlure.correlate.engine import Result, correlate
from qlure.events import Event


def load_events(conn: sqlite3.Connection) -> list[Event]:
    rows = conn.execute("SELECT raw FROM events ORDER BY seq")
    return [Event.model_validate_json(row["raw"]) for row in rows]


def save(conn: sqlite3.Connection, result: Result) -> None:
    actor_of = {s.session_id: a.actor_id for a in result.actors for s in a.sessions}
    for table in ("findings", "sessions", "actors"):
        conn.execute(f"DELETE FROM {table}")  # noqa: S608  (fixed table names)
    for actor in result.actors:
        conn.execute(
            "INSERT INTO actors VALUES (?,?,?,?)",
            (
                actor.actor_id,
                actor.start.isoformat(),
                actor.end.isoformat(),
                json.dumps([s.session_id for s in actor.sessions]),
            ),
        )
    for s in result.sessions:
        conn.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
            (
                s.session_id,
                actor_of[s.session_id],
                s.service,
                s.src_ip,
                s.client_fp,
                s.start.isoformat(),
                s.end.isoformat(),
                json.dumps(s.event_ids),
            ),
        )
    for f in result.findings:
        hits = [
            {
                "rule_id": h.rule_id,
                "name": h.name,
                "family": h.family,
                "weight": h.weight,
                "confidence": h.confidence,
                "attack": list(h.attack),
                "measured": h.measured,
                "threshold": h.threshold,
                "evidence": list(h.evidence),
            }
            for h in f.hits
        ]
        conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
            (
                f.session.session_id,
                f.actor_id,
                f.verdict,
                f.score,
                json.dumps(f.families),
                json.dumps(sorted({h.rule_id for h in f.hits}, key=lambda r: int(r[1:]))),
                json.dumps(hits),
                json.dumps(f.suppressors),
                f.explanation,
            ),
        )
    conn.commit()


def run(conn: sqlite3.Connection) -> Result:
    result = correlate(load_events(conn))
    save(conn, result)
    return result
