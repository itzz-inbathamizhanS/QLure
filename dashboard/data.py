"""Reads for the session view. Everything here comes from the SQLite store."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from qlure.events import Event

GAP_SECONDS = 60
FAMILY_ORDER = ["recon", "credential", "exploit", "misuse", "chain"]


def _loads(text: str | None, default: Any) -> Any:
    return json.loads(text) if text else default


def _first_agent(conn: sqlite3.Connection, event_ids: list[str]) -> str:
    for event_id in event_ids[:5]:
        row = conn.execute("SELECT raw FROM events WHERE event_id=?", (event_id,)).fetchone()
        if row:
            headers = (json.loads(row["raw"]).get("request") or {}).get("headers") or {}
            if headers.get("user-agent"):
                return str(headers["user-agent"])
    return ""


def list_findings(conn: sqlite3.Connection, filters: dict[str, str]) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT f.*, s.service, s.src_ip, s.first_seen, s.last_seen, s.event_ids,"
        " l.label AS label FROM findings f JOIN sessions s ON s.session_id = f.session_id"
        " LEFT JOIN labels l ON l.session_id = f.session_id"
    ).fetchall()
    sessions_per_actor: dict[str, int] = {}
    services_per_actor: dict[str, set[str]] = {}
    for row in rows:
        sessions_per_actor[row["actor_id"]] = sessions_per_actor.get(row["actor_id"], 0) + 1
        services_per_actor.setdefault(row["actor_id"], set()).add(row["service"])

    token_events: set[str] = set()
    if filters.get("honeytoken"):
        token_events = {
            r["event_id"]
            for r in conn.execute(
                "SELECT event_id FROM events WHERE honeytoken_id=?", (filters["honeytoken"],)
            )
        }

    out = []
    for row in rows:
        rule_ids = _loads(row["rule_ids"], [])
        event_ids = _loads(row["event_ids"], [])
        if filters.get("verdict") and row["verdict"] != filters["verdict"]:
            continue
        if filters.get("service") and row["service"] != filters["service"]:
            continue
        if filters.get("rule") and filters["rule"] not in rule_ids:
            continue
        if filters.get("actor") and row["actor_id"] != filters["actor"]:
            continue
        if filters.get("since") and row["last_seen"] < filters["since"]:
            continue
        if filters.get("until") and row["first_seen"] > filters["until"]:
            continue
        if filters.get("honeytoken") and not token_events.intersection(event_ids):
            continue
        out.append(
            {
                "session_id": row["session_id"],
                "verdict": row["verdict"],
                "score": row["score"],
                "actor_id": row["actor_id"],
                "actor_sessions": sessions_per_actor[row["actor_id"]],
                "services": sorted(services_per_actor[row["actor_id"]]),
                "service": row["service"],
                "src_ip": row["src_ip"],
                "agent": _first_agent(conn, event_ids)[:48],
                "rules": rule_ids,
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "label": row["label"] or "unreviewed",
            }
        )
    key = filters.get("sort", "score")
    if key == "time":
        out.sort(key=lambda r: r["first_seen"], reverse=True)
    else:
        out.sort(key=lambda r: (-r["score"], r["first_seen"]))
    return out


def filter_options(conn: sqlite3.Connection) -> dict[str, list[str]]:
    def column(sql: str) -> list[str]:
        return [r[0] for r in conn.execute(sql) if r[0]]

    return {
        "services": column("SELECT DISTINCT service FROM sessions ORDER BY 1"),
        "actors": column("SELECT DISTINCT actor_id FROM findings ORDER BY 1"),
        "honeytokens": column("SELECT DISTINCT honeytoken_id FROM events ORDER BY 1"),
        "rules": [f"R{i}" for i in range(1, 11)],
        "verdicts": ["Noteworthy", "Suspicious", "Benign"],
    }


def session_detail(conn: sqlite3.Connection, session_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT f.*, s.service, s.src_ip, s.client_fp, s.first_seen, s.last_seen, s.event_ids"
        " FROM findings f JOIN sessions s ON s.session_id = f.session_id WHERE f.session_id=?",
        (session_id,),
    ).fetchone()
    if row is None:
        return None
    hits = _loads(row["hits"], [])
    event_family: dict[str, set[str]] = {}
    for hit in hits:
        for event_id in hit["evidence"]:
            event_family.setdefault(event_id, set()).add(hit["family"])

    events: list[dict[str, Any]] = []
    previous: datetime | None = None
    for event_id in _loads(row["event_ids"], []):
        stored = conn.execute(
            "SELECT raw, prev_hash, hash FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        if stored is None:
            continue
        event = Event.model_validate_json(stored["raw"])
        moment = event.replay_ts or event.ts
        gap = int((moment - previous).total_seconds()) if previous else 0
        previous = moment
        families = sorted(event_family.get(event_id, ()), key=FAMILY_ORDER.index)
        events.append(
            {
                "event": event,
                "raw": json.dumps(json.loads(stored["raw"]), indent=2, sort_keys=True),
                "prev_hash": stored["prev_hash"],
                "hash": stored["hash"],
                "families": families,
                "family": families[0] if families else "none",
                "gap": gap if gap > GAP_SECONDS else 0,
                "summary": summarize(event),
            }
        )

    linked = conn.execute(
        "SELECT f.session_id, f.verdict, f.score, s.service FROM findings f"
        " JOIN sessions s ON s.session_id = f.session_id"
        " WHERE f.actor_id=? AND f.session_id<>? ORDER BY s.first_seen",
        (row["actor_id"], session_id),
    ).fetchall()
    label = conn.execute("SELECT * FROM labels WHERE session_id=?", (session_id,)).fetchone()
    return {
        "session_id": session_id,
        "actor_id": row["actor_id"],
        "service": row["service"],
        "src_ip": row["src_ip"],
        "client_fp": row["client_fp"],
        "verdict": row["verdict"],
        "score": row["score"],
        "explanation": row["explanation"],
        "hits": hits,
        "suppressors": _loads(row["suppressors"], []),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "events": events,
        "linked": [dict(r) for r in linked],
        "label": label["label"] if label else "unreviewed",
        "evidence_marked": _loads(label["evidence_event_ids"], []) if label else [],
    }


def summarize(event: Event) -> str:
    request = event.request or {}
    if event.action.value in ("http_request", "api_call", "file_read"):
        return f"{request.get('method', '')} {request.get('path', '')}".strip()
    if event.action.value == "command":
        return str(request.get("command", ""))
    if event.credential:
        return f"{event.credential.username or ''} / {event.credential.password or ''}"
    if event.honeytoken_id:
        return event.honeytoken_id
    return ""


def save_label(
    conn: sqlite3.Connection, session_id: str, label: str, evidence: list[str], who: str, now: str
) -> None:
    conn.execute(
        "INSERT INTO labels (session_id, label, evidence_event_ids, who, ts) VALUES (?,?,?,?,?)"
        " ON CONFLICT(session_id) DO UPDATE SET label=excluded.label,"
        " evidence_event_ids=excluded.evidence_event_ids, who=excluded.who, ts=excluded.ts",
        (session_id, label, json.dumps(evidence), who, now),
    )
    conn.commit()


def pqc_share(conn: sqlite3.Connection) -> dict[str, Any]:
    """Share of SSH sessions whose client offered quantum-safe key exchange, by verdict.

    Context only: nothing here feeds a rule or a score.
    """
    rows = conn.execute(
        "SELECT f.verdict, s.event_ids FROM findings f JOIN sessions s"
        " ON s.session_id = f.session_id WHERE s.service = 'ssh'"
    ).fetchall()
    counts = {v: {"sessions": 0, "offered": 0} for v in ("Benign", "Suspicious", "Noteworthy")}
    for row in rows:
        known = None
        for event_id in _loads(row["event_ids"], []):
            stored = conn.execute("SELECT raw FROM events WHERE event_id=?", (event_id,)).fetchone()
            value = json.loads(stored["raw"]).get("pqc_capable") if stored else None
            if value is not None:
                known = bool(value)
                break
        if known is None:
            continue  # no key-exchange offer was seen, so the session is not counted
        counts[row["verdict"]]["sessions"] += 1
        counts[row["verdict"]]["offered"] += int(known)
    bars = []
    for verdict, c in counts.items():
        share = c["offered"] / c["sessions"] if c["sessions"] else None
        bars.append({"verdict": verdict, **c, "share": share, "width": round((share or 0) * 300)})
    return {"bars": bars, "total": sum(c["sessions"] for c in counts.values())}
