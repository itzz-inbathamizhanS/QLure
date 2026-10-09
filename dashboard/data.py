"""Reads for the session view. Everything here comes from the SQLite store."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from typing import Any

from qlure.events import Event

GAP_SECONDS = 60
FAMILY_ORDER = ["recon", "credential", "exploit", "misuse", "chain"]


def _loads(text: str | None, default: Any) -> Any:
    return json.loads(text) if text else default


_ORDER = {"Benign": 0, "Suspicious": 1, "Noteworthy": 2, None: 0}


def _effective(verdict: str, actor_verdict: str | None, hit_count: int) -> str:
    """The more serious of a session's own verdict and its actor's combined verdict.

    Only promoted when the session has at least one rule hit of its own (see
    `qlure.correlate.model.Finding.effective_verdict`, which this mirrors for stored rows).
    """
    if not hit_count:
        return verdict
    return max((verdict, actor_verdict or "Benign"), key=lambda v: _ORDER[v])


def disagrees(verdict: str, ml_score: float | None) -> bool:
    """Rules and the learned model point opposite ways: worth a human look."""
    if ml_score is None:
        return False
    return (verdict == "Noteworthy" and ml_score < 0.2) or (
        verdict != "Noteworthy" and ml_score >= 0.8
    )


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
        hits = _loads(row["hits"], [])
        effective = _effective(row["verdict"], row["actor_verdict"], len(hits))
        if filters.get("verdict") and effective != filters["verdict"]:
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
                "ml_score": row["ml_score"],
                "disagrees": disagrees(effective, row["ml_score"]),
                "actor_score": row["actor_score"],
                "actor_verdict": row["actor_verdict"],
                "effective_verdict": effective,
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
    event_rules: dict[str, list[str]] = {}
    for hit in hits:
        for event_id in hit["evidence"]:
            event_family.setdefault(event_id, set()).add(hit["family"])
            event_rules.setdefault(event_id, []).append(hit["rule_id"])

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
                "rules": event_rules.get(event_id, []),
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
        "ml_score": row["ml_score"],
        "ml_why": row["ml_why"],
        "ml_factors": ml_factors(row["ml_why"]),
        "segments": score_segments(hits),
        "disagrees": disagrees(
            _effective(row["verdict"], row["actor_verdict"], len(hits)), row["ml_score"]
        ),
        "actor_score": row["actor_score"],
        "actor_verdict": row["actor_verdict"],
        "actor_explanation": row["actor_explanation"],
        "effective_verdict": _effective(row["verdict"], row["actor_verdict"], len(hits)),
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


_FACTOR = re.compile(r"([a-z0-9 ]+?) = (-?[0-9.]+) pushes toward (malicious|benign)")


def ml_factors(ml_why: str | None) -> list[dict[str, Any]]:
    """Split the model's explanation into its named factors, for the factor list."""
    if not ml_why or "Biggest factors:" not in ml_why:
        return []
    tail = ml_why.split("Biggest factors:", 1)[1]
    return [
        {"name": name.strip(), "value": value, "toward": toward}
        for name, value, toward in _FACTOR.findall(tail)
    ]


def score_segments(hits: list[dict[str, Any]], width: int = 600) -> dict[str, Any]:
    """Each rule's weight as a run of one bar, in rule order.

    The bar spans the larger of 100 and the summed weights, so a session whose rules add up
    past the 100 cap still shows every rule; `scale` places the threshold marks on it.
    """
    ordered = sorted(hits, key=lambda h: int(h["rule_id"][1:]))
    total = sum(h["weight"] for h in ordered)
    scale = width / max(total, 100)
    segments, x = [], 0.0
    for hit in ordered:
        w = hit["weight"] * scale
        segments.append({"rule_id": hit["rule_id"], "family": hit["family"], "x": x, "w": w})
        x += w
    return {"runs": segments, "scale": scale, "total": total, "cap": 100 * scale}


def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    """Headline numbers for the top of the sessions page, from one pass over the findings."""
    verdicts = {"Noteworthy": 0, "Suspicious": 0, "Benign": 0}
    disagreements = 0
    reviewed = 0
    actors: dict[str, str] = {}
    labelled = {r[0] for r in conn.execute("SELECT session_id FROM labels")}
    for row in conn.execute(
        "SELECT session_id, actor_id, verdict, hits, ml_score, actor_verdict FROM findings"
    ):
        effective = _effective(row["verdict"], row["actor_verdict"], len(_loads(row["hits"], [])))
        verdicts[effective] += 1
        disagreements += disagrees(effective, row["ml_score"])
        reviewed += row["session_id"] in labelled
        actors[row["actor_id"]] = max(
            (actors.get(row["actor_id"], "Benign"), row["actor_verdict"] or "Benign"),
            key=lambda v: _ORDER[v],
        )
    total = sum(verdicts.values())
    events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    tokens = conn.execute(
        "SELECT COUNT(DISTINCT honeytoken_id) FROM events WHERE honeytoken_id IS NOT NULL"
    ).fetchone()[0]
    span = conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
    bar, x = [], 0.0
    for verdict in ("Noteworthy", "Suspicious", "Benign"):
        w = verdicts[verdict] / total * 1000 if total else 0
        bar.append({"verdict": verdict, "count": verdicts[verdict], "x": x, "w": w})
        x += w
    return {
        "sessions": total,
        "verdicts": verdicts,
        "bar": bar,
        "events": events,
        "actors": len(actors),
        "noteworthy_actors": sum(v == "Noteworthy" for v in actors.values()),
        "honeytokens": tokens,
        "disagreements": disagreements,
        "reviewed": reviewed,
        "first": span[0],
        "last": span[1],
        "has_model": conn.execute(
            "SELECT 1 FROM findings WHERE ml_score IS NOT NULL LIMIT 1"
        ).fetchone()
        is not None,
    }


def list_actors(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    by_actor: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT f.actor_id, f.verdict, f.score, f.actor_score, f.actor_verdict, f.rule_ids,"
        " s.service, s.src_ip, s.first_seen, s.last_seen"
        " FROM findings f JOIN sessions s ON s.session_id = f.session_id"
    ):
        a = by_actor.setdefault(
            row["actor_id"],
            {
                "actor_id": row["actor_id"],
                "sessions": 0,
                "services": set(),
                "ips": set(),
                "rules": set(),
                "score": 0,
                "verdict": "Benign",
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "counts": {"Noteworthy": 0, "Suspicious": 0, "Benign": 0},
            },
        )
        a["sessions"] += 1
        a["services"].add(row["service"])
        a["ips"].add(row["src_ip"])
        a["rules"].update(_loads(row["rule_ids"], []))
        a["counts"][row["verdict"]] += 1
        a["score"] = max(a["score"], row["actor_score"] or 0, row["score"])
        a["verdict"] = max(
            (a["verdict"], row["actor_verdict"] or "Benign", row["verdict"]),
            key=lambda v: _ORDER[v],
        )
        a["first_seen"] = min(a["first_seen"], row["first_seen"])
        a["last_seen"] = max(a["last_seen"], row["last_seen"])
    out = []
    for a in by_actor.values():
        a["services"] = sorted(a["services"])
        a["ips"] = sorted(a["ips"])
        a["rules"] = sorted(a["rules"], key=lambda r: int(r[1:]))
        out.append(a)
    out.sort(key=lambda a: (-_ORDER[a["verdict"]], -a["score"], -a["sessions"]))
    return out


def actor_detail(conn: sqlite3.Connection, actor_id: str) -> dict[str, Any] | None:
    actor = next((a for a in list_actors(conn) if a["actor_id"] == actor_id), None)
    if actor is None:
        return None
    sessions = list_findings(conn, {"actor": actor_id, "sort": "time"})
    sessions.sort(key=lambda r: r["first_seen"])
    explanation = conn.execute(
        "SELECT actor_explanation FROM findings WHERE actor_id=? AND actor_explanation IS NOT NULL"
        " ORDER BY actor_score DESC LIMIT 1",
        (actor_id,),
    ).fetchone()
    by_service: dict[str, int] = {}
    for s in sessions:
        by_service[s["service"]] = by_service.get(s["service"], 0) + 1
    most = max(by_service.values()) if by_service else 1
    return {
        **actor,
        "explanation": explanation[0] if explanation else "",
        "session_rows": sessions,
        "by_service": [
            {"service": k, "count": v, "w": round(v / most * 240)}
            for k, v in sorted(by_service.items(), key=lambda kv: -kv[1])
        ],
    }
