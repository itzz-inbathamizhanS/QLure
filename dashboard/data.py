"""Reads for the session view. Everything here comes from the SQLite store."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from qlure.events import Event

GAP_SECONDS = 60
SERVICE_BAR_WIDTH = 200  # the track of the actor's per-decoy bars, in SVG units
FAMILY_ORDER = ["recon", "credential", "exploit", "misuse", "chain"]
# The stages of the actor kill-chain strip: the rule families R10 counts, in order.
KILL_CHAIN = (("recon", "Recon"), ("credential", "Credential"), ("misuse", "Misuse"))
_LOGIN_WHERE = {
    "ssh": "over SSH",
    "ftp": "over FTP",
    "mysql": "over MySQL",
    "redis": "over Redis",
    "web": "to the web app",
    "api": "to the API",
}
_DOWNLOAD = re.compile(r"\b(?:wget|curl|tftp|scp)\b")
TERMINAL_SHOWN_CHARS = 2048  # the longest output the SSH replay prints; the decoy stores up to this
OLD_PREVIEW_CHARS = 256  # the decoy's earlier output cap; a preview this long was likely cut
TERMINAL_HOST = "srv"  # events do not record the decoy's hostname, so the replay uses a fixed label
DEFAULT_SHELL_USER = "deploy"  # the decoy's shell user when the visitor logged in without a name

# ATT&CK tactic columns of the matrix page, in order.
ATTACK_TACTICS = (
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control",
    "Impact",
)
# Every technique id the rules can emit (rules.yaml attack lists and technique_map), with the one
# tactic column it is shown under and its ATT&CK name. tests/dashboard/test_attack_matrix.py checks
# this table against rules.yaml, so a new rule id cannot go unmapped.
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595.002": ("Reconnaissance", "Vulnerability Scanning"),
    "T1595.003": ("Reconnaissance", "Wordlist Scanning"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1078.001": ("Initial Access", "Default Accounts"),
    "T1059": ("Execution", "Command and Scripting Interpreter"),
    "T1059.004": ("Execution", "Unix Shell"),
    "T1610": ("Execution", "Deploy Container"),
    "T1505.003": ("Persistence", "Web Shell"),
    "T1098.004": ("Persistence", "SSH Authorized Keys"),
    "T1053.003": ("Persistence", "Cron"),
    "T1548.003": ("Privilege Escalation", "Sudo and Sudo Caching"),
    "T1611": ("Privilege Escalation", "Escape to Host"),
    "T1110.001": ("Credential Access", "Password Guessing"),
    "T1552.001": ("Credential Access", "Credentials In Files"),
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1082": ("Discovery", "System Information Discovery"),
    "T1033": ("Discovery", "System Owner/User Discovery"),
    "T1021.004": ("Lateral Movement", "Remote Services: SSH"),
    "T1005": ("Collection", "Data from Local System"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1496": ("Impact", "Resource Hijacking"),
    "T1485": ("Impact", "Data Destruction"),
}


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

    token_of = {
        r["event_id"]: r["honeytoken_id"]
        for r in conn.execute(
            "SELECT event_id, honeytoken_id FROM events WHERE honeytoken_id IS NOT NULL"
        )
    }
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
                "techniques": sorted({a for h in hits for a in h["attack"]}),
                "honeytokens": sorted({token_of[e] for e in event_ids if e in token_of}),
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
        "story": session_story([e["event"] for e in events], hits),
        "terminal": terminal_replay([e["event"] for e in events]),
        "honeytokens": sorted(
            {e["event"].honeytoken_id for e in events if e["event"].honeytoken_id}
        ),
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


def _moment(event: Event) -> datetime:
    return event.replay_ts or event.ts


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def session_story(events: list[Event], hits: list[dict[str, Any]]) -> str:
    """One plain sentence about a session, built only from its rule hits and its events.

    Pure and deterministic: the same events and hits always give the same sentence, and
    nothing is guessed beyond what the events record (paths, credentials, commands, tokens).
    """
    if not events:
        return "No events were recorded for this session."
    ordered = sorted(events, key=_moment)
    seconds = int((_moment(ordered[-1]) - _moment(ordered[0])).total_seconds())
    minutes = seconds // 60
    when = f"{minutes} min" if minutes else "under a minute"
    source = ordered[0].src_ip
    by_id = {e.event_id: e for e in ordered}

    def req(e: Event, key: str) -> str:
        return str((e.request or {}).get(key) or "")

    clauses: list[str] = []
    # The scanner paths are the ones the R2 hit names as evidence (its events), counted once each.
    probed = {
        req(by_id[event_id], "path")
        for hit in hits
        if hit["rule_id"] == "R2"
        for event_id in hit["evidence"]
        if event_id in by_id and req(by_id[event_id], "path")
    }
    paths = {
        req(e, "path")
        for e in ordered
        if e.action.value in ("http_request", "api_call") and not e.honeytoken_id and req(e, "path")
    }
    if probed:
        clauses.append(f"probed {_plural(len(probed), 'scanner path')}")
    elif paths:
        clauses.append(f"requested {_plural(len(paths), 'path')}")
    clauses.extend(
        f"triggered {h['name']} ({h['rule_id']})" for h in hits if h["family"] == "exploit"
    )

    attempts = [e for e in ordered if e.action.value == "login_attempt"]
    successes = [e for e in ordered if e.action.value == "login_success"]
    # Tokens already described by a read, a login or an attempt: not repeated as "used".
    covered = {e.honeytoken_id for e in attempts + successes if e.honeytoken_id}
    seen_reads: set[tuple[str, str]] = set()
    for e in ordered:
        if e.action.value == "file_read" and e.honeytoken_id:
            covered.add(e.honeytoken_id)
            read = (req(e, "path") or "a file", e.honeytoken_id)
            if read not in seen_reads:
                seen_reads.add(read)
                clauses.append(f"read {read[0]} (honeytoken {read[1]})")
    tokens = {e.honeytoken_id for e in ordered if e.action.value == "honeytoken_use"}
    for token in sorted(t for t in tokens - covered if t):
        clauses.append(f"used honeytoken {token}")

    leaked = any(e.honeytoken_id for e in attempts + successes)
    if successes:
        text = f"logged in {_LOGIN_WHERE.get(ordered[0].service.value, 'to the decoy')}"
        if leaked:
            text += " with the leaked password"
        failed = len(attempts) - len(successes)
        if failed > 0:
            text += f" after {_plural(failed, 'failed attempt')}"
        clauses.append(text)
    elif attempts:
        text = f"tried {_plural(len(attempts), 'login')}"
        if leaked:
            text += " including a leaked password"
        clauses.append(text)

    commands = [
        str((e.request or {}).get("command") or "") for e in ordered if e.action.value == "command"
    ]
    if commands:
        text = f"ran {_plural(len(commands), 'command')}"
        if any(_DOWNLOAD.search(c) for c in commands):
            text += " including a download"
        clauses.append(text)

    if not clauses:
        return f"From {source} over {when}: only connection events were recorded."
    body = clauses[0] if len(clauses) == 1 else f"{', '.join(clauses[:-1])} and {clauses[-1]}"
    return f"From {source} over {when}: {body}."


def _event_owners(conn: sqlite3.Connection) -> dict[str, tuple[str, str]]:
    """Event id -> (session id, actor id). A session lists its events in `sessions.event_ids`."""
    owners: dict[str, tuple[str, str]] = {}
    for row in conn.execute(
        "SELECT f.session_id, f.actor_id, s.event_ids FROM findings f"
        " JOIN sessions s ON s.session_id = f.session_id"
    ):
        for event_id in _loads(row["event_ids"], []):
            owners[event_id] = (row["session_id"], row["actor_id"])
    return owners


def honeytoken_banner(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """The most recent use of a planted secret, with the session that used it."""
    owners = _event_owners(conn)
    for row in conn.execute(
        "SELECT event_id, honeytoken_id, src_ip FROM events"
        " WHERE honeytoken_id IS NOT NULL ORDER BY ts DESC"
    ):
        if row["event_id"] in owners:
            session_id, actor_id = owners[row["event_id"]]
            return {
                "honeytoken_id": row["honeytoken_id"],
                "src_ip": row["src_ip"],
                "session_id": session_id,
                "actor_id": actor_id,
            }
    return None


def kill_chain(conn: sqlite3.Connection, actor_id: str) -> list[dict[str, Any]]:
    """Recon, credential and misuse: which stages the actor reached, and when (first event)."""
    evidence: dict[str, set[str]] = {family: set() for family, _ in KILL_CHAIN}
    for row in conn.execute("SELECT hits FROM findings WHERE actor_id=?", (actor_id,)):
        for hit in _loads(row["hits"], []):
            if hit["family"] in evidence:
                evidence[hit["family"]].update(hit["evidence"])
    moments: dict[str, datetime] = {}
    for event_id in set().union(*evidence.values()):
        row = conn.execute(
            "SELECT ts, replay_ts FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        if row:
            moments[event_id] = datetime.fromisoformat(row["replay_ts"] or row["ts"])
    out = []
    for family, label in KILL_CHAIN:
        times = [moments[e] for e in evidence[family] if e in moments]
        out.append(
            {
                "stage": family,
                "label": label,
                "reached": bool(evidence[family]),
                "events": len(evidence[family]),
                "first": min(times).isoformat() if times else None,
            }
        )
    return out


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
    total = len(sessions)
    return {
        **actor,
        "kill_chain": kill_chain(conn, actor_id),
        "explanation": explanation[0] if explanation else "",
        "session_rows": sessions,
        "by_service": [
            {
                "service": k,
                "count": v,
                "share": v / total,
                "w": round(v / total * SERVICE_BAR_WIDTH),
            }
            for k, v in sorted(by_service.items(), key=lambda kv: -kv[1])
        ],
    }


def terminal_replay(events: list[Event]) -> list[dict[str, Any]]:
    """The command events of a session, in order, as a prompt and output transcript.

    Output is the decoy's own preview text, shown as stored. Long output is cut for display and
    the cut is named in `note`; the template escapes everything, so nothing here is markup.
    """
    ordered = sorted(events, key=_moment)
    user = next(
        (
            e.credential.username
            for e in ordered
            if e.action.value == "login_success" and e.credential and e.credential.username
        ),
        DEFAULT_SHELL_USER,
    )
    steps: list[dict[str, Any]] = []
    for e in ordered:
        if e.action.value != "command":
            continue
        command = str((e.request or {}).get("command") or "")
        raw = str((e.response or {}).get("output_preview") or "")
        note = ""
        if len(raw) > TERMINAL_SHOWN_CHARS:
            note = f"output cut for display: {TERMINAL_SHOWN_CHARS} of {len(raw)} characters shown"
        elif len(raw) == OLD_PREVIEW_CHARS:
            note = f"the decoy keeps at most {OLD_PREVIEW_CHARS} characters; more may be missing"
        steps.append(
            {
                "prompt": f"{user}@{TERMINAL_HOST}:~$",
                "command": command,
                "output": raw[:TERMINAL_SHOWN_CHARS].rstrip("\n"),
                "note": note,
            }
        )
    return steps


def attack_matrix(conn: sqlite3.Connection) -> dict[str, Any]:
    """Each mapped technique with its rule-hit count, session count and first session.

    The first session is the highest-scoring one that shows the technique (the same order as the
    sessions list), so a seen cell links to the session that matters most.
    """
    hit_count: dict[str, int] = {}
    sessions: dict[str, set[str]] = {}
    first: dict[str, tuple[tuple[int, str], str]] = {}
    for row in conn.execute(
        "SELECT f.session_id, f.score, f.hits, s.first_seen FROM findings f"
        " JOIN sessions s ON s.session_id = f.session_id"
    ):
        order = (-row["score"], row["first_seen"])
        for hit in _loads(row["hits"], []):
            for technique in dict.fromkeys(hit["attack"]):
                hit_count[technique] = hit_count.get(technique, 0) + 1
                sessions.setdefault(technique, set()).add(row["session_id"])
                best = first.get(technique)
                if best is None or order < best[0]:
                    first[technique] = (order, row["session_id"])

    def cell(tid: str, name: str | None) -> dict[str, Any]:
        return {
            "id": tid,
            "name": name,
            "hits": hit_count.get(tid, 0),
            "sessions": len(sessions.get(tid, ())),
            "first_session": first[tid][1] if tid in first else None,
        }

    columns = [
        {
            "tactic": tactic,
            "cells": [
                cell(tid, name) for tid, (t, name) in ATTACK_TECHNIQUES.items() if t == tactic
            ],
        }
        for tactic in ATTACK_TACTICS
    ]
    return {
        "columns": columns,
        "seen": sum(1 for tid in ATTACK_TECHNIQUES if tid in hit_count),
        "total": len(ATTACK_TECHNIQUES),
        # Seen in the store but not in the table: listed so nothing the rules emit is hidden.
        "other": [cell(tid, None) for tid in sorted(hit_count) if tid not in ATTACK_TECHNIQUES],
    }


# Probes and scrapers read the store with a short wait: a busy store answers "error" instead of
# holding the request open.
READ_TIMEOUT_SECONDS = 1.0
VERDICT_LABELS = ("benign", "suspicious", "noteworthy")


def open_read_only(path: Path) -> sqlite3.Connection:
    """Open the store with mode=ro. A missing file raises sqlite3.Error; nothing is created."""
    uri = f"{path.resolve().as_uri()}?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=READ_TIMEOUT_SECONDS)


def store_counts(conn: sqlite3.Connection) -> dict[str, Any]:
    """Totals for /healthz and /metrics: plain counts, one pass over findings and one newest row.

    Sessions are counted by the effective verdict the sessions page shows. `newest` is the time of
    the newest stored event: the store keeps no forwarding timestamp of its own.
    """
    verdicts = dict.fromkeys(VERDICT_LABELS, 0)
    for verdict, actor_verdict, hits in conn.execute(
        "SELECT verdict, actor_verdict, hits FROM findings"
    ):
        effective = _effective(verdict, actor_verdict, len(_loads(hits, [])))
        verdicts[effective.lower()] += 1
    newest = conn.execute("SELECT ts FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    return {
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "sessions": conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
        "actors": conn.execute("SELECT COUNT(*) FROM actors").fetchone()[0],
        "honeytoken_hits": conn.execute(
            "SELECT COUNT(*) FROM events WHERE honeytoken_id IS NOT NULL"
        ).fetchone()[0],
        "verdicts": verdicts,
        "newest": newest[0] if newest else None,
    }


def escape_label(value: str) -> str:
    """A label value in the Prometheus text format: backslash, double quote and newline escaped."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def metrics_text(counts: dict[str, Any], last_pass: float) -> str:
    """The Prometheus text exposition. Clearing the store lowers the counts, so they are gauges."""
    families: list[tuple[str, str, str, list[tuple[str, Any]]]] = [
        ("qlure_events_total", "gauge", "Events stored in the database.", [("", counts["events"])]),
        (
            "qlure_sessions_total",
            "gauge",
            "Sessions by effective verdict, counted as the sessions page counts them.",
            [(f'verdict="{escape_label(v)}"', counts["verdicts"][v]) for v in VERDICT_LABELS],
        ),
        ("qlure_actors_total", "gauge", "Actors in the database.", [("", counts["actors"])]),
        (
            "qlure_honeytoken_hits_total",
            "gauge",
            "Events that used a honeytoken.",
            [("", counts["honeytoken_hits"])],
        ),
        (
            "qlure_live_last_pass_timestamp_seconds",
            "gauge",
            "Unix time of the last background correlation pass; 0 if none has finished.",
            [("", round(last_pass, 3))],
        ),
    ]
    lines: list[str] = []
    for name, kind, help_text, samples in families:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lines.append(f"{name}{{{labels}}} {value}" if labels else f"{name} {value}")
    return "\n".join(lines) + "\n"
