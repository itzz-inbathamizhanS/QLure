"""Run the whole pipeline: sessions, actors, rules, scoring, explanations."""

from __future__ import annotations

from dataclasses import dataclass, replace

from qlure.correlate.actors import build_actors
from qlure.correlate.explain import explain
from qlure.correlate.model import Actor, Finding, RuleHit, Session, event_time
from qlure.correlate.rules import (
    SESSION_RULES,
    load_config,
    r1_service_sweep,
    r10_kill_chain,
)
from qlure.correlate.sessions import build_sessions
from qlure.events import Event

BENIGN_ACTIONS = {"connect", "disconnect"}
REQUEST_ACTIONS = ("http_request", "command", "login_attempt", "banner")


@dataclass
class Result:
    sessions: list[Session]
    actors: list[Actor]
    findings: list[Finding]


def _suppressors(session: Session, hits: list[RuleHit]) -> list[tuple[str, int]]:
    cfg = load_config()["suppressors"]
    found: list[tuple[str, int]] = []

    allow = cfg["allowlisted_clients"]
    agents = [a.lower() for a in allow["user_agents"]]
    first_http = next((e for e in session.events if e.action.value == "http_request"), None)
    agent = (
        str(((first_http.request or {}).get("headers") or {}).get("user-agent", "")).lower()
        if first_http
        else ""
    )
    if session.src_ip in allow["ips"] or (agent and any(a in agent for a in agents)):
        found.append(("allowlisted client", allow["subtract"]))

    benign_paths = set(cfg["only_benign_paths"]["paths"])
    http = [e for e in session.events if e.action.value == "http_request"]
    others = [e for e in session.events if e.action.value not in BENIGN_ACTIONS | {"http_request"}]
    if http and not others and all((e.request or {}).get("path") in benign_paths for e in http):
        found.append(("only benign paths", cfg["only_benign_paths"]["subtract"]))

    logins = [
        e.action.value
        for e in session.events
        if e.action.value in ("login_attempt", "login_success")
    ]
    failed = logins.count("login_attempt") - logins.count("login_success")
    if failed == 1 and logins and logins[-1] == "login_success":
        found.append(("failed login then success", cfg["failed_then_success"]["subtract"]))

    requests = [e for e in session.events if e.action.value in REQUEST_ACTIONS]
    if len(requests) < cfg["too_few_requests"]["min_requests"]:
        found.append(("fewer than 3 requests", cfg["too_few_requests"]["subtract"]))
    return found


def verdict_for(score: int, hits: list[RuleHit]) -> str:
    cfg = load_config()["verdicts"]
    if score >= cfg["noteworthy"]:
        families = {h.family for h in hits}
        if len(families) >= 2 or any(h.confidence == "high" for h in hits):
            return "Noteworthy"
        return "Suspicious"
    if score >= cfg["suspicious"]:
        return "Suspicious"
    return "Benign"


def _score(session: Session, hits: list[RuleHit]) -> tuple[int, list[tuple[str, int]]]:
    raw = sum(h.weight for h in hits)
    suppressors: list[tuple[str, int]] = []
    if not any(h.confidence == "high" for h in hits):
        suppressors = _suppressors(session, hits)
    score = max(0, min(100, raw - sum(amount for _, amount in suppressors)))
    return score, suppressors


def _actor_hits(all_hits: list[RuleHit]) -> list[RuleHit]:
    """One combined hit per distinct rule the actor triggered anywhere, evidence merged.

    A rule that fired identically in two of the actor's sessions (R1 and R10 do, by
    construction) must count once in the actor's score, not once per session.
    """
    by_rule: dict[str, RuleHit] = {}
    for hit in all_hits:
        existing = by_rule.get(hit.rule_id)
        if existing is None:
            by_rule[hit.rule_id] = hit
            continue
        by_rule[hit.rule_id] = replace(
            existing,
            evidence=tuple(dict.fromkeys(existing.evidence + hit.evidence)),
            first_seen=min(
                (t for t in (existing.first_seen, hit.first_seen) if t is not None), default=None
            ),
        )
    return sorted(by_rule.values(), key=lambda h: int(h.rule_id[1:]))


def _actor_score(actor: Actor, hits: list[RuleHit]) -> tuple[int, list[tuple[str, int]]]:
    """Score the actor the same way a session is scored, over all its events at once."""
    combined = Session(
        session_id=f"{actor.actor_id}-combined",
        service=actor.sessions[0].service,
        src_ip=actor.sessions[0].src_ip,
        client_fp=None,
        events=sorted((e for s in actor.sessions for e in s.events), key=lambda e: event_time(e)),
    )
    return _score(combined, hits)


def correlate(events: list[Event]) -> Result:
    sessions = build_sessions(events)
    actors = build_actors(sessions)

    findings: list[Finding] = []
    for actor in actors:
        per_session: dict[str, list[RuleHit]] = {}
        for session in actor.sessions:
            per_session[session.session_id] = [
                hit for rule in SESSION_RULES if (hit := rule(session)) is not None
            ]
        all_hits = [h for hits in per_session.values() for h in hits]

        sweep = r1_service_sweep(actor)
        if sweep is not None:
            evidence = set(sweep.evidence)
            for session in actor.sessions:
                if evidence & set(session.event_ids):
                    per_session[session.session_id].append(sweep)
            all_hits.append(sweep)
        chain = r10_kill_chain(actor, all_hits)
        if chain is not None:
            for session in actor.sessions:
                if per_session[session.session_id]:
                    per_session[session.session_id].append(chain)
            all_hits.append(chain)

        actor_hits = _actor_hits(all_hits)
        actor_score, actor_suppressors = _actor_score(actor, actor_hits)
        actor_verdict = verdict_for(actor_score, actor_hits)
        actor_explanation = explain(
            Finding(
                session=actor.sessions[0],
                actor_id=actor.actor_id,
                score=actor_score,
                verdict=actor_verdict,
                hits=actor_hits,
                suppressors=actor_suppressors,
            )
        )

        for session in actor.sessions:
            hits = per_session[session.session_id]
            score, suppressors = _score(session, hits)
            finding = Finding(
                session=session,
                actor_id=actor.actor_id,
                score=score,
                verdict=verdict_for(score, hits),
                hits=hits,
                suppressors=suppressors,
                actor_score=actor_score,
                actor_verdict=actor_verdict,
                actor_hits=actor_hits,
                actor_explanation=actor_explanation,
            )
            finding.explanation = explain(finding)
            findings.append(finding)

    findings.sort(key=lambda f: (-f.score, f.session.start, f.session.session_id))
    return Result(sessions=sessions, actors=actors, findings=findings)
