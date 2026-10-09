"""Step 3: the rules. Their weights and thresholds live in qlure/rules/rules.yaml."""

from __future__ import annotations

import posixpath
import re
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml

from qlure.correlate.model import Actor, RuleHit, Session, event_time
from qlure.events import Event

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"
FAMILY_ORDER = ("recon", "credential", "misuse")


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    """rules.yaml with the operator's saved weights, thresholds and allowlist laid on top."""
    from qlure.settings import load_settings

    config = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    saved = load_settings()
    tuning = saved["rules"]
    config["verdicts"] = {"suspicious": tuning["suspicious"], "noteworthy": tuning["noteworthy"]}
    for rule_id, weight in tuning["weights"].items():
        config["rules"][rule_id]["weight"] = weight
    for rule_id, values in tuning["thresholds"].items():
        config["rules"][rule_id]["threshold"].update(values)
    allow = config["suppressors"]["allowlisted_clients"]
    allow["ips"] = list(saved["allowlist"]["ips"])
    allow["user_agents"] = list(saved["allowlist"]["user_agents"])
    return config


@lru_cache(maxsize=1)
def _injection() -> list[tuple[str, re.Pattern[str]]]:
    patterns = load_config()["lists"]["injection_patterns"]
    return [(kind, re.compile(p)) for kind, group in patterns.items() for p in group]


def _hit(
    rule_id: str, measured: str, events: list[Event], attack: tuple[str, ...] | None = None
) -> RuleHit:
    spec = load_config()["rules"][rule_id]
    ids = tuple(dict.fromkeys(e.event_id for e in events))
    times = [event_time(e) for e in events]
    return RuleHit(
        rule_id=rule_id,
        name=spec["name"],
        family=spec["family"],
        weight=spec["weight"],
        confidence=spec["confidence"],
        attack=tuple(spec["attack"]) if attack is None else attack,
        measured=measured,
        threshold=spec["threshold_text"],
        evidence=ids,
        first_seen=min(times) if times else None,
    )


def _threshold(rule_id: str, key: str) -> int:
    return load_config()["rules"][rule_id]["threshold"][key]


def _http(session: Session) -> list[Event]:
    return [e for e in session.events if e.action.value == "http_request"]


def _path(event: Event) -> str:
    return str((event.request or {}).get("path", ""))


def _status(event: Event) -> int | None:
    return (event.response or {}).get("status")


def _attempts(session: Session) -> list[Event]:
    return [e for e in session.events if e.action.value == "login_attempt" and e.credential]


def _user_agent(event: Event) -> str:
    return str(((event.request or {}).get("headers") or {}).get("user-agent", ""))


def r2_path_enumeration(session: Session) -> RuleHit | None:
    if session.service not in ("web", "api"):
        return None
    needed = _threshold("R2", "distinct_404_paths")
    missing = {}
    for e in _http(session):
        if _status(e) == 404:
            missing.setdefault(_path(e), e)
    scanner_paths = tuple(load_config()["lists"]["scanner_paths"])
    known = [e for e in _http(session) if _path(e).lower().startswith(scanner_paths)]
    if len(missing) >= needed:
        return _hit("R2", f"{len(missing)} distinct 404 paths", list(missing.values()))
    if known:
        paths = sorted({_path(e) for e in known})
        return _hit("R2", f"scanner path requested: {', '.join(paths[:3])}", known)
    return None


def r3_brute_force(session: Session) -> RuleHit | None:
    attempts = _attempts(session)
    successes = [e for e in session.events if e.action.value == "login_success"]
    failed = len(attempts) - len(successes)
    names = {e.credential.username for e in attempts if e.credential and e.credential.username}
    if failed >= _threshold("R3", "failed_logins"):
        return _hit("R3", f"{failed} failed logins", attempts)
    if len(names) >= _threshold("R3", "usernames"):
        return _hit("R3", f"{len(names)} different usernames tried", attempts)
    return None


def r4_default_credentials(session: Session) -> RuleHit | None:
    defaults = {tuple(pair) for pair in load_config()["lists"]["default_credentials"]}
    found = [
        e for e in _attempts(session) if (e.credential.username, e.credential.password) in defaults
    ]
    if not found:
        return None
    pairs = sorted({f"{e.credential.username}/{e.credential.password}" for e in found})
    return _hit("R4", f"default credentials tried: {', '.join(pairs[:3])}", found)


def _scan_text(event: Event) -> str:
    request = event.request or {}
    parts = [
        str(request.get("path", "")),
        str(request.get("query", "")),
        str(request.get("body_preview", "")),
        str(request.get("command", "")),
        *[str(v) for v in (request.get("headers") or {}).values()],
    ]
    raw = " ".join(parts)
    # Raw text too: the decoded copy loses encoded dots ("%252e%252e" becomes "..").
    return f"{raw} {unquote(unquote(raw))}"


def r5_injection(session: Session) -> RuleHit | None:
    matched: list[Event] = []
    kinds: set[str] = set()
    for event in session.events:
        # Web and API requests only. Every api_call repeats an http_request (it would count
        # twice), and in the SSH shell `;`, `|`, `../` and /etc/passwd are ordinary typing that
        # R8 and R9 already judge.
        if event.action.value != "http_request":
            continue
        text = _scan_text(event)
        kinds_here: set[str] = set()
        for kind, pattern in _injection():
            if pattern.search(text):
                if not kinds_here:
                    matched.append(event)
                kinds_here.add(kind)
        kinds |= kinds_here
    if not matched:
        return None
    kind_ids = load_config()["technique_map"]["r5_kinds"]
    ids = tuple(dict.fromkeys(i for k in sorted(kinds) for i in kind_ids.get(k, ())))
    return _hit(
        "R5",
        f"{'/'.join(sorted(kinds))} pattern in {len(matched)} request(s)",
        matched,
        ids or None,
    )


def r6_scanner_tool(session: Session) -> RuleHit | None:
    tools = load_config()["lists"]["scanner_agents"]
    found = [e for e in session.events if any(t in _user_agent(e).lower() for t in tools)]
    if found:
        agent = _user_agent(found[0])
        return _hit("R6", f"scanner user agent: {agent[:40]}", found)
    if session.service in ("ftp", "mysql", "redis"):
        banners = [e for e in session.events if e.action.value == "banner"]
        silent = [e for e in banners if not (e.request or {}).get("bytes_len")]
        if silent and len(session.events) <= 3:
            return _hit("R6", "banner grab with no follow-up", silent)
    return None


def r7_honeytoken_use(session: Session) -> RuleHit | None:
    used = [e for e in session.events if e.action.value == "honeytoken_use"]
    if not used:
        return None
    tokens = sorted({e.honeytoken_id for e in used if e.honeytoken_id})
    return _hit("R7", f"planted secret used: {', '.join(tokens)}", used)


@lru_cache(maxsize=1)
def _r8_categories() -> list[tuple[str, tuple[str, ...], re.Pattern[str]]]:
    spec = load_config()["technique_map"]["r8_categories"]
    return [(n, tuple(v["ids"]), re.compile(v["pattern"], re.IGNORECASE)) for n, v in spec.items()]


def _r8_labels(commands: list[Event]) -> tuple[list[str], tuple[str, ...]]:
    """Category names and ATT&CK IDs for the commands (labels only, never scoring)."""
    names: dict[str, None] = {}
    ids: dict[str, None] = {}
    for e in commands:
        text = str((e.request or {}).get("command", ""))
        for name, technique_ids, pattern in _r8_categories():
            if pattern.search(text):
                # account_discovery is the T1033 half of "discovery"; show one category name.
                names["discovery" if name == "account_discovery" else name] = None
                ids.update(dict.fromkeys(technique_ids))
    return list(names), tuple(ids)


def r8_post_login(session: Session) -> RuleHit | None:
    if session.service != "ssh":  # Redis/FTP/MySQL commands are judged by R11, not here
        return None
    commands = [e for e in session.events if e.action.value == "command"]
    discovery = set(load_config()["lists"]["discovery_commands"])
    danger = set(load_config()["lists"]["download_persistence"])
    seen_discovery, seen_danger = [], []
    for e in commands:
        text = str((e.request or {}).get("command", ""))
        words = set(re.findall(r"[\w./-]+", text))
        words |= {posixpath.basename(w) for w in words}  # ~/.ssh/authorized_keys too
        if words & danger:
            seen_danger.append(e)
        elif text.split()[:1] and text.split()[0] in discovery:
            seen_discovery.append(e)
    names, ids = _r8_labels(commands)
    tag = f" [categories: {', '.join(names)}]" if names else ""
    if seen_danger:
        text = f"{len(seen_danger)} download or persistence command(s){tag}"
        return _hit("R8", text, seen_danger, ids or None)
    if len(seen_discovery) >= _threshold("R8", "discovery_commands"):
        return _hit(
            "R8", f"{len(seen_discovery)} discovery commands{tag}", seen_discovery, ids or None
        )
    return None


def r9_sensitive_files(session: Session) -> RuleHit | None:
    needles = tuple(load_config()["lists"]["sensitive_paths"])
    found: list[Event] = []
    targets: set[str] = set()
    for e in session.events:
        if e.action.value in ("file_read", "http_request"):
            target = _path(e)
        elif e.action.value == "command":
            target = str((e.request or {}).get("command", ""))
        else:
            continue
        if any(n in target for n in needles) and _status(e) != 404:
            found.append(e)
            targets.add(target)
    if not found:
        return None
    return _hit("R9", f"sensitive file read: {', '.join(sorted(targets)[:3])}", found)


@lru_cache(maxsize=1)
def _r11_commands() -> list[tuple[str, tuple[str, ...], re.Pattern[str]]]:
    spec = load_config()["technique_map"]["r11_commands"]
    return [(n, tuple(v["ids"]), re.compile(v["pattern"], re.IGNORECASE)) for n, v in spec.items()]


def r11_data_store_abuse(session: Session) -> RuleHit | None:
    if session.service != "redis":
        return None
    found: list[Event] = []
    names: dict[str, None] = {}
    ids: dict[str, None] = {}
    for e in session.events:
        if e.action.value != "command":
            continue
        text = str((e.request or {}).get("command", ""))
        for name, technique_ids, pattern in _r11_commands():
            if pattern.search(text):
                if not found or found[-1] is not e:
                    found.append(e)
                names[name] = None
                ids.update(dict.fromkeys(technique_ids))
    if len(found) < _threshold("R11", "commands"):
        return None
    return _hit(
        "R11",
        f"{len(found)} risky Redis command(s) [{', '.join(names)}]",
        found,
        tuple(ids) or None,
    )


SESSION_RULES = (
    r2_path_enumeration,
    r3_brute_force,
    r4_default_credentials,
    r5_injection,
    r6_scanner_tool,
    r7_honeytoken_use,
    r8_post_login,
    r9_sensitive_files,
    r11_data_store_abuse,
)


def r1_service_sweep(actor: Actor) -> RuleHit | None:
    window = timedelta(seconds=_threshold("R1", "window_s"))
    needed = _threshold("R1", "services")
    events = sorted(
        (
            e
            for s in actor.sessions
            for e in s.events
            if e.action.value in ("connect", "banner", "http_request")
        ),
        key=event_time,
    )
    for i, first in enumerate(events):
        inside = [e for e in events[i:] if event_time(e) - event_time(first) <= window]
        services = {e.service.value for e in inside}
        if len(services) >= needed:
            seen: dict[str, Event] = {}
            for e in inside:
                seen.setdefault(e.service.value, e)
            return _hit(
                "R1",
                f"{len(services)} services touched within {int(window.total_seconds())} seconds",
                list(seen.values()),
            )
    return None


def r10_kill_chain(actor: Actor, hits: list[RuleHit]) -> RuleHit | None:
    first: dict[str, Any] = {}
    for hit in hits:
        if hit.family in FAMILY_ORDER and hit.first_seen is not None:
            if hit.family not in first or hit.first_seen < first[hit.family]:
                first[hit.family] = hit.first_seen
    if len(first) < _threshold("R10", "families"):
        return None
    # The families present must appear in kill-chain order. (Indexing all three would raise
    # KeyError once an operator lowers the threshold to 2.)
    times = [first[f] for f in FAMILY_ORDER if f in first]
    if times != sorted(times):
        return None
    evidence = [e for h in hits if h.family in FAMILY_ORDER for e in h.evidence]
    spec = load_config()["rules"]["R10"]
    return RuleHit(
        rule_id="R10",
        name=spec["name"],
        family=spec["family"],
        weight=spec["weight"],
        confidence=spec["confidence"],
        attack=tuple(dict.fromkeys(i for h in hits if h.family in FAMILY_ORDER for i in h.attack)),
        measured=", then ".join(f for f in FAMILY_ORDER if f in first),
        threshold=spec["threshold_text"],
        evidence=tuple(dict.fromkeys(evidence)),
        first_seen=times[0],
    )
