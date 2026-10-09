"""Read-only IOC export of decoy-observed indicators (ROADMAP P3.4).

Three renderings of the same data: a STIX 2.1 bundle, a CSV with one row per indicator, and a
plain IP blocklist. The database is opened with mode=ro and only the sessions, findings and events
tables are read. Passwords leave this module only as SHA-256 hashes. Honeytoken IDs are exported,
but their secret values are never read here (they live in decoys/honeytokens.yaml).
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qlure.correlate.model import event_time
from qlure.events import Event

FORMATS = ("stix", "csv", "blocklist")
MIN_VERDICTS = ("suspicious", "noteworthy")
DEFAULT_MIN_VERDICT = "noteworthy"
CSV_COLUMNS = (
    "type",
    "value",
    "first_seen",
    "last_seen",
    "sessions",
    "actor",
    "verdict",
    "rules",
    "attack_ids",
)
VERDICT_RANK = {"Benign": 0, "Suspicious": 1, "Noteworthy": 2}
STIX_LABEL = {"Noteworthy": "malicious-activity", "Suspicious": "anomalous-activity"}
STIX_CONFIDENCE = {"Noteworthy": 85, "Suspicious": 50}
# Indicator kinds STIX 2.1 can express. The rest (url-path, user-agent, credential-hash,
# honeytoken-id) stay in the CSV only.
STIX_PATTERNS = {
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "sha256": "file:hashes.'SHA-256'",
}
# A fixed time for the identity and ATT&CK objects, so two exports of one database are identical.
STIX_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:qlure:ioc-export")
# Python counts these as private, but they are the demo's visitor addresses, so they stay.
DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


class ExportError(Exception):
    """The database cannot be read. The CLI prints the message and exits 1."""


@dataclass(frozen=True)
class Session:
    session_id: str
    actor_id: str
    src_ip: str
    verdict: str  # the effective verdict: the session's own, or its actor's if that is higher
    rules: tuple[str, ...]
    attacks: tuple[str, ...]


@dataclass
class Indicator:
    kind: str  # ipv4, ipv6, url-path, user-agent, credential-hash, honeytoken-id or sha256
    value: str
    first_seen: datetime
    last_seen: datetime
    sessions: set[str] = field(default_factory=set)
    actors: set[str] = field(default_factory=set)
    verdict: str = "Benign"
    rules: set[str] = field(default_factory=set)
    attacks: set[str] = field(default_factory=set)

    def add(self, when: datetime, session: Session) -> None:
        self.first_seen = min(self.first_seen, when)
        self.last_seen = max(self.last_seen, when)
        self.sessions.add(session.session_id)
        self.actors.add(session.actor_id)
        if VERDICT_RANK[session.verdict] > VERDICT_RANK[self.verdict]:
            self.verdict = session.verdict
        self.rules.update(session.rules)
        self.attacks.update(session.attacks)


@dataclass
class Export:
    min_verdict: str
    sessions: list[Session]
    indicators: list[Indicator]  # sorted by kind, then value


def _utc(when: datetime) -> datetime:
    return (when if when.tzinfo else when.replace(tzinfo=UTC)).astimezone(UTC)


def _stamp(when: datetime) -> str:
    """STIX timestamp: UTC, millisecond precision, trailing Z."""
    utc = _utc(when)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _rule_key(rule_id: str) -> tuple[int, str]:
    return (len(rule_id), rule_id)  # R2 before R10


def _open(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise ExportError(f"database not found: {path}")
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)


def _indicators(event: Event) -> list[tuple[str, str]]:
    found = [("ipv6" if ":" in event.src_ip else "ipv4", event.src_ip)]
    request = event.request or {}
    path = request.get("path")
    if isinstance(path, str) and path:  # the query string is never exported
        found.append(("url-path", path))
    headers = request.get("headers")
    agent = headers.get("user-agent") if isinstance(headers, dict) else None
    if isinstance(agent, str) and agent:
        found.append(("user-agent", agent))
    body_hash = request.get("body_sha256")
    if body_hash and request.get("body_len") and event.credential is None:
        found.append(("sha256", str(body_hash)))
    if event.credential and event.credential.password:
        digest = hashlib.sha256(event.credential.password.encode("utf-8")).hexdigest()
        found.append(("credential-hash", digest))
    if event.honeytoken_id:
        found.append(("honeytoken-id", event.honeytoken_id))
    return found


def _collect(conn: sqlite3.Connection, floor: int, min_verdict: str) -> Export:
    sessions: dict[str, Session] = {}
    owner: dict[str, Session] = {}  # event_id -> the kept session it belongs to
    rows = conn.execute(
        "SELECT s.session_id, s.actor_id, s.src_ip, s.event_ids, f.verdict, f.actor_verdict,"
        " f.rule_ids, f.hits FROM sessions s JOIN findings f USING (session_id)"
    )
    for sid, actor, src_ip, event_ids, verdict, actor_verdict, rule_ids, hits in rows.fetchall():
        own_hits = json.loads(hits or "[]")
        effective = verdict
        if own_hits:  # same rule as Finding.effective_verdict: thin sessions are not promoted
            effective = max(
                verdict, actor_verdict or "Benign", key=lambda v: VERDICT_RANK.get(v, 0)
            )
        if VERDICT_RANK.get(effective, 0) < floor:
            continue
        attacks = {attack for hit in own_hits for attack in hit.get("attack", [])}
        session = Session(
            session_id=sid,
            actor_id=actor or "",
            src_ip=src_ip,
            verdict=effective,
            rules=tuple(sorted(json.loads(rule_ids or "[]"), key=_rule_key)),
            attacks=tuple(sorted(attacks)),
        )
        sessions[sid] = session
        for event_id in json.loads(event_ids or "[]"):
            owner[event_id] = session

    found: dict[tuple[str, str], Indicator] = {}
    if owner:
        for event_id, raw in conn.execute("SELECT event_id, raw FROM events ORDER BY seq"):
            session = owner.get(event_id)
            if session is None:
                continue
            event = Event.model_validate_json(raw)
            when = _utc(event_time(event))
            for kind, value in _indicators(event):
                indicator = found.get((kind, value))
                if indicator is None:
                    indicator = Indicator(kind, value, when, when)
                    found[(kind, value)] = indicator
                indicator.add(when, session)

    ordered = [found[key] for key in sorted(found)]
    return Export(min_verdict, list(sessions.values()), ordered)


def load(path: Path, min_verdict: str = DEFAULT_MIN_VERDICT) -> Export:
    """Read the indicators of sessions at or above min_verdict. Never writes to the database."""
    floor = VERDICT_RANK[min_verdict.capitalize()]
    try:
        conn = _open(path)
    except sqlite3.Error as exc:
        raise ExportError(f"cannot open {path}: {exc}") from exc
    try:
        return _collect(conn, floor, min_verdict)
    except sqlite3.Error as exc:
        raise ExportError(f"cannot read {path}: {exc}") from exc
    finally:
        conn.close()


def _skipped(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback, link-local and private addresses are not blocklisted. Documentation ranges are."""
    if any(ip in net for net in DOCUMENTATION_NETS):
        return False
    return ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_unspecified


def blocklist_text(data: Export) -> str:
    ips = {ipaddress.ip_address(s.src_ip) for s in data.sessions}
    kept = sorted((ip for ip in ips if not _skipped(ip)), key=lambda ip: (ip.version, int(ip)))
    stamp = _stamp(datetime.now(UTC))
    header = [
        f"# generated {stamp} by QLure (decoy-observed, review before blocking)",
        f"# sessions at or above {data.min_verdict}; loopback, link-local and private addresses"
        " are skipped; documentation ranges are kept",
    ]
    return "\n".join(header + [str(ip) for ip in kept]) + "\n"


def csv_text(data: Export) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for ind in data.indicators:
        writer.writerow(
            [
                ind.kind,
                ind.value,
                _stamp(ind.first_seen),
                _stamp(ind.last_seen),
                len(ind.sessions),
                ";".join(sorted(ind.actors)),
                ind.verdict,
                ";".join(sorted(ind.rules, key=_rule_key)),
                ";".join(sorted(ind.attacks)),
            ]
        )
    return buf.getvalue()


def _object(kind: str, key: str, created: str, modified: str, **props: Any) -> dict[str, Any]:
    """A STIX object whose id is a UUIDv5 of its kind and key, so it is the same every run."""
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{key}')}",
        "created": created,
        "modified": modified,
        **props,
    }


def _attack_pattern(technique: str) -> dict[str, Any]:
    epoch = _stamp(STIX_EPOCH)
    url = "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"
    return _object(
        "attack-pattern",
        technique,
        epoch,
        epoch,
        name=f"ATT&CK {technique}",
        external_references=[{"source_name": "mitre-attack", "external_id": technique, "url": url}],
    )


def stix_bundle(data: Export) -> dict[str, Any]:
    epoch = _stamp(STIX_EPOCH)
    identity = _object("identity", "qlure", epoch, epoch, name="QLure", identity_class="system")
    indicators: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    attacks: dict[str, dict[str, Any]] = {}
    for ind in data.indicators:
        if ind.kind not in STIX_PATTERNS:
            continue
        first, last = _stamp(ind.first_seen), _stamp(ind.last_seen)
        obj = _object(
            "indicator",
            f"{ind.kind}:{ind.value}",
            first,
            last,
            name=f"{ind.kind} {ind.value}",
            pattern=f"[{STIX_PATTERNS[ind.kind]} = '{ind.value}']",
            pattern_type="stix",
            valid_from=first,
            labels=[STIX_LABEL[ind.verdict]],
            confidence=STIX_CONFIDENCE[ind.verdict],
            created_by_ref=identity["id"],
        )
        indicators.append(obj)
        for technique in sorted(ind.attacks):
            target = attacks.setdefault(technique, _attack_pattern(technique))
            relationships.append(
                _object(
                    "relationship",
                    f"{obj['id']}|{target['id']}",
                    first,
                    last,
                    relationship_type="indicates",
                    source_ref=obj["id"],
                    target_ref=target["id"],
                )
            )
    objects = [
        identity,
        *indicators,
        *sorted(attacks.values(), key=lambda o: o["id"]),
        *relationships,
    ]
    digest = uuid.uuid5(NAMESPACE, json.dumps(objects, sort_keys=True))
    return {"type": "bundle", "id": f"bundle--{digest}", "objects": objects}


def render(db: Path, fmt: str, min_verdict: str = DEFAULT_MIN_VERDICT) -> str:
    data = load(db, min_verdict)
    if fmt == "csv":
        return csv_text(data)
    if fmt == "blocklist":
        return blocklist_text(data)
    if fmt == "stix":
        return json.dumps(stix_bundle(data), indent=2) + "\n"
    raise ValueError(f"unknown format: {fmt}")
