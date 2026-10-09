"""Data shapes the correlation engine passes around."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from qlure.events import Event


def event_time(event: Event) -> datetime:
    """Rules use the original timestamp when traffic comes from a replay."""
    return event.replay_ts or event.ts


@dataclass
class Session:
    session_id: str
    service: str
    src_ip: str
    client_fp: str | None
    events: list[Event]  # sorted by event_time

    @property
    def start(self) -> datetime:
        return event_time(self.events[0])

    @property
    def end(self) -> datetime:
        return event_time(self.events[-1])

    @property
    def event_ids(self) -> list[str]:
        return [e.event_id for e in self.events]


@dataclass
class Actor:
    actor_id: str
    sessions: list[Session]

    @property
    def start(self) -> datetime:
        return min(s.start for s in self.sessions)

    @property
    def end(self) -> datetime:
        return max(s.end for s in self.sessions)


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    name: str
    family: str
    weight: int
    confidence: str
    attack: tuple[str, ...]
    measured: str  # what was observed, in words
    threshold: str  # what the rule needs, in words
    evidence: tuple[str, ...]  # event ids
    first_seen: datetime | None = None


@dataclass
class Finding:
    session: Session
    actor_id: str
    score: int
    verdict: str
    hits: list[RuleHit]
    suppressors: list[tuple[str, int]] = field(default_factory=list)
    explanation: str = ""

    @property
    def families(self) -> list[str]:
        return sorted({h.family for h in self.hits})
