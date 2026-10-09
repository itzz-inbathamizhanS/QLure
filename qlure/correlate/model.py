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
    # The same actor's whole picture: every rule it hit across all its sessions, combined and
    # scored once. A thin session that is Benign alone can belong to a Noteworthy actor; the
    # session's own score and verdict above are never changed by this.
    actor_score: int = 0
    actor_verdict: str = "Benign"
    actor_hits: list[RuleHit] = field(default_factory=list)
    actor_explanation: str = ""

    @property
    def families(self) -> list[str]:
        return sorted({h.family for h in self.hits})

    @property
    def effective_verdict(self) -> str:
        """The more serious of this session's own verdict and its actor's combined verdict.

        Only promoted when this session has at least one rule hit of its own: a session with
        none is a bystander swept into the actor by a weak link (e.g. a guessed password it
        happened to reuse), not evidence that this session's own traffic was part of an attack.
        """
        if not self.hits:
            return self.verdict
        order = {"Benign": 0, "Suspicious": 1, "Noteworthy": 2}
        return max((self.verdict, self.actor_verdict), key=lambda v: order[v])
