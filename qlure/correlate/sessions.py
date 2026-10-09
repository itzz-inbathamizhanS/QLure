"""Step 1: group events into sessions.

A session is every event from the same (src_ip, client_fp, service) with no gap longer than
10 minutes. Events that share a decoy session id (cookie or SSH connection) always stay together.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from qlure.correlate.model import Session, event_time
from qlure.events import Event

SESSION_GAP = timedelta(minutes=10)


class _Groups:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def build_sessions(events: list[Event]) -> list[Session]:
    ordered = sorted(events, key=lambda e: (event_time(e), e.event_id))
    groups = _Groups(len(ordered))

    by_decoy_session: dict[tuple[str, str], int] = {}
    by_key: dict[tuple[str, str | None, str], int] = {}
    for i, event in enumerate(ordered):
        sid = (event.service.value, event.session_id)
        if sid in by_decoy_session:
            groups.union(i, by_decoy_session[sid])
        else:
            by_decoy_session[sid] = i

        key = (event.src_ip, event.client_fp, event.service.value)
        previous = by_key.get(key)
        if (
            previous is not None
            and event_time(event) - event_time(ordered[previous]) <= SESSION_GAP
        ):
            groups.union(i, previous)
        by_key[key] = i  # events are in time order, so this is always the latest

    members: dict[int, list[Event]] = defaultdict(list)
    for i, event in enumerate(ordered):
        members[groups.find(i)].append(event)

    sessions = []
    for group in members.values():
        first = group[0]
        fps = [e.client_fp for e in group if e.client_fp]
        sessions.append(
            Session(
                session_id="sess-" + hashlib.sha1(first.event_id.encode()).hexdigest()[:12],  # noqa: S324
                service=first.service.value,
                src_ip=first.src_ip,
                client_fp=max(set(fps), key=fps.count) if fps else None,
                events=group,
            )
        )
    return sorted(sessions, key=lambda s: (s.start, s.session_id))
