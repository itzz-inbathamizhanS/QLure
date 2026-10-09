"""Step 1: group events into sessions.

A session is every event from the same (src_ip, client_fp, service) with no gap longer than
10 minutes. Events that share a decoy session id (cookie or SSH connection) always stay together.

A long, tight burst from the same (src_ip, service) also stays together, even across a changing
`client_fp`: real scanners found in testing (Nikto, in particular) put a per-request test name
inside their User-Agent, so `client_fp` changes on nearly every request, and without this a single
scan fragments into one session per request. The burst rule needs both a short gap and a long run
to fire, so it never merges two unrelated visitors behind one address who happen to click within a
second of each other: `test_same_ip_alone_never_merges_sessions` in tests/correlate covers exactly
that case. `BURST_GAP` is 5x the slowest gap measured in a real ~5,800-request Nikto run
(docs/eval-results-2026-10-09.md), and `MIN_BURST_EVENTS` is well above a two-visitor coincidence
and far below that run's length.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from qlure.correlate.model import Session, event_time
from qlure.events import Event

SESSION_GAP = timedelta(minutes=10)
BURST_GAP = timedelta(seconds=1)
MIN_BURST_EVENTS = 6


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


def _union_tight_bursts(ordered: list[Event], groups: _Groups) -> None:
    """Merge a long, tight-gap run of same (src_ip, service) events, whatever their `client_fp`.

    Runs shorter than `MIN_BURST_EVENTS` are left alone, so a single coincidental quick repeat
    (two different visitors behind one address, or a page and its one redirect) never merges.
    """
    by_ip_service: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, event in enumerate(ordered):
        by_ip_service[(event.src_ip, event.service.value)].append(i)

    for indices in by_ip_service.values():
        indices.sort(key=lambda i: event_time(ordered[i]))
        run: list[int] = [indices[0]]
        for previous, current in zip(indices, indices[1:], strict=False):
            if event_time(ordered[current]) - event_time(ordered[previous]) <= BURST_GAP:
                run.append(current)
                continue
            _union_run(run, groups)
            run = [current]
        _union_run(run, groups)


def _union_run(run: list[int], groups: _Groups) -> None:
    if len(run) >= MIN_BURST_EVENTS:
        for a, b in zip(run, run[1:], strict=False):
            groups.union(a, b)


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

    _union_tight_bursts(ordered, groups)

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
