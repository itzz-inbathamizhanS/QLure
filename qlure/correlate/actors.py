"""Step 2: link sessions into actors, only on strong evidence.

Sessions merge when they share:
  * a honeytoken that one of them used (a lone reader of that token joins the user),
  * a tried password that is not a common default, or the same list of 2+ usernames,
  * a client fingerprint on the same IP within 30 minutes. Raw TCP banner services have no
    fingerprint, so banner-only sessions from one IP within 30 minutes count as one client.

An IP address alone never merges sessions: replayed judge traffic will share one IP.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from qlure.correlate.model import Actor, Session
from qlure.correlate.rules import load_config
from qlure.correlate.sessions import _Groups

ACTOR_WINDOW = timedelta(minutes=30)
BANNER_SERVICES = {"ftp", "mysql", "redis"}
USE_ACTIONS = {"honeytoken_use", "login_success", "api_call"}


def _links(sessions: list[Session]) -> list[tuple[int, int]]:
    cfg = load_config()
    default_passwords = {pw for _, pw in cfg["lists"]["default_credentials"]}
    links: list[tuple[int, int]] = []

    users: dict[str, set[int]] = defaultdict(set)
    readers: dict[str, set[int]] = defaultdict(set)
    passwords: dict[str, set[int]] = defaultdict(set)
    username_lists: dict[tuple[str, ...], set[int]] = defaultdict(set)

    for i, session in enumerate(sessions):
        names: list[str] = []
        for event in session.events:
            if event.honeytoken_id:
                bucket = users if event.action.value in USE_ACTIONS else readers
                bucket[event.honeytoken_id].add(i)
            if event.action.value == "login_attempt" and event.credential:
                cred = event.credential
                if cred.password and cred.password not in default_passwords:
                    passwords[cred.password].add(i)
                if cred.username and cred.username not in names:
                    names.append(cred.username)
        if len(names) >= 2:
            username_lists[tuple(sorted(names))].add(i)

    for token, used in users.items():
        group = set(used)
        if len(readers[token] - used) == 1:
            group |= readers[token]
        links += [(a, b) for a, b in zip(sorted(group), sorted(group)[1:], strict=False)]
    for table in (passwords, username_lists):
        for group in table.values():
            ordered = sorted(group)
            links += list(zip(ordered, ordered[1:], strict=False))

    by_client: dict[tuple[str, str | None], list[int]] = defaultdict(list)
    for i, session in enumerate(sessions):
        if session.client_fp:
            by_client[(session.src_ip, session.client_fp)].append(i)
        elif session.service in BANNER_SERVICES:
            by_client[(session.src_ip, None)].append(i)
    for indices in by_client.values():
        indices.sort(key=lambda i: sessions[i].start)
        for a, b in zip(indices, indices[1:], strict=False):
            if sessions[b].start - sessions[a].end <= ACTOR_WINDOW:
                links.append((a, b))
    return links


def build_actors(sessions: list[Session]) -> list[Actor]:
    groups = _Groups(len(sessions))
    for a, b in _links(sessions):
        groups.union(a, b)
    members: dict[int, list[Session]] = defaultdict(list)
    for i, session in enumerate(sessions):
        members[groups.find(i)].append(session)
    actors = []
    for group in members.values():
        group.sort(key=lambda s: (s.start, s.session_id))
        digest = hashlib.sha1(group[0].session_id.encode()).hexdigest()[:8]  # noqa: S324
        actors.append(Actor(actor_id=f"actor-{digest}", sessions=group))
    return sorted(actors, key=lambda a: (a.start, a.actor_id))
