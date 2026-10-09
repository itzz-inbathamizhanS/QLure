"""Behaviour features for one session. Counts and rates only: no tool names, no addresses.

Keeping tool names and IPs out stops the model from memorising which scanner we happened to
run. `pqc_capable` is left out on purpose, it is context for the investigator, not evidence.
"""

from __future__ import annotations

import math
import statistics
from urllib.parse import unquote

from qlure.correlate.model import Session, event_time

FEATURES = [
    "log_events",
    "log_duration_s",
    "log_requests_per_min",
    "log_distinct_paths",
    "share_4xx",
    "share_post",
    "share_with_query",
    "share_hidden_or_backup_paths",
    "special_char_share",
    "log_failed_logins",
    "log_distinct_usernames",
    "log_distinct_passwords",
    "logged_in",
    "log_commands",
    "honeytoken_used",
    "log_median_gap_s",
    "banner_only",
]
_SPECIAL = set("'\"<>;|`$(){}\\")
_HIDDEN = ("/.", ".bak", ".old", ".sql", ".zip", ".tar", "/backup", "id_rsa", "/etc/")


def _log(value: float) -> float:
    return math.log1p(max(0.0, value))


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def extract(session: Session) -> list[float]:
    events = session.events
    http = [e for e in events if e.action.value in ("http_request", "api_call")]
    paths = [str((e.request or {}).get("path", "")) for e in http]
    queries = [str((e.request or {}).get("query", "")) for e in http]
    bodies = [str((e.request or {}).get("body_preview", "")) for e in http]
    statuses = [(e.response or {}).get("status") for e in http]
    attempts = [e for e in events if e.action.value == "login_attempt" and e.credential]
    successes = [e for e in events if e.action.value == "login_success"]
    times = [event_time(e) for e in events]
    duration = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0.0
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
    text = unquote(" ".join(paths + queries + bodies))

    return [
        _log(len(events)),
        _log(duration),
        _log(len(http) / max(duration / 60, 1 / 60) if http else 0),
        _log(len(set(paths))),
        _ratio(sum(1 for s in statuses if isinstance(s, int) and 400 <= s < 500), len(http)),
        _ratio(sum(1 for e in http if (e.request or {}).get("method") == "POST"), len(http)),
        _ratio(sum(1 for q in queries if q), len(http)),
        _ratio(sum(1 for p in paths if any(t in p.lower() for t in _HIDDEN)), len(http)),
        _ratio(sum(1 for c in text if c in _SPECIAL), len(text)),
        _log(len(attempts) - len(successes)),
        _log(len({e.credential.username for e in attempts if e.credential.username})),
        _log(len({e.credential.password for e in attempts if e.credential.password})),
        1.0 if successes else 0.0,
        _log(sum(1 for e in events if e.action.value == "command")),
        1.0 if any(e.honeytoken_id for e in events) else 0.0,
        _log(statistics.median(gaps)) if gaps else 0.0,
        1.0 if all(e.action.value in ("connect", "banner", "disconnect") for e in events) else 0.0,
    ]
