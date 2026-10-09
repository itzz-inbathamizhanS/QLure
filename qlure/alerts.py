"""Webhook alerts for new Noteworthy findings (ROADMAP P4.3). Off by default, operator side only.

Runs on the operator host (CLI, cron or the dashboard host), never inside a decoy container.
The payload is minimal: verdict, score, short actor id, source IP, services, rule and ATT&CK ids,
honeytoken IDs (never their secret values), times, a host-less dashboard path and the version.
Request bodies and passwords are never read. The webhook URL is a secret and is only ever logged
masked. A failed post leaves the session un-alerted so the next run retries it.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from qlure import export as ioc_export
from qlure.settings import mask_url

log = logging.getLogger("qlure.alerts")

DEFAULT_MAX_ALERTS = 10
STATE_LIMIT = 5000  # alerted session ids kept; the oldest are dropped first
RETRIES = 1
ALLOW_PRIVATE_ENV = "QLURE_ALERT_ALLOW_PRIVATE"
# Cloud metadata addresses that are not link-local.
METADATA_IPS = {ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("fd00:ec2::254")}

Post = Callable[[str, bytes, float], int]  # (url, json body, timeout) -> HTTP status; may raise


class AlertConfigError(Exception):
    """The URL is unusable (scheme, host or address). The CLI prints it and exits 1."""


@dataclass
class Result:
    sent: int = 0
    failed: int = 0
    more: int = 0  # new sessions held back by the per-run cap
    payloads: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("qlure")
    except Exception:
        return "unknown"


def _resolve(host: str) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, None)]


def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:  # ::ffff:127.0.0.1 is 127.0.0.1
        ip = mapped
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip in METADATA_IPS


def resolve_checked(url: str) -> list[str]:
    """Validate the URL and resolve its host exactly once. Returns the validated addresses.

    Every returned address passed the check; the caller must connect to these and never resolve
    the name again (DNS rebinding). Raises AlertConfigError.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018
    except ValueError:
        raise AlertConfigError("webhook URL is not valid") from None
    if parts.scheme not in ("http", "https"):
        raise AlertConfigError("webhook URL scheme must be http or https")
    if not host or "@" in parts.netloc:
        raise AlertConfigError("webhook URL needs a host and no embedded credentials")
    allow_private = os.environ.get(ALLOW_PRIVATE_ENV) == "1"
    try:
        addresses = [text.split("%")[0] for text in _resolve(host)]
        parsed = [ipaddress.ip_address(text) for text in addresses]
    except (OSError, ValueError):
        raise AlertConfigError(f"cannot resolve the webhook host {host}") from None
    if not parsed:
        raise AlertConfigError(f"cannot resolve the webhook host {host}")
    if not allow_private and any(_blocked(ip) for ip in parsed):
        raise AlertConfigError(
            f"webhook host {host} resolves to a loopback/link-local/metadata address"
            f" (set {ALLOW_PRIVATE_ENV}=1 to allow)"
        )
    return addresses


def check_url(url: str) -> None:
    """Raise AlertConfigError unless the URL is http(s) to a host that is not loopback/metadata."""
    resolve_checked(url)


class _PinnedBackend:
    """httpcore network backend that connects only to pre-validated addresses.

    The request URL keeps the original hostname, so the Host header, SNI and certificate
    verification all use it; only the TCP connect target is pinned. It never resolves a name.
    """

    def __init__(self, ips: list[str], inner: Any = None) -> None:
        import httpcore

        self._ips = list(ips)[:4]
        self._inner = inner or httpcore.SyncBackend()

    def connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any) -> Any:
        last: Exception | None = None
        for ip in self._ips:
            try:
                return self._inner.connect_tcp(ip, port, *args, **kwargs)
            except Exception as exc:
                last = exc
        raise last or OSError("no validated address")

    def __getattr__(self, name: str) -> Any:  # connect_unix_socket, sleep
        return getattr(self._inner, name)


def _pinned_transport(ips: list[str]) -> Any:
    import httpx

    transport = httpx.HTTPTransport()  # default TLS verification stays on
    pool = transport._pool  # type: ignore[attr-defined]
    if not hasattr(pool, "_network_backend"):
        raise RuntimeError("cannot pin the connection address")  # fail closed
    pool._network_backend = _PinnedBackend(ips)
    return transport


def _httpx_post(url: str, body: bytes, timeout: float, pinned: list[str] | None = None) -> int:
    import httpx

    if pinned is None:
        pinned = resolve_checked(url)
    with httpx.Client(
        transport=_pinned_transport(pinned), timeout=timeout, follow_redirects=False
    ) as client:
        response = client.post(url, content=body, headers={"Content-Type": "application/json"})
    return response.status_code


# ---- state ----


def _load_state(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ids = data["alerted"]
        return [i for i in ids if isinstance(i, str)][-STATE_LIMIT:]
    except FileNotFoundError:
        return []
    except (OSError, ValueError, KeyError, TypeError):
        log.warning("alert state %s is unreadable; starting empty", path)
        return []


def _save_state(path: Path, alerted: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps({"version": 1, "alerted": alerted[-STATE_LIMIT:]}), encoding="utf-8")
    tmp.replace(path)


# ---- payloads ----


def _session_rows(db_path: Path) -> dict[str, tuple[Any, ...]]:
    conn = ioc_export._open(db_path)
    try:
        rows = conn.execute(
            "SELECT s.session_id, s.service, s.first_seen, s.last_seen, f.score"
            " FROM sessions s JOIN findings f USING (session_id)"
        ).fetchall()
    finally:
        conn.close()
    return {r[0]: r for r in rows}


def build_payloads(db_path: Path, min_verdict: str, skip: set[str]) -> list[dict[str, Any]]:
    """One minimal payload per session at/above min_verdict that is not in skip, oldest first."""
    data = ioc_export.load(db_path, min_verdict)
    extra = _session_rows(db_path)
    tokens: dict[str, set[str]] = {}
    for ind in data.indicators:
        if ind.kind == "honeytoken-id":
            for sid in ind.sessions:
                tokens.setdefault(sid, set()).add(ind.value)
    version = _version()
    out = []
    for session in data.sessions:
        if session.session_id in skip:
            continue
        _, service, first, last, score = extra.get(session.session_id, (None,) * 5)
        rules = list(session.rules)
        text = (
            f"QLure {session.verdict} (score {score}) from {session.src_ip}"
            f" on {service or 'unknown'}; rules {', '.join(rules) or 'none'};"
            f" /session/{quote(session.session_id)}"
        )
        out.append(
            {
                "text": text,
                "verdict": session.verdict,
                "score": score,
                "actor": session.actor_id[:8],
                "source_ip": session.src_ip,
                "services": [service] if service else [],
                "rule_ids": rules,
                "attack_ids": list(session.attacks),
                "honeytoken_ids": sorted(tokens.get(session.session_id, ())),
                "first_seen": first,
                "last_seen": last,
                "dashboard_path": f"/session/{quote(session.session_id)}",
                "qlure_version": version,
                "_session_id": session.session_id,
            }
        )
    out.sort(key=lambda p: (p["first_seen"] or "", p["_session_id"]))
    return out


def pending(
    db_path: Path, state_path: Path, min_verdict: str = "noteworthy", limit: int | None = None
) -> tuple[list[dict[str, Any]], int]:
    """The payloads that would be sent now, and how many more the cap holds back."""
    todo = build_payloads(db_path, min_verdict, set(_load_state(state_path)))
    cap = DEFAULT_MAX_ALERTS if limit is None else limit
    return todo[:cap], max(0, len(todo) - cap)


def _body(payload: dict[str, Any]) -> bytes:
    return json.dumps({k: v for k, v in payload.items() if not k.startswith("_")}).encode()


def _deliver(post: Post, url: str, body: bytes, timeout: float) -> bool:
    for _ in range(1 + RETRIES):
        try:
            if 200 <= post(url, body, timeout) < 300:
                return True
        except Exception as exc:  # the URL is a secret: log the class only
            log.warning("alert post to %s failed: %s", mask_url(url), type(exc).__name__)
        else:
            log.warning("alert post to %s was not accepted", mask_url(url))
    return False


def notify_new_noteworthy(
    db_path: Path,
    state_path: Path,
    url: str,
    *,
    min_verdict: str = "noteworthy",
    timeout: float = 5,
    post: Post | None = None,
    max_alerts: int = DEFAULT_MAX_ALERTS,
) -> Result:
    """Post new findings once each. Never raises: problems are in Result.error and the log."""
    result = Result()
    try:
        pinned = resolve_checked(url)  # resolved once; the POST connects to these only
        todo, result.more = pending(db_path, state_path, min_verdict, max_alerts)
        sender = post or (lambda u, b, t: _httpx_post(u, b, t, pinned=pinned))
        alerted = _load_state(state_path)
        for payload in todo:
            if _deliver(sender, url, _body(payload), timeout):
                alerted.append(payload["_session_id"])
                result.sent += 1
                result.payloads.append(payload)
                _save_state(state_path, alerted)  # after each success: a crash cannot re-send it
            else:
                result.failed += 1
        if result.more:
            summary = {"text": f"QLure: +{result.more} more new {min_verdict} sessions pending"}
            _deliver(sender, url, json.dumps(summary).encode(), timeout)
    except AlertConfigError as exc:
        result.error = str(exc)
        log.warning("alerts not sent: %s", exc)
    except (ioc_export.ExportError, sqlite3.Error, OSError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        log.warning("alerts not sent: %s", result.error)
    except Exception as exc:  # never raise into the caller
        result.error = type(exc).__name__
        log.warning("alerts not sent: %s", result.error)
    return result
