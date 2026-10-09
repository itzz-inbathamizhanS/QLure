"""Domain scanner for the dashboard: the Q-CAPS checks (qlure.pqcscan) behind the admin login.

Guardrails carried over from Q-CAPS:
- the target is reduced to a bare hostname; ports, credentials and IP literals are refused
- every address is checked (no private, loopback, link-local or reserved space) and every
  connection is pinned to the checked addresses
- a full scan needs a DNS TXT record that proves the domain is controlled by the admin, and the
  record is checked live on every full scan
- one scan runs at a time, and scans are rate limited, per process

Added for QLure: the dashboard has one admin, so ownership is bound to that admin's id. Full scans
are disabled until QLURE_DASHBOARD_SECRET is set, so the ownership token stays the same across
restarts. Nothing is stored: results are shown once and not written to the database.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Any

from qlure.pqcscan import ownership
from qlure.pqcscan.engine import analyze_domain
from qlure.pqcscan.errors import ScannerException
from qlure.pqcscan.security.target_validator import normalize_hostname

ADMIN_ID = "admin"
MODES = ("standard", "full")
FULL_OFF = "Full scans are off. Set QLURE_DASHBOARD_SECRET, then restart the dashboard."
NEED_PROOF = (
    "Full scans need proof that you control this domain. "
    "Publish the DNS TXT record below, then scan again."
)
RATE_COUNT = 5
RATE_WINDOW = 60.0

_lock = threading.Lock()
_recent: deque[float] = deque()
_busy = False


def ownership_secret() -> str | None:
    """The secret that signs ownership tokens, or None when full scans are off."""
    return os.environ.get("QLURE_DASHBOARD_SECRET") or None


def verification_info(secret: str, hostname: str, proof: dict | None = None) -> dict[str, Any]:
    """The DNS TXT record the admin publishes to prove control of `hostname`."""
    info: dict[str, Any] = {
        "hostname": hostname,
        "record_name": ownership.record_name(hostname),
        "record_value": ownership.record_value(secret, ADMIN_ID, hostname),
        "note": "The record may also sit on a parent domain, for example the registered domain.",
    }
    if proof is not None:
        info["verified"] = proof["verified"]
        info["verified_domain"] = proof["domain"]
    return info


def verify(target: str) -> dict[str, Any]:
    """Check whether the ownership record is published yet. Makes DNS lookups only."""
    try:
        hostname = normalize_hostname(target)
    except ScannerException as e:
        return {"error": e.message}
    secret = ownership_secret()
    if not secret:
        return {"error": FULL_OFF}
    proof = ownership.check_ownership(secret, ADMIN_ID, hostname)
    return {"verification": verification_info(secret, hostname, proof)}


def _start() -> str | None:
    """Return None when a scan may start, otherwise the reason it may not. Pair with _finish()."""
    global _busy
    now = time.monotonic()
    with _lock:
        while _recent and now - _recent[0] > RATE_WINDOW:
            _recent.popleft()
        if _busy:
            return "A scan is already running. Wait for it to finish."
        if len(_recent) >= RATE_COUNT:
            return "Rate limit reached. Try again in a minute."
        _recent.append(now)
        _busy = True
    return None


def _finish() -> None:
    global _busy
    with _lock:
        _busy = False


def run(target: str, mode: str) -> dict[str, Any]:
    """Scan `target`. Returns {"result": ...}, or {"error": ...} with an optional "verification"."""
    if mode not in MODES:
        return {"error": "Mode must be standard or full."}
    try:
        hostname = normalize_hostname(target)
    except ScannerException as e:
        return {"error": e.message}

    authorization = {"ownership_verified": False, "verified_domain": None}
    if mode == "full":
        secret = ownership_secret()
        if not secret:
            return {"error": FULL_OFF}
        proof = ownership.check_ownership(secret, ADMIN_ID, hostname)
        if not proof["verified"]:
            return {
                "error": NEED_PROOF,
                "verification": verification_info(secret, hostname, proof),
            }
        authorization = {"ownership_verified": True, "verified_domain": proof["domain"]}

    reason = _start()
    if reason:
        return {"error": reason}
    try:
        result = analyze_domain(hostname, mode=mode, authorization=authorization)
    except Exception as e:  # a failing check must not take the dashboard down
        return {"error": f"Scan failed: {type(e).__name__}"}
    finally:
        _finish()
    if result.get("error"):
        return {"error": result["error"]}
    return {"result": result}
