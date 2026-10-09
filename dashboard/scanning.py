"""Domain scanner for the dashboard: the Q-CAPS checks (qlure.pqcscan) behind the admin login.

Standard scans only: public information (DNS, WHOIS, HTTP headers, TLS handshake, key exchange,
certificate, certificate-transparency subdomains). The active checks of a full scan are not
reachable from the dashboard.

Guardrails carried over from Q-CAPS:
- the target is reduced to a bare hostname; ports, credentials and IP literals are refused
- every address is checked (no private, loopback, link-local or reserved space) and every
  connection is pinned to the checked addresses
- one scan runs at a time, and scans are rate limited, per process

Nothing is stored: results are shown once and not written to the database.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from qlure.pqcscan.engine import analyze_domain
from qlure.pqcscan.errors import ScannerException
from qlure.pqcscan.security.target_validator import normalize_hostname

RATE_COUNT = 5
RATE_WINDOW = 60.0

_lock = threading.Lock()
_recent: deque[float] = deque()
_busy = False


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


def run(target: str) -> dict[str, Any]:
    """Standard-scan `target`. Returns {"result": ...} or {"error": ...}."""
    try:
        hostname = normalize_hostname(target)
    except ScannerException as e:
        return {"error": e.message}

    reason = _start()
    if reason:
        return {"error": reason}
    try:
        result = analyze_domain(hostname, mode="standard")
    except Exception as e:  # a failing check must not take the dashboard down
        return {"error": f"Scan failed: {type(e).__name__}"}
    finally:
        _finish()
    if result.get("error"):
        return {"error": result["error"]}
    return {"result": result}
