"""Fake-content settings the operator chose in the dashboard, read from one small file.

The decoys only get a read-only folder that holds this file (QLURE_CONTENT), never the
database or the full settings. Bad or missing content falls back to the defaults.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULTS = {
    "company_name": "Veltrix Logistics",
    "ftp_banner": "220 ProFTPD 1.3.8 Server (Veltrix Files)",
}
MAX_LENGTH = 120


def _load() -> dict[str, str]:
    path = os.environ.get("QLURE_CONTENT")
    if not path:
        return dict(DEFAULTS)
    try:
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULTS)
    out = dict(DEFAULTS)
    for key in DEFAULTS:
        value = saved.get(key) if isinstance(saved, dict) else None
        if isinstance(value, str) and value and len(value) <= MAX_LENGTH and value.isprintable():
            out[key] = value
    return out


def company_name() -> str:
    return _load()["company_name"]


def ftp_greeting() -> bytes:
    return _load()["ftp_banner"].encode("ascii", errors="replace") + b"\r\n"
