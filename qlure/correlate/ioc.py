"""Offline indicator matcher for decoy events.

Adapted from HybridDFIR's ioc_engine.py. Same indicator file format (STIX-like JSON:
{"indicators": [{"value": ..., "type": ...}]}), but it matches decoy events instead of the
local machine. Hits are context for an analyst; they never score on their own.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_TOKEN = re.compile(r"[A-Za-z0-9._-]+")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{64}$")


@dataclass(frozen=True)
class IOCHit:
    indicator_type: str
    value: str
    field: str  # which part of the event matched: "src_ip", "request", "honeytoken_id", ...


class IOCSet:
    def __init__(self) -> None:
        self.ips: set[str] = set()
        self.domains: set[str] = set()
        self.hashes: set[str] = set()
        self.filenames: set[str] = set()

    @classmethod
    def from_indicators(cls, data: dict[str, Any]) -> IOCSet:
        iocs = cls()
        for item in data.get("indicators", []):
            kind = str(item.get("type", "")).lower()
            value = str(item.get("value", "")).strip().lower()
            if not value:
                continue
            if kind in {"ipv4-addr", "ipv6-addr"}:
                iocs.ips.add(_ip(value))
            elif kind == "domain-name":
                iocs.domains.add(value)
            elif kind == "file:hashes":
                iocs.hashes.add(value)
            elif kind == "file:name":
                iocs.filenames.add(value)
        return iocs

    @classmethod
    def load(cls, path: str | Path) -> IOCSet:
        return cls.from_indicators(json.loads(Path(path).read_text(encoding="utf-8")))

    def __len__(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.hashes) + len(self.filenames)


def _ip(value: str) -> str:
    """Canonical text of an address, so 2001:DB8:0::1 and 2001:db8::1 are one indicator."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _ip_type(value: str) -> str:
    return "ipv6-addr" if ":" in value else "ipv4-addr"


def _strings(value: Any) -> list[str]:
    """Every string inside a nested request/response payload."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def match_event(event: dict[str, Any], iocs: IOCSet) -> list[IOCHit]:
    """Match one event (a dict in the Event schema shape) against the indicator set."""
    hits: list[IOCHit] = []
    src = _ip(str(event.get("src_ip", "")))
    if src in iocs.ips:
        hits.append(IOCHit(_ip_type(src), src, "src_ip"))

    honeytoken = event.get("honeytoken_id")
    if honeytoken and honeytoken.lower() in iocs.filenames:
        hits.append(IOCHit("file:name", honeytoken.lower(), "honeytoken_id"))

    for text in _strings(event.get("request")) + _strings(event.get("response")):
        for token in _TOKEN.findall(text.lower()):
            if token in iocs.ips:
                hits.append(IOCHit(_ip_type(token), token, "request"))
            if token in iocs.filenames:
                hits.append(IOCHit("file:name", token, "request"))
            if _HEX_DIGEST.match(token) and token in iocs.hashes:
                hits.append(IOCHit("file:hashes", token, "request"))
            for domain in iocs.domains:
                if token == domain or token.endswith("." + domain):
                    hits.append(IOCHit("domain-name", domain, "request"))

    unique = dict.fromkeys(hits)  # keep order, drop repeats
    return list(unique)
