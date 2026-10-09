"""Offline indicator matcher for decoy events.

Adapted from HybridDFIR's ioc_engine.py. Same indicator file format (STIX-like JSON:
{"indicators": [{"value": ..., "type": ...}]}), but it matches decoy events instead of the
local machine. Hits are context for an analyst; they never score on their own.
"""

from __future__ import annotations

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
                iocs.ips.add(value)
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
    if event.get("src_ip", "").lower() in iocs.ips:
        hits.append(IOCHit("ipv4-addr", event["src_ip"].lower(), "src_ip"))

    honeytoken = event.get("honeytoken_id")
    if honeytoken and honeytoken.lower() in iocs.filenames:
        hits.append(IOCHit("file:name", honeytoken.lower(), "honeytoken_id"))

    for text in _strings(event.get("request")) + _strings(event.get("response")):
        for token in _TOKEN.findall(text.lower()):
            if token in iocs.ips:
                hits.append(IOCHit("ipv4-addr", token, "request"))
            if token in iocs.filenames:
                hits.append(IOCHit("file:name", token, "request"))
            if _HEX_DIGEST.match(token) and token in iocs.hashes:
                hits.append(IOCHit("file:hashes", token, "request"))
            for domain in iocs.domains:
                if token == domain or token.endswith("." + domain):
                    hits.append(IOCHit("domain-name", domain, "request"))

    unique = dict.fromkeys(hits)  # keep order, drop repeats
    return list(unique)
