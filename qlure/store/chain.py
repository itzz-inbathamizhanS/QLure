"""Hash chain over events: each hash covers the previous hash and the event's canonical JSON."""

from __future__ import annotations

import hashlib
import json

from qlure.events import Event

GENESIS = "0" * 64
_CHAIN_FIELDS = {"prev_hash", "hash"}


def canonical(event: Event) -> str:
    """The event as stable JSON: sorted keys, no spaces, chain fields left out."""
    data = event.model_dump(mode="json", exclude_none=True, exclude=_CHAIN_FIELDS)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def link_hash(prev_hash: str, canonical_json: str) -> str:
    return hashlib.sha256(f"{prev_hash}\n{canonical_json}".encode()).hexdigest()


ANCHOR_FIELDS = ("prev_anchor", "upto_seq", "upto_hash", "ts", "cutoff", "pruned", "total_pruned")


def anchor_hash(row: dict) -> str:
    """SHA-256 over one retention anchor row (which includes the previous anchor's hash)."""
    body = json.dumps({k: row[k] for k in ANCHOR_FIELDS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


CONFIG_FIELDS = ("ts", "who", "key", "old_value", "new_value", "outcome", "reason")


def config_hash(prev_hash: str, row: dict) -> str:
    """Hash of one config_audit row, chained to the row before it (same scheme as events)."""
    body = json.dumps({k: row[k] for k in CONFIG_FIELDS}, sort_keys=True, separators=(",", ":"))
    return link_hash(prev_hash, body)
