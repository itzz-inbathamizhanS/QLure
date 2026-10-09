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
