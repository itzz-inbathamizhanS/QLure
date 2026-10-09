"""Planted secrets, loaded from honeytokens.yaml. Every value is fake."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

HONEYTOKEN_FILE = Path(__file__).parent / "honeytokens.yaml"


@lru_cache(maxsize=1)
def load() -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(HONEYTOKEN_FILE.read_text(encoding="utf-8"))
    return {token["id"]: token for token in data["honeytokens"]}


def get(token_id: str) -> dict[str, Any]:
    return load()[token_id]


def find(kind: str, value: str, username: str | None = None) -> dict[str, Any] | None:
    """Return the honeytoken with this kind and value, or None.

    A token that names a username only matches that username.
    """
    for token in load().values():
        if token["kind"] == kind and token["value"] == value:
            if token.get("username") in (None, username):
                return token
    return None
