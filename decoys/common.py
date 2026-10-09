"""Helpers shared by the decoys: the gateway's PROXY header, visitor identity, fingerprints."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
from dataclasses import dataclass
from typing import Any

MAX_BODY_BYTES = 64 * 1024
PROXY_LINE_LIMIT = 107  # PROXY protocol v1 maximum, including CRLF
PROXY_TIMEOUT = 10


@dataclass(frozen=True)
class Client:
    ip: str
    port: int | None


class BadProxyHeader(ValueError):
    """The connection did not start with a valid PROXY line from the gateway."""


async def read_proxy_header(reader: asyncio.StreamReader) -> Client:
    """Read the PROXY v1 line the gateway writes before any protocol bytes.

    Only the gateway can reach these ports and it always sends the line, so a
    missing or malformed line means the connection is dropped.
    """
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), PROXY_TIMEOUT)
    except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        raise BadProxyHeader("no PROXY line") from exc
    if len(line) > PROXY_LINE_LIMIT:
        raise BadProxyHeader("PROXY line too long")
    parts = line[:-2].decode("ascii", errors="replace").split(" ")
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] not in ("TCP4", "TCP6"):
        raise BadProxyHeader("unexpected PROXY line")
    try:
        return Client(ip=str(ipaddress.ip_address(parts[2])), port=int(parts[4]))
    except ValueError as exc:
        raise BadProxyHeader("bad address in PROXY line") from exc


def fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


async def read_capped(request: Any) -> bytes | None:
    """Read the request body. Returns None if it is larger than MAX_BODY_BYTES,
    even when the request sends no Content-Length."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)
