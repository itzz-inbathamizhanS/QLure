"""Helpers shared by the decoys: the gateway's PROXY header, visitor identity, fingerprints."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

MAX_BODY_BYTES = 64 * 1024
PROXY_LINE_LIMIT = 107  # PROXY protocol v1 maximum, including CRLF
PROXY_TIMEOUT = 10
PROXY_ENV = "QLURE_PROXY_PROTOCOL"
PROXY_OPTIONAL_WAIT = 0.5  # how long optional mode waits for a client that speaks first
_PROXY_PREFIX = b"PROXY "


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
    return parse_proxy_line(line)


def parse_proxy_line(line: bytes) -> Client:
    if len(line) > PROXY_LINE_LIMIT:
        raise BadProxyHeader("PROXY line too long")
    parts = line[:-2].decode("ascii", errors="replace").split(" ")
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] not in ("TCP4", "TCP6"):
        raise BadProxyHeader("unexpected PROXY line")
    try:
        return Client(ip=str(ipaddress.ip_address(parts[2])), port=int(parts[4]))
    except ValueError as exc:
        raise BadProxyHeader("bad address in PROXY line") from exc


def proxy_mode() -> str:
    """`required` (default) or `optional` from QLURE_PROXY_PROTOCOL; anything else is `required`."""
    value = os.environ.get(PROXY_ENV, "").strip().lower()
    return "optional" if value == "optional" else "required"


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_proxy_mode_safe(host: str) -> None:
    """Exit non-zero if `optional` is asked for on an address that is not loopback.

    In optional mode any client can forge a PROXY line and claim any source address.
    """
    if proxy_mode() == "optional" and not is_loopback_host(host):
        raise SystemExit(
            f"error: {PROXY_ENV}=optional lets any client forge its source address, so it is "
            f"only allowed on a loopback bind address (got {host!r}). Set QLURE_BIND_HOST="
            "127.0.0.1 or use --host 127.0.0.1, or unset the option."
        )


class PrefixedReader:
    """A reader that hands back bytes already taken from the stream before the real ones."""

    def __init__(self, reader: asyncio.StreamReader, prefix: bytes) -> None:
        self._reader = reader
        self._prefix = prefix

    async def read(self, n: int = -1) -> bytes:
        if self._prefix:
            take = self._prefix if n < 0 else self._prefix[:n]
            self._prefix = self._prefix[len(take) :]
            return take
        return await self._reader.read(n)


async def accept_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> tuple[Client, Any]:
    """Who is connecting, and a reader that still yields every byte the client sent.

    required: the connection must start with the gateway's PROXY line (BadProxyHeader if not).
    optional (localhost runs only): a valid PROXY line is used as is; anything else is a direct
    client whose socket address is the source, and its first bytes are replayed.
    """
    if proxy_mode() == "required":
        return await read_proxy_header(reader), reader
    head = b""
    closed = False
    try:
        async with asyncio.timeout(PROXY_OPTIONAL_WAIT):
            while len(head) < len(_PROXY_PREFIX) and _PROXY_PREFIX.startswith(head):
                chunk = await reader.read(len(_PROXY_PREFIX) - len(head))
                if not chunk:
                    closed = True
                    break
                head += chunk
    except TimeoutError:
        pass
    if closed and not head:
        raise BadProxyHeader("closed before sending anything")  # a port probe, not a visitor
    if head == _PROXY_PREFIX:
        try:
            rest = await asyncio.wait_for(reader.readuntil(b"\r\n"), PROXY_TIMEOUT)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise BadProxyHeader("no PROXY line") from exc
        return parse_proxy_line(head + rest), reader
    peer = writer.get_extra_info("peername") or ("127.0.0.1", None)
    return Client(ip=str(peer[0]), port=peer[1]), PrefixedReader(reader, head)


def replay_ts(headers: Any) -> datetime | None:
    """The original time of a replayed request, only when it carries the replay token.

    Without QLURE_REPLAY_TOKEN set, or with a wrong token, a visitor cannot choose the
    time an event is filed under.
    """
    token = os.environ.get("QLURE_REPLAY_TOKEN", "")
    given = headers.get("x-qlure-replay-token", "")
    if not token or not hmac.compare_digest(given.encode(), token.encode()):
        return None
    try:
        moment = datetime.fromisoformat(headers.get("x-qlure-replay-ts", ""))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


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
