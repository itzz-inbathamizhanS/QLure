"""FTP, MySQL and Redis listeners.

Each sends its greeting (Redis has none) and runs a short fixed-reply dialogue from
decoys/banners/dialogues.py (at most 8 commands, 10 s), logs the first bytes, and closes.
Like the SSH decoy, each listener reads the gateway's PROXY line first so events carry the
real visitor address.
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import os
import secrets
import string
import struct
import uuid
from collections.abc import Callable
from functools import partial

from decoys import content
from decoys.banners import dialogues
from decoys.common import BadProxyHeader, read_proxy_header
from qlure.events import Action, Service, emit

READ_TIMEOUT = 10
FTP_BANNER = b"220 ProFTPD 1.3.8 Server (Veltrix Files)\r\n"  # the default greeting
REDIS_NOAUTH = dialogues.NOAUTH
_BUDGETS = {
    Service.FTP: dialogues.FTP_BUDGET,
    Service.MYSQL: dialogues.MYSQL_PACKET_LIMIT + 4,
    Service.REDIS: dialogues.REDIS_BUDGET,
}


def mysql_greeting(connection_id: int = 1) -> bytes:
    """A MySQL 8.0 initial handshake packet, as a client reads it on connect."""
    scramble = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
    raw = scramble.encode()
    payload = (
        b"\x0a"  # protocol version 10
        + b"8.0.36\x00"
        + struct.pack("<I", connection_id)
        + raw[:8]
        + b"\x00"
        + struct.pack("<H", 0xF7FF)  # capability flags, lower 16 bits
        + bytes([33])  # utf8mb4 character set
        + struct.pack("<H", 0x0002)  # status: autocommit
        + struct.pack("<H", 0x000F)  # capability flags, upper 16 bits
        + bytes([21])  # length of auth plugin data
        + b"\x00" * 10
        + raw[8:20]
        + b"\x00"
        + b"mysql_native_password\x00"
    )
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


async def _handle(
    service: Service,
    greeting: bytes | Callable[[], bytes],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        visitor = await read_proxy_header(reader)
    except BadProxyHeader:
        writer.close()
        return

    base = {
        "service": service,
        "src_ip": visitor.ip,
        "src_port": visitor.port,
        "session_id": uuid.uuid4().hex,
    }
    emit({**base, "action": Action.CONNECT})

    def log(action: Action, **extra: object) -> None:
        emit({**base, "action": action, **extra})

    banner_sent = False

    def log_banner(first: bytes) -> None:
        nonlocal banner_sent
        banner_sent = True
        log(
            Action.BANNER,
            request={
                "bytes_len": len(first),
                "first_bytes_hex": first[:64].hex(),
                "first_bytes_preview": first[:256].decode("utf-8", errors="replace"),
            },
        )

    buf = dialogues.Buf(reader, _BUDGETS[service], log_banner)
    try:
        data = greeting() if callable(greeting) else greeting  # FTP's banner can be changed live
        async with asyncio.timeout(READ_TIMEOUT):  # the whole conversation, not each read
            if data:
                writer.write(data)
                await writer.drain()
            if service is Service.FTP:
                await dialogues.ftp(buf, writer, log)
            elif service is Service.MYSQL:
                await dialogues.mysql(buf, writer, log, data, visitor.ip)
            else:
                await dialogues.redis(buf, writer, log)
    except (TimeoutError, OSError, dialogues.Closed):
        pass
    finally:  # also when the server is shut down mid-conversation
        if not banner_sent:
            log_banner(b"")
        writer.close()
        log(Action.DISCONNECT)


_mysql_ids = itertools.count(1)


def next_mysql_greeting() -> bytes:
    """A fresh scramble and a rising connection id on every connect, as a real server sends.

    One greeting built at import would repeat the same salt and id 1 to every visitor, which
    is a well-known way to spot a honeypot.
    """
    return mysql_greeting(next(_mysql_ids))


LISTENERS: list[tuple[Service, int, bytes | Callable[[], bytes]]] = [
    (Service.FTP, 2121, content.ftp_greeting),
    (Service.MYSQL, 3306, next_mysql_greeting),
    (Service.REDIS, 6379, b""),
]


async def start(
    service: Service,
    port: int,
    greeting: bytes | Callable[[], bytes],
    host: str | None = None,
) -> asyncio.Server:
    handler: Callable[..., object] = partial(_handle, service, greeting)
    return await asyncio.start_server(handler, host or bind_host(), port)


def bind_host() -> str:
    """Address the listeners bind: QLURE_BIND_HOST, default all interfaces (Docker)."""
    return os.environ.get("QLURE_BIND_HOST") or "0.0.0.0"  # noqa: S104


async def main(host: str | None = None) -> None:
    servers = [await start(service, port, greeting, host) for service, port, greeting in LISTENERS]
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Q-Lure FTP, MySQL and Redis decoys")
    parser.add_argument(
        "--host", default=None, help="bind address (default: QLURE_BIND_HOST or 0.0.0.0)"
    )
    asyncio.run(main(parser.parse_args().host))
