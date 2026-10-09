"""FTP, MySQL and Redis listeners.

Each sends its greeting (Redis has none), reads the first bytes the visitor sends,
logs them, and closes. Like the SSH decoy, each listener reads the gateway's PROXY
line first so events carry the real visitor address.
"""

from __future__ import annotations

import asyncio
import secrets
import string
import struct
import uuid
from collections.abc import Callable
from functools import partial

from decoys import content
from decoys.common import BadProxyHeader, read_proxy_header
from qlure.events import Action, Service, emit

READ_TIMEOUT = 10
FTP_BANNER = b"220 ProFTPD 1.3.8 Server (Veltrix Files)\r\n"
REDIS_NOAUTH = b"-NOAUTH Authentication required.\r\n"


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
    first = b""
    try:
        data = greeting() if callable(greeting) else greeting  # FTP's banner can be changed live
        if data:
            writer.write(data)
            await writer.drain()
        first = await asyncio.wait_for(reader.read(1024), READ_TIMEOUT)
        if service is Service.REDIS and first:
            writer.write(REDIS_NOAUTH)
            await writer.drain()
    except (TimeoutError, OSError):
        pass
    emit(
        {
            **base,
            "action": Action.BANNER,
            "request": {
                "bytes_len": len(first),
                "first_bytes_hex": first[:64].hex(),
                "first_bytes_preview": first[:256].decode("utf-8", errors="replace"),
            },
        }
    )
    writer.close()
    emit({**base, "action": Action.DISCONNECT})


LISTENERS: list[tuple[Service, int, bytes | Callable[[], bytes]]] = [
    (Service.FTP, 2121, content.ftp_greeting),
    (Service.MYSQL, 3306, mysql_greeting()),
    (Service.REDIS, 6379, b""),
]


async def start(
    service: Service,
    port: int,
    greeting: bytes | Callable[[], bytes],
    host: str = "0.0.0.0",  # noqa: S104
) -> asyncio.Server:
    handler: Callable[..., object] = partial(_handle, service, greeting)
    return await asyncio.start_server(handler, host, port)


async def main() -> None:
    servers = [await start(service, port, greeting) for service, port, greeting in LISTENERS]
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
