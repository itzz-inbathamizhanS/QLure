import asyncio
import struct

from decoys.banners import listeners
from qlure.events import Service

VISITOR = b"PROXY TCP4 198.51.100.9 10.0.0.1 51000 2121\r\n"


async def _open(port: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(VISITOR)
    await writer.drain()
    return reader, writer


async def _started(service, greeting):
    return await listeners.start(service, 0, greeting, host="127.0.0.1")


def test_ftp_sends_its_banner_and_logs_what_the_visitor_typed(log_dir, read_events):
    async def scenario():
        server = await _started(Service.FTP, listeners.FTP_BANNER)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await _open(port)
        greeting = await reader.readuntil(b"\r\n")
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        server.close()
        return greeting

    assert asyncio.run(scenario()) == listeners.FTP_BANNER
    events = read_events("ftp")
    assert [e.action for e in events] == ["connect", "banner", "disconnect"]
    banner = events[1]
    assert banner.src_ip == "198.51.100.9"
    assert bytes.fromhex(banner.request["first_bytes_hex"]) == b"USER anonymous\r\n"


def test_redis_answers_the_first_command_with_noauth(log_dir, read_events):
    async def scenario():
        server = await _started(Service.REDIS, b"")
        port = server.sockets[0].getsockname()[1]
        reader, writer = await _open(port)
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(100), 5)
        writer.close()
        server.close()
        return reply

    assert asyncio.run(scenario()) == listeners.REDIS_NOAUTH
    assert any(e.action == "banner" for e in read_events("redis"))


def test_mysql_greeting_is_a_valid_handshake_packet(log_dir, read_events):
    async def scenario():
        server = await _started(Service.MYSQL, listeners.mysql_greeting())
        port = server.sockets[0].getsockname()[1]
        reader, writer = await _open(port)
        header = await reader.readexactly(4)
        length = int.from_bytes(header[:3], "little")
        payload = await reader.readexactly(length)
        writer.close()
        await asyncio.sleep(0.2)  # let the listener finish logging
        server.close()
        return header, payload

    header, payload = asyncio.run(scenario())
    assert header[3] == 0  # sequence number
    assert payload[0] == 0x0A  # protocol version 10
    assert payload[1:8] == b"8.0.36\x00"
    assert b"mysql_native_password\x00" in payload
    assert (
        struct.unpack("<I", listeners.mysql_greeting()[:3] + b"\x00")[0]
        == len(listeners.mysql_greeting()) - 4
    )
    assert any(e.action == "banner" for e in read_events("mysql"))
