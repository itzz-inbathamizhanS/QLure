"""QLURE_PROXY_PROTOCOL: required (default) rejects direct clients, optional accepts them."""

from __future__ import annotations

import asyncio
import socket

import asyncssh
import pytest

from decoys import honeytokens
from decoys.banners import listeners
from decoys.common import check_proxy_mode_safe, proxy_mode
from decoys.ssh import server as ssh_server
from qlure.events import Service

VISITOR = b"PROXY TCP4 198.51.100.9 10.0.0.1 51000 6379\r\n"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("value", [None, "", "required", "bogus", "OPTIONAL "])
def test_mode_parsing(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("QLURE_PROXY_PROTOCOL", raising=False)
    else:
        monkeypatch.setenv("QLURE_PROXY_PROTOCOL", value)
    assert proxy_mode() == ("optional" if value == "OPTIONAL " else "required")


def test_optional_refused_on_non_loopback(monkeypatch):
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "optional")
    for host in ("0.0.0.0", "192.168.1.5", "example.com"):  # noqa: S104
        with pytest.raises(SystemExit) as exc:
            check_proxy_mode_safe(host)
        assert "loopback" in str(exc.value)
    check_proxy_mode_safe("127.0.0.1")
    check_proxy_mode_safe("::1")
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "required")
    check_proxy_mode_safe("0.0.0.0")  # noqa: S104


def test_banner_start_refuses_optional_on_all_interfaces(monkeypatch):
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "optional")
    monkeypatch.delenv("QLURE_BIND_HOST", raising=False)
    with pytest.raises(SystemExit):
        asyncio.run(listeners.start(Service.REDIS, 0, b""))


def _redis(mode, send, log_dir):
    async def go():
        server = await listeners.start(Service.REDIS, 0, b"", host="127.0.0.1")
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(send)
        await writer.drain()
        try:
            reply = await asyncio.wait_for(reader.read(200), 3)
        except TimeoutError:
            reply = b"<timeout>"
        writer.close()
        await asyncio.sleep(0.2)
        server.close()
        return reply

    return asyncio.run(go())


def test_required_rejects_direct_client(monkeypatch, log_dir, read_events):
    monkeypatch.delenv("QLURE_PROXY_PROTOCOL", raising=False)
    reply = _redis("required", b"PING\r\n", log_dir)
    assert reply == b""  # closed
    assert read_events("redis") == []


def test_optional_direct_client_uses_socket_address_and_keeps_bytes(
    monkeypatch, log_dir, read_events
):
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "optional")
    reply = _redis("optional", b"PING\r\n", log_dir)
    assert reply.startswith(b"-NOAUTH") or reply.startswith(b"+PONG")
    events = read_events("redis")
    assert {e.src_ip for e in events} == {"127.0.0.1"}
    banner = next(e for e in events if e.action == "banner")
    assert bytes.fromhex(banner.request["first_bytes_hex"]).startswith(b"PING")


def test_optional_still_honours_a_valid_proxy_line(monkeypatch, log_dir, read_events):
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "optional")
    reply = _redis("optional", VISITOR + b"PING\r\n", log_dir)
    assert reply
    assert {e.src_ip for e in read_events("redis")} == {"198.51.100.9"}


def test_optional_server_speaks_first_client_waits(monkeypatch, log_dir, read_events):
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "optional")

    async def go():
        server = await listeners.start(Service.FTP, 0, listeners.FTP_BANNER, host="127.0.0.1")
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        greeting = await asyncio.wait_for(reader.readuntil(b"\r\n"), 3)
        writer.close()
        await asyncio.sleep(0.2)
        server.close()
        return greeting

    assert asyncio.run(go()) == listeners.FTP_BANNER
    assert {e.src_ip for e in read_events("ftp")} == {"127.0.0.1"}


def _ssh(prefix: bytes):
    async def go():
        listen, backend = free_port(), free_port()
        task = asyncio.create_task(ssh_server.serve(listen, backend, host="127.0.0.1"))
        try:
            for _ in range(100):
                try:
                    _, w = await asyncio.open_connection("127.0.0.1", listen)
                    w.close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            sock = socket.create_connection(("127.0.0.1", listen))
            sock.sendall(prefix)
            sock.setblocking(False)
            password = honeytokens.get("ht-ssh-001")["value"]
            async with await asyncio.wait_for(
                asyncssh.connect(
                    "127.0.0.1", sock=sock, username="deploy", password=password, known_hosts=None
                ),
                10,
            ) as conn:
                await conn.run("id", check=False)
            await asyncio.sleep(0.2)
        finally:
            task.cancel()

    asyncio.run(go())


def test_ssh_optional_direct_and_proxied(monkeypatch, log_dir, read_events):
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "optional")
    _ssh(b"")
    assert {e.src_ip for e in read_events("ssh")} == {"127.0.0.1"}
    _ssh(b"PROXY TCP4 198.51.100.7 10.0.0.1 40404 2222\r\n")
    assert "198.51.100.7" in {e.src_ip for e in read_events("ssh")}


def test_ssh_required_rejects_direct(monkeypatch, log_dir, read_events):
    monkeypatch.delenv("QLURE_PROXY_PROTOCOL", raising=False)
    with pytest.raises((asyncssh.Error, OSError, TimeoutError)):
        _ssh(b"")
    assert read_events("ssh") == []


def test_optional_probe_that_sends_nothing_is_not_logged(monkeypatch, log_dir, read_events):
    monkeypatch.setenv("QLURE_PROXY_PROTOCOL", "optional")

    async def go():
        server = await listeners.start(Service.REDIS, 0, b"", host="127.0.0.1")
        port = server.sockets[0].getsockname()[1]
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await asyncio.sleep(0.3)
        server.close()

    asyncio.run(go())
    assert read_events("redis") == []
