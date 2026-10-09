"""QLURE_BIND_HOST / --host for the SSH and banner decoys, and the 2 KB SSH output preview."""

from __future__ import annotations

import asyncio
import socket

import asyncssh

from decoys import honeytokens
from decoys.banners import listeners
from decoys.ssh import server as ssh_server
from qlure.events import Service


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def proxy_line(ip: str) -> bytes:
    return f"PROXY TCP4 {ip} 10.0.0.1 40404 2222\r\n".encode()


def _local_ip() -> str | None:
    """A non-loopback address of this machine, if there is one."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
            ip = sock.getsockname()[0]
    except OSError:
        return None
    return None if ip.startswith("127.") else ip


def test_bind_host_defaults_to_all_interfaces(monkeypatch):
    monkeypatch.delenv("QLURE_BIND_HOST", raising=False)
    assert ssh_server.bind_host() == "0.0.0.0"  # noqa: S104
    assert listeners.bind_host() == "0.0.0.0"  # noqa: S104
    monkeypatch.setenv("QLURE_BIND_HOST", "127.0.0.1")
    assert ssh_server.bind_host() == listeners.bind_host() == "127.0.0.1"


def test_banner_listener_honours_bind_host(monkeypatch):
    monkeypatch.setenv("QLURE_BIND_HOST", "127.0.0.1")

    async def go():
        server = await listeners.start(Service.REDIS, 0, b"")
        try:
            return server.sockets[0].getsockname()[0]
        finally:
            server.close()

    assert asyncio.run(go()) == "127.0.0.1"


def test_ssh_relay_honours_bind_host_and_refuses_other_interfaces(monkeypatch):
    monkeypatch.setenv("QLURE_BIND_HOST", "127.0.0.1")
    listen, backend = free_port(), free_port()

    async def go():
        task = asyncio.create_task(ssh_server.serve(listen, backend))
        try:
            for _ in range(100):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", listen)
                    writer.close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            else:
                raise AssertionError("relay never started")
            other = _local_ip()
            if other is None:
                return None
            try:
                _, writer = await asyncio.open_connection(other, listen)
            except OSError:
                return True
            writer.close()
            return False
        finally:
            task.cancel()

    assert asyncio.run(go()) is not False


def test_ssh_command_output_preview_keeps_2048_chars(log_dir, read_events):
    async def go():
        listen, backend = free_port(), free_port()
        task = asyncio.create_task(ssh_server.serve(listen, backend, host="127.0.0.1"))
        try:
            for _ in range(100):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", listen)
                    writer.close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            sock = socket.create_connection(("127.0.0.1", listen))
            sock.sendall(proxy_line("198.51.100.77"))
            sock.setblocking(False)
            password = honeytokens.get("ht-ssh-001")["value"]
            async with await asyncssh.connect(
                "127.0.0.1", sock=sock, username="deploy", password=password, known_hosts=None
            ) as conn:
                result = await conn.run("cat /var/log/auth.log", check=False)
                return len(result.stdout)
        finally:
            task.cancel()

    full = asyncio.run(go())
    previews = [
        len(e.response["output_preview"]) for e in read_events("ssh") if e.action.value == "command"
    ]
    assert full > 256  # the old cap would have cut this output
    assert previews == [min(full, 2048)]
