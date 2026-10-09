"""Drive the real decoys so correlation tests run on events the decoys actually logged."""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import asyncssh
from fastapi.testclient import TestClient

from decoys import honeytokens
from decoys.api.app import app as api_app
from decoys.banners import listeners
from decoys.ssh import server as ssh_server
from decoys.web.app import app as web_app
from qlure.correlate.engine import correlate
from qlure.events import Event, Service

FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"


def _client(app, ip: str, agent: str) -> TestClient:
    client = TestClient(app, client=(ip, 40404))
    client.headers["user-agent"] = agent  # the constructor's headers lose to the default agent
    return client


def web(ip: str = "198.51.100.7", agent: str = FIREFOX) -> TestClient:
    return _client(web_app, ip, agent)


def api(ip: str = "198.51.100.7", agent: str = "curl/8.5.0") -> TestClient:
    return _client(api_app, ip, agent)


def proxy_line(ip: str) -> bytes:
    return f"PROXY TCP4 {ip} 10.0.0.1 40404 2222\r\n".encode()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _wait_for(port: int) -> None:
    for _ in range(100):
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        return
    raise RuntimeError("listener never started")


@asynccontextmanager
async def ssh_decoy():
    listen, backend = free_port(), free_port()
    task = asyncio.create_task(ssh_server.serve(listen, backend))
    await _wait_for(listen)
    try:
        yield listen
    finally:
        task.cancel()


async def ssh_login(listen: int, ip: str, password: str, commands: list[str]):
    sock = socket.create_connection(("127.0.0.1", listen))
    sock.sendall(proxy_line(ip))
    sock.setblocking(False)
    async with await asyncssh.connect(
        "127.0.0.1", sock=sock, username="deploy", password=password, known_hosts=None
    ) as conn:
        for command in commands:
            await conn.run(command, check=False)


def ssh_with_honeytoken(ip: str, commands: list[str]) -> None:
    async def go():
        async with ssh_decoy() as listen:
            await ssh_login(listen, ip, honeytokens.get("ht-ssh-001")["value"], commands)

    asyncio.run(go())


def banner_visits(ip: str, services: list[Service], payload: bytes = b"") -> None:
    """Connect to the real FTP, MySQL and Redis listeners the way a port scan would."""
    greetings = {
        Service.FTP: listeners.FTP_BANNER,
        Service.MYSQL: listeners.mysql_greeting(),
        Service.REDIS: b"",
    }

    async def go():
        for service in services:
            server = await listeners.start(service, 0, greetings[service], host="127.0.0.1")
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(proxy_line(ip) + payload)
            await writer.drain()
            await asyncio.sleep(0.1)
            writer.close()
            await asyncio.sleep(0.1)
            server.close()

    asyncio.run(go())


def run(read_events) -> object:
    """Correlate every event the decoys have logged so far."""
    events: list[Event] = []
    for service in Service:
        events += read_events(service.value)
    return correlate(events)


def hits_of(finding) -> set[str]:
    return {h.rule_id for h in finding.hits}


def finding_for(result, ip: str, service: str):
    return next(
        f for f in result.findings if f.session.src_ip == ip and f.session.service == service
    )
