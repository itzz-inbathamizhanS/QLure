"""SSH-like decoy (port 2222).

A small relay listens on port 2222 and reads the gateway's PROXY line, then hands
each connection to AsyncSSH on loopback. The relay registers the real visitor
before it connects, so every SSH session carries the right source address.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from datetime import UTC, datetime
from functools import partial
from typing import Any

import asyncssh
from asyncssh.kex import get_default_kex_algs

from decoys import honeytokens
from decoys.common import BadProxyHeader, Client, fingerprint, read_proxy_header
from decoys.ssh.shell import ShellState, run_session
from qlure.events import Action, Service, emit
from qlure.pqc.kex import KexSniffer, kex_fingerprint, pqc_capable

LISTEN_PORT = 2222
BACKEND_PORT = 2223
HOST_VERSION = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
# Offered first so the decoy looks current: the key exchange recent OpenSSH prefers.
PREFERRED_KEX = ("mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com")
KEX_ACTIONS = (Action.CONNECT, Action.LOGIN_ATTEMPT, Action.LOGIN_SUCCESS)


def kex_algs() -> list[str]:
    """The preferred hybrid exchanges this AsyncSSH build supports, then its own defaults."""
    defaults = [a.decode() for a in get_default_kex_algs()]
    return [a for a in PREFERRED_KEX if a in defaults] + [
        a for a in defaults if a not in PREFERRED_KEX
    ]


_visitors: dict[int, Client] = {}  # relay's loopback source port -> real visitor
_sniffers: dict[int, KexSniffer] = {}  # relay's loopback source port -> what the client offered
_connections: dict[Any, DecoySSHServer] = {}  # AsyncSSH connection -> its decoy state


class DecoySSHServer(asyncssh.SSHServer):
    def __init__(self) -> None:
        self.conn: Any = None
        self.visitor = Client("0.0.0.0", None)  # noqa: S104
        self.session_id = uuid.uuid4().hex
        self.client_fp = ""
        self.username: str | None = None
        self.sniffer = KexSniffer()
        self.connected_at = datetime.now(UTC)
        self.announced = False

    def connection_made(self, conn: Any) -> None:
        self.conn = conn
        port = conn.get_extra_info("peername")[1]
        self.visitor = _visitors.get(port, self.visitor)
        self.sniffer = _sniffers.get(port, self.sniffer)
        self.connected_at = datetime.now(UTC)
        _connections[conn] = self

    def connection_lost(self, exc: Exception | None) -> None:
        _connections.pop(self.conn, None)
        self._emit(Action.DISCONNECT)

    def begin_auth(self, username: str) -> bool:
        return True  # every connection must log in

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        credential = {"username": username, "password": password}
        token = honeytokens.find("ssh_password", password, username)
        self._emit(
            Action.LOGIN_ATTEMPT,
            credential=credential,
            honeytoken_id=token["id"] if token else None,
        )
        if token is None:
            return False
        self.username = username
        self._emit(Action.LOGIN_SUCCESS, credential=credential, honeytoken_id=token["id"])
        self._emit(Action.HONEYTOKEN_USE, honeytoken_id=token["id"])
        return True

    def _announce(self) -> None:
        """Log the connection once, with what the relay read from the client's first bytes.

        The client's key-exchange offer only arrives after the connection opens, so the
        connect event is written with the first later event, stamped with the real time.
        """
        if self.announced:
            return
        self.announced = True
        if self.sniffer.client_version:
            self.client_fp = fingerprint(self.sniffer.client_version)
        self._write(Action.CONNECT, ts=self.connected_at)

    def _emit(self, action: Action, **extra: Any) -> None:
        self._announce()
        self._write(action, **extra)

    def _write(self, action: Action, **extra: Any) -> None:
        kex: dict[str, Any] = {}
        if action in KEX_ACTIONS and self.sniffer.kex_offered:
            offered = self.sniffer.kex_offered
            kex = {
                "kex_offered": offered if action is Action.CONNECT else None,
                "kex_fp": kex_fingerprint(offered),
                "pqc_capable": pqc_capable(offered),
            }
        emit(
            {
                "service": Service.SSH,
                "src_ip": self.visitor.ip,
                "src_port": self.visitor.port,
                "client_fp": self.client_fp or None,
                "session_id": self.session_id,
                "action": action,
                **kex,
                **extra,
            }
        )


async def _process(process: asyncssh.SSHServerProcess) -> None:
    server = _connections.get(process.channel.get_connection())
    username = server.username if server and server.username else "deploy"
    state = ShellState(user=username)

    def record(line: str, output: str) -> None:
        if server is not None:
            server._emit(
                Action.COMMAND,
                request={"command": line},
                response={"output_preview": output[:256]},
            )

    await run_session(process, state, record)


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    sniffer: KexSniffer | None = None,
) -> None:
    try:
        while data := await reader.read(65536):
            if sniffer is not None:
                sniffer.feed(data)  # reads a copy; the bytes are forwarded untouched
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def _relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    backend_port: int,
) -> None:
    try:
        visitor = await read_proxy_header(client_reader)
    except BadProxyHeader:
        client_writer.close()
        return

    # Bind the outgoing socket first so its port is known before AsyncSSH sees it.
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    local_port = sock.getsockname()[1]
    _visitors[local_port] = visitor
    sniffer = _sniffers[local_port] = KexSniffer()
    try:
        await loop.sock_connect(sock, ("127.0.0.1", backend_port))
        backend_reader, backend_writer = await asyncio.open_connection(sock=sock)
        await asyncio.gather(
            _pipe(client_reader, backend_writer, sniffer),
            _pipe(backend_reader, client_writer),
        )
    except OSError:
        sock.close()
    finally:
        _visitors.pop(local_port, None)
        _sniffers.pop(local_port, None)
        client_writer.close()


async def serve(
    listen_port: int = LISTEN_PORT,
    backend_port: int = BACKEND_PORT,
    host: str = "0.0.0.0",  # noqa: S104
) -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    backend = await asyncssh.create_server(
        DecoySSHServer,
        "127.0.0.1",
        backend_port,
        server_host_keys=[key],
        process_factory=_process,
        server_version=HOST_VERSION,
        kex_algs=kex_algs(),
    )
    relay = await asyncio.start_server(
        partial(_relay, backend_port=backend_port), host, listen_port
    )
    try:
        async with relay:
            await relay.serve_forever()
    finally:
        backend.close()


if __name__ == "__main__":
    asyncio.run(serve())
