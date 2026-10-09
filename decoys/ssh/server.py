"""SSH-like decoy (port 2222).

A small relay listens on port 2222 and reads the gateway's PROXY line, then hands
each connection to AsyncSSH on loopback. The relay registers the real visitor
before it connects, so every SSH session carries the right source address.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from functools import partial
from typing import Any

import asyncssh

from decoys import honeytokens
from decoys.common import BadProxyHeader, Client, fingerprint, read_proxy_header
from decoys.ssh.shell import ShellState, run_session
from qlure.events import Action, Service, emit

LISTEN_PORT = 2222
BACKEND_PORT = 2223
HOST_VERSION = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"

_visitors: dict[int, Client] = {}  # relay's loopback source port -> real visitor
_connections: dict[Any, DecoySSHServer] = {}  # AsyncSSH connection -> its decoy state


class DecoySSHServer(asyncssh.SSHServer):
    def __init__(self) -> None:
        self.conn: Any = None
        self.visitor = Client("0.0.0.0", None)  # noqa: S104
        self.session_id = uuid.uuid4().hex
        self.client_fp = ""
        self.username: str | None = None

    def connection_made(self, conn: Any) -> None:
        self.conn = conn
        port = conn.get_extra_info("peername")[1]
        self.visitor = _visitors.get(port, self.visitor)
        version = str(conn.get_extra_info("client_version", ""))
        self.client_fp = fingerprint(version) if version else ""  # not every build exposes it
        _connections[conn] = self
        self._emit(Action.CONNECT)

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

    def _emit(self, action: Action, **extra: Any) -> None:
        emit(
            {
                "service": Service.SSH,
                "src_ip": self.visitor.ip,
                "src_port": self.visitor.port,
                "client_fp": self.client_fp or None,
                "session_id": self.session_id,
                "action": action,
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


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
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
    try:
        await loop.sock_connect(sock, ("127.0.0.1", backend_port))
        backend_reader, backend_writer = await asyncio.open_connection(sock=sock)
        await asyncio.gather(
            _pipe(client_reader, backend_writer),
            _pipe(backend_reader, client_writer),
        )
    except OSError:
        sock.close()
    finally:
        _visitors.pop(local_port, None)
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
