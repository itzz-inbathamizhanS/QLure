"""SSH-like decoy (port 2222).

A small relay listens on port 2222 and reads the gateway's PROXY line (optional on localhost
runs), then hands each connection to AsyncSSH on loopback. The relay registers the real visitor
before it connects, so every SSH session carries the right source address.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import uuid
from datetime import UTC, datetime
from functools import partial
from typing import Any

import asyncssh
from asyncssh.kex import get_default_kex_algs

from decoys import honeytokens
from decoys.common import (
    BadProxyHeader,
    Client,
    accept_client,
    check_proxy_mode_safe,
    fingerprint,
)
from decoys.ssh.shell import ShellState, run_session
from qlure.events import Action, Service, emit
from qlure.pqc.kex import KexSniffer, kex_fingerprint, pqc_capable

LISTEN_PORT = 2222
BACKEND_PORT = 2223
OUTPUT_PREVIEW_CHARS = 2048  # enough for the dashboard playback to show real output
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
                response={"output_preview": output[:OUTPUT_PREVIEW_CHARS]},
            )

    await run_session(process, state, record)


async def _pipe(
    reader: Any,
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
        visitor, client_reader = await accept_client(client_reader, client_writer)
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


def host_key() -> asyncssh.SSHKey:
    """The decoy's host key, kept across restarts when QLURE_SSH_HOST_KEY names a file.

    A new key on every start makes a returning client's known_hosts check fail, which tells an
    attacker the box is rebuilt each time. Without the variable a fresh key is used (tests, demos).
    """
    path = os.environ.get("QLURE_SSH_HOST_KEY")
    if path and os.path.exists(path):
        return asyncssh.read_private_key(path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    if path:
        try:
            key.write_private_key(path)
            os.chmod(path, 0o600)
        except OSError:
            pass  # read-only mount: carry on with this run's key
    return key


def bind_host() -> str:
    """Address the relay listens on: QLURE_BIND_HOST, default all interfaces (Docker)."""
    return os.environ.get("QLURE_BIND_HOST") or "0.0.0.0"  # noqa: S104


async def serve(
    listen_port: int = LISTEN_PORT,
    backend_port: int = BACKEND_PORT,
    host: str | None = None,
) -> None:
    host = host or bind_host()
    check_proxy_mode_safe(host)
    key = host_key()
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
    parser = argparse.ArgumentParser(description="Q-Lure SSH decoy")
    parser.add_argument(
        "--host", default=None, help="bind address (default: QLURE_BIND_HOST or 0.0.0.0)"
    )
    parser.add_argument(
        "--proxy-protocol",
        choices=("required", "optional"),
        default=None,
        help="PROXY v1 line from the gateway: required (default) or optional (localhost only)",
    )
    args = parser.parse_args()
    if args.proxy_protocol:
        os.environ["QLURE_PROXY_PROTOCOL"] = args.proxy_protocol
    asyncio.run(serve(host=args.host))
