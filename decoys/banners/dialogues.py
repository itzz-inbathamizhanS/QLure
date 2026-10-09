"""Short, bounded dialogues for the FTP, MySQL and Redis decoys.

Every reply is a fixed constant. Nothing the visitor sends is executed, stored or echoed
back (the one exception is the MySQL error text, which names the sanitised, capped user as
a real server does). Reads are capped in bytes, lines and commands; the caller bounds the
whole conversation in time.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

import qlure
from decoys import honeytokens
from qlure.events import Action

MAX_COMMANDS = 8
FTP_LINE_LIMIT = 512
FTP_BUDGET = MAX_COMMANDS * (FTP_LINE_LIMIT + 2)
REDIS_BUDGET = 4096
REDIS_MAX_ARGS = 16
REDIS_MAX_BULK = 1024
MYSQL_PACKET_LIMIT = 4096
NAME_LIMIT = 64
PASSWORD_LIMIT = 128
COMMAND_LIMIT = 256
PREVIEW_LIMIT = 1024

Emit = Callable[..., None]
RULES_FILE = Path(qlure.__file__).resolve().parent / "rules" / "rules.yaml"


@lru_cache(maxsize=1)
def default_credentials() -> list[tuple[str, str]]:
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return [(str(u), str(p)) for u, p in data["lists"]["default_credentials"]]


class Closed(Exception):
    """The visitor hung up, sent something malformed, or exceeded a cap."""


class Buf:
    """A byte-budgeted reader. Remembers the first bytes seen for the banner event."""

    def __init__(
        self,
        reader: Any,
        budget: int,
        on_first: Callable[[bytes], None] | None = None,
    ) -> None:
        self.on_first = on_first
        self.reader = reader
        self.budget = budget
        self.buf = b""
        self.first = b""

    async def _more(self) -> bool:
        if self.budget <= 0:
            raise Closed("byte budget used up")
        chunk = await self.reader.read(min(1024, self.budget))
        if not chunk:
            return False
        self.budget -= len(chunk)
        if not self.first:
            self.first = chunk[:PREVIEW_LIMIT]
            if self.on_first:
                self.on_first(self.first)
        self.buf += chunk
        return True

    async def line(self, limit: int) -> bytes | None:
        """One line without its terminator; None at a clean end of stream."""
        while True:
            end = self.buf.find(b"\n")
            if end > limit:
                raise Closed("line too long")
            if end >= 0:
                line, self.buf = self.buf[:end], self.buf[end + 1 :]
                return line.rstrip(b"\r")
            if len(self.buf) > limit:
                raise Closed("line too long")
            if not await self._more():
                line, self.buf = self.buf, b""
                return line or None

    async def exact(self, size: int) -> bytes:
        while len(self.buf) < size:
            if not await self._more():
                raise Closed("short read")
        data, self.buf = self.buf[:size], self.buf[size:]
        return data


def printable(raw: bytes | str, limit: int) -> str:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    return "".join(c if c.isprintable() else "?" for c in text)[:limit]


# FTP


async def ftp(buf: Buf, writer: asyncio.StreamWriter, emit: Emit) -> None:
    user: str | None = None
    for _ in range(MAX_COMMANDS):
        raw = await buf.line(FTP_LINE_LIMIT)
        if raw is None:
            return
        verb, _, rest = raw.decode("utf-8", errors="replace").strip().partition(" ")
        verb = verb.upper()
        if verb == "USER":
            user = printable(rest.strip(), NAME_LIMIT)
            reply = b"331 Please specify the password.\r\n"
        elif verb == "PASS":
            password = printable(rest, PASSWORD_LIMIT)
            token = _ftp_token(user, password)
            emit(
                Action.LOGIN_ATTEMPT,
                credential={"username": user, "password": password},
                honeytoken_id=token["id"] if token else None,
            )
            if token:
                emit(Action.HONEYTOKEN_USE, honeytoken_id=token["id"])
            user = None
            reply = b"530 Login incorrect.\r\n"
        elif verb == "QUIT":
            writer.write(b"221 Goodbye.\r\n")
            await writer.drain()
            return
        else:
            reply = b"530 Please login with USER and PASS.\r\n"
        writer.write(reply)
        await writer.drain()


def _ftp_token(user: str | None, password: str) -> dict[str, Any] | None:
    for kind in ("ftp_password", "ssh_password", "db_password"):
        token = honeytokens.find(kind, password, user)
        if token:
            return token
    return None


# MySQL

CLIENT_SECURE_CONNECTION = 0x8000
CLIENT_PLUGIN_AUTH_LENENC = 0x200000


def _scramble(greeting: bytes) -> bytes | None:
    """The 20-byte salt inside our own greeting packet."""
    try:
        payload = greeting[4:]
        start = 1 + len(b"8.0.36\x00") + 4
        part1 = payload[start : start + 8]
        part2 = payload[start + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 :][:12]
        salt = part1 + part2
    except IndexError:
        return None
    return salt if len(salt) == 20 else None


def _native_token(password: str, salt: bytes) -> bytes:
    """mysql_native_password response for a guess, to recognise default passwords."""
    stage1 = hashlib.sha1(password.encode()).digest()  # noqa: S324 - protocol-mandated
    stage2 = hashlib.sha1(stage1).digest()  # noqa: S324
    mask = hashlib.sha1(salt + stage2).digest()  # noqa: S324
    return bytes(a ^ b for a, b in zip(stage1, mask, strict=True))


def parse_handshake_response(payload: bytes) -> tuple[str, bytes] | None:
    """Return (username, auth_response) from a client handshake response, or None."""
    if len(payload) < 33:
        return None
    flags = int.from_bytes(payload[:4], "little")
    end = payload.find(b"\x00", 32)
    if end < 0:
        return None
    name = printable(payload[32:end], NAME_LIMIT)
    rest = payload[end + 1 :]
    if flags & CLIENT_PLUGIN_AUTH_LENENC and rest and rest[0] < 0xFB:
        size, rest = rest[0], rest[1:]
    elif flags & CLIENT_SECURE_CONNECTION and rest:
        size, rest = rest[0], rest[1:]
    else:
        size = rest.find(b"\x00")
        size = len(rest) if size < 0 else size
    return name, rest[:size]


def mysql_denied(sequence: int, name: str, ip: str, using_password: bool) -> bytes:
    used = "YES" if using_password else "NO"
    text = f"Access denied for user '{name}'@'{ip}' (using password: {used})"
    payload = b"\xff" + (1045).to_bytes(2, "little") + b"#28000" + text.encode("ascii", "replace")
    return len(payload).to_bytes(3, "little") + bytes([sequence & 0xFF]) + payload


async def mysql(
    buf: Buf, writer: asyncio.StreamWriter, emit: Emit, greeting: bytes, ip: str
) -> None:
    header = await buf.exact(4)
    size = int.from_bytes(header[:3], "little")
    if size > MYSQL_PACKET_LIMIT:
        raise Closed("packet too large")
    parsed = parse_handshake_response(await buf.exact(size))
    if parsed is None:
        return  # not a handshake response: the raw preview is logged by the caller
    name, auth = parsed
    password: str | None = "" if not auth else None
    salt = _scramble(greeting)
    if auth and salt:
        for user, guess in default_credentials():
            if user == name and _native_token(str(guess), salt) == auth:
                password = str(guess)  # a default pair, recognised by its scramble response
                break
    emit(
        Action.LOGIN_ATTEMPT,
        credential={"username": name, "password": password},
        request={"auth_response_len": len(auth)},
    )
    writer.write(mysql_denied(header[3] + 1, name, ip, bool(auth)))
    await writer.drain()


# Redis

NOAUTH = b"-NOAUTH Authentication required.\r\n"
WRONGPASS = b"-WRONGPASS invalid username-password pair or user is disabled.\r\n"
FAKE_INFO = (
    b"# Server\r\nredis_version:7.0.15\r\nredis_mode:standalone\r\nos:Linux 5.15.0 x86_64\r\n"
    b"tcp_port:6379\r\nuptime_in_days:41\r\n# Clients\r\nconnected_clients:1\r\n"
    b"# Memory\r\nused_memory_human:1.02M\r\n# Keyspace\r\n"
)
OK = b"+OK\r\n"
_OK_AFTER_AUTH = {"CONFIG", "SLAVEOF", "REPLICAOF", "SET", "FLUSHALL", "FLUSHDB", "SAVE", "BGSAVE"}


def redis_reply(args: list[str]) -> bytes:
    """Fixed reply for a command after the planted password was accepted."""
    name = args[0].upper() if args else ""
    if name in _OK_AFTER_AUTH:
        return OK
    if name == "PING":
        return b"+PONG\r\n"
    if name == "GET":
        return b"$-1\r\n"
    if name == "INFO":
        return b"$%d\r\n" % len(FAKE_INFO) + FAKE_INFO + b"\r\n"
    if name == "KEYS":
        return b"*0\r\n"
    if name == "DBSIZE":
        return b":0\r\n"
    if name == "EVAL":
        return b"$-1\r\n"
    if name == "MODULE":
        return b"-ERR Error loading the extension. Please check the server logs.\r\n"
    return b"-ERR unknown command\r\n"


async def _redis_command(buf: Buf) -> list[bytes] | None:
    """One command, inline or RESP array. None at end of stream."""
    while True:
        first = await buf.line(REDIS_MAX_BULK)
        if first is None:
            return None
        if first.strip():
            break
    if not first.startswith(b"*"):
        return first.split()[:REDIS_MAX_ARGS]
    try:
        count = int(first[1:])
    except ValueError as exc:
        raise Closed("bad array header") from exc
    if not 0 < count <= REDIS_MAX_ARGS:
        raise Closed("bad argument count")
    args: list[bytes] = []
    for _ in range(count):
        head = await buf.line(32)
        if head is None or not head.startswith(b"$"):
            raise Closed("bad bulk header")
        try:
            length = int(head[1:])
        except ValueError as exc:
            raise Closed("bad bulk length") from exc
        if not 0 <= length <= REDIS_MAX_BULK:
            raise Closed("bulk too large")
        args.append((await buf.exact(length + 2))[:length])
    return args


async def redis(buf: Buf, writer: asyncio.StreamWriter, emit: Emit) -> None:
    authed = False
    for _ in range(MAX_COMMANDS):
        raw = await _redis_command(buf)
        if raw is None:
            return
        args = [printable(a, COMMAND_LIMIT) for a in raw]
        if not args:
            return
        name = args[0].upper()
        if name == "AUTH":
            if len(args) not in (2, 3):
                reply = b"-ERR wrong number of arguments for 'auth' command\r\n"
            else:
                user = args[1] if len(args) == 3 else "default"
                password = printable(raw[-1], PASSWORD_LIMIT)
                token = honeytokens.find("redis_password", password)
                emit(
                    Action.LOGIN_ATTEMPT,
                    credential={"username": user[:NAME_LIMIT], "password": password},
                    honeytoken_id=token["id"] if token else None,
                )
                if token:
                    emit(Action.HONEYTOKEN_USE, honeytoken_id=token["id"])
                    authed = True
                    reply = OK
                else:
                    reply = WRONGPASS
        else:
            reply = OK if name == "QUIT" else redis_reply(args) if authed else NOAUTH
            emit(
                Action.COMMAND,
                request={"command": " ".join(args)[:COMMAND_LIMIT]},
                response={"output_preview": printable(reply.strip(), COMMAND_LIMIT)},
            )
        writer.write(reply)
        await writer.drain()
        if name == "QUIT":
            return
