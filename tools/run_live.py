"""Run the whole QLure stack locally, without Docker: `python tools/run_live.py`.

Starts the decoys, the forwarder and the dashboard as child processes, all bound to 127.0.0.1,
then waits until Ctrl+C. Browse, curl or ssh the decoys and watch the sessions appear on the
dashboard. Standard library only; works on Windows, Linux and macOS.

Direct clients (ssh, ftp, redis-cli, mysql) have no nginx gateway to add the PROXY header, so
the SSH and banner decoys run with QLURE_PROXY_PROTOCOL=optional here. That mode is only
allowed on loopback addresses (see docs/architecture/07-security-model.md). Docker keeps the
strict, gateway-fronted setup.
"""

from __future__ import annotations

import argparse
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

REPO = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
READY_TIMEOUT = 25.0
KILL_AFTER = 5.0
HONEYTOKEN_FILE = REPO / "decoys" / "honeytokens.yaml"


@dataclass
class Service:
    name: str
    port: int
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""


def build_services(
    args: argparse.Namespace, python: str | None = None, workdir: Path | None = None
) -> list[Service]:
    py = python or sys.executable
    work = workdir or Path(args.workdir)
    logs, data = work / "logs", work / "data"
    local = {"QLURE_BIND_HOST": HOST, "QLURE_PROXY_PROTOCOL": "optional"}
    services = [
        Service(
            "web decoy",
            8080,
            [py, "-m", "uvicorn", "decoys.web.app:app", "--host", HOST, "--port", "8080"],
            url="http://127.0.0.1:8080",
        ),
        Service(
            "API decoy",
            8081,
            [py, "-m", "uvicorn", "decoys.api.app:app", "--host", HOST, "--port", "8081"],
            url="http://127.0.0.1:8081",
        ),
        Service("SSH decoy", 2222, [py, "-m", "decoys.ssh.server"], dict(local), "127.0.0.1:2222"),
        Service(
            "FTP decoy", 2121, [py, "-m", "decoys.banners.listeners"], dict(local), "127.0.0.1:2121"
        ),
        Service("MySQL decoy", 3306, [], {}, "127.0.0.1:3306"),
        Service("Redis decoy", 6379, [], {}, "127.0.0.1:6379"),
    ]
    # One process serves FTP, MySQL and Redis; the last two entries only add ports to check.
    if not args.no_docker_api:
        services.append(
            Service(
                "Docker API decoy",
                2375,
                [py, "-m", "uvicorn", "decoys.dockerapi.app:app", "--host", HOST, "--port", "2375"],
                url="http://127.0.0.1:2375",
            )
        )
    services.append(
        Service(
            "forwarder",
            0,
            [
                py,
                "-m",
                "qlure.cli",
                "forward",
                "--logs",
                str(logs),
                "--db",
                str(data / "qlure.db"),
                "--follow",
            ],
        )
    )
    dash_env = {
        "QLURE_DB": str(data / "qlure.db"),
        "QLURE_LOGS": str(logs),
        "QLURE_LIVE": "1",
        "QLURE_LIVE_INTERVAL": "5",
        "QLURE_SETTINGS": str(data / "settings.json"),
        "QLURE_MODEL": str(data / "model.json"),
        "QLURE_CONTENT": str(data / "content.json"),
        "QLURE_DASHBOARD_PASSWORD": args.password,
        "QLURE_DASHBOARD_SECRET": os.environ.get("QLURE_DASHBOARD_SECRET") or secrets.token_hex(32),
    }
    services.append(
        Service(
            "dashboard",
            args.dashboard_port,
            [
                py,
                "-m",
                "uvicorn",
                "dashboard.app:app",
                "--host",
                HOST,
                "--port",
                str(args.dashboard_port),
            ],
            dash_env,
            f"http://127.0.0.1:{args.dashboard_port}",
        )
    )
    return services


def port_is_free(port: int, host: str = HOST) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def busy_ports(services: Sequence[Service], is_free: Callable[[int], bool] = port_is_free):
    return [s for s in services if s.port and not is_free(s.port)]


def busy_message(busy: Sequence[Service], windows: bool | None = None) -> str:
    windows = (os.name == "nt") if windows is None else windows
    lines = ["These ports are already in use, nothing was started:"]
    for s in busy:
        hint = f"netstat -ano | findstr :{s.port}" if windows else f"lsof -i :{s.port}"
        lines.append(f"  {s.port:<5} ({s.name})  find the owner with: {hint}")
    lines.append("Stop the other program (or `docker compose down`) and run this again.")
    return "\n".join(lines)


def planted_ssh_password() -> tuple[str, str]:
    """The decoy SSH login (username, password), read from honeytokens.yaml."""
    import yaml

    for token in yaml.safe_load(HONEYTOKEN_FILE.read_text(encoding="utf-8"))["honeytokens"]:
        if token["kind"] == "ssh_password":
            return token.get("username", "deploy"), token["value"]
    return "deploy", ""


def summary(services: Sequence[Service], args: argparse.Namespace, ssh_login=None) -> str:
    user, password = ssh_login or planted_ssh_password()
    rows = [("Service", "Address")]
    for s in services:
        if s.port or s.name == "forwarder":
            rows.append((s.name, s.url or "(follows logs into the store)"))
    width = max(len(r[0]) for r in rows)
    out = [f"{a:<{width}}  {b}" for a, b in rows]
    out.insert(1, "-" * (width + 30))
    out += [
        "",
        f"Dashboard: http://127.0.0.1:{args.dashboard_port} (password: {args.password})",
        "",
        "Make some traffic (everything stays on this computer):",
        "  curl http://127.0.0.1:8080/",
        "  curl -i http://127.0.0.1:8080/.env",
        "  curl -i http://127.0.0.1:8080/admin",
        "  curl -i http://127.0.0.1:8081/api/v1/users",
        f"  ssh -p 2222 {user}@127.0.0.1        (password: {password})",
        "  redis-cli -p 6379      or: curl telnet://127.0.0.1:6379   (type: INFO)",
        "  curl ftp://127.0.0.1:2121/ --user anonymous:guest",
        "  mysql -h 127.0.0.1 -P 3306 -u root -p",
        "  python tools/demo_scenario.py      (15 labelled attack steps)",
        "",
        "Press Ctrl+C to stop everything.",
    ]
    return "\n".join(out)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run QLure locally without Docker (all services on 127.0.0.1)."
    )
    parser.add_argument("--no-docker-api", action="store_true", help="skip the fake Docker API")
    parser.add_argument(
        "--password",
        default=None,
        help="dashboard password (else QLURE_DASHBOARD_PASSWORD, else random and printed once)",
    )
    parser.add_argument("--dashboard-port", type=int, default=9100)
    parser.add_argument(
        "--scenario", action="store_true", help="run tools/demo_scenario.py once when ready"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="delete logs/*.jsonl and data/qlure.db first (asks for 'yes' unless --yes)",
    )
    parser.add_argument("--yes", action="store_true", help="do not ask before --reset")
    parser.add_argument(
        "--workdir", default=".", help="directory that holds logs/ and data/ (default: .)"
    )
    args = parser.parse_args(argv)
    args.password = (
        args.password or os.environ.get("QLURE_DASHBOARD_PASSWORD") or secrets.token_urlsafe(9)
    )
    return args


def reset_files(workdir: Path) -> list[Path]:
    victims = sorted((workdir / "logs").glob("*.jsonl"))
    victims += [
        p
        for p in sorted((workdir / "data").glob("qlure.db*"))
        if p.name in ("qlure.db", "qlure.db-wal", "qlure.db-shm")
    ]
    for path in victims:
        path.unlink(missing_ok=True)
    return victims


def wait_ready(
    port: int,
    proc: Any,
    timeout: float = READY_TIMEOUT,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            sleep(0.2)
    return False


def tail(path: Path, lines: int = 15) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    except OSError:
        return "(no output)"


def stop_all(procs: Sequence[Any], kill_after: float = KILL_AFTER) -> None:
    for proc in procs:
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
    deadline = time.monotonic() + kill_after
    for proc in procs:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()


def main(
    argv: Sequence[str] | None = None,
    popen: Callable[..., Any] = subprocess.Popen,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    args = parse_args(argv)
    work = Path(args.workdir).resolve()
    services = build_services(args, workdir=work)
    busy = busy_ports(services)
    if busy:
        print(busy_message(busy), file=sys.stderr)
        return 2

    if args.reset:
        if not args.yes and input("Delete logs/*.jsonl and data/qlure.db? Type 'yes': ") != "yes":
            print("Not reset; nothing started.")
            return 1
        for path in reset_files(work):
            print(f"deleted {path}")
    (work / "logs").mkdir(parents=True, exist_ok=True)
    (work / "data").mkdir(parents=True, exist_ok=True)

    base_env = dict(os.environ)
    base_env.update(
        QLURE_LOG_DIR=str(work / "logs"),
        QLURE_BIND_HOST=HOST,
        PYTHONPATH=os.pathsep.join(filter(None, [str(REPO), os.environ.get("PYTHONPATH", "")])),
        PYTHONUNBUFFERED="1",
    )
    base_env.pop("QLURE_PROXY_PROTOCOL", None)

    try:  # SIGTERM stops the children too (not just Ctrl+C)
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    except ValueError:
        pass  # not the main thread
    procs: list[Any] = []
    files: list[IO[bytes]] = []
    started: list[tuple[Service, Any, Path]] = []
    code = 0
    try:
        for svc in services:
            if not svc.argv:
                continue  # shares a process with another entry
            log_path = work / "data" / f"run_live-{svc.name.replace(' ', '-')}.log"
            out = open(log_path, "wb")  # noqa: SIM115 - closed in finally
            files.append(out)
            proc = popen(
                svc.argv,
                cwd=str(REPO),
                env={**base_env, **svc.env},
                stdout=out,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
            procs.append(proc)
            started.append((svc, proc, log_path))
        owners = {s.port: (s, p, lp) for s, p, lp in started if s.port}
        banner_owner = next(x for x in started if x[0].name == "FTP decoy")
        for svc in services:
            if not svc.port:
                continue
            _, proc, log_path = owners.get(svc.port, banner_owner)
            if wait_ready(svc.port, proc, sleep=sleep):
                print(f"ready  {svc.name} (port {svc.port})")
            else:
                print(f"FAILED {svc.name} (port {svc.port}); last output:\n{tail(log_path)}")
                code = 1
                return code
        print()
        print(summary(services, args))
        if args.scenario:
            subprocess.run(  # noqa: S603
                [sys.executable, str(REPO / "tools" / "demo_scenario.py")], cwd=REPO, check=False
            )
        while True:
            for svc, proc, log_path in started:
                if proc.poll() is not None:
                    print(
                        f"{svc.name} exited with {proc.poll()}; stopping the rest.\n"
                        f"{tail(log_path)}"
                    )
                    return 1
            sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping ...")
        return code
    finally:
        stop_all(procs)
        for out in files:
            out.close()
        print("stopped")


if __name__ == "__main__":
    sys.exit(main())
