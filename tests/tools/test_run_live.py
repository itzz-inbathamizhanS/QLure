"""tools/run_live.py: argument parsing, port checks, summary, and a clean shutdown with fakes."""

from __future__ import annotations

import importlib.util
import socket
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "run_live.py"


@pytest.fixture(scope="module")
def run_live():
    spec = importlib.util.spec_from_file_location("run_live", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_live"] = module
    spec.loader.exec_module(module)
    return module


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_args_defaults_and_password_sources(run_live, monkeypatch):
    monkeypatch.delenv("QLURE_DASHBOARD_PASSWORD", raising=False)
    args = run_live.parse_args([])
    assert args.dashboard_port == 9100 and not args.no_docker_api and not args.reset
    assert len(args.password) >= 8
    assert run_live.parse_args([]).password != args.password  # random each run
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", "from-env")
    assert run_live.parse_args([]).password == "from-env"
    assert run_live.parse_args(["--password", "cli"]).password == "cli"


def test_services_are_loopback_and_optional_only_for_ssh_and_banners(run_live):
    args = run_live.parse_args(["--password", "x", "--no-docker-api"])
    services = run_live.build_services(args, python="py", workdir=Path("/w"))
    assert 2375 not in {s.port for s in services}
    assert {s.port for s in services} >= {8080, 8081, 2222, 2121, 3306, 6379, 9100}
    for s in services:
        assert "0.0.0.0" not in s.argv  # noqa: S104
        if s.argv and "--host" in s.argv:
            assert s.argv[s.argv.index("--host") + 1] == "127.0.0.1"
        optional = s.env.get("QLURE_PROXY_PROTOCOL") == "optional"
        assert optional == (s.name in ("SSH decoy", "FTP decoy"))
        if optional:
            assert s.env["QLURE_BIND_HOST"] == "127.0.0.1"
    dash = next(s for s in services if s.name == "dashboard")
    assert dash.env["QLURE_LIVE"] == "1" and dash.env["QLURE_LIVE_INTERVAL"] == "5"
    assert dash.env["QLURE_DASHBOARD_PASSWORD"] == "x" and dash.env["QLURE_DASHBOARD_SECRET"]
    forwarder = next(s for s in services if s.name == "forwarder")
    assert forwarder.argv[-1] == "--follow"
    with_api = run_live.build_services(run_live.parse_args(["--password", "x"]), workdir=Path("."))
    assert 2375 in {s.port for s in with_api}


def test_busy_ports_detected_with_hint(run_live):
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen()
    port = holder.getsockname()[1]
    try:
        assert not run_live.port_is_free(port)
    finally:
        holder.close()
    assert run_live.port_is_free(port)
    svc = run_live.Service("web decoy", 8080, [])
    assert "netstat -ano | findstr :8080" in run_live.busy_message([svc], windows=True)
    assert "lsof" in run_live.busy_message([svc], windows=False)


def test_busy_port_exits_2_and_starts_nothing(run_live, tmp_path):
    def boom(*a, **k):
        raise AssertionError("must not start anything")

    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen()
    try:
        port = holder.getsockname()[1]
        code = run_live.main(
            ["--workdir", str(tmp_path), "--dashboard-port", str(port), "--password", "p"],
            popen=boom,
        )
    finally:
        holder.close()
    assert code == 2
    assert not (tmp_path / "logs").exists()


def test_busy_ports_honours_patched_port_is_free(run_live, monkeypatch):
    args = run_live.parse_args(["--password", "x", "--dashboard-port", str(free_port())])
    services = run_live.build_services(args, workdir=Path("."))
    monkeypatch.setattr(run_live, "port_is_free", lambda port, host="127.0.0.1": True)
    assert run_live.busy_ports(services) == []
    monkeypatch.setattr(run_live, "port_is_free", lambda port, host="127.0.0.1": False)
    assert run_live.busy_ports(services) == [s for s in services if s.port]


def test_permission_error_is_needs_admin_not_in_use(run_live, tmp_path, monkeypatch, capsys):
    port = free_port()  # bind before patching, the patch refuses every bind

    def refuse(self, address):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(socket.socket, "bind", refuse)
    assert run_live.port_status(port) == "needs_admin"
    assert not run_live.port_is_free(port)
    svc = run_live.Service("dashboard", port, [])
    text = run_live.busy_message([svc], windows=False, needs_admin={port})
    assert "administrator rights" in text and "in use" not in text

    def boom(*a, **k):
        raise AssertionError("must not start anything")

    code = run_live.main(
        ["--workdir", str(tmp_path), "--dashboard-port", str(port), "--password", "p"], popen=boom
    )
    err = capsys.readouterr().err
    assert code == 2 and f"port {port} needs administrator rights" in err
    assert "in use" not in err


def test_busy_dashboard_port_exits_2_with_no_process(run_live, tmp_path, capsys):
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen()
    procs = []

    def fake_popen(argv, **kwargs):
        procs.append(FakeProc())
        return procs[-1]

    try:
        port = holder.getsockname()[1]
        code = run_live.main(
            ["--workdir", str(tmp_path), "--dashboard-port", str(port), "--password", "p"],
            popen=fake_popen,
        )
    finally:
        holder.close()
    err = capsys.readouterr().err
    assert code == 2 and procs == []
    assert f"  {port:<5} (dashboard)" in err and "already in use" in err


def test_summary_has_dashboard_line_and_planted_password(run_live):
    args = run_live.parse_args(["--password", "pw123"])
    services = run_live.build_services(args, workdir=Path("."))
    text = run_live.summary(services, args, ssh_login=("deploy", "Deploy-Decoy-2026"))
    assert "Dashboard: http://127.0.0.1:9100 (password: pw123)" in text
    assert "ssh -p 2222 deploy@127.0.0.1" in text and "Deploy-Decoy-2026" in text
    assert "curl ftp://127.0.0.1:2121/" in text and "redis-cli -p 6379" in text
    assert run_live.planted_ssh_password()[1]  # read from honeytokens.yaml


class FakeProc:
    def __init__(self, dies_on_terminate=True, exit_after_polls=None):
        self.dies = dies_on_terminate
        self.code = None
        self.terminated = self.killed = False
        self.polls = 0
        self.exit_after = exit_after_polls

    def poll(self):
        self.polls += 1
        if self.exit_after is not None and self.polls > self.exit_after:
            self.code = 3
        return self.code

    def terminate(self):
        self.terminated = True
        if self.dies:
            self.code = 0

    def kill(self):
        self.killed = True
        self.code = -9

    def wait(self, timeout=None):
        if self.code is None:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.code


def test_stop_all_terminates_then_kills_stubborn(run_live):
    good, stubborn = FakeProc(), FakeProc(dies_on_terminate=False)
    run_live.stop_all([good, stubborn], kill_after=0.05)
    assert good.terminated and not good.killed
    assert stubborn.terminated and stubborn.killed


def _listening(ports):
    socks = []
    for port in ports:
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.listen()
        socks.append(s)
    return socks


def test_main_clean_shutdown_on_ctrl_c(run_live, tmp_path, monkeypatch, capsys):
    dash = free_port()
    args = ["--workdir", str(tmp_path), "--dashboard-port", str(dash), "--password", "p"]
    procs = []

    def fake_popen(argv, **kwargs):
        procs.append(FakeProc())
        return procs[-1]

    monkeypatch.setattr(run_live, "port_is_free", lambda port, host="127.0.0.1": True)
    monkeypatch.setattr(run_live, "wait_ready", lambda port, proc, **k: True)

    def interrupt(_):
        raise KeyboardInterrupt

    code = run_live.main(args, popen=fake_popen, sleep=interrupt)
    out = capsys.readouterr().out
    assert code == 0 and out.rstrip().endswith("stopped")
    assert procs and all(p.terminated for p in procs)
    assert (tmp_path / "logs").is_dir() and (tmp_path / "data").is_dir()
    assert f"Dashboard: http://127.0.0.1:{dash} (password: p)" in out


def test_main_reports_crashed_child_and_stops_rest(run_live, tmp_path, monkeypatch, capsys):
    procs = []

    def fake_popen(argv, **kwargs):
        procs.append(FakeProc(exit_after_polls=1 if len(procs) == 2 else None))
        return procs[-1]

    monkeypatch.setattr(run_live, "port_is_free", lambda port, host="127.0.0.1": True)
    monkeypatch.setattr(run_live, "wait_ready", lambda port, proc, **k: True)
    code = run_live.main(
        ["--workdir", str(tmp_path), "--dashboard-port", str(free_port()), "--password", "p"],
        popen=fake_popen,
        sleep=lambda _: None,
    )
    assert code == 1
    assert "exited with 3" in capsys.readouterr().out
    assert all(p.terminated or p.code is not None for p in procs)


def test_main_reports_service_that_never_gets_ready(run_live, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_live, "port_is_free", lambda port, host="127.0.0.1": True)
    monkeypatch.setattr(run_live, "wait_ready", lambda port, proc, **k: False)
    procs = []

    def fake_popen(argv, **kwargs):
        procs.append(FakeProc())
        return procs[-1]

    code = run_live.main(
        ["--workdir", str(tmp_path), "--dashboard-port", str(free_port()), "--password", "p"],
        popen=fake_popen,
    )
    assert code == 1 and "FAILED web decoy" in capsys.readouterr().out
    assert all(p.terminated for p in procs)


def test_reset_deletes_only_after_yes(run_live, tmp_path, monkeypatch):
    (tmp_path / "logs").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "logs" / "web.jsonl").write_text("x")
    (tmp_path / "data" / "qlure.db").write_text("x")
    (tmp_path / "data" / "keep.txt").write_text("x")
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    code = run_live.main(["--workdir", str(tmp_path), "--reset", "--password", "p"])
    assert code == 1 and (tmp_path / "logs" / "web.jsonl").exists()
    removed = run_live.reset_files(tmp_path)
    assert len(removed) == 2 and (tmp_path / "data" / "keep.txt").exists()


def test_real_web_decoy_comes_up_and_goes_away(run_live, tmp_path):
    port = free_port()
    proc = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "uvicorn",
            "decoys.web.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=run_live.REPO,
        env={**__import__("os").environ, "QLURE_LOG_DIR": str(tmp_path)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert run_live.wait_ready(port, proc, timeout=30)
    finally:
        run_live.stop_all([proc])
    assert proc.poll() is not None
    assert run_live.port_is_free(port)
