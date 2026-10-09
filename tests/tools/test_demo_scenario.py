"""The demo scenario script: dry run, target refusal, step catalogue, and a live web and API run."""

from __future__ import annotations

import importlib.util
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import ModuleType

import httpx
import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "demo_scenario.py"
RULES = REPO / "qlure" / "rules" / "rules.yaml"
HONEYTOKENS = REPO / "decoys" / "honeytokens.yaml"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_scenario", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["demo_scenario"] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


demo = _load_script()


@pytest.fixture
def no_traffic(monkeypatch):
    """Fail the test if anything tries to open a socket or send an HTTP request."""

    def refuse(*args, **kwargs):
        raise AssertionError("the script tried to send traffic")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(httpx.Client, "request", refuse)


def test_dry_run_lists_every_step_and_sends_nothing(no_traffic, capsys):
    assert demo.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "nothing was sent" in out
    for item in demo.STEPS:
        assert f"{item.id} " in out


def test_list_prints_steps_and_exits_zero(no_traffic, capsys):
    assert demo.main(["--list"]) == 0
    assert "ssh-login" in capsys.readouterr().out


def test_dry_run_as_a_subprocess_exits_zero():
    done = subprocess.run(  # noqa: S603 - fixed interpreter and script path
        [sys.executable, str(SCRIPT), "--dry-run"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "redis-auth" in done.stdout


@pytest.mark.parametrize(
    "target",
    ["203.0.113.5", "0.0.0.0", "127.0.0.2", "example.com", "192.168.1.10", ""],  # noqa: S104
)
def test_non_local_target_is_refused_with_exit_2(no_traffic, capsys, target):
    assert demo.main(["--target", target, "--dry-run"]) == 2
    err = capsys.readouterr().err
    assert "refused" in err and "loopback" in err


def test_refusal_also_applies_to_a_real_run(no_traffic, capsys):
    assert demo.main(["--target", "10.0.0.1"]) == 2
    assert "refused" in capsys.readouterr().err


def test_local_targets_are_accepted():
    for target in ("127.0.0.1", "::1", "localhost", "LocalHost"):
        assert demo.is_local(target)


def test_default_target_is_loopback():
    assert demo.DEFAULT_TARGET == "127.0.0.1"
    assert demo.is_local(demo.DEFAULT_TARGET)


def test_unknown_only_step_exits_two(no_traffic, capsys):
    assert demo.main(["--only", "no-such-step", "--dry-run"]) == 2
    assert "unknown step" in capsys.readouterr().err


def test_step_ids_are_unique():
    ids = [item.id for item in demo.STEPS]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 10


def test_every_step_names_rules_that_exist_in_rules_yaml():
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    assert set(rules) == {f"R{n}" for n in range(1, 12)}
    for item in demo.STEPS:
        assert item.rules, f"{item.id} names no expected rule"
        for rule_id in item.rules:
            assert rule_id in rules, f"{item.id} names unknown rule {rule_id}"


def test_planted_secrets_come_from_the_yaml_not_the_script():
    source = SCRIPT.read_text(encoding="utf-8")
    honeytokens = yaml.safe_load(HONEYTOKENS.read_text(encoding="utf-8"))["honeytokens"]
    for token in honeytokens:
        assert token["value"] not in source, f"{token['id']} value is hardcoded"
    assert demo.planted("ht-api-001")["value"] == "qlk_decoy_7f3a9c21e5d84b0a"


def test_proxy_line_uses_the_documentation_range():
    line = demo.proxy_line("198.51.100.23", 2222)
    assert line.startswith(b"PROXY TCP4 198.51.100.23 127.0.0.1 ")
    assert line.endswith(b" 2222\r\n")


def test_source_outside_documentation_range_is_refused(no_traffic, capsys):
    assert demo.main(["--source-ip", "10.1.2.3", "--dry-run"]) == 2
    assert "--source-ip" in capsys.readouterr().err


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def web_and_api(log_dir):
    """The real web and API decoy apps on loopback, served by uvicorn in threads."""
    uvicorn = pytest.importorskip("uvicorn")
    pytest.importorskip("fastapi")
    pytest.importorskip("jinja2")
    from decoys.api.app import app as api_app
    from decoys.web.app import app as web_app

    servers = []
    ports = {}
    for name, app in (("web", web_app), ("api", api_app)):
        port = _free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        servers.append((server, thread))
        ports[name] = port
    deadline = time.monotonic() + 10
    for server, _ in servers:
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        if not server.started:
            pytest.skip("uvicorn did not start the decoys in time")
    yield ports
    for server, thread in servers:
        server.should_exit = True
        thread.join(5)


HTTP_STEPS = (
    "web-scan",
    "web-hunt",
    "web-lfi",
    "web-injection",
    "web-exploit-strings",
    "web-login",
    "web-phpmyadmin",
    "web-scanner-ua",
    "api-key-reuse",
)


def test_http_steps_run_against_the_live_decoys(web_and_api, read_events):
    ctx = demo.Context(
        host="127.0.0.1",
        ports={**demo.PORTS, **web_and_api},
        proxy=False,
    )
    by_id = {item.id: item for item in demo.STEPS}
    for step_id in HTTP_STEPS:
        out = demo.run_step(ctx, by_id[step_id])
        assert out.error is None, f"{step_id}: {out.error}"
        assert out.sent and len(out.sent) == len(out.replies)

    web = read_events("web")
    api = read_events("api")
    assert any(event.request and event.request.get("path") == "/.env" for event in web)
    assert any(event.request and event.request.get("path") == "/login" for event in web)
    assert api, "the API decoy logged nothing"
    assert any(event.honeytoken_id == "ht-api-001" for event in api)
    assert {event.src_ip for event in web + api} == {demo.DEFAULT_SOURCE}


def test_planted_api_key_reply_is_accepted_by_the_api_decoy(web_and_api):
    key = str(demo.planted("ht-api-001")["value"])
    with httpx.Client(base_url=f"http://127.0.0.1:{web_and_api['api']}", timeout=5) as api:
        assert api.get("/api/v1/users", headers={"X-API-Key": key}).status_code == 200
        assert api.get("/api/v1/users", headers={"X-API-Key": "wrong"}).status_code == 401


def test_mysql_handshake_token_matches_what_the_decoy_recognises():
    from decoys.banners import dialogues, listeners

    packet = listeners.mysql_greeting(1)  # a fresh scramble each call, so use one packet
    greeting = packet[4:]  # the payload, without the packet header
    salt = demo._mysql_salt(greeting)
    assert salt == dialogues._scramble(packet)
    token = demo._mysql_token("root", salt)
    assert token == dialogues._native_token("root", salt)
    assert len(token) == 20
