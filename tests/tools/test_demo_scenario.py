"""The demo scenario script: dry run, target refusal, step catalogue, and a live web and API run."""

from __future__ import annotations

import importlib.util
import ipaddress
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
        if item.persona != "benign":  # the benign visit is the one step that expects no rule
            assert item.rules, f"{item.id} names no expected rule"
        for rule_id in item.rules:
            assert rule_id in rules, f"{item.id} names unknown rule {rule_id}"


def test_every_step_has_a_persona_and_an_address_in_the_documentation_ranges():
    assert {item.persona for item in demo.STEPS} == set(demo.PERSONA_IPS)
    for item in demo.STEPS:
        ip = ipaddress.ip_address(demo.PERSONA_IPS[item.persona])
        assert any(ip in net for net in demo.SOURCE_NETS), f"{item.id}: {ip} is not documentation"
        assert demo.visitor_ip(demo.Context(), item) == str(ip)


def test_personas_use_the_same_addresses_as_the_seed():
    spec = importlib.util.spec_from_file_location(
        "seed_demo_check", REPO / "tools" / "seed_demo.py"
    )
    assert spec and spec.loader
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    assert demo.PERSONA_IPS == {
        "scanner": seed.SCANNER_IP,
        "credential-stuffer": seed.STUFFER_IP,
        "full-chain": seed.CHAIN_IP,
        "data-store": seed.DATASTORE_IP,
        "benign": seed.BENIGN_IPS[0],
    }


def test_unknown_persona_is_rejected_at_registration():
    with pytest.raises(ValueError, match="nobody"):
        demo.step("bad-step", "title", "nobody", ("R2",))(lambda ctx, out: None)


def test_only_flag_uses_the_persona_address(capsys):
    assert demo.main(["--only", "redis-auth", "--dry-run"]) == 0
    assert "data-store" in capsys.readouterr().out
    item = next(s for s in demo.STEPS if s.id == "redis-auth")
    assert demo.visitor_ip(demo.Context(), item) == demo.PERSONA_IPS["data-store"]


def test_summary_lists_each_persona_with_its_address_and_a_mixed_verdict(capsys):
    results = [
        (item, demo.Outcome(sent=["x"], replies=["y"], source_ip=demo.PERSONA_IPS[item.persona]))
        for item in demo.STEPS
    ]
    demo.render_summary(results)
    out = capsys.readouterr().out
    for persona, ip in demo.PERSONA_IPS.items():
        assert f"{persona} " in out and ip in out, persona
    assert "suppressors can lower a score" in out
    verdicts = {
        persona: demo.expected_verdict(
            demo.persona_rules([item for item in demo.STEPS if item.persona == persona])
        )
        for persona in demo.PERSONA_IPS
    }
    assert verdicts["benign"] == "Benign"
    assert verdicts["credential-stuffer"] == "Suspicious"
    assert verdicts["full-chain"] == "Noteworthy"
    assert len(set(verdicts.values())) >= 3


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


@pytest.mark.parametrize("source", ["10.1.2.3", "198.51.101.1", "192.0.2.1", "::1", "not-an-ip"])
def test_source_outside_documentation_range_is_refused(no_traffic, capsys, source):
    assert demo.main(["--source-ip", source, "--dry-run"]) == 2
    err = capsys.readouterr().err
    assert "--source-ip" in err and "198.51.100.0/24" in err and "203.0.113.0/24" in err


@pytest.mark.parametrize("source", ["198.51.100.9", "203.0.113.5"])
def test_source_ip_override_in_either_documentation_range_is_accepted(no_traffic, capsys, source):
    assert demo.main(["--source-ip", source, "--dry-run"]) == 0
    assert f"every step from {source}" in capsys.readouterr().out


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
    "api-key-brute",
    "api-key-reuse",
    "benign-visit",
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
    # Each persona reads as its own visitor, so the HTTP steps show four distinct addresses.
    expected = {demo.PERSONA_IPS[name] for name in ("scanner", "credential-stuffer")}
    expected |= {demo.PERSONA_IPS[name] for name in ("full-chain", "benign")}
    assert {event.src_ip for event in web + api} == expected


def test_source_ip_override_forces_one_address_on_every_step(web_and_api, read_events):
    ctx = demo.Context(
        host="127.0.0.1",
        ports={**demo.PORTS, **web_and_api},
        proxy=False,
        override_ip="203.0.113.9",
    )
    by_id = {item.id: item for item in demo.STEPS}
    for step_id in ("web-scan", "web-login", "api-key-reuse", "benign-visit"):
        out = demo.run_step(ctx, by_id[step_id])
        assert out.error is None, f"{step_id}: {out.error}"
        assert out.source_ip == "203.0.113.9"
    web = read_events("web")
    api = read_events("api")
    assert {event.src_ip for event in web + api} == {"203.0.113.9"}


def test_planted_api_key_reply_is_accepted_by_the_api_decoy(web_and_api):
    key = str(demo.planted("ht-api-001")["value"])
    with httpx.Client(base_url=f"http://127.0.0.1:{web_and_api['api']}", timeout=5) as api:
        assert api.get("/api/v1/users", headers={"X-API-Key": key}).status_code == 200
        assert api.get("/api/v1/users", headers={"X-API-Key": "wrong"}).status_code == 401


def test_every_step_names_the_decoy_it_talks_to():
    assert {item.id for item in demo.STEPS} == set(demo.STEP_SERVICE)
    assert set(demo.STEP_SERVICE.values()) <= set(demo.PORTS)


def test_all_decoys_closed_exits_3_with_the_start_message(no_traffic, monkeypatch, capsys):
    monkeypatch.setattr(demo, "probe", lambda host, port: False)
    assert demo.main([]) == 3
    captured = capsys.readouterr()
    assert "No QLure decoys are listening on 127.0.0.1" in captured.err
    assert "python tools" in captured.err and "run_live.py" in captured.err
    assert "--no-proxy-header" in captured.err
    assert "Traceback" not in captured.err
    assert "from:" not in captured.out  # no step ran, so no step output


def test_preflight_probes_only_the_ports_the_selected_steps_use(no_traffic, monkeypatch, capsys):
    probed = []

    def record(host, port):
        probed.append((host, port))
        return False

    monkeypatch.setattr(demo, "probe", record)
    assert demo.main(["--only", "redis-auth", "--target", "::1"]) == 3
    assert probed == [("::1", demo.PORTS["redis"])]


def test_one_decoy_down_skips_its_steps_and_the_others_still_run(web_and_api, monkeypatch, capsys):
    ssh_port = demo.PORTS["ssh"]
    monkeypatch.setitem(demo.PORTS, "web", web_and_api["web"])
    monkeypatch.setitem(demo.PORTS, "api", web_and_api["api"])
    subset = [item for item in demo.STEPS if item.id in ("web-scan", "ssh-login", "benign-visit")]
    monkeypatch.setattr(demo, "STEPS", subset)
    monkeypatch.setattr(demo, "probe", lambda host, port: port != ssh_port)

    assert demo.main([]) == 1
    out = capsys.readouterr().out
    assert "warning: no decoy is listening on 127.0.0.1 for ssh (2222)" in out
    assert "These steps will be skipped: ssh-login" in out
    assert "skipped: ssh decoy not listening" in out
    assert "ConnectError" not in out and "WinError" not in out
    assert "  > GET /wp-login.php" in out  # the web steps really ran
    assert "ssh-login" in out and "skipped" in out.split("Summary", 1)[1]


def test_dry_run_and_list_never_probe(no_traffic, monkeypatch, capsys):
    def refuse(host, port):
        raise AssertionError("dry run or list probed a port")

    monkeypatch.setattr(demo, "probe", refuse)
    assert demo.main(["--dry-run"]) == 0
    assert demo.main(["--list"]) == 0
    assert "nothing was sent" in capsys.readouterr().out


def test_probe_reports_a_closed_port_as_not_listening():
    assert demo.probe("127.0.0.1", _free_port()) is False


def test_mysql_handshake_token_matches_what_the_decoy_recognises():
    from decoys.banners import dialogues, listeners

    packet = listeners.mysql_greeting(1)  # a fresh scramble each call, so use one packet
    greeting = packet[4:]  # the payload, without the packet header
    salt = demo._mysql_salt(greeting)
    assert salt == dialogues._scramble(packet)
    token = demo._mysql_token("root", salt)
    assert token == dialogues._native_token("root", salt)
    assert len(token) == 20
