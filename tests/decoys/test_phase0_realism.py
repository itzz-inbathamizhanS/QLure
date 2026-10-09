"""P0.2 web login honeytoken use and P0.3 SSH shell realism."""
# ruff: noqa: S108

import os

import pytest
from fastapi.testclient import TestClient

from decoys import honeytokens
from decoys.ssh.shell import ShellState, run
from decoys.web.app import app
from qlure.correlate.rules import r7_honeytoken_use
from qlure.events import Event


def _web_events(log_dir):
    path = log_dir / "web.jsonl"
    return [Event.model_validate_json(line) for line in path.read_text().splitlines()]


@pytest.mark.parametrize("token_id", ["ht-ssh-001", "ht-db-001"])
def test_web_login_with_planted_password_is_honeytoken_use(log_dir, token_id):
    token = honeytokens.get(token_id)
    client = TestClient(app, client=("198.51.100.7", 40404))
    resp = client.post(
        "/login", data={"username": token.get("username", "admin"), "password": token["value"]}
    )
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.text
    events = _web_events(log_dir)
    assert [e.action.value for e in events] == ["http_request", "login_attempt", "honeytoken_use"]
    assert events[1].honeytoken_id == token_id
    assert events[2].honeytoken_id == token_id
    assert events[2].session_id == events[0].session_id
    assert r7_honeytoken_use(_session_of(events)) is not None


def _session_of(events):
    from qlure.correlate.sessions import build_sessions

    [session] = build_sessions(events)
    return session


def test_web_login_with_wrong_password_is_not_honeytoken_use(log_dir):
    client = TestClient(app, client=("198.51.100.7", 40404))
    client.post("/login", data={"username": "admin", "password": "admin123"})
    assert [e.action.value for e in _web_events(log_dir)] == ["http_request", "login_attempt"]


def test_root_only_paths_are_permission_denied():
    state = ShellState(user="deploy")
    assert run("cat /etc/shadow", state) == "cat: /etc/shadow: Permission denied\n"
    assert run("cat /root/.bash_history", state) == "cat: /root/.bash_history: Permission denied\n"
    assert "Permission denied" in run("ls /root", state)


def test_missing_executable_is_no_such_file():
    state = ShellState(user="deploy")
    assert run("./xmrig", state) == "bash: ./xmrig: No such file or directory\n"
    assert run("/tmp/x", state) == "bash: /tmp/x: No such file or directory\n"
    assert run("nosuchtool", state) == "bash: nosuchtool: command not found\n"


def test_redirects_echo_nothing_and_protected_paths_are_denied():
    state = ShellState(user="deploy")
    key = "echo ssh-rsa AAAA attacker"
    assert run(f"{key} >> ~/.ssh/authorized_keys", state) == ""
    assert run(f"{key}>>~/.ssh/authorized_keys", state) == ""
    assert run("echo hi > /tmp/x", state) == ""
    assert run("echo hi >> /etc/passwd", state) == "bash: /etc/passwd: Permission denied\n"
    assert run("echo hi > /root/x", state) == "bash: /root/x: Permission denied\n"
    assert run("ls nosuch 2>/dev/null", state) == ""


def test_redirects_write_nothing_to_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = ShellState(user="deploy")
    before = set(os.listdir(tmp_path))
    run("echo hi > out.txt; echo hi >> out2.txt; echo hi > /tmp/qlure-should-not-exist", state)
    assert set(os.listdir(tmp_path)) == before
    assert not os.path.exists("/tmp/qlure-should-not-exist")
    assert "out.txt" not in run("ls", state)


def test_uname_release_matches_banner():
    from decoys.ssh.shell import BANNER

    out = run("uname -r", ShellState(user="deploy"))
    assert out == "5.15.0-101-generic\n"
    assert out.strip() in BANNER
