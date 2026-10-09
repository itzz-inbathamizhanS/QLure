"""Drive the real web decoy app and check what it logs."""

import json

import pytest
from fastapi.testclient import TestClient

from decoys.web.app import MAX_BODY_BYTES, SESSION_COOKIE, app
from qlure.events import Event


@pytest.fixture
def client(log_dir):
    return TestClient(app, client=("198.51.100.7", 40404))


def events(log_dir):
    path = log_dir / "web.jsonl"
    if not path.exists():
        return []
    return [Event.model_validate_json(line) for line in path.read_text().splitlines()]


def test_login_page_is_served_and_logged(client, log_dir):
    resp = client.get("/login", headers={"User-Agent": "Mozilla/5.0"})
    assert resp.status_code == 200
    assert "Staff Portal" in resp.text
    assert resp.headers["server"] == "nginx/1.24.0"
    [event] = events(log_dir)
    assert event.action == "http_request"
    assert event.request["path"] == "/login"
    assert event.request["headers"]["user-agent"] == "Mozilla/5.0"
    assert event.response["status"] == 200
    assert event.client_fp


def test_login_attempt_records_credential(client, log_dir):
    resp = client.post("/login", data={"username": "admin", "password": "admin123"})
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.text
    http, attempt = events(log_dir)
    assert http.action == "http_request"
    assert attempt.action == "login_attempt"
    assert attempt.credential.username == "admin"
    assert attempt.credential.password == "admin123"
    assert attempt.session_id == http.session_id


def test_cookie_keeps_one_session(client, log_dir):
    client.get("/login")
    assert SESSION_COOKIE in client.cookies
    client.post("/login", data={"username": "a", "password": "b"})
    client.get("/admin")
    assert len({e.session_id for e in events(log_dir)}) == 1


def test_unknown_paths_get_a_realistic_404_and_are_logged(client, log_dir):
    resp = client.get("/wp-admin/setup.php?x=1")
    assert resp.status_code == 404
    assert "nginx" in resp.text
    [event] = events(log_dir)
    assert event.request["path"] == "/wp-admin/setup.php"
    assert event.request["query"] == "x=1"
    assert event.response["status"] == 404


def test_attacker_text_is_stored_verbatim(client, log_dir):
    client.get("/<script>alert(1)</script>")
    [event] = events(log_dir)
    assert event.request["path"] == "/<script>alert(1)</script>"


def test_oversized_body_is_refused_but_logged(client, log_dir):
    resp = client.post("/login", content=b"x" * (MAX_BODY_BYTES + 1))
    assert resp.status_code == 413
    [event] = events(log_dir)
    assert event.action == "http_request"
    assert event.response["status"] == 413


def test_body_preview_and_hash(client, log_dir):
    client.post("/login", data={"username": "root", "password": "toor"})
    event = events(log_dir)[0]
    assert event.request["body_preview"] == "username=root&password=toor"
    assert len(event.request["body_sha256"]) == 64


def test_every_logged_line_is_plain_json(client, log_dir):
    client.get("/")
    for line in (log_dir / "web.jsonl").read_text().splitlines():
        json.loads(line)
