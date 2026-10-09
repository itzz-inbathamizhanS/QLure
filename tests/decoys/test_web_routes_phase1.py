"""P1.3 fake web content: fixed replies, honeytoken events, nothing stored or read from the host."""

import socket
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from decoys import honeytokens
from decoys.web.app import app
from qlure.correlate.engine import correlate
from qlure.events import Event

sys.path.insert(0, str(Path(__file__).parent.parent / "correlate"))
from helpers import finding_for, hits_of  # noqa: E402

IP = "198.51.100.9"


@pytest.fixture
def client(log_dir):
    return TestClient(app, client=(IP, 40404))


def events(log_dir):
    path = log_dir / "web.jsonl"
    return [Event.model_validate_json(x) for x in path.read_text().splitlines()]


def test_git_head_and_config(client, log_dir):
    assert client.get("/.git/HEAD").text.strip() == "ref: refs/heads/main"
    resp = client.get("/.git/config")
    token = honeytokens.get("ht-git-001")["value"]
    assert resp.status_code == 200 and token in resp.text
    reads = [e for e in events(log_dir) if e.action == "file_read"]
    assert [(e.request["path"], e.honeytoken_id) for e in reads] == [
        ("/.git/HEAD", None),
        ("/.git/config", "ht-git-001"),
    ]


def test_robots(client):
    text = client.get("/robots.txt").text
    assert "Disallow: /backup/" in text and "Disallow: /admin" in text


def test_directory_indexes(client):
    assert "config.bak" in client.get("/backup/").text
    assert "invoice-2026-07.pdf" in client.get("/uploads/").text


@pytest.mark.parametrize("path", ["/phpmyadmin", "/phpmyadmin/", "/pma"])
def test_phpmyadmin_page(client, path):
    resp = client.get(path)
    assert resp.status_code == 200 and "phpMyAdmin" in resp.text


def test_phpmyadmin_login_attempt_with_honeytoken(client, log_dir):
    db = honeytokens.get("ht-db-001")
    resp = client.post(
        "/phpmyadmin/index.php", data={"pma_username": "root", "pma_password": db["value"]}
    )
    assert resp.status_code == 200 and "phpMyAdmin" in resp.text
    by_action = {e.action: e for e in events(log_dir)}
    attempt = by_action["login_attempt"]
    assert attempt.credential.username == "root"
    assert attempt.credential.password == db["value"]
    assert attempt.honeytoken_id == db["id"]
    assert by_action["honeytoken_use"].honeytoken_id == db["id"]


def test_phpmyadmin_plain_failure(client, log_dir):
    client.post("/pma", data={"pma_username": "root", "pma_password": "x"})
    attempt = [e for e in events(log_dir) if e.action == "login_attempt"][0]
    assert attempt.honeytoken_id is None


def test_server_status_forbidden(client):
    resp = client.get("/server-status")
    assert resp.status_code == 403 and "403 Forbidden" in resp.text


@pytest.mark.parametrize("method", ["post", "put"])
def test_upload_forbidden_and_never_stored(client, log_dir, method):
    big = b"A" * 5000
    resp = getattr(client, method)(
        "/upload", files={"f": ("../../evil.php", big, "application/octet-stream")}
    )
    assert resp.status_code == 403 and "403 Forbidden" in resp.text
    raw = getattr(client, method)("/upload", content=big, headers={"content-type": "text/plain"})
    assert raw.status_code == 403
    http = [e for e in events(log_dir) if e.action == "http_request"]
    assert len(http[1].request["body_preview"]) == 2048
    assert http[1].request["body_len"] == 5000
    assert [p.name for p in log_dir.rglob("*") if p.is_file()] == ["web.jsonl"]
    assert not Path("evil.php").exists()


def test_download_serves_only_the_fake_filesystem(client, log_dir):
    resp = client.get("/download", params={"file": "../../etc/passwd"})
    assert resp.status_code == 200
    assert "root:x:0:0" in resp.text
    host_passwd = Path("/etc/passwd").read_text() if Path("/etc/passwd").exists() else ""
    assert resp.text != host_passwd
    assert socket.gethostname() not in resp.text
    from decoys.ssh.shell import load_fs

    assert resp.text == load_fs().files["/etc/passwd"]
    deep = client.get("/download", params={"file": "../" * 30 + "etc/passwd"})
    assert deep.text == resp.text
    absolute = client.get("/download", params={"file": "/etc/passwd"})
    assert absolute.text == resp.text


@pytest.mark.parametrize("name", ["", "nope.txt", "/etc", "../../etc/shadow-missing", "a\x00b"])
def test_download_unknown_is_404(client, name):
    resp = client.get("/download", params={"file": name})
    assert resp.status_code == 404
    assert "root:" not in resp.text


def test_download_traversal_fires_r5_and_backup_fires_r9(client, read_events):
    client.get("/download", params={"file": "../../etc/passwd"})
    client.get("/backup/config.bak")
    events_ = read_events("web")
    finding = finding_for(correlate(events_), IP, "web")
    assert {"R5", "R9"} <= hits_of(finding)
