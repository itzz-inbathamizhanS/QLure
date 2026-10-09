"""Webhook alerts: minimal payloads, once each, safe URLs, never raise."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from decoys import honeytokens
from qlure import alerts
from qlure.cli import main as cli

ROOT = Path(__file__).resolve().parents[1]
URL = "https://hooks.example.test/services/SECRETPATH123"


def _seed_module():
    spec = importlib.util.spec_from_file_location("seed_demo", ROOT / "tools" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    root = tmp_path_factory.mktemp("alerts")
    db_path = root / "demo.db"
    assert _seed_module().main(["--db", str(db_path), "--logs", str(root / "logs")]) == 0
    return db_path


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.delenv(alerts.ALLOW_PRIVATE_ENV, raising=False)
    monkeypatch.setattr(alerts, "_resolve", lambda host: ["93.184.216.34"])


class Stub:
    def __init__(self, status=200, raises=False):
        self.calls, self.status, self.raises = [], status, raises

    def __call__(self, url, body, timeout):
        self.calls.append((url, body, timeout))
        if self.raises:
            raise OSError("boom")
        return self.status


def _noteworthy(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT count(*) FROM findings WHERE verdict='Noteworthy'").fetchone()[
            0
        ]
    finally:
        conn.close()


def test_first_run_payload_is_minimal_and_has_no_secrets(seeded, tmp_path):
    stub, state = Stub(), tmp_path / "state.json"
    res = alerts.notify_new_noteworthy(seeded, state, URL, post=stub)
    assert res.sent == len(stub.calls) >= 1 and res.failed == 0
    allowed = {
        "text", "verdict", "score", "actor", "source_ip", "services", "rule_ids", "attack_ids",
        "honeytoken_ids", "first_seen", "last_seen", "dashboard_path", "qlure_version",
    }  # fmt: skip
    seen_tokens = set()
    for _, body, timeout in stub.calls:
        assert timeout == 5
        data = json.loads(body)
        if "verdict" not in data:
            continue
        assert set(data) == allowed
        assert data["dashboard_path"].startswith("/session/") and "://" not in str(data)
        assert len(data["actor"]) <= 8 and data["verdict"] == "Noteworthy"
        seen_tokens.update(data["honeytoken_ids"])
    blob = b"".join(body for _, body, _ in stub.calls).decode()
    assert seen_tokens, "the seeded chain uses honeytokens"
    for token_id in ("ht-db-001", "ht-ssh-001", "ht-api-001", "ht-redis-001"):
        assert honeytokens.get(token_id)["value"] not in blob
    for word in ("password", "body_sha256", "Authorization", "SECRETPATH123"):
        assert word not in blob


def test_second_run_sends_nothing(seeded, tmp_path):
    state = tmp_path / "state.json"
    assert alerts.notify_new_noteworthy(seeded, state, URL, post=Stub()).sent >= 1
    stub = Stub()
    res = alerts.notify_new_noteworthy(seeded, state, URL, post=stub)
    assert (res.sent, res.failed, res.more, stub.calls) == (0, 0, 0, [])


def test_failed_post_leaves_session_unalerted_and_retries_once(seeded, tmp_path):
    state = tmp_path / "state.json"
    bad = Stub(raises=True)
    res = alerts.notify_new_noteworthy(seeded, state, URL, post=bad)
    assert res.sent == 0 and res.failed >= 1 and res.error == ""
    assert len(bad.calls) == 2 * res.failed  # one retry each, never a loop
    assert not state.exists()
    good = Stub()
    assert alerts.notify_new_noteworthy(seeded, state, URL, post=good).sent >= 1
    assert alerts.notify_new_noteworthy(seeded, state, URL, post=Stub(status=500)).sent == 0


def test_http_error_status_is_a_failure(seeded, tmp_path):
    res = alerts.notify_new_noteworthy(seeded, tmp_path / "s.json", URL, post=Stub(status=500))
    assert res.sent == 0 and res.failed >= 1


def test_cap_and_more_summary(seeded, tmp_path):
    total = _noteworthy(seeded)
    assert total >= 2
    stub = Stub()
    res = alerts.notify_new_noteworthy(seeded, tmp_path / "s.json", URL, post=stub, max_alerts=1)
    assert res.sent == 1 and res.more >= 1
    assert f"+{res.more} more" in json.loads(stub.calls[-1][1])["text"]
    assert len(stub.calls) == 2


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "gopher://x/", "ftp://x/y", "https://u:p@hooks.example.test/x", ""],
)
def test_bad_scheme_or_credentials_refused(seeded, tmp_path, url):
    stub = Stub()
    res = alerts.notify_new_noteworthy(seeded, tmp_path / "s.json", url, post=stub)
    assert res.error and not stub.calls and res.sent == 0


@pytest.mark.parametrize("addr", ["127.0.0.1", "::1", "169.254.169.254", "100.100.100.200"])
def test_loopback_and_metadata_refused_unless_allowed(seeded, tmp_path, monkeypatch, addr):
    monkeypatch.setattr(alerts, "_resolve", lambda host: [addr])
    stub = Stub()
    res = alerts.notify_new_noteworthy(seeded, tmp_path / "s.json", URL, post=stub)
    assert "loopback" in res.error and not stub.calls
    monkeypatch.setenv(alerts.ALLOW_PRIVATE_ENV, "1")
    assert alerts.notify_new_noteworthy(seeded, tmp_path / "s.json", URL, post=stub).sent >= 1


def test_missing_database_never_raises(tmp_path):
    res = alerts.notify_new_noteworthy(tmp_path / "none.db", tmp_path / "s.json", URL, post=Stub())
    assert res.error and res.sent == 0


def test_state_is_bounded_and_corrupt_state_tolerated(tmp_path):
    state = tmp_path / "s.json"
    alerts._save_state(state, [f"s{i}" for i in range(alerts.STATE_LIMIT + 50)])
    ids = alerts._load_state(state)
    assert len(ids) == alerts.STATE_LIMIT and ids[-1] == f"s{alerts.STATE_LIMIT + 49}"
    state.write_text("{not json")
    assert alerts._load_state(state) == []


def test_default_post_does_not_follow_redirects(monkeypatch):
    import httpx

    seen = {}

    def fake(url, **kw):
        seen.update(kw)
        return httpx.Response(302)

    monkeypatch.setattr(httpx, "post", fake)
    assert alerts._httpx_post(URL, b"{}", 5) == 302
    assert seen["follow_redirects"] is False and seen["timeout"] == 5


def test_cli_dry_run_sends_nothing(seeded, tmp_path, capsys, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(alerts, "_httpx_post", forbidden)
    state = tmp_path / "s.json"
    assert cli(["alert", "--db", str(seeded), "--state", str(state), "--dry-run"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out and json.loads(out[0])["verdict"] == "Noteworthy"
    assert not state.exists()


def test_cli_without_url_is_a_config_error(seeded, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("QLURE_ALERT_WEBHOOK", raising=False)
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "none.json"))
    assert cli(["alert", "--db", str(seeded), "--state", str(tmp_path / "s.json")]) == 1


def test_cli_sends_and_never_prints_full_url(seeded, tmp_path, monkeypatch, capsys):
    stub = Stub()
    monkeypatch.setattr(alerts, "_httpx_post", stub)
    monkeypatch.setenv("QLURE_ALERT_WEBHOOK", URL)
    args = ["alert", "--db", str(seeded), "--state", str(tmp_path / "s.json")]
    assert cli(args) == 0 and stub.calls
    captured = capsys.readouterr()
    assert "SECRETPATH123" not in captured.out + captured.err
    assert cli(args) == 0
