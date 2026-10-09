"""P4.2: /healthz and /metrics on the dashboard. Public probe, login-gated scrape, no secrets."""

from __future__ import annotations

import importlib.util
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard import data
from dashboard.app import create_app
from decoys.web.app import app as web_app
from qlure.store import db

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "test-password"
METRIC_LINE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^{}]*)\})? (?P<value>-?[0-9.eE+-]+)$"
)
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
HEALTH_KEYS = {"status", "db", "events", "sessions", "last_forward", "live", "version"}


def _load_seed():
    spec = importlib.util.spec_from_file_location("seed_demo", ROOT / "tools" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed_demo = _load_seed()


def parse_metrics(text: str) -> dict[tuple[str, frozenset], float]:
    """Every sample line as ((name, labels), value). Fails the test on any line it cannot read."""
    samples: dict[tuple[str, frozenset], float] = {}
    declared: set[str] = set()
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            declared.add(line.split()[2])
            continue
        if line.startswith("# HELP "):
            continue
        match = METRIC_LINE.match(line)
        assert match, f"unparseable metrics line: {line!r}"
        name = match["name"]
        assert name in declared, f"{name} has no # TYPE line before its samples"
        labels = frozenset(LABEL.findall(match["labels"] or ""))
        samples[(name, labels)] = float(match["value"])
    return samples


def _value(samples, name, **labels):
    return samples[(name, frozenset((k, v) for k, v in labels.items()))]


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    root = tmp_path_factory.mktemp("health-seed")
    db_path, logs = root / "demo.db", root / "logs"
    assert seed_demo.main(["--db", str(db_path), "--logs", str(logs)]) == 0
    return {"db": db_path, "logs": logs, "root": root}


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    monkeypatch.delenv("QLURE_METRICS_PUBLIC", raising=False)
    monkeypatch.delenv("QLURE_LIVE", raising=False)


@pytest.fixture
def app(seeded, clean_env):
    return create_app(seeded["db"], seeded["logs"])


@pytest.fixture
def client(app):
    c = TestClient(app)
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return c


@pytest.fixture
def anonymous(app):
    return TestClient(app)


def _rows(db_path: Path, sql: str) -> list:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


# /healthz


def test_healthz_is_public_and_ok_on_the_seeded_store(anonymous, seeded):
    r = anonymous.get("/healthz")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert set(body) == HEALTH_KEYS
    assert body["status"] == "ok" and body["db"] == "ok"
    assert body["events"] == _rows(seeded["db"], "SELECT COUNT(*) FROM events")[0][0] > 0
    assert body["sessions"] == _rows(seeded["db"], "SELECT COUNT(*) FROM sessions")[0][0] > 0
    assert datetime.fromisoformat(body["last_forward"]) is not None
    assert body["live"] is False  # no lifespan in the test client, so no background loop
    assert body["version"]


def test_healthz_leaks_no_paths_secrets_or_config(anonymous, seeded):
    text = anonymous.get("/healthz").text
    for secret in (PASSWORD, str(seeded["root"]), str(seeded["db"]), str(seeded["logs"])):
        assert secret not in text
    assert "/" not in text  # no path of any kind, and no ISO time carries a slash
    assert not {"password", "secret", "token", "path", "config"} & set(
        re.findall(r'"(\w+)":', text)
    )


def test_healthz_on_a_missing_store_is_503_and_creates_nothing(tmp_path, clean_env):
    missing = tmp_path / "gone" / "qlure.db"
    anonymous = TestClient(create_app(missing, tmp_path / "logs"))
    r = anonymous.get("/healthz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded" and body["db"] == "error"
    assert body["events"] is None and body["sessions"] is None and body["last_forward"] is None
    assert str(tmp_path) not in r.text and "gone" not in r.text
    assert not missing.exists()


def test_healthz_on_an_empty_store_is_valid(tmp_path, clean_env):
    path = tmp_path / "empty.db"
    db.connect(path).close()
    r = TestClient(create_app(path, tmp_path / "logs")).get("/healthz")
    assert r.status_code == 200
    assert r.json()["events"] == 0 and r.json()["last_forward"] is None


def test_healthz_is_not_served_by_the_decoys():
    r = TestClient(web_app, client=("198.51.100.5", 40404)).get("/healthz")
    assert '"live"' not in r.text and '"db"' not in r.text


# /metrics


def test_metrics_requires_login_by_default(anonymous):
    r = anonymous.get("/metrics", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


@pytest.mark.parametrize("flag", ["0", "", "true", "yes"])
def test_metrics_stays_private_unless_the_flag_is_exactly_one(app, monkeypatch, flag, anonymous):
    monkeypatch.setenv("QLURE_METRICS_PUBLIC", flag)
    assert anonymous.get("/metrics", follow_redirects=False).status_code == 303


def test_metrics_public_with_the_flag_and_only_metrics(app, monkeypatch, anonymous):
    monkeypatch.setenv("QLURE_METRICS_PUBLIC", "1")
    assert anonymous.get("/metrics").status_code == 200
    assert anonymous.get("/export.csv", follow_redirects=False).status_code == 303
    assert anonymous.get("/config", follow_redirects=False).status_code == 303


def test_metrics_format_parses_and_matches_the_store(client, seeded):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    samples = parse_metrics(r.text)
    events = _rows(seeded["db"], "SELECT COUNT(*) FROM events")[0][0]
    tokens = _rows(seeded["db"], "SELECT COUNT(*) FROM events WHERE honeytoken_id IS NOT NULL")[0][
        0
    ]
    assert _value(samples, "qlure_events_total") == events > 0
    assert (
        _value(samples, "qlure_actors_total")
        == _rows(seeded["db"], "SELECT COUNT(*) FROM actors")[0][0]
    )
    assert _value(samples, "qlure_honeytoken_hits_total") == tokens
    # The sessions page's own count, so the scrape and the page agree.
    conn = db.connect(seeded["db"])
    try:
        shown = data.overview(conn)["verdicts"]
    finally:
        conn.close()
    for verdict, count in shown.items():
        assert _value(samples, "qlure_sessions_total", verdict=verdict.lower()) == count
    assert sum(shown.values()) > 0


def test_metrics_omits_chain_verified(client):
    # Verifying the whole chain on every scrape is too costly, so the gauge is left out.
    assert "qlure_chain_verified" not in client.get("/metrics").text


def test_metrics_reports_the_last_live_pass(client, app):
    assert (
        _value(parse_metrics(client.get("/metrics").text), "qlure_live_last_pass_timestamp_seconds")
        == 0
    )
    when = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
    app.state.live.updated = when
    samples = parse_metrics(client.get("/metrics").text)
    assert _value(samples, "qlure_live_last_pass_timestamp_seconds") == when.timestamp()


def test_metrics_on_an_empty_store_is_valid(tmp_path, clean_env, monkeypatch):
    path = tmp_path / "empty.db"
    db.connect(path).close()
    monkeypatch.setenv("QLURE_METRICS_PUBLIC", "1")
    text = TestClient(create_app(path, tmp_path / "logs")).get("/metrics").text
    samples = parse_metrics(text)
    assert _value(samples, "qlure_events_total") == 0
    for verdict in ("benign", "suspicious", "noteworthy"):
        assert _value(samples, "qlure_sessions_total", verdict=verdict) == 0


def test_metrics_503_when_the_store_is_missing(tmp_path, clean_env, monkeypatch):
    monkeypatch.setenv("QLURE_METRICS_PUBLIC", "1")
    missing = tmp_path / "nope.db"
    r = TestClient(create_app(missing, tmp_path / "logs")).get("/metrics")
    assert r.status_code == 503 and str(tmp_path) not in r.text
    assert not missing.exists()


def test_label_values_are_escaped():
    assert data.escape_label('a"b\\c\nd') == 'a\\"b\\\\c\\nd'
    line = data.metrics_text(
        {
            "events": 0,
            "sessions": 0,
            "actors": 0,
            "honeytoken_hits": 0,
            "verdicts": {"benign": 0, "suspicious": 0, "noteworthy": 0},
            "newest": None,
        },
        0.0,
    )
    assert 'verdict="benign"' in line
    parse_metrics(line)
