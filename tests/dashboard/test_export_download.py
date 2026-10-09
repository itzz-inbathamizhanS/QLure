"""P3.4 in the dashboard: the three indicator downloads and the page that links them.

The downloads call qlure/export.py, so each body must equal what `render` returns for the same
database. They need a login, judge mode does not block them, and the CSV neutralises formulas.
"""

from __future__ import annotations

import csv
import importlib.util
import io
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from decoys.web.app import app as web_app
from qlure import export as ioc_export
from qlure.correlate import store as correlate_store
from qlure.store import db, forwarder

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "test-password"
FORMULA_IP = "198.51.100.91"
DOWNLOADS = {
    "/export.csv": ("text/csv", "csv"),
    "/export.json": ("application/stix+json", "json"),
    "/export.txt": ("text/plain", "txt"),
}
CSV_COLUMNS = [
    "type",
    "value",
    "first_seen",
    "last_seen",
    "sessions",
    "actor",
    "verdict",
    "rules",
    "attack_ids",
]


def _load_seed():
    spec = importlib.util.spec_from_file_location("seed_demo", ROOT / "tools" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed_demo = _load_seed()


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    root = tmp_path_factory.mktemp("download-seed")
    db_path, logs = root / "demo.db", root / "logs"
    assert seed_demo.main(["--db", str(db_path), "--logs", str(logs)]) == 0
    return {"db": db_path, "logs": logs}


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    monkeypatch.delenv("QLURE_METRICS_PUBLIC", raising=False)


@pytest.fixture
def client(seeded, clean_env):
    c = TestClient(create_app(seeded["db"], seeded["logs"]))
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return c


@pytest.fixture
def anonymous(seeded, clean_env):
    return TestClient(create_app(seeded["db"], seeded["logs"]))


@pytest.fixture
def formula_store(tmp_path, log_dir, monkeypatch, clean_env):
    """A store whose one session carries a user agent that starts with a spreadsheet formula."""
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    load_config = __import__("qlure.correlate.rules", fromlist=["load_config"]).load_config
    load_config.cache_clear()
    visitor = TestClient(web_app, client=(FORMULA_IP, 40404))
    visitor.headers["user-agent"] = '=HYPERLINK("http://203.0.113.9/x","open")'
    for path in ("/wp-login.php", "/phpmyadmin/", "/backup/config.bak"):
        visitor.get(path)
    for i in range(6):
        visitor.post("/login", data={"username": "ops", "password": f"guess-{i}"})
    db_path = tmp_path / "formula.db"
    conn = db.connect(db_path)
    forwarder.forward_once(conn, log_dir)
    correlate_store.run(conn)
    conn.close()
    load_config.cache_clear()
    return {"db": db_path, "logs": log_dir}


def _today() -> str:
    return datetime.now(UTC).strftime("%Y%m%d")


def _csv_rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


# Access and page


def test_every_download_and_the_page_need_a_login(anonymous):
    for path in ("/export", *DOWNLOADS):
        r = anonymous.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", path


def test_the_nav_links_the_export_page(client):
    assert 'href="/export"' in client.get("/").text


def test_export_page_links_the_three_downloads(client):
    html = client.get("/export").text
    for path in DOWNLOADS:
        assert f'href="{path}"' in html
    assert 'href="/export?min=suspicious"' in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and " style=" not in html


def test_export_page_with_suspicious_carries_the_option(client):
    html = client.get("/export", params={"min": "suspicious"}).text
    for path in DOWNLOADS:
        assert f'href="{path}?min=suspicious"' in html


@pytest.mark.parametrize("path", ["/export", "/export.csv", "/export.json", "/export.txt"])
def test_unknown_min_is_refused(client, path):
    assert client.get(path, params={"min": "everything"}).status_code == 400


# Headers


@pytest.mark.parametrize("path", list(DOWNLOADS))
def test_downloads_have_the_right_type_and_a_fixed_attachment_name(client, path):
    media, extension = DOWNLOADS[path]
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(media)
    assert r.headers["content-disposition"] == (
        f'attachment; filename="qlure-indicators-{_today()}.{extension}"'
    )
    assert r.headers["cache-control"] == "no-store"


# Content and reuse of qlure/export.py


def test_csv_download_is_the_export_module_output(client, seeded):
    body = client.get("/export.csv").text
    assert body == ioc_export.render(seeded["db"], "csv", "noteworthy")
    rows = _csv_rows(body)
    assert rows[0] == CSV_COLUMNS and len(rows) > 1
    assert all(len(row) == len(CSV_COLUMNS) for row in rows)


def test_json_download_is_a_stix_bundle_from_the_export_module(client, seeded):
    body = client.get("/export.json").text
    assert body == ioc_export.render(seeded["db"], "stix", "noteworthy")
    bundle = json.loads(body)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    objects = bundle["objects"]
    assert objects[0]["type"] == "identity" and objects[0]["name"] == "QLure"
    indicators = [o for o in objects if o["type"] == "indicator"]
    assert indicators, "the seeded store has indicators"
    for obj in indicators:
        assert obj["spec_version"] == "2.1"
        assert obj["pattern_type"] == "stix"
        assert obj["pattern"].startswith("[") and obj["pattern"].endswith("]")
        assert obj["labels"] and 0 <= obj["confidence"] <= 100


def test_text_download_is_the_export_module_blocklist(client, seeded):
    body = client.get("/export.txt").text
    lines = body.splitlines()
    assert lines[0].startswith("# generated ")
    # The first line carries the time of the run, so the rest is compared.
    expected = ioc_export.render(seeded["db"], "blocklist", "noteworthy").splitlines()
    assert lines[1:] == expected[1:]
    addresses = [ipaddress.ip_address(line) for line in lines[2:] if not line.startswith("#")]
    documentation = ioc_export.DOCUMENTATION_NETS
    assert addresses
    assert all(not ip.is_private or any(ip in net for net in documentation) for ip in addresses)


def test_suspicious_option_includes_at_least_the_noteworthy_rows(client):
    noteworthy = _csv_rows(client.get("/export.csv").text)
    suspicious = _csv_rows(client.get("/export.csv", params={"min": "suspicious"}).text)
    assert len(suspicious) >= len(noteworthy) >= 2
    assert (
        client.get("/export.csv", params={"min": "noteworthy"}).text
        == client.get("/export.csv").text
    )


def test_downloads_are_still_served_in_judge_mode(client):
    client.post("/config", data={"judge_mode": "true"})
    assert client.get("/").text.count("Judge mode") >= 1
    for path in DOWNLOADS:
        assert client.get(path).status_code == 200, path
    client.post("/config", data={"judge_mode": "false"})


# Formula neutralisation


def test_csv_download_neutralises_formula_cells(formula_store, clean_env):
    client = TestClient(create_app(formula_store["db"], formula_store["logs"]))
    client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    rows = _csv_rows(client.get("/export.csv", params={"min": "suspicious"}).text)
    agents = [row[1] for row in rows[1:] if row[0] == "user-agent"]
    assert agents, "the formula visitor's user agent is exported"
    for value in agents:
        assert not value.startswith("=")
    assert '\'=HYPERLINK("http://203.0.113.9/x","open")' in agents


# Empty and missing stores


def test_empty_store_gives_valid_empty_downloads(tmp_path, clean_env):
    path = tmp_path / "empty.db"
    db.connect(path).close()
    client = TestClient(create_app(path, tmp_path / "logs"))
    client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert client.get("/export.csv").text == ",".join(CSV_COLUMNS) + "\n"
    bundle = json.loads(client.get("/export.json").text)
    assert [o["type"] for o in bundle["objects"]] == ["identity"]
    lines = client.get("/export.txt").text.splitlines()
    assert lines[0].startswith("# generated ")
    assert not [line for line in lines[1:] if not line.startswith("#")]
    assert client.get("/export").status_code == 200


def test_missing_store_is_503_and_is_not_created(tmp_path, clean_env):
    missing = tmp_path / "absent" / "qlure.db"
    client = TestClient(create_app(missing, tmp_path / "logs"))
    client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    for path in DOWNLOADS:
        r = client.get(path)
        assert r.status_code == 503, path
        assert str(tmp_path) not in r.text
    assert not missing.exists()
