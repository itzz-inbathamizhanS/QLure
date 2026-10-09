"""The IOC export: read-only, three formats, no plaintext credentials, stable STIX output."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import re
import sqlite3
import uuid
from collections import Counter
from pathlib import Path

import pytest

from decoys import honeytokens
from qlure import export as ioc_export
from qlure.cli import main as cli
from qlure.store import db

ROOT = Path(__file__).resolve().parents[1]
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
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
PATTERN = re.compile(r"^\[(ipv4-addr:value|ipv6-addr:value|file:hashes\.'SHA-256') = '[^']+'\]$")
VISITOR_IP = "198.51.100.77"


def _load_seed():
    spec = importlib.util.spec_from_file_location("seed_demo", ROOT / "tools" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed_demo = _load_seed()


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    root = tmp_path_factory.mktemp("export")
    db_path, logs = root / "demo.db", root / "logs"
    assert seed_demo.main(["--db", str(db_path), "--logs", str(logs)]) == 0
    return db_path


def _csv_rows(text: str) -> list[list[str]]:
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == CSV_COLUMNS
    return rows[1:]


def conn_rows(db_path: Path, sql: str) -> list[str]:
    conn = sqlite3.connect(db_path)
    try:
        return [row[0] for row in conn.execute(sql)]
    finally:
        conn.close()


def _passwords(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        raws = [row[0] for row in conn.execute("SELECT raw FROM events")]
    finally:
        conn.close()
    found = set()
    for raw in raws:
        credential = json.loads(raw).get("credential") or {}
        if credential.get("password"):
            found.add(credential["password"])
    return found


def _check_stix(bundle: dict) -> Counter:
    """Hand-written STIX 2.1 shape check: the properties every object needs, and references."""
    assert bundle["type"] == "bundle"
    assert re.fullmatch(rf"bundle--{UUID}", bundle["id"])
    objects = bundle["objects"]
    ids = {obj["id"] for obj in objects}
    assert len(ids) == len(objects), "object ids must be unique"
    for obj in objects:
        assert obj["spec_version"] == "2.1"
        kind = obj["type"]
        assert re.fullmatch(rf"{re.escape(kind)}--{UUID}", obj["id"]), obj["id"]
        assert TIMESTAMP.match(obj["created"]) and TIMESTAMP.match(obj["modified"])
        assert obj["created"] <= obj["modified"]
        if kind == "identity":
            assert obj["name"] == "QLure"
        if kind == "indicator":
            assert obj["pattern_type"] == "stix"
            assert PATTERN.match(obj["pattern"]), obj["pattern"]
            assert TIMESTAMP.match(obj["valid_from"])
            assert obj["labels"]
            assert 0 <= obj["confidence"] <= 100
            assert obj["created_by_ref"] in ids
        if kind == "relationship":
            assert obj["relationship_type"] == "indicates"
            assert obj["source_ref"] in ids and obj["target_ref"] in ids
        if kind == "attack-pattern":
            [ref] = obj["external_references"]
            assert ref["source_name"] == "mitre-attack"
            assert ref["external_id"].startswith("T")
    return Counter(obj["type"] for obj in objects)


def test_csv_has_the_documented_columns_and_one_row_per_indicator(seeded, capsys):
    assert (
        cli(["export", "--db", str(seeded), "--format", "csv", "--min-verdict", "suspicious"]) == 0
    )
    rows = _csv_rows(capsys.readouterr().out)
    assert rows
    kinds = {row[0] for row in rows}
    assert kinds <= {
        "ipv4",
        "ipv6",
        "url-path",
        "user-agent",
        "credential-hash",
        "honeytoken-id",
        "sha256",
    }
    assert {"ipv4", "credential-hash", "honeytoken-id", "url-path"} <= kinds
    keys = [(row[0], row[1]) for row in rows]
    assert len(keys) == len(set(keys)), "one row per indicator"
    assert keys == sorted(keys)
    for row in rows:
        assert len(row) == len(CSV_COLUMNS)
        assert TIMESTAMP.match(row[2]) and TIMESTAMP.match(row[3])
        assert int(row[4]) >= 1
        assert row[6] in {"Suspicious", "Noteworthy"}


def test_csv_never_holds_a_plaintext_password_or_honeytoken_secret(seeded, capsys):
    passwords = _passwords(seeded)
    assert passwords, "the seed should contain login attempts"
    assert (
        cli(["export", "--db", str(seeded), "--format", "csv", "--min-verdict", "suspicious"]) == 0
    )
    out = capsys.readouterr().out
    rows = _csv_rows(out)
    hashes = {hashlib.sha256(p.encode()).hexdigest() for p in passwords}
    credential_rows = [row for row in rows if row[0] == "credential-hash"]
    assert credential_rows
    for row in credential_rows:
        assert re.fullmatch(r"[0-9a-f]{64}", row[1])
        assert row[1] in hashes
    for row in rows:
        for cell in row:
            assert cell not in passwords
    for token in honeytokens.load().values():
        for field_name in ("value", "secret"):
            secret = str(token.get(field_name) or "")
            if secret and "\n" not in secret:
                assert secret not in out, f"{token['id']} {field_name} leaked"


def test_csv_honeytoken_rows_carry_only_the_id(seeded, capsys):
    assert (
        cli(["export", "--db", str(seeded), "--format", "csv", "--min-verdict", "suspicious"]) == 0
    )
    rows = _csv_rows(capsys.readouterr().out)
    ids = [row[1] for row in rows if row[0] == "honeytoken-id"]
    assert ids and all(i.startswith("ht-") for i in ids)
    assert "ht-ssh-001" in ids


def test_blocklist_is_sorted_unique_and_documented(seeded, capsys):
    assert cli(["export", "--db", str(seeded), "--format", "blocklist"]) == 0
    lines = capsys.readouterr().out.splitlines()
    header = [line for line in lines if line.startswith("#")]
    ips = [line for line in lines if line and not line.startswith("#")]
    assert header[0].startswith("# generated ")
    assert "by QLure (decoy-observed, review before blocking)" in header[0]
    assert "private" in header[1] and "documentation ranges are kept" in header[1]
    assert ips == sorted(set(ips), key=lambda ip: (":" in ip, ip))
    assert VISITOR_IP in ips
    assert not [ip for ip in ips if ip.startswith(("127.", "10.", "192.168.", "169.254."))]


def test_blocklist_skips_loopback_link_local_and_private(seeded, tmp_path, capsys):
    copy = tmp_path / "copy.db"
    copy.write_bytes(seeded.read_bytes())
    conn = sqlite3.connect(copy)
    noteworthy = [
        sid
        for (sid,) in conn.execute(
            "SELECT session_id FROM findings WHERE verdict = 'Noteworthy' ORDER BY session_id"
        )
    ]
    odd = ["10.1.2.3", "127.0.0.1", "169.254.9.9"]
    assert len(noteworthy) >= len(odd)
    for ip, sid in zip(odd, noteworthy, strict=False):
        conn.execute("UPDATE sessions SET src_ip = ? WHERE session_id = ?", (ip, sid))
    conn.commit()
    conn.close()
    assert cli(["export", "--db", str(copy), "--format", "blocklist"]) == 0
    out = capsys.readouterr().out
    assert not [ip for ip in odd if ip in out]
    still_noteworthy = conn_rows(
        copy,
        "SELECT DISTINCT s.src_ip FROM sessions s JOIN findings f USING (session_id)"
        " WHERE f.verdict = 'Noteworthy'",
    )
    documentation = [ip for ip in still_noteworthy if ip not in odd]
    assert documentation and all(ip in out for ip in documentation)  # documentation ranges stay


def test_blocklist_min_verdict_filters_sessions(seeded, capsys):
    scanner = "198.51.100.23"  # a Suspicious actor in the seed
    assert cli(["export", "--db", str(seeded), "--format", "blocklist"]) == 0
    noteworthy = capsys.readouterr().out
    assert scanner not in noteworthy
    assert (
        cli(["export", "--db", str(seeded), "--format", "blocklist", "--min-verdict", "suspicious"])
        == 0
    )
    assert scanner in capsys.readouterr().out


def test_csv_min_verdict_filters_rows(seeded, capsys):
    assert cli(["export", "--db", str(seeded), "--format", "csv"]) == 0
    strict = _csv_rows(capsys.readouterr().out)
    assert {row[6] for row in strict} == {"Noteworthy"}
    assert (
        cli(["export", "--db", str(seeded), "--format", "csv", "--min-verdict", "suspicious"]) == 0
    )
    loose = _csv_rows(capsys.readouterr().out)
    assert {row[6] for row in loose} >= {"Suspicious", "Noteworthy"}
    assert {(r[0], r[1]) for r in strict} <= {(r[0], r[1]) for r in loose}


def test_stix_bundle_has_the_required_shape(seeded, tmp_path, capsys):
    out = tmp_path / "bundle.json"
    assert cli(["export", "--db", str(seeded), "--format", "stix", "--out", str(out)]) == 0
    bundle = json.loads(out.read_text(encoding="utf-8"))
    counts = _check_stix(bundle)
    assert counts["identity"] == 1
    assert counts["indicator"] >= 1
    assert counts["attack-pattern"] >= 1
    assert counts["relationship"] >= counts["indicator"]
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert f"[ipv4-addr:value = '{VISITOR_IP}']" in patterns
    techniques = {
        o["external_references"][0]["external_id"]
        for o in bundle["objects"]
        if o["type"] == "attack-pattern"
    }
    assert "T1552.001" in techniques
    assert "wrote" in capsys.readouterr().out


def test_stix_output_is_identical_across_runs(seeded, tmp_path):
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    assert cli(["export", "--db", str(seeded), "--format", "stix", "--out", str(first)]) == 0
    assert cli(["export", "--db", str(seeded), "--format", "stix", "--out", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()


def test_stix_prints_a_valid_bundle_to_stdout(seeded, capsys):
    assert cli(["export", "--db", str(seeded), "--format", "stix"]) == 0
    assert _check_stix(json.loads(capsys.readouterr().out))["indicator"] >= 1


def test_empty_database_gives_valid_empty_output(tmp_path, capsys):
    empty = tmp_path / "empty.db"
    db.connect(empty).close()
    assert cli(["export", "--db", str(empty), "--format", "csv"]) == 0
    assert _csv_rows(capsys.readouterr().out) == []
    assert cli(["export", "--db", str(empty), "--format", "blocklist"]) == 0
    assert [ln for ln in capsys.readouterr().out.splitlines() if not ln.startswith("#")] == []
    assert cli(["export", "--db", str(empty), "--format", "stix"]) == 0
    bundle = json.loads(capsys.readouterr().out)
    assert _check_stix(bundle) == Counter({"identity": 1})
    assert uuid.UUID(bundle["objects"][0]["id"].split("--")[1]).version == 5


def test_missing_database_is_a_clear_error(tmp_path, capsys):
    missing = tmp_path / "nope.db"
    assert cli(["export", "--db", str(missing), "--format", "csv"]) == 1
    assert "database not found" in capsys.readouterr().err
    assert not missing.exists()


def test_export_never_writes_to_the_database(seeded, tmp_path):
    before = seeded.read_bytes()
    for fmt in ("csv", "blocklist", "stix"):
        assert ioc_export.render(seeded, fmt, "suspicious")
    assert seeded.read_bytes() == before
    conn = ioc_export._open(seeded)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM events")
    finally:
        conn.close()


def test_export_help_lists_the_formats(capsys):
    with pytest.raises(SystemExit) as exc:
        cli(["export", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert "--format" in text and "stix" in text and "--min-verdict" in text
