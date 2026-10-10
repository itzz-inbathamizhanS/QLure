"""The hosted-demo blueprint and the script that turns judge mode on after the seed."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from qlure.store import db
from qlure.store.verify import verify, verify_config

ROOT = Path(__file__).resolve().parents[2]
RENDER = ROOT / "render.yaml"
SECRET_NAME = re.compile(r"PASSWORD|SECRET|TOKEN|KEY", re.I)
SECRET_VALUE = re.compile(
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|-----BEGIN|xox[bp]-|rnd_[A-Za-z0-9]{10,}"
)


@pytest.fixture(scope="module")
def blueprint() -> dict:
    return yaml.safe_load(RENDER.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def service(blueprint) -> dict:
    assert len(blueprint["services"]) == 1
    return blueprint["services"][0]


def test_service_shape(service):
    assert service["name"] == "qlure-demo"
    assert service["type"] == "web"
    assert service["runtime"] == "python"
    assert service["plan"] == "free"
    assert service["region"] == "oregon"
    assert service["branch"] == "main"
    assert service["autoDeploy"] is True
    assert service["healthCheckPath"] == "/healthz"
    assert service["startCommand"] == (
        "python -m uvicorn dashboard.app:app --host 0.0.0.0 --port $PORT"
    )


def test_build_command(service):
    steps = [s.strip() for s in service["buildCommand"].split("&&")]
    assert steps[0] == 'pip install -e ".[decoys,dashboard]"'
    assert "tools/seed_demo.py --db data/demo.db --logs data/demo-logs --force" in steps[1]
    assert (
        "tools/prepare_hosted_demo.py --db data/demo.db --settings data/settings.json" in steps[2]
    )
    assert len(steps) == 3
    for step in steps[1:]:
        assert (ROOT / shlex.split(step)[1]).is_file()


def test_env_vars(service):
    env = {item["key"]: item for item in service["envVars"]}
    assert re.fullmatch(r"3\.12\.\d+", str(env["PYTHON_VERSION"]["value"]))
    expected = {
        "QLURE_DB": "data/demo.db",
        "QLURE_LOGS": "data/demo-logs",
        "QLURE_SETTINGS": "data/settings.json",
        "QLURE_LIVE": "0",
        "QLURE_COOKIE_SECURE": "1",
    }
    for key, value in expected.items():
        assert env[key]["value"] == value
    for key in ("QLURE_DASHBOARD_PASSWORD", "QLURE_DASHBOARD_SECRET"):
        assert env[key] == {"key": key, "generateValue": True}


def test_no_literal_secrets(service):
    for item in service["envVars"]:
        if SECRET_NAME.search(item["key"]):
            assert item.get("generateValue") is True
            assert "value" not in item
    assert not SECRET_VALUE.search(RENDER.read_text(encoding="utf-8"))


def _run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "tools" / script), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.fixture(scope="module")
def seeded(tmp_path_factory) -> dict[str, Path]:
    base = tmp_path_factory.mktemp("hosted")
    paths = {
        "db": base / "data" / "demo.db",
        "logs": base / "data" / "demo-logs",
        "settings": base / "data" / "settings.json",
    }
    seed = _run("seed_demo.py", "--db", str(paths["db"]), "--logs", str(paths["logs"]), "--force")
    assert seed.returncode == 0, seed.stderr
    return paths


def test_prepare_enables_judge_mode_audited_and_is_idempotent(seeded):
    db_path, settings = seeded["db"], seeded["settings"]
    args = ("--db", str(db_path), "--settings", str(settings))

    first = _run("prepare_hosted_demo.py", *args)
    assert first.returncode == 0, first.stderr
    assert len(first.stdout.strip().splitlines()) == 1
    assert json.loads(settings.read_text(encoding="utf-8"))["judge_mode"] is True

    conn = db.connect(db_path)
    try:
        rows = conn.execute("SELECT who, key, outcome FROM config_audit").fetchall()
        assert [(r["who"], r["key"], r["outcome"]) for r in rows] == [
            ("deploy-script", "judge_mode", "applied")
        ]
        checked, problem = verify(conn, seeded["logs"])
        assert problem is None and checked > 0
        config_checked, _, config_problem = verify_config(conn)
        assert config_problem is None and config_checked == 1
    finally:
        conn.close()

    before = settings.read_bytes()
    second = _run("prepare_hosted_demo.py", *args)
    assert second.returncode == 0, second.stderr
    assert settings.read_bytes() == before
    conn = db.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM config_audit").fetchone()[0] == 1
    finally:
        conn.close()

    cli = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "qlure.cli", "verify", "--logs", str(seeded["logs"]),
         "--db", str(db_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )  # fmt: skip
    assert cli.returncode == 0, cli.stderr


def test_missing_db_exits_2(tmp_path):
    result = _run(
        "prepare_hosted_demo.py",
        "--db", str(tmp_path / "nope.db"),
        "--settings", str(tmp_path / "settings.json"),
    )  # fmt: skip
    assert result.returncode == 2
    assert "does not exist" in result.stderr
    assert not (tmp_path / "nope.db").exists()
    assert not (tmp_path / "settings.json").exists()
