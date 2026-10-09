"""/download mirrors the SSH shell's root-only rule but still serves honeytoken files."""

import pytest
from fastapi.testclient import TestClient

from decoys.web.app import app

CLIENT = ("198.51.100.9", 40404)


@pytest.mark.parametrize(
    "name",
    [
        "/etc/shadow",
        "../../../etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/root/.bash_history",
        "/root",
        "..%2f..%2froot/x",
    ],
)
def test_root_only_files_are_forbidden(log_dir, name):
    resp = TestClient(app, client=CLIENT).get("/download", params={"file": name})
    assert resp.status_code in (403, 404)
    assert "root:" not in resp.text


def test_shadow_is_403(log_dir):
    resp = TestClient(app, client=CLIENT).get("/download", params={"file": "/etc/shadow"})
    assert resp.status_code == 403


def test_honeytoken_file_is_still_served(log_dir):
    resp = TestClient(app, client=CLIENT).get("/download", params={"file": "app/config.yaml"})
    assert resp.status_code == 200 and resp.text
