"""Sessions, actors, the kill chain, explanations and storage, on events from the real decoys."""

from helpers import FIREFOX, banner_visits, finding_for, hits_of, run, ssh_with_honeytoken, web

from qlure.correlate import store as correlate_store
from qlure.correlate.engine import correlate
from qlure.correlate.explain import explain
from qlure.events import Service
from qlure.store import db, forwarder

ATTACKER = "198.51.100.200"


def _attack():
    """Recon, then password guessing, then the planted login found in a backup file."""
    scanner = web(ATTACKER, agent="Nikto/2.5.0")
    scanner.get("/wp-login.php")
    scanner.get("/phpmyadmin/")
    for i in range(6):
        scanner.post("/login", data={"username": "ops", "password": f"guess-{i}"})
    scanner.get("/backup/config.bak")
    ssh_with_honeytoken(ATTACKER, ["whoami", "id", "ls", "cat ~/.bash_history"])


def test_same_ip_alone_never_merges_sessions(read_events):
    web("198.51.100.210", agent=FIREFOX).get("/login")
    web("198.51.100.210", agent="Mozilla/5.0 (Macintosh) Safari/17").get("/login")
    result = run(read_events)
    assert len(result.sessions) == 2
    assert len(result.actors) == 2


def test_cookie_keeps_one_session_and_gaps_split_sessions(read_events):
    client = web("198.51.100.211")
    client.get("/login")
    client.get("/login")
    result = run(read_events)
    assert len(result.sessions) == 1

    events = [e for e in read_events("web")]
    from datetime import timedelta

    late = events[-1].model_copy(
        update={
            "event_id": "late-event-0001",
            "session_id": "another-cookie-9999",
            "replay_ts": events[-1].ts + timedelta(minutes=11),
        }
    )
    assert len(correlate(events + [late]).sessions) == 2  # 11 minutes later: new session


def test_kill_chain_links_web_and_ssh_into_one_noteworthy_actor(read_events):
    _attack()
    result = run(read_events)
    mine = [f for f in result.findings if f.session.src_ip == ATTACKER]
    assert {f.session.service for f in mine} == {"web", "ssh"}
    assert len({f.actor_id for f in mine}) == 1  # the planted password linked them

    web_finding = next(f for f in mine if f.session.service == "web")
    ssh_finding = next(f for f in mine if f.session.service == "ssh")
    assert {"R2", "R3", "R6", "R9", "R10"} <= hits_of(web_finding)
    assert {"R7", "R8", "R10"} <= hits_of(ssh_finding)
    assert ssh_finding.verdict == "Noteworthy"
    assert web_finding.verdict == "Noteworthy"


def test_explanations_name_rule_threshold_value_and_evidence(read_events):
    _attack()
    result = run(read_events)
    event_ids = {e.event_id for s in result.sessions for e in s.events}
    for finding in result.findings:
        if finding.verdict == "Benign":
            continue
        text = finding.explanation
        for hit in finding.hits:
            assert hit.rule_id in text
            assert hit.threshold in text
            assert hit.measured in text
            assert hit.evidence[0] in text
            assert set(hit.evidence) <= event_ids


def test_same_input_always_gives_the_same_explanation(read_events):
    _attack()
    events = []
    for service in Service:
        events += read_events(service.value)
    first = [f.explanation for f in correlate(events).findings]
    second = [f.explanation for f in correlate(list(reversed(events))).findings]
    assert first == second
    assert first == [explain(f) for f in correlate(events).findings]


def test_service_sweep_from_one_ip_is_one_actor(read_events):
    banner_visits("198.51.100.220", [Service.FTP, Service.MYSQL, Service.REDIS])
    result = run(read_events)
    assert len(result.actors) == 1
    assert len(result.actors[0].sessions) == 3


def test_actor_score_promotes_a_thin_session_but_never_a_clean_bystander(read_events):
    """A single probe is thin alone but belongs to the same actor as a loud scanner;
    a stranger who merely reused the same guessed password must not be swept up."""
    scanner = web("198.51.100.231", agent="Nikto/2.5.0")
    for i in range(6):
        scanner.post("/login", data={"username": "ops", "password": f"guess-{i}"})
    scanner.get("/backup/config.bak")

    probe = web("198.51.100.232", agent=FIREFOX)
    probe.post("/login", data={"username": "ops", "password": "guess-0"})
    probe.get("/wp-login.php")

    bystander = web("198.51.100.233", agent="Safari/17")
    bystander.post("/login", data={"username": "ops", "password": "guess-0"})

    result = run(read_events)
    scanner_f = finding_for(result, "198.51.100.231", "web")
    probe_f = finding_for(result, "198.51.100.232", "web")
    bystander_f = finding_for(result, "198.51.100.233", "web")

    assert scanner_f.actor_id == probe_f.actor_id == bystander_f.actor_id  # linked by the password

    assert scanner_f.verdict == "Noteworthy"  # loud on its own

    assert probe_f.hits  # R2: a known scanner path was requested
    assert probe_f.verdict != "Noteworthy"  # thin alone
    assert probe_f.effective_verdict == "Noteworthy"  # but the actor's evidence is clear
    assert probe_f.score != probe_f.actor_score  # the session's own score is untouched

    assert not bystander_f.hits  # one ordinary failed login fires no rule at all
    assert bystander_f.verdict == "Benign"
    assert bystander_f.effective_verdict == "Benign"  # never promoted by a bystander link alone


def test_findings_are_stored_and_queryable(read_events, log_dir, tmp_path):
    _attack()
    conn = db.connect(tmp_path / "q.db")
    forwarder.forward_once(conn, log_dir)
    result = correlate_store.run(conn)

    rows = conn.execute("SELECT * FROM findings ORDER BY score DESC").fetchall()
    assert len(rows) == len(result.findings)
    top = rows[0]
    assert top["verdict"] == "Noteworthy"
    assert "R7" in top["rule_ids"] or "R3" in top["rule_ids"]
    stored_ids = {r["event_id"] for r in conn.execute("SELECT event_id FROM events")}
    for row in rows:
        import json

        for hit in json.loads(row["hits"]):
            assert set(hit["evidence"]) <= stored_ids
    assert conn.execute("SELECT COUNT(*) FROM actors").fetchone()[0] == len(result.actors)
