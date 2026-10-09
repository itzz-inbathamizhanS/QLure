"""P3.2 ATT&CK matrix: the static table against rules.yaml, the cells for seeded techniques,
the links, the dimmed unseen cells, and escaping."""

import json
import re

import pytest
from fastapi.testclient import TestClient

from dashboard import data
from dashboard.app import create_app
from decoys.web.app import app as web_app
from qlure.correlate import store as correlate_store
from qlure.correlate.rules import load_config
from qlure.store import db, forwarder

PASSWORD = "test-password"
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _visit(ip, agent, paths):
    client = TestClient(web_app, client=(ip, 40404))
    client.headers["user-agent"] = agent
    for path in paths:
        client.get(path)


def _ids_in(node):
    """Every technique id anywhere in a loaded rules.yaml structure."""
    if isinstance(node, dict):
        return {i for v in node.values() for i in _ids_in(v)}
    if isinstance(node, list | tuple):
        return {i for v in node for i in _ids_in(v)}
    return {node} if isinstance(node, str) and TECHNIQUE.match(node) else set()


@pytest.fixture(autouse=True)
def _rule_config(monkeypatch):
    load_config.cache_clear()
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    yield
    load_config.cache_clear()


@pytest.fixture
def store(tmp_path, log_dir):
    # A scanner that probes and runs an injection (T1190), and a brute forcer (T1110.001).
    _visit(
        "198.51.100.77",
        "Nikto/2.5.0",
        ["/wp-login.php", "/phpmyadmin/", "/search?q=1' union select 1,2--"],
    )
    brute = TestClient(web_app, client=("198.51.100.90", 40404))
    brute.headers["user-agent"] = "Mozilla/5.0 Firefox/131.0"
    for i in range(6):
        brute.post("/login", data={"username": "ops", "password": f"guess-{i}"})
    db_path = tmp_path / "qlure.db"
    conn = db.connect(db_path)
    forwarder.forward_once(conn, log_dir)
    correlate_store.run(conn)
    conn.close()
    return db_path


@pytest.fixture
def client(store, tmp_path, log_dir):
    app = create_app(store, log_dir)
    c = TestClient(app, base_url="http://testserver")
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return c


def _cell(matrix, tid):
    return next(c for col in matrix["columns"] for c in col["cells"] if c["id"] == tid)


# ---------- the table agrees with the rules ----------


def test_every_technique_the_rules_emit_is_in_the_table():
    config = load_config()
    emitted = _ids_in(config["rules"]) | _ids_in(config["technique_map"])
    assert emitted, "rules.yaml should name at least one technique"
    assert emitted <= set(data.ATTACK_TECHNIQUES)


def test_every_table_row_is_in_a_known_tactic_column():
    assert all(tactic in data.ATTACK_TACTICS for tactic, _ in data.ATTACK_TECHNIQUES.values())
    assert all(TECHNIQUE.match(tid) for tid in data.ATTACK_TECHNIQUES)


def test_the_matrix_has_the_twelve_columns_in_order():
    assert data.ATTACK_TACTICS == (
        "Reconnaissance",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Exfiltration",
        "Command and Control",
        "Impact",
    )


# ---------- cells for seeded techniques ----------


def test_seen_techniques_count_hits_and_sessions(store):
    conn = db.connect(store)
    matrix = data.attack_matrix(conn)
    probe = _cell(matrix, "T1595.002")  # the scanner's user agent (R6)
    assert probe["hits"] >= 1 and probe["sessions"] >= 1
    brute = _cell(matrix, "T1110.001")  # the brute forcer (R3)
    assert brute["hits"] >= 1
    injection = _cell(matrix, "T1190")  # the union select (R5)
    assert injection["hits"] >= 1
    assert matrix["seen"] >= 3
    assert matrix["other"] == []


def test_a_seen_cell_links_to_its_highest_scoring_session(store):
    conn = db.connect(store)
    rows = data.list_findings(conn, {})
    expected = max(
        (r for r in rows if "T1190" in r["techniques"]), key=lambda r: (r["score"], r["first_seen"])
    )
    cell = _cell(data.attack_matrix(conn), "T1190")
    assert cell["first_session"] == expected["session_id"]


def test_the_page_shows_each_seen_cell_with_id_name_and_counts(client, store):
    html = client.get("/attack").text
    assert 'class="cell seen" href="/session/' in html
    assert "T1190" in html and "Exploit Public-Facing Application" in html
    assert re.search(r"seen: \d+ hits?, \d+ sessions?", html)
    # The injection lands under Initial Access, not under a column it does not belong to.
    initial = html.index('id="tactic-2"')
    execution = html.index('id="tactic-3"')
    assert initial < html.index("T1190") < execution


def test_unseen_cells_are_dimmed_and_say_they_are_not_seen(client):
    html = client.get("/attack").text
    assert 'class="cell unseen"' in html
    assert "not seen" in html
    assert "Impact" in html and "T1485" in html


def test_seen_cells_link_to_a_session_that_exists(client, store):
    html = client.get("/attack").text
    links = re.findall(r'class="cell seen" href="/session/([^"]+)"', html)
    assert links
    conn = db.connect(store)
    known = {r["session_id"] for r in data.list_findings(conn, {})}
    assert set(links) <= known


def test_the_matrix_is_linked_from_the_nav(client):
    assert 'href="/attack"' in client.get("/").text


def test_matrix_page_needs_a_login(store, log_dir):
    anonymous = TestClient(create_app(store, log_dir))
    response = anonymous.get("/attack", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


# ---------- escaping: a technique id from the store is text, never markup ----------


def test_an_unmapped_technique_id_from_the_store_is_escaped(client, store):
    conn = db.connect(store)
    row = conn.execute("SELECT session_id, hits FROM findings LIMIT 1").fetchone()
    hits = data._loads(row["hits"], [])
    hits[0]["attack"] = ["<script>alert(1)</script>"]
    conn.execute(
        "UPDATE findings SET hits=? WHERE session_id=?", (json.dumps(hits), row["session_id"])
    )
    conn.commit()
    html = client.get("/attack").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)" not in html
    assert "Seen, but not in the matrix table" in html
