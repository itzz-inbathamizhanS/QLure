"""Layout fixes on the overview table and the ATT&CK matrix: CSS string checks on /static/app.css
and rendered-page checks on seeded sample data. No browser is needed for these; the widths are
reasoned about in the stylesheet comments."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard import data
from dashboard.app import create_app
from qlure.store import db

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "test-password"
TACTIC_HEADINGS = [
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
]


def _load_seed():
    spec = importlib.util.spec_from_file_location("seed_demo", ROOT / "tools" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed_demo = _load_seed()


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    root = tmp_path_factory.mktemp("layout-seed")
    db_path, logs = root / "demo.db", root / "logs"
    assert seed_demo.main(["--db", str(db_path), "--logs", str(logs)]) == 0
    return {"db": db_path, "logs": logs}


@pytest.fixture
def client(seeded, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    monkeypatch.delenv("QLURE_METRICS_PUBLIC", raising=False)
    c = TestClient(create_app(seeded["db"], seeded["logs"]))
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return c


@pytest.fixture(scope="module")
def css(seeded):
    client = TestClient(create_app(seeded["db"], seeded["logs"]))
    response = client.get("/static/app.css")
    assert response.status_code == 200
    return response.text


def _rule(css_text, selector):
    """The declaration block of a top-level rule such as `.matrix { ... }`."""
    match = re.search(r"^" + re.escape(selector) + r" \{([^}]*)\}", css_text, re.M)
    assert match, f"no rule for {selector}"
    return match.group(1)


def _media_blocks(css_text, query):
    """Every `@media <query> { ... }` block in the stylesheet, braces matched."""
    blocks = []
    for match in re.finditer(re.escape(f"@media {query}"), css_text):
        depth = 0
        for i in range(css_text.index("{", match.start()), len(css_text)):
            if css_text[i] == "{":
                depth += 1
            elif css_text[i] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(css_text[match.start() : i + 1])
                    break
    return blocks


# ---------- defect 1: the overview table ----------


def test_truncated_agent_is_narrower(css):
    assert "max-width: 160px" in _rule(css, ".trunc")


def test_rule_and_technique_chips_wrap_inside_the_table(css):
    chips = _rule(css, "td .chips")
    assert "flex-wrap: wrap" in chips and "max-width: 200px" in chips
    assert "white-space: normal" in _rule(css, "td .chips .chip")


def test_started_cell_is_nowrap_with_a_minimum_width(css):
    assert "white-space: nowrap" in _rule(css, ".started-cell")
    assert "min-width: 11.5em" in _rule(css, ".started-when")


def test_table_wrap_has_a_scroll_hint_built_from_theme_variables(css):
    rule = _rule(css, ".table-wrap")
    assert "overflow-x: auto" in rule
    assert "local" in rule and "scroll" in rule
    assert "var(--panel)" in rule and "color-mix(in srgb, var(--text)" in rule
    # Theme variables only: no literal colours in the hint.
    assert "#" not in rule and not re.search(r"(?<![a-z])rgba?\(", rule)


def test_the_overview_started_column_is_marked_up(client):
    html = client.get("/").text
    assert 'class="table-wrap"' in html
    assert 'class="started-cell"' in html and 'class="mono started-when"' in html


# ---------- defect 2: the ATT&CK matrix ----------


def test_the_matrix_wraps_by_rows_instead_of_a_fixed_twelve_columns(css):
    rule = _rule(css, ".matrix")
    assert "repeat(auto-fill, minmax(150px, 1fr))" in rule
    assert "repeat(12" not in rule
    assert "overflow-x" not in rule


def test_the_matrix_has_no_horizontal_scroll_wrapper(css):
    assert ".matrix-scroll" not in css
    assert "overflow-x: visible" not in css


def test_the_single_column_fallback_stays_at_860px(css):
    assert any(
        ".matrix { grid-template-columns: minmax(0, 1fr); }" in block
        for block in _media_blocks(css, "(max-width: 860px)")
    )


def test_the_matrix_page_has_no_scroll_wrapper_and_keeps_the_grid(client):
    html = client.get("/attack").text
    assert "matrix-scroll" not in html
    assert '<div class="matrix">' in html


def test_all_twelve_tactics_render_in_kill_chain_order(client):
    html = client.get("/attack").text
    positions = []
    for number, name in enumerate(TACTIC_HEADINGS, start=1):
        heading = f'<h3 id="tactic-{number}" class="tactic-name">{name}</h3>'
        assert heading in html, name
        positions.append(html.index(heading))
    assert positions == sorted(positions)


def test_the_tactic_list_matches_the_data_module():
    assert list(data.ATTACK_TACTICS) == TACTIC_HEADINGS


def test_unseen_cells_stay_dimmed_and_labelled(client):
    html = client.get("/attack").text
    assert 'class="cell unseen"' in html and "not seen" in html


def test_seen_cells_still_link_to_sessions(client, seeded):
    html = client.get("/attack").text
    links = re.findall(r'class="cell seen" href="/session/([^"]+)"', html)
    assert links
    conn = db.connect(seeded["db"])
    known = {r["session_id"] for r in data.list_findings(conn, {})}
    assert set(links) <= known
