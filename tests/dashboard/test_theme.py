"""Light and dark themes: the toggle on every page, the script that drives it, and the CSS sets."""

import re

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app

PASSWORD = "test-password"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    return create_app(db_path=tmp_path / "qlure.db", logs_dir=tmp_path / "logs")


@pytest.fixture
def client(app):
    c = TestClient(app)
    c.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    return c


def _assert_toggle(html):
    assert "data-theme-toggle" in html
    assert 'aria-pressed="false"' in html
    assert "Dark mode" in html


def test_login_page_has_toggle_and_theme_script(app):
    r = TestClient(app).get("/login")
    assert r.status_code == 200
    _assert_toggle(r.text)
    assert '<script src="/static/theme.js"></script>' in r.text


def test_authenticated_page_has_toggle_and_theme_script(client):
    r = client.get("/config")
    assert r.status_code == 200
    _assert_toggle(r.text)
    assert '<script src="/static/theme.js"></script>' in r.text


def test_theme_script_loads_before_stylesheet_and_not_deferred(client):
    html = client.get("/config").text
    script = html.index('<script src="/static/theme.js"></script>')
    sheet = html.index('<link rel="stylesheet" href="/static/app.css">')
    assert script < sheet
    assert 'theme.js" defer' not in html


def test_colour_scheme_meta_present(client):
    assert '<meta name="color-scheme" content="light dark">' in client.get("/config").text


def test_theme_script_is_served(app):
    r = TestClient(app).get("/static/theme.js")
    assert r.status_code == 200
    assert "data-theme" in r.text
    assert "localStorage" in r.text
    assert "<script" not in r.text


def test_stylesheet_has_light_and_dark_sets(app):
    css = TestClient(app).get("/static/app.css").text
    # Light values sit on :root; dark values follow the system and the explicit attribute.
    assert re.search(r":root\s*\{[^}]*--bg:\s*#f2f2f2", css)
    assert "@media (prefers-color-scheme: dark)" in css
    assert ':root:not([data-theme="light"])' in css
    assert ':root[data-theme="dark"]' in css
    assert re.search(r":root\[data-theme=\"dark\"\]\s*\{[^}]*--bg:\s*#000000", css)
    for name in ("--bg", "--text", "--panel", "--line", "--muted", "--bad", "--warn", "--good"):
        assert f"{name}:" in css


def test_stylesheet_has_no_hard_coded_colours_outside_variables(app):
    css = TestClient(app).get("/static/app.css").text
    # Only the variable sets and the print block (paper is always light) may name a colour.
    in_print = False
    for line in css.splitlines():
        if line.startswith("@media print"):
            in_print = True
        elif in_print and line == "}":
            in_print = False
        if in_print:
            continue
        stripped = re.sub(r"--[\w-]+:[^;}]*;?", "", line)
        assert not re.search(r"#[0-9a-fA-F]{3,6}\b", stripped), line


def test_csp_unchanged(client):
    r = client.get("/config")
    assert r.headers["content-security-policy"] == CSP
    assert "unsafe-inline" not in r.headers["content-security-policy"]
