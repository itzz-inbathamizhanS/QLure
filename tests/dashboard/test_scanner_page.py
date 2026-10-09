"""The domain scanner page: login required, and the Q-CAPS guardrails hold through the page."""

import copy
import json
import re

import pytest
from fastapi.testclient import TestClient

from dashboard import scanning
from dashboard.app import create_app
from dashboard.report import scan_pdf

PASSWORD = "test-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    monkeypatch.setattr(scanning, "_recent", scanning._recent.__class__())
    app = create_app(db_path=tmp_path / "qlure.db", logs_dir=tmp_path / "logs")
    c = TestClient(app)
    c.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    return c


def test_scanner_needs_login(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    app = create_app(db_path=tmp_path / "qlure.db", logs_dir=tmp_path / "logs")
    anon = TestClient(app)
    r = anon.get("/scanner", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_page_renders_with_standard_scan_only(client):
    r = client.get("/scanner")
    assert r.status_code == 200
    assert "Domain scanner" in r.text
    for gone in ("Full", "full scan", "Check DNS record", 'name="mode"', "QLURE_DASHBOARD_SECRET"):
        assert gone not in r.text


@pytest.mark.parametrize(
    "target, message",
    [
        ("localhost", "restricted address"),
        ("https://example.com:8443", "Ports are not accepted"),
        ("10.0.0.1", "Enter a hostname"),
    ],
)
def test_refused_targets_are_not_scanned(client, target, message):
    r = client.post("/scanner", data={"target": target})
    assert r.status_code == 200
    assert message in r.text
    assert "Findings" not in r.text


def test_one_scan_at_a_time_and_rate_limited(monkeypatch):
    monkeypatch.setattr(scanning, "_recent", scanning._recent.__class__())
    monkeypatch.setattr(scanning, "_busy", False)
    assert scanning._start() is None
    assert "already running" in scanning._start()
    scanning._finish()
    for _ in range(scanning.RATE_COUNT - 1):
        assert scanning._start() is None
        scanning._finish()
    assert "Rate limit" in scanning._start()


RESULT = {
    "target_url": "https://example.com",
    "scan_timestamp": "2026-10-09T12:00:00+00:00",
    "resolved_addresses": ["93.184.216.34"],
    "pqc_posture": {"key_exchange": "classical", "summary": "Classical key exchange only."},
    "tls": {
        "version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "trusted": True,
        "key_exchange": {"preferred_group_name": "x25519", "evidence": ["offered x25519"]},
        "certificate": {
            "subject_cn": "example.com",
            "issuer_cn": "CA",
            "not_after": "2027-01-01T00:00:00",
            "days_remaining": 83,
            "public_key_algorithm": "RSA",
            "key_size": 2048,
        },
    },
    "checks": {"dns": {"status": "passed", "reason": None}},
    "findings": [
        {
            "severity": "medium",
            "title": "No hybrid post-quantum key exchange",
            "detail": "Only x25519.",
            "evidence": "group=x25519",
            "recommendation": "Enable X25519MLKEM768.",
        },
    ],
    "subdomains": [{"name": "www.example.com"}],
}


def test_scan_page_offers_a_pdf_download(client, monkeypatch):
    monkeypatch.setattr(scanning, "run", lambda target: {"result": RESULT})
    r = client.post("/scanner", data={"target": "example.com"})
    assert "Download PDF report" in r.text
    assert 'action="/scanner/report.pdf"' in r.text


def test_pdf_report_downloads_without_rescanning(client, monkeypatch):
    def boom(target):
        raise AssertionError("the report must not run another scan")

    monkeypatch.setattr(scanning, "run", boom)
    r = client.post("/scanner/report.pdf", data={"report": json.dumps(RESULT)})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"]
    assert "example.com" in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF")


def test_pdf_report_survives_odd_input():
    odd = {
        "target_url": "https://例え.example",
        "findings": [
            {"severity": "high", "title": "x" * 500, "detail": "y" * 2000 + "☃", "evidence": None}
        ],
        "tls": None,
        "checks": {"a": "not a dict"},
        "subdomains": [{"name": f"s{i}.example.com"} for i in range(200)],
    }
    assert scan_pdf(odd).startswith(b"%PDF")
    assert scan_pdf({}).startswith(b"%PDF")


@pytest.mark.parametrize("report", ["", "not json", "[1, 2]", "null"])
def test_pdf_report_refuses_bad_input(client, report):
    r = client.post("/scanner/report.pdf", data={"report": report})
    assert r.status_code == 400


def test_pdf_report_refuses_an_oversized_body(client):
    r = client.post("/scanner/report.pdf", data={"report": "x" * 2_100_000})
    assert r.status_code == 400


def test_pdf_report_needs_login(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    app = create_app(db_path=tmp_path / "qlure.db", logs_dir=tmp_path / "logs")
    r = TestClient(app).post("/scanner/report.pdf", data={"report": "{}"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
EMPTY_TEXT = (
    "No subdomains found in certificate logs for example.com. "
    "Absence from the logs does not mean none exist."
)


def _result(**changes):
    result = copy.deepcopy(RESULT)
    result.update(changes)
    return result


def _ct_check(status="ok", reason=None):
    check = {"status": status}
    if reason:
        check["reason"] = reason
    return {"ct_subdomains": check}


def _scan(client, monkeypatch, result):
    monkeypatch.setattr(scanning, "run", lambda target: {"result": result})
    return client.post("/scanner", data={"target": "example.com"})


def test_subdomains_panel_found_state(client, monkeypatch):
    names = [{"name": "www.example.com"}, {"name": "api.example.com"}]
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=names,
            ct_status="ok",
            ct_reason=None,
            ct_truncated=0,
            related_names=[],
            checks=_ct_check(),
        ),
    )
    assert "2 subdomains found in certificate logs" in r.text
    assert "api.example.com" in r.text
    assert "more not shown" not in r.text
    assert "dropped by the 50-name limit" not in r.text
    assert "Related names on the parent domain" not in r.text
    assert "Source: crt.sh certificate transparency logs (passive; no DNS guessing)." in r.text


def test_subdomains_panel_empty_state(client, monkeypatch):
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=[],
            ct_status="empty",
            ct_reason=None,
            ct_truncated=0,
            related_names=[],
            checks=_ct_check("ok"),
        ),
    )
    assert EMPTY_TEXT in r.text
    assert 'class="subdomain-summary"' not in r.text


def test_subdomains_panel_error_state(client, monkeypatch):
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=[],
            ct_status="error",
            ct_reason="crt.sh answered HTTP 503",
            ct_truncated=0,
            related_names=[],
            checks=_ct_check("failed", "crt.sh answered HTTP 503"),
        ),
    )
    assert (
        "Certificate-log lookup failed: crt.sh answered HTTP 503. Try again in a minute; "
        "crt.sh is a third-party service and is often slow."
    ) in r.text
    assert "callout warn" in r.text
    assert EMPTY_TEXT not in r.text


def test_checks_table_explains_the_certificate_log_row(client, monkeypatch):
    """The ct_subdomains row says what happened in words, not only the raw reason."""
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=[{"name": "www.example.com"}],
            ct_status="ok",
            checks=_ct_check(),
        ),
    )
    assert '<td class="muted small">1 name in certificate logs</td>' in r.text
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=[],
            ct_status="error",
            ct_reason="timed out",
            checks=_ct_check("failed", "timed out"),
        ),
    )
    assert '<td class="muted small">Certificate-log lookup failed: timed out</td>' in r.text


def test_related_names_section_appears_and_is_labelled(client, monkeypatch):
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=[],
            ct_status="empty",
            ct_truncated=0,
            related_names=["mail.example.org", "shop.example.org"],
            checks=_ct_check("ok"),
        ),
    )
    assert "Related names on the parent domain (not scanned)" in r.text
    assert "shop.example.org" in r.text


def test_truncation_notes(client, monkeypatch):
    names = [{"name": f"h{i}.example.com"} for i in range(65)]
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=names,
            ct_status="ok",
            ct_truncated=3,
            related_names=[],
            checks=_ct_check(),
        ),
    )
    assert "65 subdomains found in certificate logs" in r.text
    assert "and 5 more not shown" in r.text
    assert "3 more were dropped by the 50-name limit" in r.text
    assert '<span class="chip mono">h59.example.com</span>' in r.text
    assert '<span class="chip mono">h60.example.com</span>' not in r.text


def test_hostile_names_and_reasons_are_escaped(client, monkeypatch):
    hostile_name = "<script>alert(1)</script>.example.com"
    hostile_reason = "<img src=x onerror=alert(1)>"
    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=[{"name": hostile_name}],
            ct_status="ok",
            ct_truncated=0,
            related_names=[],
            checks=_ct_check(),
        ),
    )
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.example.com" in r.text
    assert "<script>alert(1)" not in r.text

    r = _scan(
        client,
        monkeypatch,
        _result(
            subdomains=[],
            ct_status="error",
            ct_reason=hostile_reason,
            ct_truncated=0,
            related_names=[],
            checks=_ct_check("failed", hostile_reason),
        ),
    )
    assert "&lt;img src=x onerror=alert(1)&gt;" in r.text
    assert "<img src=x" not in r.text


def test_results_without_the_new_keys_still_render(client, monkeypatch):
    r = _scan(client, monkeypatch, _result())  # RESULT has no ct_status or related_names
    assert r.status_code == 200
    assert "1 subdomain found in certificate logs" in r.text
    assert "www.example.com" in r.text

    old = _result(subdomains=[])
    r = _scan(client, monkeypatch, old)
    assert EMPTY_TEXT in r.text
    assert "Related names" not in r.text


def test_progress_state_uses_a_static_script_not_inline_js(client, monkeypatch):
    r = _scan(client, monkeypatch, _result())
    assert '<script src="/static/scanner.js" defer></script>' in r.text
    assert 'class="scan-status"' in r.text
    assert "Scanning... up to 30 s, please wait" in r.text
    assert "data-scan-button" in r.text
    # the only script tags are the ones with a src: no inline script
    assert re.findall(r"<script(?![^>]*\ssrc=)", r.text) == []
    assert "onsubmit" not in r.text
    assert " style=" not in r.text

    js = client.get("/static/scanner.js")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    assert "data-scan-status" in js.text


def test_csp_is_unchanged(client):
    r = client.get("/scanner")
    assert r.headers["content-security-policy"] == CSP


def test_pdf_report_accepts_the_new_fields(client):
    posted = _result(
        subdomains=[{"name": "www.example.com", "source": "ct_log"}],
        ct_status="error",
        ct_reason="crt.sh answered HTTP 503",
        ct_truncated=4,
        related_names=["mail.example.org"],
        checks=_ct_check("failed", "crt.sh answered HTTP 503"),
    )
    r = client.post("/scanner/report.pdf", data={"report": json.dumps(posted)})
    assert r.status_code == 200
    assert r.content.startswith(b"%PDF")
