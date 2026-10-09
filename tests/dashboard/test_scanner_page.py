"""The domain scanner page: login required, and the Q-CAPS guardrails hold through the page."""

import json

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
