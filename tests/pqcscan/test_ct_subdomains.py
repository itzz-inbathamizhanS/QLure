"""crt.sh subdomain lookup: retries, deadline, status, scope rules. Everything is mocked."""

import json
import threading
import time

import pytest
import requests

from dashboard import scanning
from qlure.pqcscan import checks, engine
from qlure.pqcscan.errors import ScannerException
from qlure.pqcscan.security import target_validator


class FakeResp:
    def __init__(self, status=200, body=b"[]", chunks=None):
        self.status_code = status
        self._chunks = chunks if chunks is not None else [body]

    def iter_content(self, size):
        yield from self._chunks

    def close(self):
        pass


def entries(*names):
    return json.dumps([{"name_value": n} for n in names]).encode()


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(checks, "CT_BACKOFF", 0.0)
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("unmocked network call"))


def serve(monkeypatch, responses):
    """Answer requests.get from `responses`; returns the list of queries seen."""
    queries, queue = [], list(responses)

    def fake_get(url, params=None, **kw):
        queries.append(params["q"])
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(requests, "get", fake_get)
    return queries


def test_success_with_several_names(monkeypatch):
    serve(monkeypatch, [FakeResp(body=entries("b.example.com\na.example.com", "c.example.com"))])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "ok" and r["ct_reason"] is None
    assert [n["name"] for n in r["names"]] == ["a.example.com", "b.example.com", "c.example.com"]
    assert r["ct_truncated"] == 0 and r["related_names"] == []


def test_empty_list(monkeypatch):
    serve(monkeypatch, [FakeResp(body=b"[]")])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "empty" and r["names"] == []


def test_502_then_200_retries(monkeypatch):
    q = serve(monkeypatch, [FakeResp(502), FakeResp(body=entries("a.example.com"))])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "ok" and len(q) == 2


@pytest.mark.parametrize(
    "first",
    [FakeResp(503), requests.exceptions.ConnectionError("x"), requests.exceptions.ReadTimeout()],
)
def test_retry_on_transient_failures(monkeypatch, first):
    serve(monkeypatch, [first, FakeResp(body=entries("a.example.com"))])
    assert checks.check_ct_subdomains("example.com")["ct_status"] == "ok"


def test_503_twice_is_error(monkeypatch):
    q = serve(monkeypatch, [FakeResp(503), FakeResp(503)])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "error" and r["ct_reason"] == "crt.sh answered HTTP 503"
    assert len(q) == 2


def test_other_http_status_not_retried(monkeypatch):
    q = serve(monkeypatch, [FakeResp(404)])
    assert checks.check_ct_subdomains("example.com")["ct_status"] == "error"
    assert len(q) == 1


@pytest.mark.parametrize("body", [b"<html><body>Oops</body></html>", b"", b"\xff\xfe"])
def test_200_with_non_json_body(monkeypatch, body):
    serve(monkeypatch, [FakeResp(body=body)])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "error" and r["ct_reason"] == "unexpected response from crt.sh"


def test_json_not_a_list(monkeypatch):
    serve(monkeypatch, [FakeResp(body=b'{"a": 1}')])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "error" and r["ct_reason"] == "unexpected response from crt.sh"


def test_non_dict_entries_ignored(monkeypatch):
    serve(monkeypatch, [FakeResp(body=b'[1, "x", null, {"name_value": "a.example.com"}]')])
    r = checks.check_ct_subdomains("example.com")
    assert [n["name"] for n in r["names"]] == ["a.example.com"]


def test_cap_of_50_and_truncated_count(monkeypatch):
    names = [f"s{i:03d}.example.com" for i in range(73)]
    serve(monkeypatch, [FakeResp(body=entries(*names))])
    r = checks.check_ct_subdomains("example.com")
    assert len(r["names"]) == 50 and r["ct_truncated"] == 23


def test_wildcard_and_out_of_scope_dropped(monkeypatch):
    body = entries(
        "*.example.com",
        "a.example.com",
        "evil.org",
        "example.com",
        "x.notexample.com",
        "b c.example.com",
    )
    serve(monkeypatch, [FakeResp(body=body)])
    r = checks.check_ct_subdomains("example.com")
    assert [n["name"] for n in r["names"]] == ["a.example.com"]


def test_size_cap(monkeypatch):
    monkeypatch.setattr(checks, "MAX_CT_BYTES", 10)
    serve(monkeypatch, [FakeResp(chunks=[b"[" * 8, b"[" * 8])])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "error" and "too large" in r["ct_reason"]


def test_apex_fallback_related_names(monkeypatch):
    q = serve(
        monkeypatch,
        [
            FakeResp(body=entries("api.www.example.com")),
            FakeResp(
                body=entries(
                    "mail.example.com", "api.www.example.com", "www.example.com", "*.example.com"
                )
            ),
        ],
    )
    r = checks.check_ct_subdomains("www.example.com")
    assert q == ["%.www.example.com", "%.example.com"]
    assert [n["name"] for n in r["names"]] == ["api.www.example.com"]
    assert r["related_names"] == ["mail.example.com"]


def test_related_names_capped_and_parent_failure_ignored(monkeypatch):
    many = [f"h{i:02d}.example.com" for i in range(40)]
    serve(monkeypatch, [FakeResp(body=b"[]"), FakeResp(body=entries(*many))])
    r = checks.check_ct_subdomains("www.example.com")
    assert r["ct_status"] == "empty" and len(r["related_names"]) == checks.CT_MAX_RELATED
    serve(monkeypatch, [FakeResp(body=entries("a.www.example.com")), FakeResp(503), FakeResp(503)])
    r = checks.check_ct_subdomains("www.example.com")
    assert r["ct_status"] == "ok" and r["related_names"] == []


@pytest.mark.parametrize(
    "host,parent",
    [
        ("example.com", None),
        ("www.example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        ("example.co.uk", None),
        ("www.example.co.uk", "example.co.uk"),
        ("x.y.example.com.au", "example.com.au"),
    ],
)
def test_registrable_parent(host, parent):
    assert checks.registrable_parent(host) == parent


def test_total_deadline_with_fake_clock(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(checks.time, "monotonic", lambda: clock[0])

    def slow_chunks():
        for _ in range(100):
            clock[0] += 5.0  # each chunk "takes" 5 s: the deadline must stop the loop
            yield b" "

    resp = FakeResp()
    resp.iter_content = lambda size: slow_chunks()
    q = serve(monkeypatch, [resp])
    r = checks.check_ct_subdomains("example.com")
    assert r["ct_status"] == "error" and "timed out" in r["ct_reason"]
    assert clock[0] - 1000.0 <= checks.CT_DEADLINE + 5.0 and len(q) == 1


def test_no_retry_when_deadline_nearly_spent(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(checks.time, "monotonic", lambda: clock[0])

    def fake_get(url, params=None, **kw):
        clock[0] += checks.CT_DEADLINE - 0.5
        return FakeResp(502)

    monkeypatch.setattr(requests, "get", fake_get)
    assert checks.check_ct_subdomains("example.com")["ct_status"] == "error"


def test_cancel_stops_the_loop(monkeypatch):
    cancel = threading.Event()
    resp = FakeResp()

    def chunks(size):
        cancel.set()
        yield b" "
        pytest.fail("loop kept reading after cancel")

    resp.iter_content = chunks
    serve(monkeypatch, [resp])
    assert checks.check_ct_subdomains("example.com", cancel)["ct_status"] == "error"


# ---------------------------------------------------------------- engine / dashboard


def stub_engine(monkeypatch, host="www.example.com"):
    def boom(*a, **k):
        raise ScannerException(None, "stubbed")

    monkeypatch.setattr(engine, "resolve_target", lambda t: (host, ["93.184.216.34"]))
    for name in ("check_dns", "check_whois", "check_http"):
        monkeypatch.setattr(checks, name, boom)
    monkeypatch.setattr(engine, "probe_tls", boom)
    monkeypatch.setattr(engine, "RawTLSProbe", boom)


def test_fields_reach_the_final_result(monkeypatch):
    stub_engine(monkeypatch)
    serve(
        monkeypatch,
        [FakeResp(body=entries("a.www.example.com")), FakeResp(body=entries("mail.example.com"))],
    )
    res = engine.analyze_domain("www.example.com")
    assert [s["name"] for s in res["subdomains"]] == ["a.www.example.com"]
    assert (res["ct_status"], res["ct_reason"], res["ct_truncated"]) == ("ok", None, 0)
    assert res["related_names"] == ["mail.example.com"]
    assert res["checks"]["ct_subdomains"]["status"] == "ok"
    json.dumps(res)


def test_error_reaches_the_final_result(monkeypatch):
    stub_engine(monkeypatch)
    serve(monkeypatch, [FakeResp(body=b"<html>")])
    res = engine.analyze_domain("www.example.com")
    assert res["ct_status"] == "error" and res["ct_reason"] == "unexpected response from crt.sh"
    assert res["subdomains"] == [] and res["checks"]["ct_subdomains"]["status"] == "failed"


def test_internal_retry_counts_as_one_scan(monkeypatch):
    stub_engine(monkeypatch, "example.com")
    monkeypatch.setattr(scanning, "_recent", scanning.deque())
    q = serve(monkeypatch, [FakeResp(502), FakeResp(body=entries("a.example.com"))])
    out = scanning.run("example.com")
    assert out["result"]["ct_status"] == "ok" and len(q) == 2
    assert len(scanning._recent) == 1 and scanning._busy is False


def test_getaddrinfo_timeout_is_a_clean_refusal(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(target_validator, "RESOLVE_TIMEOUT", 0.2)
    monkeypatch.setattr(target_validator.socket, "getaddrinfo", lambda *a, **k: release.wait(5))
    monkeypatch.setattr(scanning, "_recent", scanning.deque())
    started = time.monotonic()
    try:
        out = scanning.run("example.com")
    finally:
        release.set()
    assert out == {"error": "could not resolve host in time"}
    assert time.monotonic() - started < 3
    assert scanning._busy is False


def test_getaddrinfo_errors_still_propagate(monkeypatch):
    def fail(*a, **k):
        raise target_validator.socket.gaierror("nope")

    monkeypatch.setattr(target_validator.socket, "getaddrinfo", fail)
    with pytest.raises(ScannerException, match="DNS resolution failed"):
        target_validator.resolve_target("example.com")
