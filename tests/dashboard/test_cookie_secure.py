"""QLURE_COOKIE_SECURE: the login cookie gets Secure only when the operator opts in."""

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from qlure.store import db

PASSWORD = "test-password"


def _app(tmp_path, monkeypatch, flag):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    if flag is None:
        monkeypatch.delenv("QLURE_COOKIE_SECURE", raising=False)
    else:
        monkeypatch.setenv("QLURE_COOKIE_SECURE", flag)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    db.connect(tmp_path / "q.db").close()
    return create_app(tmp_path / "q.db", logs)


def _attrs(header):
    return [part.strip().lower() for part in header.split(";")]


def _login(client):
    return client.post("/login", data={"password": PASSWORD}, follow_redirects=False)


@pytest.mark.parametrize("flag", ["1", "true", "TRUE", "Yes"])
def test_secure_flag_on(tmp_path, monkeypatch, flag):
    client = TestClient(_app(tmp_path, monkeypatch, flag), base_url="http://testserver")
    r = _login(client)
    assert r.status_code == 303
    attrs = _attrs(r.headers["set-cookie"])
    assert "secure" in attrs and "httponly" in attrs and "samesite=strict" in attrs
    assert "path=/" in attrs and any(a.startswith("max-age=") for a in attrs)


@pytest.mark.parametrize("flag", [None, "0", "", "no", "false", "2"])
def test_secure_flag_off(tmp_path, monkeypatch, flag):
    client = TestClient(_app(tmp_path, monkeypatch, flag), base_url="http://testserver")
    attrs = _attrs(_login(client).headers["set-cookie"])
    assert "secure" not in attrs
    assert "httponly" in attrs and "samesite=strict" in attrs


@pytest.mark.parametrize("flag", [None, "1"])
def test_logout_clears_session(tmp_path, monkeypatch, flag):
    # An https base URL, so the client keeps and resends the Secure cookie.
    client = TestClient(_app(tmp_path, monkeypatch, flag), base_url="https://testserver")
    assert _login(client).status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 200
    r = client.post("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    attrs = _attrs(r.headers["set-cookie"])
    assert ("secure" in attrs) == (flag == "1")
    assert "max-age=0" in attrs
    after = client.get("/", follow_redirects=False)
    assert after.status_code == 303 and after.headers["location"] == "/login"


@pytest.mark.parametrize("flag", [None, "1"])
def test_wrong_password_rejected(tmp_path, monkeypatch, flag):
    client = TestClient(_app(tmp_path, monkeypatch, flag), base_url="https://testserver")
    r = client.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert r.status_code == 401 and "set-cookie" not in r.headers


def test_security_headers_unchanged(tmp_path, monkeypatch):
    off = TestClient(_app(tmp_path, monkeypatch, None)).get("/login")
    on = TestClient(_app(tmp_path, monkeypatch, "1")).get("/login")
    assert off.headers["content-security-policy"]
    for name in off.headers:
        if name.lower() in ("content-length", "date", "set-cookie"):
            continue
        assert on.headers[name] == off.headers[name]
    assert set(on.headers) == set(off.headers)
