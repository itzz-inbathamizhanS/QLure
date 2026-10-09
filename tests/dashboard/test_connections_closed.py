"""Dashboard handlers close the SQLite connections they open."""

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from qlure.store import db

PASSWORD = "test-password"


class Tracked:
    """Delegates to a real connection and remembers whether close() was called."""

    def __init__(self, conn):
        self._conn = conn
        self.closed = False

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def close(self):
        self.closed = True
        self._conn.close()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QLURE_SETTINGS", str(tmp_path / "settings.json"))
    monkeypatch.setenv("QLURE_CONTENT", str(tmp_path / "content.json"))
    monkeypatch.setenv("QLURE_DASHBOARD_PASSWORD", PASSWORD)
    opened: list[Tracked] = []
    real_connect = db.connect

    def tracking_connect(path):
        tracked = Tracked(real_connect(path))
        opened.append(tracked)
        return tracked

    monkeypatch.setattr(db, "connect", tracking_connect)
    app = create_app(tmp_path / "q.db", tmp_path / "logs")
    c = TestClient(app, base_url="http://testserver")
    assert c.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    c.opened = opened
    return c


def test_read_handlers_close_their_connections(client):
    for path in ("/", "/actors", "/actor/nobody", "/config", "/session/nobody"):
        assert client.get(path).status_code in (200, 404)
    client.get("/session/nobody/report")
    client.get("/session/nobody/evidence.json")
    client.post("/config", data={"decoys.ssh.port": "2200"}, follow_redirects=False)
    client.post("/session/nobody/label", data={"label": "benign"}, follow_redirects=False)
    assert client.opened, "the handlers should have opened a connection"
    assert all(c.closed for c in client.opened)
