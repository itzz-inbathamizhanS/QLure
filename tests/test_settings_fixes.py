import json

from decoys.ssh import shell
from qlure import settings
from qlure.store import db


def _conn(tmp_path):
    return db.connect(tmp_path / "qlure.db")


def test_dotted_key_below_plain_value_is_refused_and_audited(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "s.json"
    ok, msg = settings.apply_change(conn, "t", {"content.company_name.x": "y"}, path)
    assert not ok and "plain value" in msg
    row = conn.execute("SELECT key, outcome FROM config_audit").fetchone()
    assert (row["key"], row["outcome"]) == ("content.company_name.x", "refused")


def test_explicit_path_gets_its_own_content_file(tmp_path, monkeypatch):
    other = tmp_path / "elsewhere"
    monkeypatch.setenv("QLURE_CONTENT", str(other / "env-content.json"))
    path = tmp_path / "custom" / "s.json"
    ok, _ = settings.apply_change(_conn(tmp_path), "t", {"content.company_name": "Acme"}, path)
    assert ok
    assert json.loads((path.parent / "content.json").read_text())["company_name"] == "Acme"
    assert not other.exists()


def test_audit_failure_leaves_nothing_applied(tmp_path, monkeypatch):
    path = tmp_path / "s.json"
    conn = _conn(tmp_path)
    assert settings.apply_change(conn, "t", {"content.company_name": "Old"}, path)[0]

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(settings, "audit", boom)
    ok, _ = settings.apply_change(conn, "t", {"content.company_name": "New"}, path)
    assert not ok
    assert settings.load_settings(path)["content"]["company_name"] == "Old"
    assert json.loads((path.parent / "content.json").read_text())["company_name"] == "Old"


def test_unread_thresholds_are_rejected(tmp_path):
    conn = _conn(tmp_path)
    for rule, name in [
        ("R4", "pairs"),
        ("R5", "matches"),
        ("R6", "matches"),
        ("R7", "uses"),
        ("R9", "reads"),
    ]:
        ok, msg = settings.apply_change(
            conn, "t", {f"rules.thresholds.{rule}.{name}": 5}, tmp_path / "s.json"
        )
        assert not ok and "no rule reads" in msg
    ok, _ = settings.apply_change(
        conn, "t", {"rules.thresholds.R3.failed_logins": 7}, tmp_path / "s.json"
    )
    assert ok


class _In:
    def __init__(self, text):
        self.text = list(text)

    async def read(self, n):
        return self.text.pop(0) if self.text else ""


class _Out:
    def write(self, s):
        pass


class _Proc:
    def __init__(self, text):
        self.stdin = _In(text)
        self.stdout = _Out()


def test_overlong_line_is_dropped():
    import asyncio

    assert asyncio.run(shell._read_line(_Proc("a" * (shell.MAX_LINE + 5) + "\n"))) is None
    assert asyncio.run(shell._read_line(_Proc("ls\n"))) == "ls"
