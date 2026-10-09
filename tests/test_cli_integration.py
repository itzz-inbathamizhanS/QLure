import json

from qlure import settings as cfg
from qlure.cli import main
from qlure.store import db


def test_correlate_prints_ioc_context_without_scoring(tmp_path, capsys):
    db_path = tmp_path / "q.db"
    db.connect(db_path).close()
    ioc = tmp_path / "indicators.json"
    ioc.write_text(
        json.dumps({"indicators": [{"value": "nc.exe", "type": "file:name"}]}), encoding="utf-8"
    )
    assert main(["correlate", "--db", str(db_path), "--iocs", str(ioc)]) == 0
    out = capsys.readouterr().out
    assert "IOC context (1 indicators, not scored)" in out
    assert "0 session(s) matched an indicator" in out


def test_verify_reports_the_config_chain(tmp_path, capsys):
    db_path = tmp_path / "q.db"
    conn = db.connect(db_path)
    cfg.apply_change(conn, "admin", {"decoys.ssh.port": 2200}, tmp_path / "settings.json")
    conn.close()
    logs = tmp_path / "logs"
    logs.mkdir()
    assert main(["verify", "--db", str(db_path), "--logs", str(logs)]) == 0
    assert "config audit verified: 1 change(s) chained" in capsys.readouterr().out


def test_watch_egress_runs_bounded_iterations(tmp_path):
    out = tmp_path / "egress.jsonl"
    rc = main(
        [
            "watch-egress",
            "--proc-net",
            str(tmp_path),
            "--out",
            str(out),
            "--interval",
            "0",
            "--iterations",
            "1",
        ]
    )
    assert rc == 0
    assert not out.exists()  # no outbound connections, so nothing to write
