from qlure import settings as cfg
from qlure.store import db
from qlure.store.verify import verify_config


def _conn(tmp_path):
    return db.connect(tmp_path / "q.db")


def test_applied_and_refused_changes_form_one_chain(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "settings.json"
    assert cfg.apply_change(conn, "admin", {"decoys.ssh.port": 2200}, path)[0]
    assert not cfg.apply_change(conn, "admin", {"decoys.ssh.port": 22}, path)[0]
    checked, legacy, problem = verify_config(conn)
    assert (checked, legacy, problem) == (2, 0, None)


def test_editing_a_change_is_caught_at_that_row(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "settings.json"
    cfg.apply_change(conn, "admin", {"decoys.ssh.port": 2200}, path)
    cfg.apply_change(conn, "admin", {"decoys.ssh.port": 2201}, path)
    conn.execute("UPDATE config_audit SET who='someone-else' WHERE audit_id=1")
    conn.commit()
    _, _, problem = verify_config(conn)
    assert problem is not None and problem.audit_id == 1
    assert "edited" in problem.reason


def test_removing_a_middle_change_breaks_the_link(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "settings.json"
    for port in (2200, 2201, 2202):
        cfg.apply_change(conn, "admin", {"decoys.ssh.port": port}, path)
    conn.execute("DELETE FROM config_audit WHERE audit_id=2")
    conn.commit()
    _, _, problem = verify_config(conn)
    assert problem is not None and problem.audit_id == 3
    assert "removed" in problem.reason


def test_rows_from_before_chaining_are_reported_as_legacy(tmp_path):
    conn = _conn(tmp_path)
    conn.execute(
        "INSERT INTO config_audit (ts, who, key, old_value, new_value, outcome, reason)"
        " VALUES ('2026-10-01T00:00:00+00:00','admin','decoys.ssh.port','2222','2200','applied','')"
    )
    conn.commit()
    path = tmp_path / "settings.json"
    cfg.apply_change(conn, "admin", {"decoys.ssh.port": 2201}, path)
    assert verify_config(conn) == (1, 1, None)


def test_a_legacy_row_after_chained_rows_is_a_problem(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "settings.json"
    cfg.apply_change(conn, "admin", {"decoys.ssh.port": 2200}, path)
    conn.execute(
        "INSERT INTO config_audit (ts, who, key, old_value, new_value, outcome, reason)"
        " VALUES ('2026-10-01T00:00:00+00:00','admin','decoys.ssh.port','1','2','applied','')"
    )
    conn.commit()
    _, _, problem = verify_config(conn)
    assert problem is not None and "unchained" in problem.reason


def test_rollback_is_chained_too(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "settings.json"
    cfg.apply_change(conn, "admin", {"decoys.ssh.port": 2200}, path)
    audit_id = conn.execute("SELECT audit_id FROM config_audit").fetchone()[0]
    assert cfg.rollback(conn, "admin", audit_id)[0]
    assert verify_config(conn) == (2, 0, None)
