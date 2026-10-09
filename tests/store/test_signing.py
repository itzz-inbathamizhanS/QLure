"""ML-DSA-65 signed checkpoints over the hash chain."""

import pytest

from qlure.cli import main
from qlure.events import Action, Service, emit
from qlure.pqc import signing
from qlure.store import db, forwarder

try:
    signing._oqs()
except signing.SigningUnavailable:  # pragma: no cover
    pytest.skip("liboqs is not installed", allow_module_level=True)


@pytest.fixture
def store(log_dir, tmp_path):
    for i in range(7):
        emit(
            {
                "service": Service.WEB,
                "src_ip": "198.51.100.9",
                "session_id": "s1",
                "action": Action.HTTP_REQUEST,
                "request": {"method": "GET", "path": f"/{i}"},
            }
        )
    conn = db.connect(tmp_path / "q.db")
    forwarder.forward_once(conn, log_dir)
    private, public = signing.keygen(tmp_path / "signing")
    return conn, private, public, log_dir, tmp_path


def test_checkpoints_are_signed_and_verify(store):
    conn, private, public, _, _ = store
    assert signing.sign(conn, private, public, every=3, include_head=True) == 3  # 3, 6 and head 7
    assert signing.sign(conn, private, public, every=3) == 0  # nothing new
    result = signing.verify_checkpoints(conn, public)
    assert result.checked == 3 and result.problem is None
    assert oct(private.stat().st_mode & 0o777) == "0o600"


def test_a_rewritten_chain_cannot_be_resigned_without_the_private_key(store):
    conn, private, public, _, tmp_path = store
    signing.sign(conn, private, public, every=3)
    # An attacker edits an event and recomputes every hash after it.
    from qlure.store.chain import GENESIS, link_hash

    rows = conn.execute("SELECT seq, raw FROM events ORDER BY seq").fetchall()
    prev = GENESIS
    for row in rows:
        raw = row["raw"].replace("/1", "/9") if row["seq"] == 2 else row["raw"]
        new = link_hash(prev, raw)
        conn.execute(
            "UPDATE events SET raw=?, prev_hash=?, hash=? WHERE seq=?", (raw, prev, new, row["seq"])
        )
        prev = new
    conn.commit()
    result = signing.verify_checkpoints(conn, public)
    assert result.problem and "no longer ends in the signed hash" in result.problem


def test_a_forged_signature_or_swapped_key_fails(store):
    conn, private, public, _, tmp_path = store
    signing.sign(conn, private, public, every=3)
    _, other_public = signing.keygen(tmp_path / "other")
    assert "different key" in signing.verify_checkpoints(conn, other_public).problem
    conn.execute("UPDATE checkpoints SET signature = ?", ("00" * 3309,))
    conn.commit()
    assert "not valid" in signing.verify_checkpoints(conn, public).problem


def test_cli_verify_checks_chain_and_signatures(store, capsys):
    conn, private, public, log_dir, tmp_path = store
    db_path = str(tmp_path / "q.db")
    common = ["--db", db_path, "--logs", str(log_dir), "--pub", str(public)]
    assert main(["verify", *common]) == 0
    assert "no signed checkpoints" in capsys.readouterr().out
    main(["sign", "--db", db_path, "--key", str(private), "--pub", str(public), "--every", "3"])
    assert main(["verify", *common]) == 0
    assert "ML-DSA-65 checkpoints verified" in capsys.readouterr().out
    conn.execute("UPDATE checkpoints SET head_hash = ?", ("f" * 64,))
    conn.commit()
    assert main(["verify", *common]) == 1
