"""`sign` reports only the checkpoints it actually inserted, not rows OR IGNORE skipped."""

import pytest

from qlure.events import Action, Service, emit
from qlure.pqc import signing
from qlure.store import db, forwarder

try:
    signing._oqs()
except signing.SigningUnavailable:  # pragma: no cover
    pytest.skip("liboqs is not installed", allow_module_level=True)


def test_skipped_checkpoint_rows_are_not_counted(log_dir, tmp_path):
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
    # Checkpoint at 2 exists; seq 3 is gone, so the target 3 falls back to seq 2 and is ignored.
    conn.execute(
        "INSERT INTO checkpoints (upto_seq, head_hash, ts, algorithm, key_id, signature)"
        " VALUES (2, 'x', '2026-01-01T00:00:00+00:00', ?, 'k', '00')",
        (signing.ALGORITHM,),
    )
    conn.execute("DELETE FROM events WHERE seq=3")
    conn.commit()
    made = signing.sign(conn, private, public, every=3)
    assert made == 1  # only the checkpoint at 6 was new
    upto = [r[0] for r in conn.execute("SELECT upto_seq FROM checkpoints ORDER BY upto_seq")]
    assert upto == [2, 6]
