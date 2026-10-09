"""Signed checkpoints: ML-DSA-65 signatures over the hash chain, so history cannot be re-chained.

Every N events, `sign` signs "the chain up to event #seq ends in hash H". `verify_checkpoints`
checks each signature against a public key you pinned, and that the stored chain still ends
in the signed hash. Rewriting history then needs the private key, which should live off the
decoy host. Needs liboqs (`pip install 'qlure[pqc]'`).
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ALGORITHM = "ML-DSA-65"
DEFAULT_EVERY = 100


class SigningUnavailable(RuntimeError):
    """liboqs is not installed, so nothing can be signed or checked."""


def _oqs():
    try:
        import oqs  # noqa: PLC0415  (heavy import, only needed when signing)
    except Exception as exc:  # liboqs may also fail to build or load
        raise SigningUnavailable(f"liboqs is not available: {exc}") from exc
    return oqs


def message(upto_seq: int, head_hash: str) -> bytes:
    return f"qlure-checkpoint-v1|{ALGORITHM}|{upto_seq}|{head_hash}".encode()


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def keygen(out_prefix: Path) -> tuple[Path, Path]:
    """Write `<prefix>.key` (private, mode 0600) and `<prefix>.pub`."""
    oqs = _oqs()
    with oqs.Signature(ALGORITHM) as signer:
        public = signer.generate_keypair()
        secret = signer.export_secret_key()
    private_path, public_path = out_prefix.with_suffix(".key"), out_prefix.with_suffix(".pub")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.touch(mode=0o600)
    private_path.write_bytes(secret)
    public_path.write_bytes(public)
    return private_path, public_path


def sign(
    conn: sqlite3.Connection,
    private_key: Path,
    public_key: Path,
    every: int = DEFAULT_EVERY,
    include_head: bool = False,
) -> int:
    """Sign a checkpoint at every multiple of `every` events (and the head if asked)."""
    oqs = _oqs()
    pub = public_key.read_bytes()
    last = conn.execute("SELECT COALESCE(MAX(upto_seq), 0) FROM checkpoints").fetchone()[0]
    head = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()[0]
    targets = list(range(((last // every) + 1) * every, head + 1, every))
    if include_head and head > last and head not in targets:
        targets.append(head)
    made = 0
    with oqs.Signature(ALGORITHM, private_key.read_bytes()) as signer:
        for seq in targets:
            row = conn.execute("SELECT hash FROM events WHERE seq=?", (seq,)).fetchone()
            if row is None:  # gaps in seq: sign the nearest earlier event instead
                row = conn.execute(
                    "SELECT seq, hash FROM events WHERE seq<=? ORDER BY seq DESC LIMIT 1", (seq,)
                ).fetchone()
                if row is None:
                    continue
                seq = row["seq"]
            signature = signer.sign(message(seq, row["hash"]))
            conn.execute(
                "INSERT OR IGNORE INTO checkpoints (upto_seq, head_hash, ts, algorithm, key_id,"
                " signature) VALUES (?,?,?,?,?,?)",
                (
                    seq,
                    row["hash"],
                    datetime.now(UTC).isoformat(),
                    ALGORITHM,
                    key_id(pub),
                    signature.hex(),
                ),
            )
            made += 1
    conn.commit()
    return made


@dataclass(frozen=True)
class CheckpointResult:
    checked: int
    problem: str | None = None


def verify_checkpoints(conn: sqlite3.Connection, public_key: Path) -> CheckpointResult:
    rows = conn.execute("SELECT * FROM checkpoints ORDER BY upto_seq").fetchall()
    if not rows:
        return CheckpointResult(0)
    oqs = _oqs()
    pub = public_key.read_bytes()
    with oqs.Signature(ALGORITHM) as verifier:
        for row in rows:
            where = f"checkpoint at event #{row['upto_seq']}"
            if row["key_id"] != key_id(pub):
                return CheckpointResult(0, f"{where} was signed with a different key")
            event = conn.execute(
                "SELECT hash FROM events WHERE seq=?", (row["upto_seq"],)
            ).fetchone()
            if event is None or event["hash"] != row["head_hash"]:
                return CheckpointResult(0, f"{where}: the chain no longer ends in the signed hash")
            ok = verifier.verify(
                message(row["upto_seq"], row["head_hash"]), bytes.fromhex(row["signature"]), pub
            )
            if not ok:
                return CheckpointResult(0, f"{where}: signature is not valid")
    return CheckpointResult(len(rows))
