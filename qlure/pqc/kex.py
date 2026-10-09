"""Read the client's SSH key-exchange offer. Context for the investigator, never a score.

We record which visitors offer quantum-safe key exchange, because that is a useful clue about
which SSH tool they use. It says nothing about quantum attacks, and no rule fires on it.
"""

from __future__ import annotations

import hashlib
import struct

# Hybrid key exchanges that mix a post-quantum KEM with a classical one.
PQC_KEX = frozenset(
    {
        "mlkem768x25519-sha256",
        "mlkem768nistp256-sha256",
        "mlkem1024nistp384-sha384",
        "sntrup761x25519-sha512",
        "sntrup761x25519-sha512@openssh.com",
    }
)
MAX_SNIFF_BYTES = 16 * 1024
MAX_BANNER_BYTES = 255
KEXINIT = 20


def pqc_capable(kex_offered: list[str]) -> bool:
    return any(name in PQC_KEX for name in kex_offered)


def kex_fingerprint(kex_offered: list[str]) -> str:
    """Short hash of the offered list in the order offered, like HASSH but for KEX only."""
    return hashlib.sha256(",".join(kex_offered).encode()).hexdigest()[:16]


class KexSniffer:
    """Reads the unencrypted start of a client's SSH stream: its version line, then its KEXINIT.

    Feed it the bytes as they pass through; it never changes them. After `done` is true,
    `client_version` and `kex_offered` hold what the client sent (`kex_offered` stays empty
    if the client did not send a valid KEXINIT).
    """

    def __init__(self) -> None:
        self.client_version = ""
        self.kex_offered: list[str] = []
        self.done = False
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        if self.done:
            return
        self._buffer += data
        self._parse()
        if len(self._buffer) > MAX_SNIFF_BYTES:
            self.done = True

    def _parse(self) -> None:
        buf = bytes(self._buffer)
        newline = buf.find(b"\n")
        if newline < 0:
            if len(buf) > MAX_BANNER_BYTES:
                self.done = True  # not SSH
            return
        line = buf[:newline].rstrip(b"\r")
        if not line.startswith(b"SSH-") or newline > MAX_BANNER_BYTES:
            self.done = True
            return
        self.client_version = line.decode("ascii", errors="replace")[:200]
        rest = buf[newline + 1 :]
        # packet_length(4) padding_length(1) type(1) cookie(16) then the first name-list
        if len(rest) < 26:
            return
        _length, _padding, kind = struct.unpack(">IBB", rest[:6])
        if kind != KEXINIT:
            self.done = True
            return
        (size,) = struct.unpack(">I", rest[22:26])
        if size > MAX_SNIFF_BYTES:
            self.done = True
            return
        if len(rest) < 26 + size:
            return
        names = rest[26 : 26 + size].decode("ascii", errors="replace")
        self.kex_offered = [n for n in names.split(",") if n]
        self.done = True
