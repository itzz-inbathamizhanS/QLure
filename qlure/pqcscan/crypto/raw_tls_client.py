"""Minimal TLS ClientHello probe used to observe what a server negotiates.

TLS 1.3 key exchange groups are not exposed by the Python ssl module. A ClientHello that lists the
groups we support but carries an EMPTY key_share forces a conforming server to answer with a
HelloRetryRequest that names the group it selected (RFC 8446 4.1.4). No key material is generated
or exchanged and no handshake is completed.

The result describes the group preference of the server for this hello. For CDN-fronted sites it is
the behaviour of the edge, not necessarily of the origin.
"""

import os
import socket
import struct

from qlure.pqcscan.errors import ScannerException
from qlure.pqcscan.net import connect_pinned

# SHA-256 of the string HelloRetryRequest: the fixed ServerHello.random of a HelloRetryRequest.
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

# Offered in order; the server chooses by its own preference among them.
HYBRID_GROUPS = [
    0x11EC,
    0x11EB,
    0x11ED,
    0x6399,
]  # X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, Kyber draft
CLASSICAL_GROUPS = [0x001D, 0x0017, 0x0018, 0x0019, 0x001E]  # X25519, P-256, P-384, P-521, X448

TLS13_SUITES = [0x1301, 0x1302, 0x1303]
LEGACY_SUITES = [0xC013, 0xC014, 0xC009, 0xC00A, 0x002F, 0x0035]
SIG_ALGS = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0807]

ALERT_PROTOCOL_VERSION = 70
LEGACY_TLS10 = b"\x03\x01"
LEGACY_TLS11 = b"\x03\x02"


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _sni(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    return _ext(0x0000, struct.pack("!H", len(entry)) + entry)


def _groups(groups) -> bytes:
    body = b"".join(struct.pack("!H", g) for g in groups)
    return _ext(0x000A, struct.pack("!H", len(body)) + body)


def build_client_hello(hostname: str, groups, legacy_version: bytes = None) -> bytes:
    """A TLS 1.3 hello with an empty key_share, or (with legacy_version) a TLS 1.0/1.1 hello."""
    sig = b"".join(struct.pack("!H", s) for s in SIG_ALGS)
    exts = _sni(hostname) + _groups(groups) + _ext(0x000D, struct.pack("!H", len(sig)) + sig)
    if legacy_version is None:
        version, suites = b"\x03\x03", TLS13_SUITES
        exts += _ext(0x002B, b"\x02\x03\x04") + _ext(0x0033, b"\x00\x00")
    else:
        version, suites = legacy_version, LEGACY_SUITES
        exts += _ext(0x000B, b"\x01\x00")  # ec_point_formats: uncompressed
    cipher_bytes = b"".join(struct.pack("!H", c) for c in suites)
    body = (
        version
        + os.urandom(32)
        + b"\x20"
        + os.urandom(32)
        + struct.pack("!H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def parse_response(data: bytes) -> dict:
    """Interpret the first TLS record a server sent back to our hello."""
    if len(data) < 7:
        return {"outcome": "error", "reason": "short or empty response"}
    if data[0] == 21:  # alert
        return {"outcome": "rejected", "alert": data[6]}
    if data[0] != 22 or data[5] != 2:
        return {"outcome": "error", "reason": "response was not a ServerHello"}
    p = data[5 : 5 + struct.unpack("!H", data[3:5])[0]]
    try:
        legacy_version = struct.unpack("!H", p[4:6])[0]
        random = p[6:38]
        i = 38
        i += 1 + p[i]  # session id
        cipher = struct.unpack("!H", p[i : i + 2])[0]
        i += 3  # cipher + compression
        selected_version, group = legacy_version, None
        if i + 2 <= len(p):
            end = i + 2 + struct.unpack("!H", p[i : i + 2])[0]
            i += 2
            while i + 4 <= min(end, len(p)):
                t, ln = struct.unpack("!HH", p[i : i + 4])
                body = p[i + 4 : i + 4 + ln]
                if t == 0x002B and len(body) >= 2:
                    selected_version = struct.unpack("!H", body[:2])[0]
                elif t == 0x0033 and len(body) >= 2:
                    group = struct.unpack("!H", body[:2])[0]
                i += 4 + ln
    except (IndexError, struct.error):
        return {"outcome": "error", "reason": "malformed ServerHello"}
    return {
        "outcome": "selected",
        "version": selected_version,
        "cipher": cipher,
        "group": group,
        "hello_retry_request": random == HRR_RANDOM,
    }


def _read_record(sock: socket.socket) -> bytes:
    data = b""
    while len(data) < 5:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    need = 5 + struct.unpack("!H", data[3:5])[0]
    while len(data) < need and len(data) < 20000:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class RawTLSProbe:
    def __init__(self, hostname: str, ips, port: int = 443, timeout: float = 4.0):
        self.hostname = hostname
        self.ips = ips
        self.port = port
        self.timeout = timeout

    def _exchange(self, hello: bytes) -> dict:
        try:
            with connect_pinned(self.ips, self.port, self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(hello)
                return parse_response(_read_record(sock))
        except ScannerException as e:
            return {"outcome": "error", "reason": e.message}
        except TimeoutError:
            return {"outcome": "error", "reason": "timed out"}
        except OSError as e:
            return {"outcome": "error", "reason": str(e)}

    def probe_groups(self, groups) -> dict:
        return self._exchange(build_client_hello(self.hostname, groups))

    def probe_legacy_version(self, version: bytes) -> dict:
        """Does the server accept a TLS 1.0 or 1.1 hello? accepted is True, False or None (unknown)."""
        res = self._exchange(
            build_client_hello(self.hostname, [0x001D, 0x0017, 0x0018], legacy_version=version)
        )
        if res["outcome"] == "selected":
            return {"accepted": res["version"] == struct.unpack("!H", version)[0], "detail": res}
        if res["outcome"] == "rejected":
            return {"accepted": False, "detail": res}
        return {"accepted": None, "detail": res}

    def probe_key_exchange(self) -> dict:
        """Observe the TLS 1.3 key exchange group the server prefers, and whether it supports hybrid PQC.

        Two hellos at most: all groups, then (only if the first choice was classical) hybrid groups alone.
        """
        first = self.probe_groups(HYBRID_GROUPS + CLASSICAL_GROUPS)
        out = {
            "first": first,
            "hybrid_only": None,
            "hybrid_pqc_supported": None,
            "preferred_group": None,
            "tls13_supported": None,
        }
        if (
            first["outcome"] == "selected"
            and first["version"] == 0x0304
            and first.get("group") is not None
        ):
            out["tls13_supported"] = True
            out["preferred_group"] = first["group"]
            if first["group"] in HYBRID_GROUPS:
                out["hybrid_pqc_supported"] = True
            else:
                second = self.probe_groups(HYBRID_GROUPS)
                out["hybrid_only"] = second
                if second["outcome"] == "selected" and second.get("group") in HYBRID_GROUPS:
                    out["hybrid_pqc_supported"] = True
                elif second["outcome"] == "rejected":
                    out["hybrid_pqc_supported"] = False
        elif (first["outcome"] == "rejected" and first.get("alert") == ALERT_PROTOCOL_VERSION) or (
            first["outcome"] == "selected" and first["version"] != 0x0304
        ):
            out["tls13_supported"] = False
            out["hybrid_pqc_supported"] = False  # no TLS 1.3, so no hybrid key exchange
        return out
