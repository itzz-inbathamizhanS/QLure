"""TLS handshake observation through the Python ssl module, pinned to validated addresses.

The negotiated key exchange GROUP is not visible here; see raw_tls_client.RawTLSProbe for that.
"""

import ssl

from qlure.pqcscan.errors import ScannerErrorType, ScannerException
from qlure.pqcscan.net import connect_pinned


def classify_tls12_cipher(cipher_name: str) -> dict:
    """Key exchange and authentication of an OpenSSL style TLS 1.2 or earlier cipher name."""
    n = cipher_name.upper()
    if n.startswith("ECDHE-"):
        kex = "ECDHE"
    elif n.startswith("DHE-") or n.startswith("EDH-"):
        kex = "DHE"
    else:
        kex = "RSA"  # plain AES128-SHA style suites use RSA key transport: no forward secrecy
    auth = "ECDSA" if "ECDSA" in n else ("RSA" if ("RSA" in n or kex == "RSA") else None)
    return {"kex": kex, "auth": auth, "forward_secrecy": kex in ("ECDHE", "DHE")}


def observation_context() -> ssl.SSLContext:
    """Client context for OBSERVING a server: it accepts legacy cipher suites and protocol versions and skips
    certificate validation, so weak servers can be assessed instead of failing the handshake.

    Never used to decide trust (probe_tls does that with a strict, verifying handshake) and never to send data
    beyond one HEAD-like request for headers.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass  # this OpenSSL build refuses the legacy list: fall back to its defaults
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def _handshake(ips, hostname: str, port: int, verify: bool, timeout: float):
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = observation_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with connect_pinned(ips, port, timeout) as sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            chain = []
            if hasattr(ssock, "get_unverified_chain"):
                chain = [
                    bytes(c)
                    if isinstance(c, (bytes, bytearray))
                    else c.public_bytes(ssl._ssl.ENCODING_DER)
                    for c in ssock.get_unverified_chain()
                ]
            if not chain:
                leaf = ssock.getpeercert(binary_form=True)
                chain = [leaf] if leaf else []
            return {
                "version": ssock.version(),
                "cipher": ssock.cipher()[0],
                "alpn": ssock.selected_alpn_protocol(),
                "chain_der": chain,
            }


def probe_tls(ips, hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Observe version, cipher, ALPN and certificate chain, and separately whether the chain is trusted."""
    try:
        observed = _handshake(ips, hostname, port, verify=False, timeout=timeout)
    except ScannerException:
        raise
    except ssl.SSLError as e:
        raise ScannerException(
            ScannerErrorType.TLS_NEGOTIATION_FAILURE, f"TLS handshake failed: {e.reason or e}"
        )
    except TimeoutError:
        raise ScannerException(
            ScannerErrorType.CONNECTION_TIMEOUT, f"TLS handshake to {hostname}:{port} timed out"
        )
    except OSError as e:
        raise ScannerException(
            ScannerErrorType.TARGET_UNREACHABLE, f"TLS connection to {hostname}:{port} failed: {e}"
        )

    trusted, trust_error = None, None
    try:
        _handshake(ips, hostname, port, verify=True, timeout=timeout)
        trusted = True
    except ssl.SSLCertVerificationError as e:
        trusted, trust_error = False, e.verify_message or str(e)
    except (ssl.SSLError, OSError, ScannerException):
        trusted, trust_error = None, "trust could not be determined"
    observed["trusted"] = trusted
    observed["trust_error"] = trust_error
    return observed
