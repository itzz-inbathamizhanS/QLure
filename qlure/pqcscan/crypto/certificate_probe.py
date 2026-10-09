"""X.509 parsing into the flat structure used by the v2 scan result."""

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from qlure.pqcscan.crypto.pqc_detector import PQCDetector
from qlure.pqcscan.errors import ScannerErrorType, ScannerException

_detector = PQCDetector()


def _public_key_info(key):
    if isinstance(key, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "key_size": key.key_size, "curve": None}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"algorithm": "ECDSA", "key_size": key.key_size, "curve": key.curve.name}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "key_size": 256, "curve": "ed25519"}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "key_size": 456, "curve": "ed448"}
    if isinstance(key, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "key_size": key.key_size, "curve": None}
    return {"algorithm": key.__class__.__name__, "key_size": None, "curve": None}


def _name(attrs, oid):
    values = attrs.get_attributes_for_oid(oid)
    return values[0].value if values else None


def parse_certificate(der_cert: bytes, now: datetime = None) -> dict:
    try:
        cert = x509.load_der_x509_certificate(der_cert)
    except Exception as e:
        raise ScannerException(
            ScannerErrorType.CERTIFICATE_PARSE_FAILURE, f"Failed to parse certificate: {e}"
        )
    now = now or datetime.now(UTC)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_name = getattr(cert.signature_algorithm_oid, "_name", None) or sig_oid
    sig_class = _detector.classify_signature_oid(sig_oid)
    pub = _public_key_info(cert.public_key())
    try:
        sans = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {
        "subject": cert.subject.rfc4514_string(),
        "subject_cn": _name(cert.subject, x509.NameOID.COMMON_NAME),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": _name(cert.issuer, x509.NameOID.COMMON_NAME),
        "issuer_org": _name(cert.issuer, x509.NameOID.ORGANIZATION_NAME),
        "sans": list(sans)[:25],
        "san_count": len(sans),
        "public_key_algorithm": pub["algorithm"],
        "key_size": pub["key_size"],
        "curve": pub["curve"],
        "signature_algorithm": sig_name,
        "signature_class": "pqc" if sig_class["class"] == "PQC" else "classical",
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "self_signed": cert.subject == cert.issuer,
    }
