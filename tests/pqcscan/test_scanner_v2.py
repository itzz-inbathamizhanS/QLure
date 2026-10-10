import pytest

from qlure.pqcscan.crypto.pqc_detector import PQCDetector
from qlure.pqcscan.errors import ScannerErrorType, ScannerException
from qlure.pqcscan.security import target_validator
from qlure.pqcscan.security.target_validator import validate_target


def test_target_validator_valid(monkeypatch):
    # A fixed public answer instead of a real DNS lookup, so the test needs no network.
    monkeypatch.setattr(
        target_validator,
        "_getaddrinfo_with_timeout",
        lambda host: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    assert validate_target("example.com") == "example.com"
    assert validate_target("https://example.com") == "example.com"


def test_target_validator_ssrf():
    with pytest.raises(ScannerException) as excinfo:
        # Assuming ALLOW_LOCAL_SCANNING is False in tests
        validate_target("localhost")
    assert excinfo.value.error_type == ScannerErrorType.PERMISSION_DENIED


def test_pqc_detector_classification():
    detector = PQCDetector()

    # Classical test
    res1 = detector.classify_key_establishment("TLS_AES_128_GCM_SHA256", "SECP256R1")
    assert res1["classification"] == "CLASSICAL"

    # Hybrid test
    res2 = detector.classify_key_establishment("TLS_AES_128_GCM_SHA256", "X25519_KYBER768")
    assert res2["classification"] == "HYBRID"

    # PQC Signature
    res3 = detector.classify_authentication("ML-DSA-44")
    assert res3["classification"] == "PQC"
