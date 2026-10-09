"""Q-CAPS scanner engine (result schema v2).

Every value in a result was observed by one of the checks below. A check that fails or is skipped is
reported in `checks` with its reason, and nothing is inferred or invented to fill the gap. The target
is resolved and validated once (scanner.security.target_validator); all connections are pinned to
those addresses.
"""

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import UTC, datetime

from qlure.pqcscan import checks
from qlure.pqcscan.crypto.certificate_probe import parse_certificate
from qlure.pqcscan.crypto.pqc_detector import PQCDetector
from qlure.pqcscan.crypto.raw_tls_client import LEGACY_TLS10, LEGACY_TLS11, RawTLSProbe
from qlure.pqcscan.crypto.tls_probe import classify_tls12_cipher, probe_tls
from qlure.pqcscan.errors import ScannerException
from qlure.pqcscan.findings import derive_findings
from qlure.pqcscan.security.target_validator import resolve_target

SCANNER_VERSION = "2.0.0"
SCHEMA_VERSION = 2
DEADLINE_SECONDS = 25.0

_detector = PQCDetector()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _error(target: str, message: str) -> dict:
    """A scan that could not run. Not a result: there is nothing to score, list or award XP for."""
    return {"target_url": target, "scan_timestamp": _now(), "error": message}


def _timed(fn):
    start = time.monotonic()
    try:
        value = fn()
        status, reason = "ok", None
    except ScannerException as e:
        value, status, reason = None, "failed", e.message
    except Exception as e:  # a third-party library failing must not abort the scan
        value, status, reason = None, "failed", f"{type(e).__name__}: {str(e)[:120]}"
    return {
        "status": status,
        "reason": reason,
        "value": value,
        "duration_ms": int((time.monotonic() - start) * 1000),
    }


def _ct_summary(outcome) -> dict:
    """Structured certificate-log status from the ct_subdomains outcome (a failed or timed-out check is an error)."""
    value = outcome["value"]
    if outcome["status"] == "ok" and isinstance(value, dict):
        return value
    return {
        "ct_status": "error",
        "ct_reason": (outcome["reason"] or "lookup failed")[:120],
        "names": [],
        "ct_truncated": 0,
        "related_names": [],
    }


def _probe_legacy(host, ips) -> dict:
    probe = RawTLSProbe(host, ips)
    return {
        "tls1_0": probe.probe_legacy_version(LEGACY_TLS10)["accepted"],
        "tls1_1": probe.probe_legacy_version(LEGACY_TLS11)["accepted"],
    }


def _key_exchange(handshake, probe) -> dict:
    """Combine the handshake and the HelloRetryRequest probe into one honest key-exchange statement."""
    kex = {
        "classification": "unknown",
        "preferred_group": None,
        "preferred_group_name": None,
        "hybrid_pqc_supported": None,
        "forward_secrecy": None,
        "kex": None,
        "method": None,
        "evidence": [],
    }
    cipher = (handshake or {}).get("cipher")
    version = (handshake or {}).get("version")
    if probe and probe.get("preferred_group") is not None:
        group = _detector.classify_group(probe["preferred_group"])
        kex.update(
            preferred_group="0x%04x" % probe["preferred_group"],
            preferred_group_name=group["name"],
            hybrid_pqc_supported=probe["hybrid_pqc_supported"],
            forward_secrecy=True,
            kex="TLS 1.3 key share",
            method="tls13_hello_retry_request",
        )
        kex["preferred_group"] = group["name"] or kex["preferred_group"]
        if group["class"] == "HYBRID_PQC":
            kex["classification"] = "hybrid_pqc"
        elif group["class"] == "CLASSICAL":
            kex["classification"] = (
                "hybrid_pqc_available" if probe["hybrid_pqc_supported"] else "classical"
            )
        kex["evidence"].append(
            f"Server selected group {group['name']} from a ClientHello listing hybrid and classical groups"
        )
        if probe["hybrid_pqc_supported"] is False:
            kex["evidence"].append("A ClientHello offering only hybrid ML-KEM groups was rejected")
        elif kex["classification"] == "hybrid_pqc_available":
            kex["evidence"].append(
                "Hybrid ML-KEM groups are accepted when offered alone, but are not the first choice"
            )
    elif cipher and version in ("TLSv1.2", "TLSv1.1", "TLSv1"):
        info = classify_tls12_cipher(cipher)
        kex.update(
            classification="classical",
            hybrid_pqc_supported=False,
            forward_secrecy=info["forward_secrecy"],
            kex=info["kex"],
            method="tls12_cipher_suite",
        )
        kex["evidence"].append(
            f"{version} cipher suite {cipher} uses {info['kex']} key exchange; TLS before 1.3 has no hybrid PQC groups"
        )
    else:
        kex["evidence"].append("The key exchange group could not be observed")
    kex["evidence"].append(
        "Observed at the endpoint that answered; for CDN-fronted sites this is the edge, not necessarily the origin"
    )
    return kex


def _posture(kex, cert) -> dict:
    cls = kex["classification"]
    kx_label = {
        "hybrid_pqc": "hybrid post-quantum",
        "hybrid_pqc_available": "classical preferred, hybrid post-quantum accepted",
        "classical": "classical only",
        "unknown": "not determined",
    }[cls]
    auth = (cert or {}).get("signature_class") or "unknown"
    group = kex.get("preferred_group_name")
    auth_detail = ""
    if cert:
        size = cert.get("curve") or cert.get("key_size")
        auth_detail = (
            f" ({cert.get('public_key_algorithm')} {size})"
            if size
            else f" ({cert.get('public_key_algorithm')})"
        )
    summary = (
        f"Key exchange: {kx_label}"
        + (f" ({group})" if group else "")
        + f". Certificate authentication: {auth}{auth_detail if cert else ''}."
    )
    return {"key_exchange": cls, "authentication": auth, "summary": summary}


def analyze_domain(target: str, mode: str = "standard", authorization: dict = None) -> dict:
    """Scan `target`. mode is standard (passive checks) or full (adds active checks; needs verified ownership)."""
    authorization = authorization or {}
    try:
        host, ips = resolve_target(target)
    except ScannerException as e:
        return _error(target, e.message)
    full = mode == "full"
    if full and not authorization.get("ownership_verified"):
        return _error(host, "Full scans require verified ownership of the domain")

    cancel = threading.Event()  # tells the crt.sh loop to stop once the deadline has passed
    jobs = {
        "dns": lambda: checks.check_dns(host),
        "whois": lambda: checks.check_whois(host),
        "http_headers": lambda: checks.check_http(host, ips),
        "tls_handshake": lambda: probe_tls(ips, host),
        "tls_key_exchange": lambda: RawTLSProbe(host, ips).probe_key_exchange(),
        "ct_subdomains": lambda: checks.check_ct_subdomains(host, cancel),
    }
    if full:
        jobs.update(
            {
                "ports": lambda: checks.check_ports(ips),
                "dns_wordlist": lambda: checks.check_wordlist_subdomains(host),
                "legacy_tls": lambda: _probe_legacy(host, ips),
            }
        )

    pool = ThreadPoolExecutor(max_workers=10)
    futures = {name: pool.submit(_timed, fn) for name, fn in jobs.items()}
    wait(futures.values(), timeout=DEADLINE_SECONDS)
    cancel.set()
    pool.shutdown(
        wait=False, cancel_futures=True
    )  # stragglers are bounded by their own socket timeouts

    outcomes = {}
    for name, fut in futures.items():
        if fut.done():
            outcomes[name] = fut.result()
        else:
            outcomes[name] = {
                "status": "failed",
                "reason": "timed out",
                "value": None,
                "duration_ms": int(DEADLINE_SECONDS * 1000),
            }
    val = lambda n: (
        outcomes[n]["value"] if n in outcomes and outcomes[n]["status"] == "ok" else None
    )  # noqa: E731

    handshake, probe = val("tls_handshake"), val("tls_key_exchange")
    cert, chain, cert_check = (
        None,
        [],
        {"status": "failed", "reason": "no TLS handshake", "duration_ms": 0},
    )
    if handshake and handshake["chain_der"]:
        started = time.monotonic()
        try:
            parsed = [parse_certificate(d) for d in handshake["chain_der"][:5]]
            cert, chain = (
                parsed[0],
                [
                    {
                        k: c[k]
                        for k in (
                            "subject_cn",
                            "issuer_cn",
                            "public_key_algorithm",
                            "signature_algorithm",
                        )
                    }
                    for c in parsed
                ],
            )
            cert_check = {"status": "ok", "reason": None}
        except ScannerException as e:
            cert_check = {"status": "failed", "reason": e.message}
        cert_check["duration_ms"] = int((time.monotonic() - started) * 1000)
    elif handshake:
        cert_check["reason"] = "the server sent no certificate"

    kex = _key_exchange(handshake, probe) if (handshake or probe) else None
    tls = None
    if handshake or probe:
        tls = {
            "version": (handshake or {}).get("version"),
            "cipher_suite": (handshake or {}).get("cipher"),
            "alpn": (handshake or {}).get("alpn"),
            "trusted": (handshake or {}).get("trusted"),
            "trust_error": (handshake or {}).get("trust_error"),
            "key_exchange": kex,
            "certificate": cert and {**cert, "chain": chain},
            "legacy_protocols": val("legacy_tls"),
        }
        if tls["version"] is None and probe and probe.get("tls13_supported"):
            tls["version"] = "TLSv1.3"

    ct = _ct_summary(outcomes["ct_subdomains"])
    subdomains = {}
    for entry in ct["names"] + (val("dns_wordlist") or []):
        subdomains.setdefault(entry["name"], entry)

    check_report = {
        n: {
            "status": o["status"],
            **({"reason": o["reason"]} if o["reason"] else {}),
            "duration_ms": o["duration_ms"],
        }
        for n, o in outcomes.items()
        if n != "tls_handshake"
    }
    check_report["tls_handshake"] = {
        "status": outcomes["tls_handshake"]["status"],
        "duration_ms": outcomes["tls_handshake"]["duration_ms"],
        **(
            {"reason": outcomes["tls_handshake"]["reason"]}
            if outcomes["tls_handshake"]["reason"]
            else {}
        ),
    }
    check_report["ct_subdomains"].update(
        status="failed" if ct["ct_status"] == "error" else "ok",
        ct_status=ct["ct_status"],
        **({"reason": ct["ct_reason"]} if ct["ct_status"] == "error" else {}),
    )
    check_report["certificate"] = cert_check
    if not full:
        for name in ("ports", "dns_wordlist", "legacy_tls"):
            check_report[name] = {
                "status": "requires_verification",
                "reason": "Active checks need verified ownership of the domain",
                "duration_ms": 0,
            }

    result = {
        "target_url": host,
        "scan_timestamp": _now(),
        "schema_version": SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "authorization": {
            "mode": "full" if full else "standard",
            "ownership_verified": bool(authorization.get("ownership_verified")),
            "verified_domain": authorization.get("verified_domain"),
        },
        "resolved_addresses": ips,
        "checks": check_report,
        "dns": val("dns"),
        "whois": val("whois"),
        "http": val("http_headers"),
        "tls": tls,
        "pqc_posture": _posture(kex, cert) if kex else None,
        "subdomains": sorted(subdomains.values(), key=lambda s: s["name"]),
        "ct_status": ct["ct_status"],
        "ct_reason": ct["ct_reason"],
        "ct_truncated": ct["ct_truncated"],
        "related_names": ct["related_names"],
    }
    if val("ports"):
        result["ports"] = val("ports")
    result["findings"] = derive_findings(result)
    return result


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    print(json.dumps(analyze_domain(args[0] if args else "example.com"), indent=2))
