"""Findings derived from observed scan data.

A finding is only produced when the check that would support it ran successfully; a failed or
skipped check yields no finding (and the checks section of the result says why). Severity rules:

  high    TLS older than 1.2, RSA key transport (no forward secrecy), untrusted or expired certificate,
          exposed Telnet / SMB / RDP / database port (verified full scans only)
  medium  classical-only key exchange (harvest-now-decrypt-later exposure), certificate expiring in
          under 14 days, missing HSTS, TLS 1.0 / 1.1 accepted
  low     missing CSP / X-Content-Type-Options / clickjacking protection, no DMARC, weak or absent SPF
  info    classical certificate signature (planning item), no CAA record, hybrid PQC in use (positive)

There is deliberately no aggregate score: a single number hides which evidence drove it.
"""

RISKY_PORTS = {
    "23": "Telnet",
    "445": "SMB",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
}


def _f(fid, category, severity, title, detail, evidence, recommendation, algorithm=None):
    return {
        "id": fid,
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "recommendation": recommendation,
        "algorithm": algorithm,
    }


def _ok(result, name):
    return (result.get("checks", {}).get(name) or {}).get("status") == "ok"


def derive_findings(result: dict) -> list:
    findings = []
    tls = result.get("tls") or {}
    kex = tls.get("key_exchange") or {}
    cert = tls.get("certificate") or {}

    # ---- key exchange (confidentiality against harvest-now-decrypt-later)
    if _ok(result, "tls_key_exchange") or _ok(result, "tls_handshake"):
        cls = kex.get("classification")
        if cls == "hybrid_pqc":
            findings.append(
                _f(
                    "pqc.kex.hybrid",
                    "pqc",
                    "info",
                    "Hybrid post-quantum key exchange in use",
                    "The server selected a hybrid group that combines a classical and a post-quantum (ML-KEM) key exchange.",
                    f"Preferred group: {kex.get('preferred_group')}",
                    "No action needed; keep the group enabled.",
                    kex.get("preferred_group"),
                )
            )
        elif cls == "hybrid_pqc_available":
            findings.append(
                _f(
                    "pqc.kex.hybrid_available",
                    "pqc",
                    "info",
                    "Hybrid post-quantum key exchange supported but not preferred",
                    "The server accepts a hybrid ML-KEM group when it is the only one offered, but chooses a classical group "
                    "when both are available, so most clients will not use post-quantum protection.",
                    f"Preferred group: {kex.get('preferred_group')}",
                    "Move a hybrid group to the top of the server group preference list.",
                    kex.get("preferred_group_name"),
                )
            )
        elif cls == "classical":
            ev = f"Preferred group: {kex.get('preferred_group') or tls.get('cipher_suite')}; hybrid PQC supported: {kex.get('hybrid_pqc_supported')}"
            findings.append(
                _f(
                    "pqc.kex.classical_only",
                    "pqc",
                    "medium",
                    "Key exchange is not post-quantum protected",
                    "Traffic protected only by classical key exchange can be recorded now and decrypted later by a "
                    "future quantum computer (harvest-now-decrypt-later).",
                    ev,
                    "Enable a hybrid group such as X25519MLKEM768 (TLS 1.3) on the server, load balancer or CDN.",
                    kex.get("preferred_group_name") or kex.get("kex") or "ECDHE",
                )
            )
        if kex.get("forward_secrecy") is False:
            findings.append(
                _f(
                    "tls.kex.no_forward_secrecy",
                    "tls",
                    "high",
                    "RSA key transport: no forward secrecy",
                    "The negotiated cipher suite encrypts the session key with the server RSA key, so one key compromise "
                    "exposes all recorded sessions.",
                    f"Cipher suite: {tls.get('cipher_suite')}",
                    "Disable static-RSA cipher suites; prefer ECDHE with TLS 1.3.",
                    "RSA",
                )
            )

    # ---- protocol versions
    if _ok(result, "tls_handshake"):
        if tls.get("version") in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"):
            findings.append(
                _f(
                    "tls.version.obsolete",
                    "tls",
                    "high",
                    "Obsolete TLS version negotiated",
                    "TLS below 1.2 has known weaknesses and is deprecated.",
                    f"Negotiated: {tls.get('version')}",
                    "Require TLS 1.2 or newer; prefer TLS 1.3.",
                )
            )
    legacy = tls.get("legacy_protocols") or {}
    for label, key in (("TLS 1.0", "tls1_0"), ("TLS 1.1", "tls1_1")):
        if legacy.get(key) is True:
            findings.append(
                _f(
                    f"tls.legacy.{key}",
                    "tls",
                    "medium",
                    f"{label} is accepted",
                    "The server completes a handshake with a deprecated protocol version.",
                    f"ServerHello selected {label} in response to a {label} ClientHello",
                    f"Disable {label} on the server.",
                )
            )

    # ---- certificate
    if _ok(result, "certificate") and cert:
        if tls.get("trusted") is False:
            findings.append(
                _f(
                    "cert.untrusted",
                    "certificate",
                    "high",
                    "Certificate is not trusted",
                    "Clients validating the chain against public roots reject this certificate.",
                    f"Validation error: {tls.get('trust_error')}",
                    "Install a certificate from a public CA with a complete chain.",
                )
            )
        days = cert.get("days_remaining")
        if isinstance(days, int):
            if days < 0:
                findings.append(
                    _f(
                        "cert.expired",
                        "certificate",
                        "high",
                        "Certificate has expired",
                        "",
                        f"Expired {-days} day(s) ago ({cert.get('not_after')})",
                        "Renew the certificate immediately.",
                    )
                )
            elif days < 14:
                findings.append(
                    _f(
                        "cert.expiring",
                        "certificate",
                        "medium",
                        "Certificate expires soon",
                        "",
                        f"{days} day(s) remaining ({cert.get('not_after')})",
                        "Renew the certificate; automate renewal.",
                    )
                )
        if cert.get("signature_class") == "classical":
            alg = cert.get("public_key_algorithm")
            detail = (
                f"{alg} {cert.get('key_size') or ''} / {cert.get('signature_algorithm')}".replace(
                    "  ", " "
                )
            )
            findings.append(
                _f(
                    "pqc.auth.classical_certificate",
                    "pqc",
                    "info",
                    "Certificate uses classical signatures",
                    "A quantum computer could forge classical signatures. Authentication is only attackable in "
                    "real time, so this is a migration-planning item, not an urgent exposure.",
                    detail,
                    "Track CA support for ML-DSA certificates; plan crypto-agility.",
                    alg,
                )
            )

    # ---- HTTP headers
    if _ok(result, "http_headers"):
        h = (result.get("http") or {}).get("headers") or {}
        if not h.get("strict_transport_security", {}).get("present"):
            findings.append(
                _f(
                    "http.hsts.missing",
                    "http",
                    "medium",
                    "HSTS is not set",
                    "Browsers can be downgraded to HTTP.",
                    "No Strict-Transport-Security header",
                    "Send Strict-Transport-Security with a long max-age.",
                )
            )
        if not h.get("content_security_policy", {}).get("present"):
            findings.append(
                _f(
                    "http.csp.missing",
                    "http",
                    "low",
                    "No Content-Security-Policy",
                    "",
                    "No Content-Security-Policy header",
                    "Define a CSP to restrict script and frame sources.",
                )
            )
        if not h.get("x_content_type_options", {}).get("present"):
            findings.append(
                _f(
                    "http.xcto.missing",
                    "http",
                    "low",
                    "X-Content-Type-Options not set",
                    "",
                    "No nosniff header",
                    "Send X-Content-Type-Options: nosniff.",
                )
            )
        if not h.get("x_frame_options", {}).get("present") and not h.get(
            "content_security_policy", {}
        ).get("frame_ancestors"):
            findings.append(
                _f(
                    "http.framing.missing",
                    "http",
                    "low",
                    "No clickjacking protection",
                    "",
                    "No X-Frame-Options and no CSP frame-ancestors",
                    "Send X-Frame-Options or CSP frame-ancestors.",
                )
            )

    # ---- DNS / email posture
    if _ok(result, "dns"):
        d = result.get("dns") or {}
        errs = d.get("errors") or {}
        if "DMARC" not in errs and not d.get("dmarc"):
            findings.append(
                _f(
                    "dns.dmarc.missing",
                    "dns",
                    "low",
                    "No DMARC policy",
                    "Spoofed mail from this domain is not constrained.",
                    "No v=DMARC1 TXT record at _dmarc",
                    "Publish a DMARC record (start with p=none and monitor).",
                )
            )
        spf = d.get("spf")
        if "TXT" not in errs and (not spf or "+all" in spf.lower()):
            findings.append(
                _f(
                    "dns.spf.weak",
                    "dns",
                    "low",
                    "SPF missing or permissive",
                    "",
                    spf or "No v=spf1 TXT record",
                    "Publish an SPF record ending in -all or ~all.",
                )
            )
        if "CAA" not in errs and not d.get("CAA"):
            findings.append(
                _f(
                    "dns.caa.missing",
                    "dns",
                    "info",
                    "No CAA record",
                    "Any CA may issue certificates for this domain.",
                    "No CAA records",
                    "Publish CAA records naming the CAs you use.",
                )
            )

    # ---- exposure (verified full scans only)
    if _ok(result, "ports"):
        for port, meta in ((result.get("ports") or {}).get("ports") or {}).items():
            if meta.get("state") == "OPEN" and port in RISKY_PORTS:
                findings.append(
                    _f(
                        f"exposure.port.{port}",
                        "exposure",
                        "high",
                        f"{RISKY_PORTS[port]} reachable from the internet",
                        "",
                        f"TCP {port} is open on {(result.get('ports') or {}).get('address')}",
                        "Restrict the service to private networks or a VPN.",
                    )
                )
    return findings
