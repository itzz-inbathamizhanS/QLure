"""Individual scan checks. Each returns a JSON-serialisable value or raises; the engine records the outcome.

Connections to the target always use addresses validated by resolve_target (pinned), never the name.
"""

import json
import re
import socket
import warnings
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import requests
import urllib3

from qlure.pqcscan.crypto.tls_probe import observation_context
from qlure.pqcscan.errors import ScannerErrorType, ScannerException
from qlure.pqcscan.security.target_validator import resolve_target

USER_AGENT = "Q-CAPS-Scanner/2 (authorised security assessment)"
MAX_REDIRECTS = 3

# Active checks, only run for domains whose ownership has been verified.
FULL_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}
WORDLIST = ["www", "mail", "api", "dev", "staging", "test", "blog", "vpn", "admin", "portal"]


# ---------------------------------------------------------------- DNS


def _query(name, rtype, resolver):
    """Return (records as text, error or None). NXDOMAIN and empty answers are not errors."""
    try:
        return [r.to_text() for r in resolver.resolve(name, rtype)], None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as e:
        return [], type(e).__name__


def _txt(records):
    return [r.replace('" "', "").strip('"') for r in records]


def check_dns(hostname: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    out, errors = {}, {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        out[rtype], err = _query(hostname, rtype, resolver)
        if err:
            errors[rtype] = err
    out["TXT"] = _txt(out["TXT"])
    out["spf"] = next((t for t in out["TXT"] if t.lower().startswith("v=spf1")), None)
    dmarc, err = _query("_dmarc." + hostname, "TXT", resolver)
    if err:
        errors["DMARC"] = err
    out["dmarc"] = next((t for t in _txt(dmarc) if t.lower().startswith("v=dmarc1")), None)
    out["errors"] = errors
    if len(errors) >= 4:
        raise ScannerException(
            ScannerErrorType.TOOL_FAILURE,
            "DNS resolver did not answer: " + ", ".join(sorted(set(errors.values()))),
        )
    return out


# ---------------------------------------------------------------- HTTP


def _parse_hsts(value):
    if not value:
        return {"present": False, "max_age": None, "include_subdomains": False, "preload": False}
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    return {
        "present": True,
        "max_age": int(m.group(1)) if m else None,
        "include_subdomains": bool(re.search(r"includeSubDomains", value, re.I)),
        "preload": bool(re.search(r"preload", value, re.I)),
    }


def analyze_headers(headers) -> dict:
    """headers: any mapping with case-insensitive lookups (urllib3 HTTPHeaderDict, requests CaseInsensitiveDict)."""
    csp = headers.get("content-security-policy") or ""
    return {
        "strict_transport_security": _parse_hsts(headers.get("strict-transport-security")),
        "content_security_policy": {
            "present": bool(csp),
            "frame_ancestors": "frame-ancestors" in csp.lower(),
        },
        "x_content_type_options": {
            "present": (headers.get("x-content-type-options") or "").lower() == "nosniff"
        },
        "x_frame_options": {"present": bool(headers.get("x-frame-options"))},
        "referrer_policy": {"present": bool(headers.get("referrer-policy"))},
    }


def _fetch_once(hostname, ips, path="/"):
    """One GET over TLS to a pinned address. The body is never read."""
    pool = urllib3.HTTPSConnectionPool(
        host=ips[0],
        port=443,
        server_hostname=hostname,
        assert_hostname=False,
        ssl_context=observation_context(),
        timeout=urllib3.Timeout(connect=4.0, read=5.0),
        retries=False,
    )
    try:
        resp = pool.request(
            "GET",
            path,
            headers={"Host": hostname, "User-Agent": USER_AGENT, "Accept": "*/*"},
            redirect=False,
            preload_content=False,
        )
        try:
            return resp.status, resp.headers
        finally:
            resp.release_conn()
    finally:
        pool.close()


def check_http(hostname: str, ips) -> dict:
    """GET / over HTTPS, following at most 3 redirects; every redirect target is re-validated and re-pinned."""
    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
    host, host_ips, redirects = hostname, ips, []
    for _ in range(MAX_REDIRECTS + 1):
        try:
            status, headers = _fetch_once(host, host_ips)
        except urllib3.exceptions.HTTPError as e:
            raise ScannerException(
                ScannerErrorType.TARGET_UNREACHABLE, f"HTTPS request failed: {type(e).__name__}"
            )
        location = headers.get("location")
        if status in (301, 302, 303, 307, 308) and location:
            target = urlsplit(location)
            redirects.append({"status": status, "to": location[:200]})
            if target.scheme == "https" and len(redirects) <= MAX_REDIRECTS:
                try:
                    host, host_ips = resolve_target(target.hostname or host)
                    continue
                except ScannerException as e:
                    redirects[-1]["blocked"] = e.message
        break
    return {
        "final_host": host,
        "status": status,
        "redirects": redirects,
        "headers": analyze_headers(headers),
    }


# ---------------------------------------------------------------- WHOIS / CT / subdomains


def _iso(value):
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def check_whois(hostname: str) -> dict:
    import whois  # imported lazily: it is slow to import and only needed here

    info = whois.whois(hostname)
    org = info.org
    return {
        "registrar": info.registrar or None,
        "creation_date": _iso(info.creation_date),
        "expiration_date": _iso(info.expiration_date),
        "organization": org if isinstance(org, str) else None,
    }


_NAME_OK = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
MAX_CT_BYTES = 6_000_000


def check_ct_subdomains(hostname: str) -> list:
    """Names seen in public Certificate Transparency logs (crt.sh). Observed data only."""
    resp = requests.get(
        "https://crt.sh/",
        params={"q": "%." + hostname, "output": "json"},
        timeout=(4, 10),
        stream=True,
        headers={"User-Agent": USER_AGENT},
    )
    if resp.status_code != 200:
        raise ScannerException(
            ScannerErrorType.TOOL_FAILURE, f"crt.sh answered HTTP {resp.status_code}"
        )
    body = b""
    for chunk in resp.iter_content(65536):
        body += chunk
        if len(body) > MAX_CT_BYTES:
            raise ScannerException(
                ScannerErrorType.TOOL_FAILURE, "crt.sh response too large; result discarded"
            )
    names = set()
    for entry in json.loads(body or b"[]"):
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lower()
            if name.endswith("." + hostname) and "*" not in name and _NAME_OK.match(name):
                names.add(name)
    return [{"name": n, "source": "ct_log"} for n in sorted(names)[:50]]


def check_wordlist_subdomains(hostname: str) -> list:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.0
    found = []
    for prefix in WORDLIST:
        name = f"{prefix}.{hostname}"
        a, _ = _query(name, "A", resolver)
        aaaa, _ = _query(name, "AAAA", resolver)
        if a or aaaa:
            found.append({"name": name, "source": "dns_wordlist"})
    return found


# ---------------------------------------------------------------- active checks (verified domains only)


def _probe_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            return "OPEN"
    except ConnectionRefusedError:
        return "CLOSED"
    except OSError:
        return "FILTERED"  # timed out or unreachable: the port state is not known


def check_ports(ips) -> dict:
    ip = ips[0]
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(lambda p: _probe_port(ip, p), FULL_PORTS))
    return {
        "address": ip,
        "ports": {
            str(p): {"service": FULL_PORTS[p], "state": s} for p, s in zip(FULL_PORTS, states)
        },
    }
