"""Individual scan checks. Each returns a JSON-serialisable value or raises; the engine records the outcome.

Connections to the target always use addresses validated by resolve_target (pinned), never the name.
"""

import json
import re
import socket
import threading
import time
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
CT_DEADLINE = (
    14.0  # total seconds for the whole crt.sh call chain, below the engine's 25 s deadline
)
CT_BACKOFF = 1.5
CT_MAX_NAMES = 50
CT_MAX_RELATED = 20
_CT_RETRY_STATUS = (502, 503, 504)
# A deliberately tiny list: for these suffixes the registrable parent keeps three labels.
_TWO_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
    "net.in",
    "org.in",
    "co.nz",
    "co.jp",
    "co.za",
    "com.br",
    "com.cn",
}


class _CtError(Exception):
    """A crt.sh failure with a short, stack-free reason."""


def registrable_parent(hostname: str) -> str | None:
    """Conservative registrable parent (last 2 labels, 3 for common 2-level suffixes), or None
    when `hostname` already is that parent."""
    labels = hostname.split(".")
    keep = 3 if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES else 2
    return ".".join(labels[-keep:]) if len(labels) > keep else None


def _ct_fetch(query: str, deadline: float, cancel: threading.Event) -> list:
    """One crt.sh query with a single retry. Returns the parsed JSON list or raises _CtError."""
    for attempt in (0, 1):
        remaining = deadline - time.monotonic()
        if cancel.is_set() or remaining <= 1.0:
            raise _CtError("crt.sh lookup timed out")
        retry_reason = None
        resp = None
        try:
            resp = requests.get(
                "https://crt.sh/",
                params={"q": query, "output": "json"},
                timeout=(min(4, remaining), min(10, remaining)),
                stream=True,
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code in _CT_RETRY_STATUS:
                retry_reason = f"crt.sh answered HTTP {resp.status_code}"
            elif resp.status_code != 200:
                raise _CtError(f"crt.sh answered HTTP {resp.status_code}")
            else:
                body = b""
                for chunk in resp.iter_content(65536):
                    body += chunk
                    if len(body) > MAX_CT_BYTES:
                        raise _CtError("crt.sh response too large; result discarded")
                    if cancel.is_set() or time.monotonic() > deadline:
                        raise _CtError("crt.sh lookup timed out")
                try:
                    data = json.loads(body)
                except ValueError:  # includes JSONDecodeError and UnicodeDecodeError
                    raise _CtError("unexpected response from crt.sh") from None
                if not isinstance(data, list):
                    raise _CtError("unexpected response from crt.sh")
                return data
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            retry_reason = (
                "crt.sh did not answer in time"
                if isinstance(e, requests.exceptions.Timeout)
                else "could not connect to crt.sh"
            )
        except requests.exceptions.RequestException:
            raise _CtError("crt.sh request failed") from None
        finally:
            if resp is not None:
                resp.close()
        if attempt == 1 or deadline - time.monotonic() <= CT_BACKOFF + 1.0:
            raise _CtError(retry_reason)
        if cancel.wait(CT_BACKOFF):
            raise _CtError("crt.sh lookup timed out")
    raise _CtError("crt.sh request failed")  # pragma: no cover


def _ct_names(entries: list) -> set:
    names = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lower()
            if "*" not in name and _NAME_OK.match(name):
                names.add(name)
    return names


def check_ct_subdomains(hostname: str, cancel: threading.Event | None = None) -> dict:
    """Names seen in public Certificate Transparency logs (crt.sh). Observed data only.

    Returns {"ct_status": ok|empty|error, "ct_reason", "names": [{"name","source"}], "ct_truncated",
    "related_names"}. `names` are only ever under `hostname`; `related_names` come from the registrable
    parent, are not under `hostname`, and are informational: nothing ever connects to them.
    """
    cancel = cancel or threading.Event()
    deadline = time.monotonic() + CT_DEADLINE
    out = {
        "ct_status": "error",
        "ct_reason": None,
        "names": [],
        "ct_truncated": 0,
        "related_names": [],
    }
    try:
        found = sorted(
            n
            for n in _ct_names(_ct_fetch("%." + hostname, deadline, cancel))
            if n.endswith("." + hostname)
        )
    except _CtError as e:
        out["ct_reason"] = str(e)[:120]
        return out
    out["names"] = [{"name": n, "source": "ct_log"} for n in found[:CT_MAX_NAMES]]
    out["ct_truncated"] = max(0, len(found) - CT_MAX_NAMES)
    out["ct_status"] = "ok" if found else "empty"
    parent = registrable_parent(hostname)
    if parent:
        try:
            related = sorted(
                n
                for n in _ct_names(_ct_fetch("%." + parent, deadline, cancel))
                if n.endswith("." + parent) and n != hostname and not n.endswith("." + hostname)
            )
            out["related_names"] = related[:CT_MAX_RELATED]
        except _CtError:
            pass  # the parent lookup is a bonus; the target's own status stands
    return out


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
