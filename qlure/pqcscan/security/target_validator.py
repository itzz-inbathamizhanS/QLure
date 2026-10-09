"""Target normalisation and SSRF protection.

resolve_target() returns the validated addresses. Every connection the scanner makes afterwards must
go to one of those addresses (never re-resolve the name), otherwise a DNS-rebinding answer between
the check and the connection would bypass the validation.
"""

import ipaddress
import os
import re
import socket
from urllib.parse import urlsplit

from qlure.pqcscan.errors import ScannerErrorType, ScannerException

HOSTNAME_REGEX = re.compile(
    r"^localhost$|^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$"
)

MAX_ADDRESSES = 8


def _embedded_ipv4(ip: ipaddress.IPv6Address):
    """IPv4 address hidden inside an IPv6 address (mapped, NAT64, 6to4, Teredo), or None."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    return None


def is_safe_ip(ip_str: str, allow_local: bool = False) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    if allow_local and ip.is_loopback:
        return True
    if ip.version == 6:
        embedded = _embedded_ipv4(ip)
        if embedded is not None and not is_safe_ip(str(embedded), allow_local):
            return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return False
    # is_global is False for private, shared (CGNAT 100.64/10), documentation, benchmarking and reserved space.
    return ip.is_global


def normalize_hostname(target: str) -> str:
    """Return a lower-case ASCII hostname from a hostname or http(s) URL, or raise TARGET_INVALID.

    Ports, credentials and IP literals are rejected: the scanner assesses named services on their
    standard ports only.
    """
    if not isinstance(target, str) or not target.strip():
        raise ScannerException(ScannerErrorType.TARGET_INVALID, "Target cannot be empty.")
    text = target.strip()
    if "://" not in text:
        text = "//" + text
    try:
        parts = urlsplit(text)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise ScannerException(
            ScannerErrorType.TARGET_INVALID, "Could not parse a hostname from the target."
        )
    if parts.scheme not in ("", "http", "https"):
        raise ScannerException(
            ScannerErrorType.TARGET_INVALID, "Only http(s) URLs or plain hostnames are accepted."
        )
    if parts.username or parts.password:
        raise ScannerException(
            ScannerErrorType.TARGET_INVALID, "Credentials in the target are not allowed."
        )
    if port is not None:
        raise ScannerException(
            ScannerErrorType.TARGET_INVALID,
            "Ports are not accepted; only standard ports are assessed.",
        )
    if not hostname:
        raise ScannerException(
            ScannerErrorType.TARGET_INVALID, "Could not parse a hostname from the target."
        )
    try:
        ipaddress.ip_address(hostname)
        raise ScannerException(
            ScannerErrorType.TARGET_INVALID, "Enter a hostname, not an IP address."
        )
    except ValueError:
        pass
    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ScannerException(ScannerErrorType.TARGET_INVALID, "Invalid hostname.")
    if len(hostname) > 253 or not HOSTNAME_REGEX.match(hostname):
        raise ScannerException(
            ScannerErrorType.TARGET_INVALID, f"Invalid hostname format: {hostname[:80]}"
        )
    return hostname


def resolve_target(target: str):
    """Normalise `target`, resolve it once and require every address to be safe.

    Returns (hostname, [ip, ...]) with IPv4 addresses first. Raises ScannerException.
    """
    hostname = normalize_hostname(target)
    allow_local = os.environ.get("ALLOW_LOCAL_SCANNING", "False").lower() == "true"
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ScannerException(
            ScannerErrorType.DNS_FAILURE, f"DNS resolution failed for {hostname}: {e}"
        )
    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ScannerException(ScannerErrorType.DNS_FAILURE, f"{hostname} has no addresses.")
    for ip in ips:
        if not is_safe_ip(ip, allow_local=allow_local):
            raise ScannerException(
                ScannerErrorType.PERMISSION_DENIED,
                f"Target '{hostname}' resolves to a restricted address ({ip}); it will not be scanned.",
            )
    ips.sort(key=lambda a: ipaddress.ip_address(a).version)
    return hostname, ips[:MAX_ADDRESSES]


def validate_target(target: str) -> str:
    """Return the normalised hostname if the target is allowed to be scanned."""
    return resolve_target(target)[0]
