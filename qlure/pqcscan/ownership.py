"""Stateless proof of domain ownership for active (full) scans.

The user publishes a DNS TXT record whose value is an HMAC bound to their user id and the domain, so
nothing needs to be stored and a record published for one account is useless to another. The record
is checked live on every full scan, so deleting it revokes access. Rotating QCAPS_JWT_SECRET
invalidates all tokens.
"""

import base64
import hashlib
import hmac

import dns.exception
import dns.resolver

LABEL = "_qcaps-verify"
PREFIX = "qcaps-verify="


def token(secret: str, user_id, domain: str) -> str:
    mac = hmac.new(
        secret.encode(), f"qcaps-domain-verify:v1:{user_id}:{domain}".encode(), hashlib.sha256
    ).digest()
    return base64.b32encode(mac)[:32].decode().lower()


def record_name(domain: str) -> str:
    return f"{LABEL}.{domain}"


def record_value(secret: str, user_id, domain: str) -> str:
    return PREFIX + token(secret, user_id, domain)


def candidate_domains(hostname: str):
    """The host and its parents that still have at least two labels (a record may sit on any of them)."""
    labels = hostname.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _lookup_txt(name: str):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    try:
        return [r.to_text().replace('" "', "").strip('"') for r in resolver.resolve(name, "TXT")]
    except dns.exception.DNSException:
        return []


def check_ownership(secret: str, user_id, hostname: str, txt_lookup=_lookup_txt) -> dict:
    for domain in candidate_domains(hostname):
        expected = record_value(secret, user_id, domain)
        if any(hmac.compare_digest(v.strip(), expected) for v in txt_lookup(record_name(domain))):
            return {"verified": True, "domain": domain, "record_name": record_name(domain)}
    return {"verified": False, "domain": None, "record_name": None}
