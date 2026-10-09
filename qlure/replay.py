"""Send a request file through the live decoys, keeping the original timestamps.

Reads HAR, JSONL or CSV. Every request goes to the web or API decoy over HTTP, so it is
logged like any other visitor. The original time travels in a header that the decoys only
honour when it carries `QLURE_REPLAY_TOKEN`; the logged event keeps it as `replay_ts`.

JSONL: one object per line with `ts`, `method`, `url` (or `path`), and optionally `headers`,
`body`, `client`. CSV: header row with `timestamp,method,url,user_agent,body,client`
(`path` may replace `url`). HAR: standard `log.entries`.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

SKIP_HEADERS = {"host", "content-length", "cookie", "connection", "accept-encoding"}
TOKEN_HEADER = "x-qlure-replay-token"  # noqa: S105  (header name, not a secret)
TS_HEADER = "x-qlure-replay-ts"


class ReplayError(Exception):
    pass


@dataclass
class Request:
    ts: datetime
    method: str
    path: str  # path plus query
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    client: str = ""


@dataclass
class Summary:
    sent: int = 0
    failed: int = 0
    skipped: int = 0
    first: datetime | None = None
    last: datetime | None = None


def _when(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.fromtimestamp(float(text), UTC)
        except ValueError as exc:
            raise ReplayError(f"unreadable timestamp: {text!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _path(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "") or "/"


def parse_har(data: dict[str, Any]) -> list[Request]:
    out = []
    for entry in data.get("log", {}).get("entries", []):
        req = entry["request"]
        headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        body = (req.get("postData") or {}).get("text", "")
        out.append(
            Request(
                _when(entry["startedDateTime"]),
                req["method"].upper(),
                _path(req["url"]),
                headers,
                body.encode(),
                entry.get("_client", ""),
            )
        )
    return out


def parse_jsonl(text: str) -> list[Request]:
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            out.append(
                Request(
                    _when(row["ts"]),
                    str(row.get("method", "GET")).upper(),
                    _path(row.get("url") or row["path"]),
                    {k.lower(): str(v) for k, v in (row.get("headers") or {}).items()},
                    str(row.get("body") or "").encode(),
                    str(row.get("client") or ""),
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ReplayError(f"line {lineno}: {exc}") from exc
    return out


def parse_csv(text: str) -> list[Request]:
    out = []
    for lineno, row in enumerate(csv.DictReader(text.splitlines()), 2):
        try:
            headers = {"user-agent": row["user_agent"]} if row.get("user_agent") else {}
            out.append(
                Request(
                    _when(row.get("timestamp") or row["ts"]),
                    (row.get("method") or "GET").upper(),
                    _path(row.get("url") or row["path"]),
                    headers,
                    (row.get("body") or "").encode(),
                    row.get("client") or "",
                )
            )
        except (KeyError, ValueError) as exc:
            raise ReplayError(f"row {lineno}: {exc}") from exc
    return out


def load(path: Path) -> list[Request]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".har":
        requests = parse_har(json.loads(text))
    elif suffix in (".jsonl", ".ndjson"):
        requests = parse_jsonl(text)
    elif suffix == ".csv":
        requests = parse_csv(text)
    else:
        raise ReplayError("expected a .har, .jsonl or .csv file")
    return sorted(requests, key=lambda r: r.ts)


def run(
    requests: list[Request],
    web_url: str,
    api_url: str,
    token: str,
    client: httpx.Client | None = None,
) -> Summary:
    """Send each request in time order, one cookie jar per visitor (`client`, else user agent)."""
    if not token:
        raise ReplayError("set QLURE_REPLAY_TOKEN (the decoys ignore replay times without it)")
    summary = Summary()
    jars: dict[str, httpx.Client] = {}
    for req in requests:
        who = req.client or req.headers.get("user-agent", "")
        visitor = jars.get(who)
        if visitor is None:  # one client per visitor, created only once
            visitor = jars[who] = client or httpx.Client(timeout=10, follow_redirects=False)
        base = api_url if req.path.startswith("/api/") else web_url
        headers = {k: v for k, v in req.headers.items() if k not in SKIP_HEADERS}
        headers[TOKEN_HEADER] = token
        headers[TS_HEADER] = req.ts.isoformat()
        try:
            visitor.request(
                req.method, base.rstrip("/") + req.path, headers=headers, content=req.body
            )
        except httpx.HTTPError:
            summary.failed += 1
            continue
        summary.sent += 1
        summary.first = summary.first or req.ts
        summary.last = req.ts
    for visitor in set(jars.values()):
        if client is None:
            visitor.close()
    return summary
