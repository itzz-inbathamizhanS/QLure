"""Web admin portal decoy (port 8080).

Emulate, never execute: every response comes from a template. Every request is
logged through qlure.events.emit before the response goes out.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from qlure.events import Action, Service, emit

COMPANY = "Veltrix Logistics"  # fictional company used across every decoy
SESSION_COOKIE = "VLXSESSID"
SERVER_HEADER = "nginx/1.24.0"
MAX_BODY_BYTES = 64 * 1024
BODY_PREVIEW_CHARS = 2048
FP_HEADERS = ("user-agent", "accept", "accept-language", "accept-encoding")
LOGGED_HEADERS = FP_HEADERS + ("referer", "content-type", "x-forwarded-for", "cookie")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def client_fingerprint(request: Request) -> str:
    raw = "|".join(request.headers.get(name, "") for name in FP_HEADERS)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _session_id(request: Request) -> tuple[str, bool]:
    current = request.cookies.get(SESSION_COOKIE, "")
    if _SESSION_RE.match(current):
        return current, False
    return secrets.token_urlsafe(24), True


def _body_summary(body: bytes) -> dict[str, Any]:
    return {
        "body_len": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_preview": body[:BODY_PREVIEW_CHARS].decode("utf-8", errors="replace"),
    }


def _credential(body: bytes) -> dict[str, str]:
    fields = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {
        "username": fields.get("username", [""])[0],
        "password": fields.get("password", [""])[0],
    }


async def _read_capped(request: Request) -> bytes | None:
    """Read the body, giving up (None) past MAX_BODY_BYTES even without a Content-Length."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


@app.middleware("http")
async def observe(request: Request, call_next):
    body = await _read_capped(request)
    if body is None:
        body = b""
        response: Response = PlainTextResponse("413 Request Entity Too Large", status_code=413)
    else:
        # Handlers never read the body; the middleware has already consumed the stream.
        response = await call_next(request)

    session_id, new_session = _session_id(request)
    if new_session:
        response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    response.headers["server"] = SERVER_HEADER

    base = {
        "service": Service.WEB,
        "src_ip": request.client.host if request.client else "0.0.0.0",  # noqa: S104
        # Behind the gateway uvicorn reports port 0: the original port is not forwarded.
        "src_port": (request.client.port or None) if request.client else None,
        "client_fp": client_fingerprint(request),
        "session_id": session_id,
        "request": {
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "http_version": request.scope.get("http_version"),
            "headers": {k: v for k, v in request.headers.items() if k in LOGGED_HEADERS},
            **_body_summary(body),
        },
        "response": {
            "status": response.status_code,
            "location": response.headers.get("location"),
        },
    }
    emit({**base, "action": Action.HTTP_REQUEST})
    if request.url.path == "/login" and request.method == "POST" and response.status_code != 413:
        emit({**base, "action": Action.LOGIN_ATTEMPT, "credential": _credential(body)})
    return response


@app.get("/")
async def index() -> Response:
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", {"company": COMPANY, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request) -> Response:
    # Phase 0: every login fails. Planted credentials arrive with honeytokens in Phase 1.
    return templates.TemplateResponse(
        request,
        "login.html",
        {"company": COMPANY, "error": "Invalid username or password."},
        status_code=401,
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def not_found(request: Request, path: str) -> Response:
    return templates.TemplateResponse(request, "404.html", {}, status_code=404)
