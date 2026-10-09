"""Web admin portal decoy (port 8080).

Responses come from fixed content only. Every request is logged through
qlure.events.emit before the response goes out.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from decoys import honeytokens
from decoys.common import fingerprint, read_capped
from qlure.events import Action, Service, emit

COMPANY = "Veltrix Logistics"  # fictional company used across every decoy
SESSION_COOKIE = "VLXSESSID"
SERVER_HEADER = "nginx/1.24.0"
BODY_PREVIEW_CHARS = 2048
FP_HEADERS = ("user-agent", "accept", "accept-language", "accept-encoding")
LOGGED_HEADERS = FP_HEADERS + ("referer", "content-type", "x-forwarded-for", "cookie")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


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


def _base(request: Request) -> dict[str, Any]:
    """Fields every web event carries, identifying the visitor and session."""
    return {
        "service": Service.WEB,
        "src_ip": request.client.host if request.client else "0.0.0.0",  # noqa: S104
        # Behind the gateway uvicorn reports port 0: the original port is not forwarded.
        "src_port": (request.client.port or None) if request.client else None,
        "client_fp": fingerprint(*(request.headers.get(name, "") for name in FP_HEADERS)),
        "session_id": request.state.session_id,
    }


def _file_read(request: Request, path: str, honeytoken_id: str | None = None) -> None:
    emit(
        {
            **_base(request),
            "action": Action.FILE_READ,
            "request": {"method": request.method, "path": path},
            "honeytoken_id": honeytoken_id,
        }
    )


def _dotenv() -> str:
    aws = honeytokens.get("ht-aws-001")
    db = honeytokens.get("ht-db-001")
    return (
        "APP_ENV=production\n"
        f"AWS_ACCESS_KEY_ID={aws['value']}\n"
        f"AWS_SECRET_ACCESS_KEY={aws['secret']}\n"
        "DB_HOST=db.veltrix.internal\n"
        "DB_USER=veltrix_app\n"
        f"DB_PASSWORD={db['value']}\n"
    )


def _backup_config() -> str:
    ssh = honeytokens.get("ht-ssh-001")
    return (
        "# legacy deploy config, do not commit\n"
        "[ssh]\n"
        "host = app-01.veltrix.internal\n"
        "port = 2222\n"
        f"user = {ssh['username']}\n"
        f"password = {ssh['value']}\n"
    )


@app.middleware("http")
async def observe(request: Request, call_next):
    body = await read_capped(request)
    session_id, new_session = _session_id(request)
    request.state.session_id = session_id
    if body is None:
        body = b""
        response: Response = PlainTextResponse("413 Request Entity Too Large", status_code=413)
    else:
        # Handlers never read the body; the middleware has already consumed the stream.
        response = await call_next(request)

    if new_session:
        response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    response.headers["server"] = SERVER_HEADER

    base = {
        **_base(request),
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
    # Only the planted SSH login works, and it works on the SSH decoy, not here.
    return templates.TemplateResponse(
        request,
        "login.html",
        {"company": COMPANY, "error": "Invalid username or password."},
        status_code=401,
    )


@app.get("/admin")
async def admin(request: Request) -> Response:
    return RedirectResponse("/login", status_code=302)


@app.get("/.env", response_class=PlainTextResponse)
async def dotenv(request: Request) -> Response:
    _file_read(request, "/.env", "ht-aws-001")
    return PlainTextResponse(_dotenv())


@app.get("/backup/", response_class=HTMLResponse)
async def backup_index(request: Request) -> Response:
    return templates.TemplateResponse(request, "backup_index.html", {"company": COMPANY})


@app.get("/backup/config.bak", response_class=PlainTextResponse)
async def backup_config(request: Request) -> Response:
    _file_read(request, "/backup/config.bak", "ht-ssh-001")
    return PlainTextResponse(_backup_config())


@app.api_route("/api{tail:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def api_gate(request: Request, tail: str) -> Response:
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def not_found(request: Request, path: str) -> Response:
    return templates.TemplateResponse(request, "404.html", {}, status_code=404)
