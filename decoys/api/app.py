"""REST API decoy (port 8081).

Answers only from fixed fake records. A planted key (honeytokens.yaml) is the only
way in. Every request, every record ID tried and every key used is logged.
"""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from decoys import honeytokens
from decoys.common import fingerprint, read_capped, replay_ts
from qlure.events import Action, Service, emit

# Header that carries each planted key, and the honeytoken it belongs to.
KEY_HEADERS = {"x-api-key": "ht-api-001", "x-aws-access-key": "ht-aws-001"}
BODY_PREVIEW_CHARS = 2048
KEY_LOG_CHARS = 128
LOGGED_HEADERS = ("user-agent", "accept", "content-type", "x-forwarded-for")

USERS: list[dict[str, Any]] = [
    {
        "id": 1,
        "name": "Ravi Kumar",
        "email": "ravi.kumar@veltrix.test",
        "role": "dispatcher",
        "active": True,
    },
    {
        "id": 2,
        "name": "Meera Iyer",
        "email": "meera.iyer@veltrix.test",
        "role": "admin",
        "active": True,
    },
    {
        "id": 3,
        "name": "Arjun Das",
        "email": "arjun.das@veltrix.test",
        "role": "warehouse",
        "active": False,
    },
]
ORDERS: list[dict[str, Any]] = [
    {"id": 1001, "customer": "Coastline Traders", "status": "shipped", "total_inr": 48250},
    {"id": 1002, "customer": "Northgate Foods", "status": "pending", "total_inr": 12900},
]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _key_token(request: Request) -> str | None:
    """Return the honeytoken id if the request carries a planted key, else None."""
    for header, token_id in KEY_HEADERS.items():
        value = request.headers.get(header)
        if value is not None and value == honeytokens.get(token_id)["value"]:
            return token_id
    return None


def _body_summary(body: bytes) -> dict[str, Any]:
    """Same fields as the web decoy, so the rules scan API bodies the same way."""
    return {
        "body_len": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_preview": body[:BODY_PREVIEW_CHARS].decode("utf-8", errors="replace"),
    }


def _presented_key(request: Request) -> str | None:
    """The key a caller offered (capped), or None when no credential was sent at all."""
    value = request.headers.get("x-api-key") or request.headers.get("x-aws-access-key")
    if not value:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            value = auth[7:].strip()
    return value[:KEY_LOG_CHARS] if value else None


def require_key(request: Request) -> None:
    if _key_token(request) is None:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


@app.middleware("http")
async def observe(request: Request, call_next):
    body = await read_capped(request)
    if body is None:
        body = b""
        response = JSONResponse({"detail": "Request body too large"}, status_code=413)
    else:
        response = await call_next(request)

    token_id = _key_token(request)
    host = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    base = {
        "service": Service.API,
        "src_ip": host,
        "src_port": (request.client.port or None) if request.client else None,
        "client_fp": fingerprint(
            request.headers.get("user-agent", ""), request.headers.get("accept", "")
        ),
        "session_id": "api-" + fingerprint(host, request.headers.get("user-agent", "")),
        "replay_ts": replay_ts(request.headers),
    }
    call = {
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query,
        "status": response.status_code,
    }
    emit(
        {
            **base,
            "action": Action.HTTP_REQUEST,
            "request": {
                **call,
                "headers": {k: v for k, v in request.headers.items() if k in LOGGED_HEADERS},
                **_body_summary(body),
            },
            "response": {"status": response.status_code},
        }
    )
    if request.url.path.startswith("/api/v1/"):
        emit(
            {
                **base,
                "action": Action.API_CALL,
                "request": call,
                "response": {"status": response.status_code},
                "honeytoken_id": token_id,
            }
        )
    if token_id is not None:
        emit({**base, "action": Action.HONEYTOKEN_USE, "honeytoken_id": token_id, "request": call})
    else:
        presented = _presented_key(request)
        if presented is not None and response.status_code != 413:
            # Key guessing looks like a failed login to the correlation rules (R3).
            emit(
                {
                    **base,
                    "action": Action.LOGIN_ATTEMPT,
                    "request": call,
                    "credential": {"username": "api-key", "password": presented},
                    "response": {"status": response.status_code},
                }
            )
    return response


v1 = APIRouter(prefix="/api/v1", dependencies=[Depends(require_key)])


@v1.get("/users")
async def list_users() -> list[dict[str, Any]]:
    return USERS


@v1.get("/users/{user_id}")
async def get_user(user_id: int) -> dict[str, Any]:
    for user in USERS:
        if user["id"] == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")


@v1.get("/orders")
async def list_orders() -> list[dict[str, Any]]:
    return ORDERS


app.include_router(v1)
