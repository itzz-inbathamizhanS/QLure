"""Session view and safe configuration dashboard (port 9000, localhost only).

Attacker-supplied text is escaped at render time by Jinja2 autoescape; nothing is marked safe.
Every page carries a strict Content Security Policy with no inline script or style.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dashboard import data
from dashboard.auth import COOKIE, LIFETIME, Auth
from qlure import settings as cfg
from qlure.correlate import store as correlate_store
from qlure.store import db
from qlure.store.verify import verify

HERE = Path(__file__).parent
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
LABELS = ("benign", "malicious")
LIST_FIELDS = {"allowlist.ips", "allowlist.user_agents"}


def _coerce(key: str, value: str) -> Any:
    if key in LIST_FIELDS:
        return [part.strip() for part in value.replace(",", "\n").splitlines() if part.strip()]
    if value in ("true", "false"):
        return value == "true"
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def create_app(db_path: Path | None = None, logs_dir: Path | None = None) -> FastAPI:
    db_file = db_path or Path(os.environ.get("QLURE_DB", "data/qlure.db"))
    logs = logs_dir or Path(os.environ.get("QLURE_LOGS", "logs"))
    auth = Auth()
    if auth.generated:
        print(f"Dashboard password (set QLURE_DASHBOARD_PASSWORD to choose one): {auth.password}")
    templates = Jinja2Templates(directory=HERE / "templates")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth = auth
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def conn() -> sqlite3.Connection:
        return db.connect(db_file)

    def page(request: Request, name: str, status: int = 200, **context: Any) -> Response:
        context.setdefault("judge_mode", cfg.load_settings()["judge_mode"])
        return templates.TemplateResponse(request, name, context, status_code=status)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if request.method == "POST":
            origin = request.headers.get("origin")
            cross_site = request.headers.get("sec-fetch-site") == "cross-site"
            if cross_site or (origin and urlparse(origin).netloc != request.headers.get("host")):
                return Response("Cross-site request refused", status_code=403)
        if not path.startswith("/static") and path != "/login":
            if not auth.valid(request.cookies.get(COOKIE)):
                return RedirectResponse("/login", status_code=303)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = (
            "same-origin"  # "no-referrer" makes forms send Origin: null
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        return page(request, "login.html", error=None)

    @app.post("/login")
    async def login(request: Request, password: str = Form("")) -> Response:
        if not auth.check_password(password):
            return page(request, "login.html", status=401, error="Wrong password.")
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            COOKIE, auth.issue(), httponly=True, samesite="strict", max_age=LIFETIME
        )
        return response

    @app.post("/logout")
    async def logout() -> Response:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Response:
        filters = {k: v for k, v in request.query_params.items() if v}
        c = conn()
        rows = data.list_findings(c, filters)
        template = "_results.html" if request.headers.get("hx-request") else "index.html"
        return page(
            request,
            template,
            rows=rows,
            filters=filters,
            options=data.filter_options(c),
        )

    @app.post("/refresh")
    async def refresh() -> Response:
        correlate_store.run(conn())
        return RedirectResponse("/", status_code=303)

    @app.get("/session/{session_id}", response_class=HTMLResponse)
    async def session_view(request: Request, session_id: str) -> Response:
        detail = data.session_detail(conn(), session_id)
        if detail is None:
            return page(request, "missing.html", status=404)
        return page(request, "session.html", s=detail)

    @app.post("/session/{session_id}/label")
    async def label_session(request: Request, session_id: str) -> Response:
        form = await request.form()
        label = str(form.get("label", ""))
        if label not in LABELS:
            return Response("Unknown label", status_code=400)
        if cfg.load_settings()["judge_mode"]:
            return Response("Judge mode is on: labels are read-only", status_code=403)
        evidence = [str(v) for v in form.getlist("evidence")]
        data.save_label(conn(), session_id, label, evidence, "admin", datetime.now(UTC).isoformat())
        return RedirectResponse(f"/session/{session_id}", status_code=303)

    def evidence_bundle(session_id: str) -> dict[str, Any] | None:
        c = conn()
        detail = data.session_detail(c, session_id)
        if detail is None:
            return None
        checked, problem = verify(c, logs)
        return {
            "exported_at": datetime.now(UTC).isoformat(),
            "session_id": session_id,
            "actor_id": detail["actor_id"],
            "verdict": detail["verdict"],
            "score": detail["score"],
            "explanation": detail["explanation"],
            "rule_hits": detail["hits"],
            "suppressors": detail["suppressors"],
            "label": detail["label"],
            "evidence_marked": detail["evidence_marked"],
            "events": [
                {**json.loads(e["raw"]), "prev_hash": e["prev_hash"], "hash": e["hash"]}
                for e in detail["events"]
            ],
            "hash_chain": {
                "verified": problem is None,
                "events_checked": checked,
                "first_problem": None
                if problem is None
                else {"event_id": problem.event_id, "reason": problem.reason},
            },
        }

    @app.get("/session/{session_id}/evidence.json")
    async def evidence_json(session_id: str) -> Response:
        bundle = evidence_bundle(session_id)
        if bundle is None:
            return JSONResponse({"detail": "not found"}, status_code=404)
        return Response(
            json.dumps(bundle, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{session_id}-evidence.json"'},
        )

    @app.get("/session/{session_id}/report", response_class=HTMLResponse)
    async def report(request: Request, session_id: str) -> Response:
        bundle = evidence_bundle(session_id)
        detail = data.session_detail(conn(), session_id)
        if bundle is None or detail is None:
            return page(request, "missing.html", status=404)
        return page(request, "report.html", s=detail, chain=bundle["hash_chain"])

    @app.get("/config", response_class=HTMLResponse)
    async def config_page(request: Request, message: str = "", ok: str = "") -> Response:
        c = conn()
        audit = c.execute("SELECT * FROM config_audit ORDER BY audit_id DESC LIMIT 30").fetchall()
        return page(
            request,
            "config.html",
            s=cfg.load_settings(),
            approved_ports=cfg.APPROVED_PORTS,
            rule_ids=[f"R{i}" for i in range(1, 11)],
            audit=audit,
            message=message,
            ok=ok == "1",
        )

    @app.post("/config")
    async def config_change(request: Request) -> Response:
        form = await request.form()
        current = cfg.load_settings()
        changes: dict[str, Any] = {}
        for key in dict.fromkeys(form.keys()):
            raw = str(form.getlist(key)[-1])
            if key.startswith("rules.weights.") and not raw.strip():
                continue
            value = _coerce(key, raw)
            if cfg._get(current, key) != value:
                changes[key] = value
        if not changes:
            return RedirectResponse("/config?message=Nothing+changed&ok=1", status_code=303)
        ok, message = cfg.apply_change(conn(), "admin", changes)
        query = f"message={message.replace(' ', '+')}&ok={int(ok)}"
        return RedirectResponse(f"/config?{query}", status_code=303)

    @app.post("/config/rollback/{audit_id}")
    async def config_rollback(audit_id: int) -> Response:
        ok, message = cfg.rollback(conn(), "admin", audit_id)
        return RedirectResponse(
            f"/config?message={message.replace(' ', '+')}&ok={int(ok)}", status_code=303
        )

    return app


app = create_app()
