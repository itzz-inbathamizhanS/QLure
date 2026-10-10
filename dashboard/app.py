"""Session view and safe configuration dashboard (port 9000, localhost only).

Attacker-supplied text is escaped at render time by Jinja2 autoescape; nothing is marked safe.
Every page carries a strict Content Security Policy with no inline script or style.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from dashboard import data, scanning
from dashboard.auth import COOKIE, LIFETIME, Auth
from dashboard.report import scan_pdf
from qlure import export as ioc_export
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
CLEARED_TABLES = (
    "events",
    "sessions",
    "actors",
    "findings",
    "forwarder_state",
    "labels",
    "checkpoints",
)
PAGE = 100
MAX_REPORT_BYTES = 2_000_000
LIVE_DEFAULT_SECONDS = 10  # QLURE_LIVE_INTERVAL: how often the background correlation runs
LIVE_MIN_SECONDS = 2
LIVE_POLL_SECONDS = 5  # how often an open overview asks for its rows (a cheap read)
# Pages that answer without a login. /metrics joins them only when QLURE_METRICS_PUBLIC=1.
PUBLIC_PATHS = ("/login", "/favicon.ico", "/healthz")
METRICS_TYPE = "text/plain; version=0.0.4"  # the Prometheus text exposition format
# The three IOC downloads: the route suffix maps to (export format, Content-Type, file extension).
EXPORT_FILES = {
    "csv": ("csv", "text/csv; charset=utf-8", "csv"),
    "json": ("stix", "application/stix+json; version=2.1", "json"),
    "txt": ("blocklist", "text/plain; charset=utf-8", "txt"),
}
log = logging.getLogger(__name__)


def _package_version() -> str:
    try:
        return metadata.version("qlure")
    except metadata.PackageNotFoundError:
        return "unknown"


def _export_min(raw: str | None) -> str | None:
    """The verdict floor an export asks for: noteworthy, or suspicious. None when unknown."""
    if not raw:
        return ioc_export.DEFAULT_MIN_VERDICT
    return raw if raw in ioc_export.MIN_VERDICTS else None


def _when(value: str | None) -> str:
    """ISO time as 'YYYY-MM-DD HH:MM:SS' (UTC) for tables; the full value stays in title=."""
    if not value:
        return ""
    return str(value).replace("T", " ")[:19]


def _span(first: str | None, last: str | None) -> str:
    if not first or not last:
        return ""
    seconds = int((datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {seconds % 3600 // 60}m"


LIST_FIELDS = {"allowlist.ips", "allowlist.user_agents"}


def _coerce(key: str, value: str) -> Any:
    if key in LIST_FIELDS:
        return [part.strip() for part in value.replace(",", "\n").splitlines() if part.strip()]
    if value in ("true", "false"):
        return value == "true"
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def _cookie_secure() -> bool:
    """QLURE_COOKIE_SECURE=1/true/yes marks the login cookie Secure (for HTTPS). Off by default."""
    return os.environ.get("QLURE_COOKIE_SECURE", "").strip().lower() in ("1", "true", "yes")


def live_interval() -> int | None:
    """Seconds between background correlation passes, or None when QLURE_LIVE=0 turns them off."""
    if os.environ.get("QLURE_LIVE", "1").strip() == "0":
        return None
    try:
        seconds = int(os.environ.get("QLURE_LIVE_INTERVAL", LIVE_DEFAULT_SECONDS))
    except ValueError:
        seconds = LIVE_DEFAULT_SECONDS
    return max(seconds, LIVE_MIN_SECONDS)


@dataclass
class LiveFeed:
    """What the live overview shows: the interval, when a pass last finished, and whether the
    last pass failed. `lock` is held by every correlation pass, so two never overlap."""

    interval: int | None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    updated: datetime | None = None
    failed: bool = False
    task: asyncio.Task[None] | None = None


def correlate_db(db_file: Path) -> None:
    """One correlation pass over the store: the work the Re-run button does."""
    c = db.connect(db_file)
    try:
        correlate_store.run(c)
    finally:
        c.close()


async def live_tick(db_file: Path, feed: LiveFeed) -> bool:
    """One background pass. Returns False when it was skipped: a pass is already running, or
    judge mode is on (a pass writes to the store, and judge mode is read-only)."""
    if feed.lock.locked() or cfg.load_settings()["judge_mode"]:
        return False
    async with feed.lock:
        await run_in_threadpool(correlate_db, db_file)
    feed.updated = datetime.now(UTC)
    feed.failed = False
    return True


async def live_loop(db_file: Path, feed: LiveFeed, interval: int) -> None:
    """Run a pass every `interval` seconds until cancelled. A failed pass is logged, not raised."""
    while True:
        try:
            await live_tick(db_file, feed)
        except Exception:
            feed.failed = True
            log.exception("live correlation pass failed; the loop carries on")
        await asyncio.sleep(interval)


def _shown_query(request: Request) -> dict[str, str]:
    """The query string of the page the browser shows, which htmx sends as HX-Current-URL."""
    return dict(parse_qsl(urlparse(request.headers.get("hx-current-url", "")).query))


def create_app(db_path: Path | None = None, logs_dir: Path | None = None) -> FastAPI:
    db_file = db_path or Path(os.environ.get("QLURE_DB", "data/qlure.db"))
    logs = logs_dir or Path(os.environ.get("QLURE_LOGS", "logs"))
    auth = Auth()
    if auth.generated:
        print(f"Dashboard password (set QLURE_DASHBOARD_PASSWORD to choose one): {auth.password}")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters["when"] = _when
    templates.env.globals["span"] = _span
    feed = LiveFeed(interval=live_interval())

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if feed.interval is not None:
            feed.task = asyncio.create_task(live_loop(db_file, feed, feed.interval))
        try:
            yield
        finally:
            if feed.task is not None:
                feed.task.cancel()
                with suppress(asyncio.CancelledError):
                    await feed.task

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.auth = auth
    app.state.live = feed
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def conn() -> sqlite3.Connection:
        return db.connect(db_file)

    def live_view() -> dict[str, Any]:
        return {
            "enabled": feed.interval is not None,
            "poll": LIVE_POLL_SECONDS,
            "updated": feed.updated.isoformat() if feed.updated else None,
            "failed": feed.failed,
        }

    def page(request: Request, name: str, status: int = 200, **context: Any) -> Response:
        context.setdefault("judge_mode", cfg.load_settings()["judge_mode"])
        context.setdefault("hosted", bool(os.environ.get("VERCEL")))
        context.setdefault("nav", "")
        return templates.TemplateResponse(request, name, context, status_code=status)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if request.method == "POST":
            origin = request.headers.get("origin")
            cross_site = request.headers.get("sec-fetch-site") == "cross-site"
            if cross_site or (origin and urlparse(origin).netloc != request.headers.get("host")):
                return Response("Cross-site request refused", status_code=403)
        public = path in PUBLIC_PATHS or (
            path == "/metrics" and os.environ.get("QLURE_METRICS_PUBLIC", "").strip() == "1"
        )
        if not path.startswith("/static") and not public:
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

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        # Public and static, like /static: browsers ask for it before any login.
        return FileResponse(HERE / "static" / "favicon.svg", media_type="image/svg+xml")

    def store_snapshot() -> dict[str, Any] | None:
        """Cheap counts from the store, read-only. None when the store cannot be read."""
        try:
            with closing(data.open_read_only(db_file)) as c:
                return data.store_counts(c)
        except sqlite3.Error:
            return None

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        """Liveness and store check for probes. Counts and times only: no paths or config."""
        counts = await run_in_threadpool(store_snapshot)
        live = feed.task is not None and not feed.task.done()
        body: dict[str, Any] = {
            "status": "ok" if counts is not None else "degraded",
            "db": "ok" if counts is not None else "error",
            "events": counts["events"] if counts else None,
            "sessions": counts["sessions"] if counts else None,
            "last_forward": counts["newest"] if counts else None,
            "live": live,
            "version": _package_version(),
        }
        return JSONResponse(body, status_code=200 if counts is not None else 503)

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Prometheus text. Login is required unless QLURE_METRICS_PUBLIC=1 (see the guard)."""
        counts = await run_in_threadpool(store_snapshot)
        if counts is None:
            return Response("store unavailable\n", status_code=503, media_type="text/plain")
        last_pass = feed.updated.timestamp() if feed.updated else 0.0
        return Response(data.metrics_text(counts, last_pass), media_type=METRICS_TYPE)

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        return page(request, "login.html", error=None)

    @app.post("/login")
    async def login(request: Request, password: str = Form("")) -> Response:
        if not auth.check_password(password):
            return page(request, "login.html", status=401, error="Wrong password.")
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            COOKIE,
            auth.issue(),
            httponly=True,
            samesite="strict",
            max_age=LIFETIME,
            secure=_cookie_secure(),
        )
        return response

    @app.post("/logout")
    async def logout() -> Response:
        response = RedirectResponse("/login", status_code=303)
        if _cookie_secure():
            response.delete_cookie(COOKIE, httponly=True, samesite="strict", secure=True)
        else:
            response.delete_cookie(COOKIE)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Response:
        query: Any = request.query_params
        if query.get("live") and request.headers.get("hx-request"):
            # A poll carries no filters of its own: it asks for the list the browser is showing.
            query = _shown_query(request)
        filters = {k: v for k, v in query.items() if v and k not in ("page", "live")}
        raw_page = query.get("page", "1")
        page_no = max(int(raw_page), 1) if raw_page.isdigit() else 1
        with closing(conn()) as c:
            rows = data.list_findings(c, filters)
            shown = rows[(page_no - 1) * PAGE : page_no * PAGE]
            pages = {
                "no": page_no,
                "total": len(rows),
                "first": (page_no - 1) * PAGE + 1 if shown else 0,
                "last": (page_no - 1) * PAGE + len(shown),
                "prev": page_no - 1 if page_no > 1 else None,
                "next": page_no + 1 if page_no * PAGE < len(rows) else None,
                "query": urlencode(filters),
            }
            if request.headers.get("hx-request"):
                return page(
                    request,
                    "_results.html",
                    rows=shown,
                    pages=pages,
                    filters=filters,
                    live=live_view(),
                )
            return page(
                request,
                "index.html",
                nav="sessions",
                rows=shown,
                pages=pages,
                filters=filters,
                options=data.filter_options(c),
                pqc=data.pqc_share(c),
                stats=data.overview(c),
                live=live_view(),
                # The banner belongs to the overview: a filtered list shows only its rows.
                token_banner=None if filters else data.honeytoken_banner(c),
            )

    @app.get("/attack", response_class=HTMLResponse)
    async def attack_page(request: Request) -> Response:
        with closing(conn()) as c:
            return page(request, "attack.html", nav="attack", matrix=data.attack_matrix(c))

    @app.get("/actors", response_class=HTMLResponse)
    async def actors(request: Request) -> Response:
        with closing(conn()) as c:
            return page(request, "actors.html", nav="actors", actors=data.list_actors(c))

    @app.get("/actor/{actor_id}", response_class=HTMLResponse)
    async def actor_view(request: Request, actor_id: str) -> Response:
        with closing(conn()) as c:
            detail = data.actor_detail(c, actor_id)
        if detail is None:
            return page(request, "missing.html", status=404)
        return page(request, "actor.html", nav="actors", a=detail)

    @app.get("/export", response_class=HTMLResponse)
    async def export_page(request: Request) -> Response:
        min_verdict = _export_min(request.query_params.get("min"))
        if min_verdict is None:
            return Response("min must be noteworthy or suspicious", status_code=400)
        query = "?min=suspicious" if min_verdict == "suspicious" else ""
        return page(
            request,
            "export.html",
            nav="export",
            min_verdict=min_verdict,
            query=query,
        )

    async def indicator_download(request: Request, suffix: str) -> Response:
        """One IOC export as a download. It only reads the store, so judge mode allows it."""
        fmt, media_type, extension = EXPORT_FILES[suffix]
        min_verdict = _export_min(request.query_params.get("min"))
        if min_verdict is None:
            return Response("min must be noteworthy or suspicious", status_code=400)
        try:
            body = await run_in_threadpool(ioc_export.render, db_file, fmt, min_verdict)
        except ioc_export.ExportError:
            return Response("The store cannot be read.", status_code=503)
        name = f"qlure-indicators-{datetime.now(UTC):%Y%m%d}.{extension}"
        return Response(
            body,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )

    @app.get("/export.csv")
    async def export_csv(request: Request) -> Response:
        return await indicator_download(request, "csv")

    @app.get("/export.json")
    async def export_json(request: Request) -> Response:
        return await indicator_download(request, "json")

    @app.get("/export.txt")
    async def export_txt(request: Request) -> Response:
        return await indicator_download(request, "txt")

    @app.post("/refresh")
    async def refresh() -> Response:
        async with feed.lock:  # waits for a background pass rather than overlapping it
            await run_in_threadpool(correlate_db, db_file)
        feed.updated = datetime.now(UTC)
        feed.failed = False
        return RedirectResponse("/", status_code=303)

    @app.post("/clear")
    async def clear_data(confirm: str = Form("")) -> Response:
        """Start over: empty the logs and the store. Refused in judge mode, always audited.

        The page asks for a ticked box rather than a JavaScript confirm(), which the CSP blocks.
        Signed checkpoints go too: they sign events that no longer exist, and `qlure verify`
        would fail on them forever.
        """
        if confirm != "yes":
            return Response("Tick the box to confirm clearing all data.", status_code=400)
        if cfg.load_settings()["judge_mode"]:
            return Response("Judge mode is on: data cannot be cleared", status_code=403)
        files = sorted(logs.glob("*.jsonl"))
        locked = [f.name for f in files if not os.access(f, os.W_OK)]
        c = conn()
        try:
            if locked:
                # Emptying the store but not the logs would make the forwarder re-read them all.
                reason = f"log files are read-only: {', '.join(locked)}"
                cfg.audit(c, "admin", "data.clear", None, None, "refused", reason)
                return Response(f"Nothing was cleared: {reason}", status_code=409)
            try:
                c.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as e:
                reason = f"store is busy: {e}"
                try:
                    cfg.audit(c, "admin", "data.clear", None, None, "refused", reason)
                except sqlite3.OperationalError:
                    pass  # still locked; the 409 below is the only record
                return Response(f"Nothing was cleared: {reason}", status_code=409)
            try:
                count = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                for table in CLEARED_TABLES:
                    c.execute(f"DELETE FROM {table}")  # noqa: S608  (fixed table names)
                for log_file in files:
                    log_file.write_text("", encoding="utf-8")
                c.commit()
            except BaseException:
                c.rollback()
                raise
            cfg.audit(c, "admin", "data.clear", {"events": count}, {"events": 0}, "applied", "")
        finally:
            c.close()
        return RedirectResponse("/", status_code=303)

    @app.get("/session/{session_id}", response_class=HTMLResponse)
    async def session_view(request: Request, session_id: str) -> Response:
        with closing(conn()) as c:
            detail = data.session_detail(c, session_id)
        if detail is None:
            return page(request, "missing.html", status=404)
        settings = cfg.load_settings()["rules"]
        return page(
            request,
            "session.html",
            nav="sessions",
            s=detail,
            marks={"suspicious": settings["suspicious"], "noteworthy": settings["noteworthy"]},
        )

    @app.post("/session/{session_id}/label")
    async def label_session(request: Request, session_id: str) -> Response:
        form = await request.form()
        label = str(form.get("label", ""))
        if label not in LABELS:
            return Response("Unknown label", status_code=400)
        if cfg.load_settings()["judge_mode"]:
            return Response("Judge mode is on: labels are read-only", status_code=403)
        evidence = [str(v) for v in form.getlist("evidence")]
        with closing(conn()) as c:
            data.save_label(c, session_id, label, evidence, "admin", datetime.now(UTC).isoformat())
        return RedirectResponse(f"/session/{session_id}", status_code=303)

    def evidence_bundle(session_id: str) -> dict[str, Any] | None:
        with closing(conn()) as c:
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
        with closing(conn()) as c:
            detail = data.session_detail(c, session_id)
        if bundle is None or detail is None:
            return page(request, "missing.html", status=404)
        return page(request, "report.html", s=detail, chain=bundle["hash_chain"])

    @app.get("/config", response_class=HTMLResponse)
    async def config_page(request: Request, message: str = "", ok: str = "") -> Response:
        with closing(conn()) as c:
            audit = c.execute(
                "SELECT * FROM config_audit ORDER BY audit_id DESC LIMIT 30"
            ).fetchall()
            return page(
                request,
                "config.html",
                nav="settings",
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
        weights = dict(current["rules"]["weights"])
        for key in dict.fromkeys(form.keys()):
            raw = str(form.getlist(key)[-1])
            if key.startswith("rules.weights."):
                rule_id = key.removeprefix("rules.weights.")
                if not raw.strip():  # blank: drop the override, the rule goes back to default
                    weights.pop(rule_id, None)
                else:
                    weights[rule_id] = _coerce(key, raw)
                continue
            value = _coerce(key, raw)
            if cfg._get(current, key) != value:
                changes[key] = value
        if weights != current["rules"]["weights"]:
            changes["rules.weights"] = weights  # whole map, so the audit row shows the change
        if not changes:
            return RedirectResponse("/config?message=Nothing+changed&ok=1", status_code=303)
        with closing(conn()) as c:
            ok, message = cfg.apply_change(c, "admin", changes)
        query = f"message={message.replace(' ', '+')}&ok={int(ok)}"
        return RedirectResponse(f"/config?{query}", status_code=303)

    @app.post("/config/rollback/{audit_id}")
    async def config_rollback(audit_id: int) -> Response:
        with closing(conn()) as c:
            ok, message = cfg.rollback(c, "admin", audit_id)
        return RedirectResponse(
            f"/config?message={message.replace(' ', '+')}&ok={int(ok)}", status_code=303
        )

    @app.get("/scanner", response_class=HTMLResponse)
    async def scanner_page(request: Request) -> Response:
        return _scanner(request)

    @app.post("/scanner", response_class=HTMLResponse)
    async def scanner_run(request: Request, target: str = Form("")) -> Response:
        outcome = await run_in_threadpool(scanning.run, target)
        return _scanner(request, target=target, outcome=outcome)

    @app.post("/scanner/report.pdf")
    async def scanner_report(report: str = Form("")) -> Response:
        """The PDF for the scan result the page just showed. The scan is not run again."""
        try:
            result = json.loads(report) if len(report) <= MAX_REPORT_BYTES else None
            pdf = scan_pdf(result) if isinstance(result, dict) else None
        except Exception:  # malformed or tampered input: refuse rather than fail
            pdf = None
        if pdf is None:
            return Response("Run a scan first, then download its report.", status_code=400)
        host = "".join(
            c for c in str(result.get("target_url", "")).split("//")[-1] if c.isalnum() or c in ".-"
        )
        return Response(
            pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="qlure-scan-{host or "report"}.pdf"'
            },
        )

    def _scanner(request: Request, target: str = "", outcome: dict | None = None) -> Response:
        return page(request, "scanner.html", nav="scanner", target=target, outcome=outcome)

    return app


app = create_app()
