"""FastAPI application - a thin adapter over :mod:`phishguard.service.scanning`.

Everything that decides anything lives in ``ScanService``; this module parses
requests, enforces authentication, authorisation and rate limits, converts
exceptions into RFC-shaped error responses, and serialises results. Keeping it
thin is what lets the decision logic be tested without an HTTP server.

Endpoints
---------
``GET  /healthz``                  liveness - never touches the model
``GET  /readyz``                   readiness - fails until a model is loaded
``GET  /metrics``                  Prometheus exposition
``POST /api/v1/scan``              assess one message            (analyst)
``POST /api/v1/scan/batch``        assess up to 100 messages     (analyst)
``POST /api/v1/scan/url``          assess a bare URL             (analyst)
``POST /api/v1/feedback``          record an analyst correction  (analyst)
``GET  /api/v1/decisions``         audit trail, paginated        (admin)
``GET  /api/v1/decisions/{id}``    one audit record              (admin)
``GET  /api/v1/model``             model card data               (analyst)
``GET  /api/v1/stats``             operational summary           (analyst)
``POST /api/v1/adversarial/probe`` attack one message            (admin)
``POST /api/v1/reports``           report a suspicious message   (reporter)
``GET  /api/v1/reports/mine``      a reporter's own reports      (reporter)
``GET  /api/v1/cases``             the review queue              (analyst)
``GET  /api/v1/cases/stats``       queue health and SLAs         (analyst)
``GET  /api/v1/cases/{id}``        one case with its history     (analyst)
``POST /api/v1/cases/{id}/actions`` claim / resolve / escalate   (analyst)
``GET  /api/v1/whoami``            the caller's key id and role  (reporter)
``GET  /api/v1/traces/recent``     recent request traces         (admin)
``GET  /``                         the analyst console
``GET  /report``                   the email-user report page
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from phishguard import __version__
from phishguard.config import find_console_asset, find_static_asset, get_settings
from phishguard.service import telemetry, tracing, workflow
from phishguard.service.contracts import (
    AdversarialProbeRequest,
    AdversarialProbeResponse,
    BatchScanRequest,
    BatchScanResponse,
    CaseActionRequest,
    CaseDetail,
    CasePage,
    DecisionPage,
    DecisionRecord,
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
    ModelInfoResponse,
    ReportList,
    ReportReceipt,
    ReportRequest,
    ScanRequest,
    ScanResponse,
    UrlScanRequest,
    UrlScanResponse,
    WhoAmI,
)
from phishguard.service.scanning import ScanService
from phishguard.service.security import (
    AuthError,
    Principal,
    RateLimitError,
    Role,
    SecurityConfig,
    build_security,
    new_request_id,
)
from phishguard.service.store import get_store, retention_sweep

logger = logging.getLogger("phishguard.api")

#: Populated at startup. Absent means the service is live but not ready.
STATE: dict[str, Any] = {"service": None, "security": None, "model_error": None}


#: Resolved lazily so that a console added after import is still found.
def _console_asset() -> Path | None:
    return find_console_asset()


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    settings = get_settings()
    telemetry.configure_logging(settings.log_level, settings.log_format)
    settings.ensure_dirs()

    security = build_security(settings)
    STATE["security"] = security
    for warning in security.warnings:
        telemetry.log_event(logger, logging.WARNING, warning, environment=settings.environment)

    store = get_store(settings.db_path)
    try:
        swept = retention_sweep(store, settings.audit_retention_days)
        if swept["removed"]:
            telemetry.log_event(logger, logging.INFO, "audit retention sweep", **swept)
    except Exception:  # noqa: BLE001
        logger.exception("retention sweep failed")

    try:
        from phishguard.models.registry import load_detector

        detector, manifest = load_detector(settings=settings)
        STATE["service"] = ScanService(detector, store, settings, manifest=manifest)
        STATE["model_error"] = None
        telemetry.log_event(
            logger,
            logging.INFO,
            "model loaded",
            model_version=detector.model_version,
            members=",".join(detector.member_names),
            defenses=",".join(detector.defenses.active_ids),
        )
    except Exception as exc:  # noqa: BLE001
        # Start anyway: /healthz and /metrics stay useful, and /readyz reports
        # the reason, which is what an orchestrator needs to act on.
        STATE["model_error"] = str(exc)
        telemetry.log_event(
            logger,
            logging.ERROR,
            "no model available - service is live but not ready",
            error=str(exc),
        )
    yield
    store.close()


app = FastAPI(
    title="PhishGuard",
    version=__version__,
    summary="Adversarially Robust Phishing Defense using Email, URL and Behavioral Features",
    description=(
        "Assesses email messages for phishing using three independent feature "
        "families (email, URL, behavioural), a calibrated ensemble, and defensive "
        "controls measured against a threat-informed adversarial suite.\n\n"
        "Authenticate with an `X-API-Key` header. Three roles: `reporter` (an email "
        "user: report a suspicious message and read the outcome of your own reports), "
        "`analyst` (scan mail and work the review queue) and `admin` (the audit trail, "
        "the adversarial probe and high-risk releases).\n\n"
        "No message content is stored: the audit trail holds salted digests, the "
        "sender's domain, sizes and the verdict."
    ),
    lifespan=lifespan,
    contact={"name": "T.Y. B.Sc. Artificial Intelligence - Capstone BAI-17"},
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(get_settings().cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)


# --------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------
@app.middleware("http")
async def request_context(request: Request, call_next):  # noqa: ANN001, ANN201
    """Assign a request id, cap the body, time it and count it."""
    request_id = request.headers.get("X-Request-ID", "").strip()[:64] or new_request_id()
    request.state.request_id = request_id
    started = time.perf_counter()

    security: SecurityConfig | None = STATE.get("security")
    if security is not None:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > security.max_body_bytes:
            telemetry.AUTH_FAILURES.inc(reason="body_too_large")
            return JSONResponse(
                status_code=413,
                content={
                    "error": "payload too large",
                    "detail": f"body exceeds {security.max_body_bytes} bytes",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )

    # Every request runs inside a trace, continuing the caller's W3C
    # ``traceparent`` when one is sent. Spans opened by the scan path below
    # (members, fusion, explanation, audit write) attach to it.
    with tracing.trace(
        f"{request.method} {request.url.path}", traceparent=request.headers.get("traceparent")
    ) as active_trace:
        return await _handle(request, call_next, request_id, started, active_trace)


async def _handle(
    request: Request,
    call_next,
    request_id: str,
    started: float,  # noqa: ANN001
    active_trace: tracing.Trace,
):  # noqa: ANN202
    try:
        response = await call_next(request)
    except Exception:  # noqa: BLE001
        logger.exception("unhandled error", extra={"extra_fields": {"request_id": request_id}})
        elapsed = (time.perf_counter() - started) * 1000.0
        endpoint = (
            request.scope.get("route").path if request.scope.get("route") else request.url.path
        )
        telemetry.REQUESTS.inc(endpoint=endpoint, method=request.method, status="500")
        telemetry.REQUEST_LATENCY.observe(elapsed, endpoint=endpoint)
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal error",
                "detail": "The request could not be completed.",
                "request_id": request_id,
            },
            headers={"X-Request-ID": request_id},
        )

    elapsed = (time.perf_counter() - started) * 1000.0
    route = request.scope.get("route")
    endpoint = getattr(route, "path", request.url.path)
    telemetry.REQUESTS.inc(
        endpoint=endpoint, method=request.method, status=str(response.status_code)
    )
    telemetry.REQUEST_LATENCY.observe(elapsed, endpoint=endpoint)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-ms"] = f"{elapsed:.2f}"
    response.headers["traceparent"] = tracing.traceparent_header(active_trace)
    if active_trace.spans:
        response.headers["Server-Timing"] = tracing.server_timing_header(active_trace)
        telemetry.log_event(
            logger,
            logging.INFO,
            "trace",
            request_id=request_id,
            trace_id=active_trace.trace_id,
            endpoint=endpoint,
            duration_ms=round(elapsed, 2),
            stages=tracing.stage_timings(active_trace),
        )
    # Conservative headers: the console is same-origin and inlines its own assets.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    )
    return response


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------
def get_service() -> ScanService:
    service = STATE.get("service")
    if service is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "No model is loaded. Run 'phishguard train --save' first. "
                f"({STATE.get('model_error') or 'model not found'})"
            ),
        )
    return service


def _authorise(request: Request, api_key: str | None, role: Role) -> Principal:
    security: SecurityConfig | None = STATE.get("security")
    if security is None:
        raise HTTPException(status_code=503, detail="security is not configured")
    try:
        principal = security.authenticator.require(api_key, role)
    except AuthError as exc:
        telemetry.AUTH_FAILURES.inc(reason=exc.reason)
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    try:
        security.limiter.check(principal.key_id)
    except RateLimitError as exc:
        telemetry.RATE_LIMITED.inc()
        raise HTTPException(
            status_code=429,
            detail="rate limit exceeded",
            headers={"Retry-After": str(int(exc.retry_after) + 1)},
        ) from exc
    request.state.principal = principal
    return principal


def require_reporter(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    return _authorise(request, x_api_key, "reporter")


def require_analyst(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    return _authorise(request, x_api_key, "analyst")


def require_admin(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    return _authorise(request, x_api_key, "admin")


ReporterDep = Annotated[Principal, Depends(require_reporter)]
AnalystDep = Annotated[Principal, Depends(require_analyst)]
AdminDep = Annotated[Principal, Depends(require_admin)]
ServiceDep = Annotated[ScanService, Depends(get_service)]


# --------------------------------------------------------------------------
# Operational endpoints
# --------------------------------------------------------------------------
@app.get("/healthz", response_model=HealthResponse, tags=["operations"])
def healthz() -> HealthResponse:
    """Liveness. Deliberately does not touch the model."""
    service = STATE.get("service")
    return HealthResponse(
        status="ok",
        version=__version__,
        model_loaded=service is not None,
        model_version=service.detector.model_version if service else None,
        uptime_seconds=round(telemetry.uptime_seconds(), 1),
    )


@app.get("/readyz", tags=["operations"])
def readyz() -> JSONResponse:
    """Readiness. 503 until a model is loaded, with the reason."""
    service = STATE.get("service")
    if service is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not ready",
                "reason": STATE.get("model_error") or "no model loaded",
                "hint": "run 'phishguard train --save'",
            },
        )
    return JSONResponse(
        status_code=200,
        content={
            "status": "ready",
            "model_version": service.detector.model_version,
            "audit_records": service.store.count(),
        },
    )


@app.get("/metrics", response_class=PlainTextResponse, tags=["operations"])
def metrics() -> PlainTextResponse:
    """Prometheus exposition."""
    return PlainTextResponse(
        telemetry.render_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
@app.post("/api/v1/scan", response_model=ScanResponse, tags=["scanning"])
def scan(
    payload: ScanRequest,
    request: Request,
    service: ServiceDep,
    principal: AnalystDep,
) -> ScanResponse:
    """Assess one message and record the decision in the audit trail."""
    return service.scan(payload, principal=principal, request_id=request.state.request_id)


@app.post("/api/v1/scan/batch", response_model=BatchScanResponse, tags=["scanning"])
def scan_batch(
    payload: BatchScanRequest,
    request: Request,
    service: ServiceDep,
    principal: AnalystDep,
) -> BatchScanResponse:
    """Assess up to 100 messages. Each is audited individually."""
    return service.scan_batch(payload, principal=principal, request_id=request.state.request_id)


@app.post("/api/v1/scan/url", response_model=UrlScanResponse, tags=["scanning"])
def scan_url(
    payload: UrlScanRequest,
    request: Request,
    service: ServiceDep,
    principal: AnalystDep,  # noqa: ARG001
) -> UrlScanResponse:
    """Assess a bare URL, for click-time protection integrations.

    Rule-based rather than model-based, and says so: the trained model expects a
    message, and inventing one around a URL would produce a confident number
    with nothing behind it.
    """
    return service.scan_url(payload, request_id=request.state.request_id)


# --------------------------------------------------------------------------
# Human oversight
# --------------------------------------------------------------------------
@app.post("/api/v1/feedback", response_model=FeedbackResponse, tags=["oversight"])
def feedback(
    payload: FeedbackRequest,
    service: ServiceDep,
    principal: AnalystDep,
) -> FeedbackResponse:
    """Record an analyst's correction on a decision.

    Stored and surfaced for review; never used to retrain automatically.
    """
    try:
        return service.submit_feedback(payload, principal=principal)
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail=f"unknown decision_id {payload.decision_id!r}"
        ) from exc


@app.get("/api/v1/decisions", response_model=DecisionPage, tags=["oversight"])
def list_decisions(
    service: ServiceDep,
    principal: AdminDep,  # noqa: ARG001
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    band: Annotated[str | None, Query(pattern="^(ALLOW|REVIEW|BLOCK)$")] = None,
    sender_domain: Annotated[str | None, Query(max_length=255)] = None,
    min_score: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
) -> DecisionPage:
    """Paginated audit trail. Contains no message content."""
    return service.list_decisions(
        limit=limit,
        offset=offset,
        band=band,
        sender_domain=sender_domain,
        min_score=min_score,
    )


@app.get("/api/v1/decisions/{decision_id}", response_model=DecisionRecord, tags=["oversight"])
def get_decision(
    decision_id: str,
    service: ServiceDep,
    principal: AdminDep,  # noqa: ARG001
) -> DecisionRecord:
    record = service.get_decision(decision_id)
    if record is None:
        raise HTTPException(status_code=404, detail="decision not found")
    return record


# --------------------------------------------------------------------------
# Model metadata and adversarial probe
# --------------------------------------------------------------------------
@app.post("/api/v1/compare", tags=["scanning"])
def compare(
    payload: ScanRequest,
    service: ServiceDep,
    principal: AnalystDep,
) -> dict:
    """Score one message with the full system and with a text-only filter.

    Exists for the console's side-by-side view and for teaching: the argument
    for tri-modal fusion is far more convincing seen on one message than read
    in a table. Not audited - it runs no decision, it explains one.
    """
    return service.compare(payload)


@app.get("/api/v1/drift", tags=["operations"])
def drift(
    service: ServiceDep,
    principal: AnalystDep,
    window_hours: int = Query(24, ge=1, le=24 * 90),
) -> dict:
    """Is recent traffic still what the model was built for? PSI and KS per quantity."""
    return service.drift(window_hours=window_hours)


@app.get("/api/v1/benchmark", tags=["model"])
def benchmark(service: ServiceDep, principal: AnalystDep) -> dict:
    """The most recent PG-HARD curated hard-case run."""
    return service.benchmark()


@app.get("/api/v1/model", response_model=ModelInfoResponse, tags=["model"])
def model_info(
    service: ServiceDep,
    principal: AnalystDep,  # noqa: ARG001
) -> ModelInfoResponse:
    """Model card data: members, defences, thresholds and the attack taxonomy."""
    return ModelInfoResponse(**service.model_info())


@app.get("/api/v1/stats", tags=["model"])
def stats(
    service: ServiceDep,
    principal: AnalystDep,  # noqa: ARG001
    window_hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> dict[str, Any]:
    """Operational summary including the score distribution, for drift watching."""
    return service.operational_stats(window_hours=window_hours)


@app.post("/api/v1/adversarial/probe", response_model=AdversarialProbeResponse, tags=["model"])
def adversarial_probe(
    payload: AdversarialProbeRequest,
    request: Request,
    service: ServiceDep,
    principal: AdminDep,
) -> AdversarialProbeResponse:
    """Run the attack suite against one message. Admin only.

    Admin-gated because it is a legitimate offensive capability: it tells the
    caller which edits reduce the score. That is exactly what a defender needs
    and exactly what an attacker would want, so it is not on the analyst path.
    """
    return service.probe(payload, principal=principal, request_id=request.state.request_id)


@app.get("/api/v1/traces/recent", tags=["operations"])
def recent_traces(
    principal: AdminDep,  # noqa: ARG001
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> dict[str, Any]:
    """The most recent request traces: per-stage timings, never content. Admin only."""
    return {"traces": tracing.recent(limit)}


# --------------------------------------------------------------------------
# Email users: reporting a suspicious message
# --------------------------------------------------------------------------
@app.get("/api/v1/whoami", response_model=WhoAmI, tags=["operations"])
def whoami(principal: ReporterDep) -> WhoAmI:
    """The caller's key id and role, so a client can show the right screens."""
    return WhoAmI(key_id=principal.key_id, role=principal.role)


@app.post("/api/v1/reports", response_model=ReportReceipt, tags=["reports"])
def report_message(
    payload: ReportRequest,
    request: Request,
    service: ServiceDep,
    principal: ReporterDep,
) -> ReportReceipt:
    """Report a suspicious message. It is assessed, audited and always queued.

    The receipt carries a case id and a plain-language status, never a score:
    a reporting endpoint that returned the verdict would be a scoring oracle.
    """
    try:
        return service.report(payload, principal=principal, request_id=request.state.request_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/v1/reports/mine", response_model=ReportList, tags=["reports"])
def my_reports(
    service: ServiceDep,
    principal: ReporterDep,
    reporter_ref: Annotated[str, Query(max_length=128)] = "",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ReportList:
    """The caller's own reports and what became of them."""
    return service.my_reports(principal=principal, reporter_ref=reporter_ref, limit=limit)


# --------------------------------------------------------------------------
# The review queue
# --------------------------------------------------------------------------
@app.get("/api/v1/cases", response_model=CasePage, tags=["review queue"])
def list_cases(
    service: ServiceDep,
    principal: AnalystDep,  # noqa: ARG001
    state: Annotated[
        str, Query(pattern="^(active|all|open|in_review|escalated|resolved)$")
    ] = "active",
    priority: Annotated[int | None, Query(ge=1, le=3)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CasePage:
    """Cases by priority and age. ``active`` = open, in review or escalated."""
    return service.list_cases(state=state, priority=priority, limit=limit, offset=offset)


@app.get("/api/v1/cases/stats", tags=["review queue"])
def queue_stats(service: ServiceDep, principal: AnalystDep) -> dict[str, Any]:  # noqa: ARG001
    """Queue depth, overdue cases, time to claim and resolve, reporter precision."""
    return service.queue_stats()


@app.get("/api/v1/cases/{case_id}", response_model=CaseDetail, tags=["review queue"])
def get_case(case_id: str, service: ServiceDep, principal: AnalystDep) -> CaseDetail:
    """One case, its full history, and the actions this caller may take next."""
    detail = service.get_case(case_id, principal=principal)
    if detail is None:
        raise HTTPException(status_code=404, detail="case not found")
    return detail


@app.post("/api/v1/cases/{case_id}/actions", response_model=CaseDetail, tags=["review queue"])
def act_on_case(
    case_id: str,
    payload: CaseActionRequest,
    service: ServiceDep,
    principal: AnalystDep,
) -> CaseDetail:
    """Claim, release, escalate, resolve, reopen or comment on a case.

    409 when the case's state does not allow the action (including a claim
    another analyst won first); 403 when the caller may not take it -- for
    example resolving a case someone else has claimed, or releasing a message
    the model scored above the block threshold without the admin role.
    """
    try:
        return service.act_on_case(case_id, payload, principal=principal)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="case not found") from exc
    except workflow.WorkflowError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


# --------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------
@app.get("/report", response_class=HTMLResponse, include_in_schema=False)
def report_page() -> HTMLResponse:
    """A plain page for email users to report a suspicious message."""
    asset = find_static_asset("report.html")
    if asset is not None:
        try:
            return HTMLResponse(asset.read_text(encoding="utf-8"))
        except OSError as exc:
            logger.warning("report page at %s is unreadable: %s", asset, exc)
    return HTMLResponse("<h1>PhishGuard</h1><p>The report page asset was not found.</p>")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def console() -> HTMLResponse:
    """The analyst console. Authenticates in the browser with an API key."""
    asset = _console_asset()
    if asset is not None:
        try:
            return HTMLResponse(asset.read_text(encoding="utf-8"))
        except OSError as exc:  # unreadable file: report it rather than 500
            logger.warning("console asset at %s is unreadable: %s", asset, exc)
    return HTMLResponse(
        "<h1>PhishGuard</h1>"
        "<p>The API is running, but the analyst console asset was not found.</p>"
        "<p>The API itself is fully available at <a href='/docs'>/docs</a>. "
        "To restore the console, set <code>PG_UI_PATH</code> to the location of "
        "<code>index.html</code>.</p>",
        status_code=200,
    )


@app.get("/openapi.json", include_in_schema=False)
def openapi_spec() -> JSONResponse:
    return JSONResponse(app.openapi())


def export_openapi(path: str | Path) -> Path:
    """Write the OpenAPI document - used by CI and by the deliverables build."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(app.openapi(), indent=2), encoding="utf-8")
    return target
