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
``GET  /``                         the analyst console
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, AsyncIterator

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from phishguard import __version__
from phishguard.config import find_console_asset, get_settings
from phishguard.service import telemetry
from phishguard.service.contracts import (
    AdversarialProbeRequest,
    AdversarialProbeResponse,
    BatchScanRequest,
    BatchScanResponse,
    DecisionPage,
    DecisionRecord,
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
    ModelInfoResponse,
    ScanRequest,
    ScanResponse,
    UrlScanRequest,
    UrlScanResponse,
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
            logger, logging.INFO, "model loaded",
            model_version=detector.model_version,
            members=",".join(detector.member_names),
            defenses=",".join(detector.defenses.active_ids),
        )
    except Exception as exc:  # noqa: BLE001
        # Start anyway: /healthz and /metrics stay useful, and /readyz reports
        # the reason, which is what an orchestrator needs to act on.
        STATE["model_error"] = str(exc)
        telemetry.log_event(
            logger, logging.ERROR,
            "no model available - service is live but not ready", error=str(exc),
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
        "Authenticate with an `X-API-Key` header. Scanning requires the `analyst` "
        "role; the audit trail and the adversarial probe require `admin`.\n\n"
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

    try:
        response = await call_next(request)
    except Exception:  # noqa: BLE001
        logger.exception("unhandled error", extra={"extra_fields": {"request_id": request_id}})
        elapsed = (time.perf_counter() - started) * 1000.0
        endpoint = request.scope.get("route").path if request.scope.get("route") else request.url.path
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
    return service.scan(
        payload, principal=principal, request_id=request.state.request_id
    )


@app.post("/api/v1/scan/batch", response_model=BatchScanResponse, tags=["scanning"])
def scan_batch(
    payload: BatchScanRequest,
    request: Request,
    service: ServiceDep,
    principal: AnalystDep,
) -> BatchScanResponse:
    """Assess up to 100 messages. Each is audited individually."""
    return service.scan_batch(
        payload, principal=principal, request_id=request.state.request_id
    )


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
        limit=limit, offset=offset, band=band,
        sender_domain=sender_domain, min_score=min_score,
    )


@app.get("/api/v1/decisions/{decision_id}", response_model=DecisionRecord,
         tags=["oversight"])
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


@app.post("/api/v1/adversarial/probe", response_model=AdversarialProbeResponse,
          tags=["model"])
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
    return service.probe(
        payload, principal=principal, request_id=request.state.request_id
    )


# --------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------
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
