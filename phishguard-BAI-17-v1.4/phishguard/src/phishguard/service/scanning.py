"""Scanning orchestration.

All of the service's behaviour lives here, deliberately free of any web
framework: assessment, audit recording, URL triage, feedback capture and the
adversarial probe. The FastAPI layer in :mod:`phishguard.service.app` is a thin
adapter that parses a request, calls one of these methods and serialises the
result.

The separation is not decoration. It means the request-handling logic is unit
testable without an HTTP server or an event loop, that the same code path can
be driven from the CLI, and that swapping the transport would not touch a line
of decision logic.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import numpy as np

from phishguard.config import Settings
from phishguard.data.hardcases import describe_benchmark
from phishguard.models.detector import PhishGuardDetector
from phishguard.runtime import limit_native_threads_for_serving
from phishguard.schemas import BAND_ALLOW, BAND_BLOCK, BAND_REVIEW, pseudonymize
from phishguard.service import telemetry, tracing, workflow
from phishguard.service.contracts import (
    AdversarialProbeRequest,
    AdversarialProbeResponse,
    BatchScanRequest,
    BatchScanResponse,
    CaseActionRequest,
    CaseDetail,
    CaseEvent,
    CasePage,
    CaseSummary,
    DecisionPage,
    DecisionRecord,
    EvidenceItem,
    FeedbackRequest,
    FeedbackResponse,
    ReportList,
    ReportReceipt,
    ReportRequest,
    ReportSummary,
    ScanRequest,
    ScanResponse,
    UrlScanRequest,
    UrlScanResponse,
)
from phishguard.service.security import (
    Principal,
    new_case_id,
    new_decision_id,
    new_feedback_id,
    new_request_id,
)
from phishguard.service.store import DecisionStore

logger = logging.getLogger("phishguard.scan")


class FairSlots:
    """A first-come, first-served semaphore.

    ``threading.Semaphore`` makes no promise about which waiter goes next, and
    in practice the thread that just released it usually wins again: under
    load that starves the others, and the load test measured a p99 above two
    seconds with a p50 of 15 ms. Handing the slot directly to the oldest waiter
    keeps the order of arrival, so latency grows with the queue, evenly.
    """

    def __init__(self, slots: int) -> None:
        if slots < 1:
            raise ValueError("at least one slot is required")
        self._free = slots
        self._lock = threading.Lock()
        self._waiters: deque[threading.Event] = deque()

    def acquire(self) -> None:
        with self._lock:
            if self._free and not self._waiters:
                self._free -= 1
                return
            turn = threading.Event()
            self._waiters.append(turn)
        turn.wait()  # the releasing thread hands its slot straight to us

    def release(self) -> None:
        with self._lock:
            if self._waiters:
                self._waiters.popleft().set()
            else:
                self._free += 1

    @property
    def waiting(self) -> int:
        with self._lock:
            return len(self._waiters)


class ScanService:
    """Everything the API does, minus the HTTP."""

    def __init__(
        self,
        detector: PhishGuardDetector,
        store: DecisionStore,
        settings: Settings,
        *,
        manifest: dict[str, Any] | None = None,
    ) -> None:
        self.detector = detector
        self.store = store
        self.settings = settings
        self.manifest = manifest or {}
        # Scoring is CPU-bound and holds the interpreter lock. When several
        # server threads score at once they do not run in parallel, they take
        # turns -- and the switching costs about a third of the throughput
        # (docs/07 section 7.14). A small number of scoring slots per process
        # makes excess requests wait in line instead, which keeps throughput
        # at its single-thread level and gives shorter tails. More throughput
        # comes from more processes (``serve --workers``), not more threads.
        self._scoring_slots = FairSlots(max(1, int(getattr(settings, "scoring_concurrency", 1))))
        telemetry.MODEL_INFO.set(
            1.0,
            model_version=detector.model_version,
            calibration=detector.calibrator.fitted_method,
        )

    @contextmanager
    def _scoring_slot(self) -> Iterator[None]:
        """Hold one of this process's scoring slots; the wait is its own span."""
        with tracing.span("wait.scoring"):
            self._scoring_slots.acquire()
        try:
            yield
        finally:
            self._scoring_slots.release()

    # ---------------------------------------------------------------- scan
    def scan(
        self,
        request: ScanRequest,
        *,
        principal: Principal | None = None,
        request_id: str | None = None,
        explain: bool = True,
        record: bool = True,
        open_review_case: bool = True,
    ) -> ScanResponse:
        request_id = request_id or new_request_id()
        message = request.to_message()
        limit_native_threads_for_serving()

        # Continues the HTTP request's trace when there is one; a CLI or batch
        # caller gets a trace of its own, so every decision carries a trace id.
        with tracing.trace("scan"), self._scoring_slot():
            started = time.perf_counter()
            with tracing.span("assess"):
                verdict = self.detector.assess(message, explain=explain)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return self._respond(
                request,
                message,
                verdict,
                elapsed_ms,
                principal=principal,
                request_id=request_id,
                record=record,
                open_review_case=open_review_case,
            )

    def _respond(
        self,
        request: ScanRequest,
        message: Any,
        verdict: Any,
        elapsed_ms: float,
        *,
        principal: Principal | None,
        request_id: str,
        record: bool,
        open_review_case: bool = True,
    ) -> ScanResponse:
        """Telemetry, audit record and response for one computed verdict."""
        decision_id = new_decision_id()
        telemetry.SCANS.inc(band=verdict.band)
        telemetry.SCAN_LATENCY.observe(elapsed_ms)
        telemetry.SCORE_HISTOGRAM.observe(verdict.score)
        telemetry.BEHAVIORAL_CONTEXT.inc(
            available="true" if verdict.behavioral_available else "false"
        )

        payload = verdict.as_dict()
        trace_id = tracing.current_trace_id()
        if record:
            try:
                with tracing.span("audit.write"):
                    self.store.record_decision(
                        decision_id=decision_id,
                        request_id=request_id,
                        verdict=payload,
                        redacted=message.redacted(self.settings.pseudonymization_salt),
                        key_id=principal.key_id if principal else "",
                        client_reference=request.client_reference,
                        trace_id=trace_id,
                    )
            except Exception:  # noqa: BLE001
                # The audit write must never take down a scan. A dropped audit
                # row is logged loudly and the verdict is still returned, which
                # is the right trade for an inline mail path.
                logger.exception("failed to record decision %s", decision_id)
            else:
                # A REVIEW band is a promise that a person will look: keep it
                # by opening a case in the analyst queue.
                if verdict.band == BAND_REVIEW and open_review_case:
                    with tracing.span("queue.open"):
                        self._open_case(
                            decision_id,
                            origin="model_review",
                            band=verdict.band,
                            principal=principal,
                        )

        telemetry.log_event(
            logger,
            logging.INFO,
            "scan",
            request_id=request_id,
            decision_id=decision_id,
            trace_id=trace_id,
            score=round(verdict.score, 4),
            band=verdict.band,
            model_version=verdict.model_version,
            sender_domain=message.sender_domain,
            behavioral=verdict.behavioral_available,
            latency_ms=round(elapsed_ms, 2),
            key_id=principal.key_id if principal else "",
        )

        return ScanResponse(
            request_id=request_id,
            decision_id=decision_id,
            score=round(verdict.score, 6),
            band=verdict.band,  # type: ignore[arg-type]
            label=verdict.label,
            model_version=verdict.model_version,
            evidence=[
                EvidenceItem(
                    kind=str(e.get("kind", "")),
                    id=str(e.get("id", "")),
                    title=str(e.get("title", "")),
                    detail=str(e.get("detail", "")),
                    direction=str(e.get("direction", "neutral")),
                    weight=float(e.get("weight", 0.0)),
                )
                for e in verdict.evidence
            ],
            signals=verdict.signals,
            member_scores=verdict.member_scores,
            defenses_applied=verdict.defenses_applied,
            behavioral_available=verdict.behavioral_available,
            abstained=verdict.abstained,
            latency_ms=round(elapsed_ms, 3),
            client_reference=request.client_reference,
            trace_id=trace_id,
            stage_ms=tracing.stage_timings(),
        )

    def scan_batch(
        self,
        request: BatchScanRequest,
        *,
        principal: Principal | None = None,
        request_id: str | None = None,
    ) -> BatchScanResponse:
        request_id = request_id or new_request_id()
        started = time.perf_counter()
        limit_native_threads_for_serving()
        # One vectorised pass for every message's score and band, then the
        # same per-message telemetry and audit write as a single scan. The
        # verdicts are identical to scanning each message on its own.
        with tracing.trace("scan_batch"):
            messages = [m.to_message() for m in request.messages]
            with self._scoring_slot(), tracing.span("assess", messages=len(messages)):
                verdicts = self.detector.assess_batch(
                    messages, explain="all" if request.explain else "none"
                )
            results = [
                self._respond(
                    req,
                    msg,
                    verdict,
                    verdict.latency_ms,
                    principal=principal,
                    request_id=request_id,
                    record=True,
                )
                for req, msg, verdict in zip(request.messages, messages, verdicts, strict=True)
            ]
        return BatchScanResponse(
            request_id=request_id,
            results=results,
            total_latency_ms=round((time.perf_counter() - started) * 1000.0, 3),
        )

    # ----------------------------------------------------------- URL triage
    def scan_url(
        self, request: UrlScanRequest, *, request_id: str | None = None
    ) -> UrlScanResponse:
        """Standalone URL assessment for click-time protection.

        Deliberately rule-based rather than model-based: the trained model
        expects a message, and feeding it a synthetic one-line email would
        produce a confident number with no support behind it. A transparent
        weighted score over the URL family is the honest answer to "here is a
        URL and nothing else", and the reasons list says exactly what drove it.
        """
        from phishguard.features.urls import canonicalize_url, parse_url, url_features

        request_id = request_id or new_request_id()
        started = time.perf_counter()
        canonical = canonicalize_url(request.url)
        parsed = parse_url(canonical)
        features = url_features(request.url)

        weights: dict[str, tuple[float, str]] = {
            "url_brand_impersonation": (0.34, "Impersonates a brand it does not belong to"),
            "url_is_ip_host": (0.20, "Uses a bare IP address as the host"),
            "url_high_risk_tld": (0.14, "Top-level domain has a high abuse rate"),
            "url_free_hosting": (0.12, "Hosted on free, anonymous infrastructure"),
            "url_is_punycode": (0.12, "Internationalised domain that can imitate ASCII"),
            "url_has_userinfo": (0.12, "Credentials embedded before the host"),
            "url_has_at_symbol": (0.10, "'@' in the authority section hides the real host"),
            "url_is_shortener": (0.08, "Destination hidden behind a shortener"),
            "url_has_redirect_param": (0.08, "Redirects through another site"),
            "url_deep_subdomain": (0.07, "Host padded with several subdomain levels"),
            "url_mixed_script_host": (0.15, "Host mixes character scripts"),
            "url_nonstandard_port": (0.06, "Served on a non-standard port"),
            "url_double_slash_in_path": (0.05, "Path contains a redirect marker"),
        }
        score = 0.0
        reasons: list[str] = []
        for name, (weight, reason) in weights.items():
            if features.get(name, 0.0) > 0:
                score += weight
                reasons.append(reason)

        suspicious = features.get("url_suspicious_token_count", 0.0)
        if suspicious >= 2:
            score += 0.08
            reasons.append(f"Path contains {int(suspicious)} credential-page keywords")
        if features.get("url_official_brand_domain", 0.0) > 0:
            score = max(score - 0.35, 0.0)
            reasons.append("Destination is a brand's genuine domain")
        if features.get("url_is_https", 0.0) == 0:
            score += 0.04
            reasons.append("Not served over HTTPS")

        score = float(min(max(score, 0.0), 0.99))
        band = (
            BAND_BLOCK
            if score >= self.detector.block_threshold
            else (BAND_REVIEW if score >= self.detector.review_threshold else BAND_ALLOW)
        )
        if not reasons:
            reasons.append("No lexical or structural risk indicators found")

        return UrlScanResponse(
            request_id=request_id,
            url=request.url[:4096],
            canonical_url=canonical[:4096],
            registered_domain=parsed.registered_domain,
            risk_score=round(score, 5),
            band=band,  # type: ignore[arg-type]
            signals={k: round(v, 5) for k, v in features.items() if v},
            reasons=reasons,
            latency_ms=round((time.perf_counter() - started) * 1000.0, 3),
            client_reference=request.client_reference,
        )

    # ------------------------------------------------------------ feedback
    def submit_feedback(
        self, request: FeedbackRequest, *, principal: Principal | None = None
    ) -> FeedbackResponse:
        record = self.store.record_feedback(
            feedback_id=new_feedback_id(),
            decision_id=request.decision_id,
            analyst_label=request.analyst_label,
            rationale=request.rationale,
            action_taken=request.action_taken,
            key_id=principal.key_id if principal else "",
        )
        telemetry.FEEDBACK.inc(label=request.analyst_label)
        telemetry.log_event(
            logger,
            logging.INFO,
            "feedback",
            decision_id=request.decision_id,
            analyst_label=request.analyst_label,
            key_id=principal.key_id if principal else "",
        )
        return FeedbackResponse(
            feedback_id=record["feedback_id"],
            decision_id=record["decision_id"],
            recorded_at=record["recorded_at"],
            note=(
                "Recorded for review. Feedback is never used to retrain "
                "automatically: an endpoint that could move the decision boundary "
                "would be a poisoning vector, so retraining stays a reviewed action."
            ),
        )

    # --------------------------------------------------------- review queue
    def _open_case(
        self,
        decision_id: str,
        *,
        origin: str,
        band: str,
        principal: Principal | None,
        reporter_px: str = "",
        category: str = "",
        note: str = "",
    ) -> str | None:
        """Open a case for a recorded decision. Never fails the scan that asked."""
        priority = workflow.priority_for(origin, band)
        case_id = new_case_id()
        try:
            opened = self.store.open_case(
                case_id=case_id,
                decision_id=decision_id,
                origin=origin,
                priority=priority,
                sla_due_ts=workflow.sla_due(time.time(), priority),
                actor=principal.key_id if principal else "system",
                actor_role=principal.role if principal else "system",
                reporter_key=principal.key_id if (principal and origin == "user_report") else "",
                reporter_px=reporter_px,
                report_category=category,
                note=note,
            )
        except Exception:  # noqa: BLE001 - the verdict still stands without a case
            logger.exception("failed to open a case for decision %s", decision_id)
            return None
        telemetry.CASES_OPENED.inc(origin=origin, priority=f"P{priority}")
        self._refresh_queue_gauges()
        telemetry.log_event(
            logger,
            logging.INFO,
            "case opened",
            case_id=case_id,
            decision_id=decision_id,
            origin=origin,
            priority=priority,
            opened_at=opened["created_at"],
        )
        return case_id

    def _refresh_queue_gauges(self) -> None:
        try:
            by_state, overdue = self.store.queue_depth()
        except Exception:  # noqa: BLE001 - metrics must never break a request
            return
        for state in workflow.ACTIVE_STATES:
            telemetry.QUEUE_DEPTH.set(float(by_state.get(state, 0)), state=state)
        telemetry.QUEUE_OVERDUE.set(float(overdue))

    def report(
        self,
        request: ReportRequest,
        *,
        principal: Principal | None = None,
        request_id: str | None = None,
    ) -> ReportReceipt:
        """An email user reports a suspicious message.

        The message is assessed and recorded like any other, then always
        opened as a case -- a report is a human signal worth a human answer,
        whatever the model thought. The receipt says nothing about the score.
        """
        # One case per report: the model's own REVIEW case is suppressed here,
        # because the user report supersedes it and a duplicate would split
        # the analysts' attention.
        response = self.scan(
            request.message, principal=principal, request_id=request_id, open_review_case=False
        )
        reporter_px = (
            pseudonymize(request.reporter_ref, self.settings.pseudonymization_salt)
            if request.reporter_ref
            else ""
        )
        case_id = self._open_case(
            response.decision_id,
            origin="user_report",
            band=response.band,
            principal=principal,
            reporter_px=reporter_px,
            category=request.category,
            note=request.note,
        )
        if case_id is None:
            raise RuntimeError("the report was assessed but could not be queued")
        case = self.store.get_case(case_id) or {}
        return ReportReceipt(
            case_id=case_id,
            received_at=str(case.get("created_at", "")),
            status=case.get("state", "open"),
            message=workflow.reporter_status(case.get("state", "open"), case.get("resolution")),
        )

    def my_reports(
        self, *, principal: Principal, reporter_ref: str = "", limit: int = 50
    ) -> ReportList:
        """A reporter's own reports and what became of them. No scores."""
        reporter_px = (
            pseudonymize(reporter_ref, self.settings.pseudonymization_salt)
            if reporter_ref
            else None
        )
        rows, total = self.store.list_cases(
            reporter_key=principal.key_id, reporter_px=reporter_px, limit=limit
        )
        return ReportList(
            total=total,
            reports=[
                ReportSummary(
                    case_id=r["case_id"],
                    received_at=r["created_at"],
                    category=r.get("report_category") or "other",
                    state=r["state"],
                    status=workflow.reporter_status(r["state"], r.get("resolution")),
                )
                for r in rows
                if r["origin"] == "user_report"
            ],
        )

    @staticmethod
    def _iso(ts: float | None) -> str:
        from datetime import datetime, timezone

        if not ts:
            return ""
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(timespec="seconds")

    def _case_summary(self, row: dict[str, Any], now: float) -> dict[str, Any]:
        active = row["state"] in workflow.ACTIVE_STATES
        return {
            "case_id": row["case_id"],
            "decision_id": row["decision_id"],
            "created_at": row["created_at"],
            "state": row["state"],
            "origin": row["origin"],
            "priority": int(row["priority"]),
            "sla_due_at": self._iso(row["sla_due_ts"]),
            "overdue": bool(active and row["sla_due_ts"] < now),
            "age_seconds": round(now - float(row["created_ts"]), 1),
            "assignee": row.get("assignee"),
            "resolution": row.get("resolution"),
            "score": round(float(row.get("score") or 0.0), 6),
            "band": row.get("band") or "",
            "sender_domain": row.get("sender_domain") or "",
            "top_evidence": list(row.get("top_evidence") or [])[:4],
            "report_category": row.get("report_category") or "",
            "model_version": row.get("model_version") or "",
            "trace_id": row.get("trace_id") or "",
        }

    def list_cases(
        self,
        *,
        state: str = "active",
        priority: int | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> CasePage:
        states = (
            workflow.ACTIVE_STATES if state == "active" else (None if state == "all" else (state,))
        )
        rows, total = self.store.list_cases(
            states=states, priority=priority, limit=limit, offset=offset
        )
        now = time.time()
        return CasePage(
            cases=[CaseSummary(**self._case_summary(r, now)) for r in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def _allowed_actions(self, row: dict[str, Any], principal: Principal) -> list[str]:
        allowed: list[str] = []
        for action in workflow.ACTIONS:
            variants = ["confirmed_phishing", "released"] if action == "resolve" else [None]
            for resolution in variants:
                try:
                    workflow.decide(
                        action=action,
                        state=row["state"],
                        actor=principal.key_id,
                        actor_role=principal.role,
                        assignee=row.get("assignee"),
                        resolution=resolution,
                        note="(probe)",
                        score=float(row.get("score") or 0.0),
                        block_threshold=float(self.detector.block_threshold),
                    )
                except workflow.WorkflowError:
                    continue
                allowed.append(f"resolve:{resolution}" if resolution else action)
        return allowed

    def get_case(self, case_id: str, *, principal: Principal | None = None) -> CaseDetail | None:
        row = self.store.get_case(case_id)
        if row is None:
            return None
        summary = self._case_summary(row, time.time())
        return CaseDetail(
            **summary,
            member_scores={k: float(v) for k, v in (row.get("member_scores") or {}).items()},
            events=[
                CaseEvent(
                    at=e["created_at"],
                    actor=e["actor"],
                    actor_role=e["actor_role"],
                    action=e["action"],
                    from_state=e["from_state"],
                    to_state=e["to_state"],
                    note=e["note"] or "",
                )
                for e in row.get("events", [])
            ],
            allowed_actions=self._allowed_actions(row, principal) if principal else [],
        )

    def act_on_case(
        self, case_id: str, request: CaseActionRequest, *, principal: Principal
    ) -> CaseDetail:
        """Validate and apply one review-queue action.

        Raises ``KeyError`` for an unknown case and :class:`workflow.WorkflowError`
        (with an HTTP-like ``status``) for an action that is not allowed.
        """
        row = self.store.get_case(case_id)
        if row is None:
            raise KeyError(case_id)
        transition = workflow.decide(
            action=request.action,
            state=row["state"],
            actor=principal.key_id,
            actor_role=principal.role,
            assignee=row.get("assignee"),
            resolution=request.resolution,
            note=request.note,
            score=float(row.get("score") or 0.0),
            block_threshold=float(self.detector.block_threshold),
        )
        applied = self.store.apply_transition(
            case_id=case_id,
            expected_state=transition.from_state,
            to_state=transition.to_state,
            assignee=transition.assignee,
            resolution=transition.resolution,
            action=request.action,
            actor=principal.key_id,
            actor_role=principal.role,
            note=request.note,
        )
        if not applied:
            raise workflow.InvalidTransition(
                "the case changed while you were looking at it - refresh and try again"
            )
        telemetry.CASE_ACTIONS.inc(action=request.action)
        if transition.to_state == "resolved" and transition.resolution:
            telemetry.CASE_RESOLUTION_SECONDS.observe(time.time() - float(row["created_ts"]))
            # A resolution is analyst feedback: record it once, through the same
            # path as the feedback endpoint, so disagreement metrics include it.
            self.store.record_feedback(
                feedback_id=new_feedback_id(),
                decision_id=row["decision_id"],
                analyst_label=workflow.RESOLUTION_LABEL[transition.resolution],
                rationale=request.note,
                action_taken=transition.resolution,
                key_id=principal.key_id,
            )
            telemetry.FEEDBACK.inc(label=workflow.RESOLUTION_LABEL[transition.resolution])
        self._refresh_queue_gauges()
        telemetry.log_event(
            logger,
            logging.INFO,
            "case action",
            case_id=case_id,
            action=request.action,
            from_state=transition.from_state,
            to_state=transition.to_state,
            resolution=transition.resolution or "",
            key_id=principal.key_id,
            role=principal.role,
        )
        detail = self.get_case(case_id, principal=principal)
        assert detail is not None  # noqa: S101 - it was just updated
        return detail

    def queue_stats(self) -> dict[str, Any]:
        stats = self.store.queue_stats()
        stats["service_levels"] = {
            f"P{p}": f"{s // 3600} h" for p, s in workflow.SLA_SECONDS.items()
        }
        return stats

    # -------------------------------------------------------------- audit
    def list_decisions(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        band: str | None = None,
        sender_domain: str | None = None,
        min_score: float | None = None,
    ) -> DecisionPage:
        rows, total = self.store.list_decisions(
            limit=limit,
            offset=offset,
            band=band,
            sender_domain=sender_domain,
            min_score=min_score,
        )
        return DecisionPage(
            items=[self._to_record(r) for r in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_decision(self, decision_id: str) -> DecisionRecord | None:
        row = self.store.get_decision(decision_id)
        return self._to_record(row) if row else None

    @staticmethod
    def _to_record(row: dict[str, Any]) -> DecisionRecord:
        return DecisionRecord(
            decision_id=row["decision_id"],
            request_id=row["request_id"],
            created_at=row["created_at"],
            score=float(row["score"]),
            band=row["band"],
            label=int(row["label"]),
            model_version=row["model_version"],
            subject_hash=row.get("subject_hash", ""),
            sender_px=row.get("sender_px", ""),
            sender_domain=row.get("sender_domain", ""),
            recipient_count=int(row.get("recipient_count", 0)),
            body_length=int(row.get("body_length", 0)),
            attachment_count=int(row.get("attachment_count", 0)),
            behavioral_available=bool(row.get("behavioral_available", False)),
            latency_ms=float(row.get("latency_ms", 0.0)),
            top_evidence=list(row.get("top_evidence", []))[:6],
            feedback_label=row.get("feedback_label"),
        )

    # --------------------------------------------------------- adversarial
    def probe(
        self,
        request: AdversarialProbeRequest,
        *,
        principal: Principal | None = None,
        request_id: str | None = None,
    ) -> AdversarialProbeResponse:
        """Run the attack suite against one message. Admin only.

        Answers "would this get through if the attacker tried harder?" for a
        specific message a security team is holding, and keeps the residual-risk
        claims honest after deployment rather than only at evaluation time.
        """
        from phishguard.adversarial.attacker import BudgetedAttacker, RawScoreSurface
        from phishguard.service.security import new_request_id as _rid

        request_id = request_id or _rid()
        message = request.message.to_message()
        families = tuple(request.families) if request.families else None
        attacker = BudgetedAttacker(
            RawScoreSurface(self.detector),
            budget=request.budget,
            evasion_threshold=self.detector.review_threshold,
            families=families,
            seed=self.settings.attack_seed,
            restarts=1,
        )
        result = attacker.attack(message)
        telemetry.ADVERSARIAL_PROBES.inc(evaded="true" if result.evaded else "false")
        try:
            self.store.record_probe(
                probe_id=request_id,
                model_version=self.detector.model_version,
                original_score=result.original_score,
                final_score=result.final_score,
                evaded=result.evaded,
                queries=result.queries,
                steps=result.steps,
                key_id=principal.key_id if principal else "",
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to record probe %s", request_id)

        if result.evaded:
            interpretation = (
                f"EVADED after {result.queries} queries using "
                f"{', '.join(result.steps) or 'no transform'}. A determined attacker "
                f"could get a message like this past the detector; route senders "
                f"matching this pattern to review and treat the finding as a gap."
            )
        elif result.score_drop > 0.05:
            interpretation = (
                f"Held, but the score fell {result.score_drop:.3f} under attack "
                f"({', '.join(result.steps)}). The margin is thinner than the clean "
                f"score suggests."
            )
        else:
            interpretation = (
                f"Held. {result.queries} queries moved the score by "
                f"{result.score_drop:.3f}; no transform in the enabled families "
                f"materially reduced the assessment."
            )

        return AdversarialProbeResponse(
            request_id=request_id,
            original_score=round(result.original_score, 6),
            final_score=round(result.final_score, 6),
            evaded=result.evaded,
            queries=result.queries,
            steps=result.steps,
            families_used=sorted(set(result.families_used)),
            trajectory=[round(s, 5) for s in result.trajectory],
            interpretation=interpretation,
        )

    # ------------------------------------------------------------ metadata
    # ------------------------------------------------------------- compare
    def _text_only_baseline(self):
        """The conventional filter this project argues against, trained lazily.

        Built on first use from a deterministic corpus and cached for the
        process lifetime. It is a demonstration and teaching aid, not part of
        the decision path -- the numbers quoted in the dossier come from the
        evaluation run, where the baseline is fitted on the same training
        split as the deployed model rather than on a fresh sample.
        """
        cached = getattr(self, "_tfidf", None)
        if cached is not None:
            return cached
        from phishguard.data.synthetic import generate_corpus
        from phishguard.models.baseline import TfidfBaseline

        messages, labels = generate_corpus(3000, seed=self.settings.random_seed)
        self._tfidf = TfidfBaseline().fit(messages, np.asarray(labels))
        return self._tfidf

    def compare(self, request: ScanRequest) -> dict[str, Any]:
        """Score one message with the full system and with a text-only filter.

        This is the project's argument on one screen. A content-only model
        reads a cloned brand template and sees the brand's own words, so it is
        not merely weaker on that message -- it is confidently wrong, which is
        worse than being uncertain.
        """
        message = request.to_message()
        with self._scoring_slot():
            verdict = self.detector.assess(message, explain=True)

        baseline = self._text_only_baseline()
        text_score = float(baseline.score([message])[0])

        # Band the baseline with the deployed boundaries so the two columns are
        # read the same way. The baseline has no abstention control, so it
        # always commits to a verdict -- which is the point being made.
        if text_score >= self.detector.block_threshold:
            text_band = BAND_BLOCK
        elif text_score >= self.detector.review_threshold:
            text_band = BAND_REVIEW
        else:
            text_band = BAND_ALLOW

        members = verdict.member_scores
        spread = self.detector.disagreement(members)
        return {
            "phishguard": {
                "label": "PhishGuard (email + URL + behavioural)",
                "score": round(verdict.score, 6),
                "band": verdict.band,
                "abstained": verdict.abstained,
                "member_scores": {k: round(v, 6) for k, v in members.items()},
                "member_disagreement": round(spread, 4),
                "evidence": verdict.evidence[:6],
            },
            "text_only": {
                "label": "Text-only filter (TF-IDF + logistic regression)",
                "score": round(text_score, 6),
                "band": text_band,
                "abstained": False,
                "note": (
                    "Reads subject and body only. No URL structure, no sender "
                    "provenance, no correspondence history."
                ),
            },
            "disagreement": round(abs(verdict.score - text_score), 6),
            "thresholds": {
                "review": self.detector.review_threshold,
                "block": self.detector.block_threshold,
            },
        }

    def benchmark(self) -> dict[str, Any]:
        """The most recent PG-HARD run, if one has been written.

        Served from the report on disk rather than recomputed: the benchmark
        takes tens of seconds and re-running it inside a request would make the
        console feel broken.
        """
        import json

        path = self.settings.reports_path / "pg-hard.json"
        if not path.exists():
            return {
                "available": False,
                "hint": (
                    "Run `phishguard hard` (or `phishguard evaluate`) to "
                    "produce artifacts/reports/pg-hard.json."
                ),
                "description": describe_benchmark(),
            }
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return {"available": False, "hint": f"could not read the report: {exc}"}
        report["available"] = True
        return report

    def drift(self, window_hours: int = 24) -> dict[str, Any]:
        """Drift of recent traffic against this model's legitimate-mail reference.

        Built entirely from the audit trail's content-free columns.
        """
        from phishguard.monitoring.drift import drift_report, live_from_audit_rows

        rows = self.store.monitoring_rows(window_hours=window_hours)
        live = live_from_audit_rows(rows, self.detector.member_names)
        report = drift_report(
            getattr(self.detector, "drift_reference", None), live, bands=[r["band"] for r in rows]
        )
        report["window_hours"] = window_hours
        return report

    def model_info(self) -> dict[str, Any]:
        from phishguard.adversarial.taxonomy import describe_taxonomy
        from phishguard.defenses.controls import describe_defenses

        described = self.detector.describe()
        # ``thresholds`` carries the numeric boundaries and, since the
        # thresholds became tuned to a false-alarm budget, a sentence saying
        # where they came from. The contract keeps the numbers numeric and
        # returns the explanation as its own field: mixing the two in one
        # mapping made this endpoint fail response validation.
        thresholds = dict(described.get("thresholds") or {})
        source = str(thresholds.pop("source", "") or "")
        return {
            **described,
            "thresholds": {k: float(v) for k, v in thresholds.items()},
            "threshold_source": source,
            "trained_at": described.get("trained_at") or "",
            "attack_taxonomy": describe_taxonomy(),
            "defense_catalogue": describe_defenses(),
            "metrics": self.manifest.get("metrics", {}),
        }

    def operational_stats(self, window_hours: int = 24) -> dict[str, Any]:
        stats = self.store.stats(window_hours=window_hours)
        stats["score_distribution"] = self.store.score_distribution(window_hours=window_hours)
        stats["model_version"] = self.detector.model_version
        return stats
