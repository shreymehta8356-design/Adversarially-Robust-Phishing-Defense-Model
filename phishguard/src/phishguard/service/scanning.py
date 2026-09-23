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
import time
from typing import Any

from phishguard.config import Settings
from phishguard.models.detector import PhishGuardDetector
from phishguard.schemas import BAND_ALLOW, BAND_BLOCK, BAND_REVIEW
from phishguard.service import telemetry
from phishguard.service.contracts import (
    AdversarialProbeRequest,
    AdversarialProbeResponse,
    BatchScanRequest,
    BatchScanResponse,
    DecisionPage,
    DecisionRecord,
    EvidenceItem,
    FeedbackRequest,
    FeedbackResponse,
    ScanRequest,
    ScanResponse,
    UrlScanRequest,
    UrlScanResponse,
)
from phishguard.service.security import (
    Principal,
    new_decision_id,
    new_feedback_id,
    new_request_id,
)
from phishguard.service.store import DecisionStore

logger = logging.getLogger("phishguard.scan")


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
        telemetry.MODEL_INFO.set(
            1.0,
            model_version=detector.model_version,
            calibration=detector.calibrator.fitted_method,
        )

    # ---------------------------------------------------------------- scan
    def scan(
        self,
        request: ScanRequest,
        *,
        principal: Principal | None = None,
        request_id: str | None = None,
        explain: bool = True,
        record: bool = True,
    ) -> ScanResponse:
        request_id = request_id or new_request_id()
        decision_id = new_decision_id()
        message = request.to_message()

        started = time.perf_counter()
        verdict = self.detector.assess(message, explain=explain)
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        telemetry.SCANS.inc(band=verdict.band)
        telemetry.SCAN_LATENCY.observe(elapsed_ms)
        telemetry.SCORE_HISTOGRAM.observe(verdict.score)
        telemetry.BEHAVIORAL_CONTEXT.inc(
            available="true" if verdict.behavioral_available else "false"
        )

        payload = verdict.as_dict()
        if record:
            try:
                self.store.record_decision(
                    decision_id=decision_id,
                    request_id=request_id,
                    verdict=payload,
                    redacted=message.redacted(self.settings.pseudonymization_salt),
                    key_id=principal.key_id if principal else "",
                    client_reference=request.client_reference,
                )
            except Exception:  # noqa: BLE001
                # The audit write must never take down a scan. A dropped audit
                # row is logged loudly and the verdict is still returned, which
                # is the right trade for an inline mail path.
                logger.exception("failed to record decision %s", decision_id)

        telemetry.log_event(
            logger, logging.INFO, "scan",
            request_id=request_id, decision_id=decision_id,
            score=round(verdict.score, 4), band=verdict.band,
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
        results = [
            self.scan(m, principal=principal, request_id=request_id,
                      explain=request.explain)
            for m in request.messages
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
            BAND_BLOCK if score >= self.settings.block_threshold
            else (BAND_REVIEW if score >= self.settings.review_threshold else BAND_ALLOW)
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
            logger, logging.INFO, "feedback",
            decision_id=request.decision_id, analyst_label=request.analyst_label,
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
            limit=limit, offset=offset, band=band,
            sender_domain=sender_domain, min_score=min_score,
        )
        return DecisionPage(
            items=[self._to_record(r) for r in rows],
            total=total, limit=limit, offset=offset,
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
            evasion_threshold=self.settings.review_threshold,
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
    def model_info(self) -> dict[str, Any]:
        from phishguard.adversarial.taxonomy import describe_taxonomy
        from phishguard.defenses.controls import describe_defenses

        described = self.detector.describe()
        return {
            **described,
            "trained_at": described.get("trained_at") or "",
            "attack_taxonomy": describe_taxonomy(),
            "defense_catalogue": describe_defenses(),
            "metrics": self.manifest.get("metrics", {}),
        }

    def operational_stats(self, window_hours: int = 24) -> dict[str, Any]:
        stats = self.store.stats(window_hours=window_hours)
        stats["score_distribution"] = self.store.score_distribution(
            window_hours=window_hours
        )
        stats["model_version"] = self.detector.model_version
        return stats
