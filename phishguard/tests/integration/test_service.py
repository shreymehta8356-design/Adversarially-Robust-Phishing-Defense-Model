"""End-to-end behaviour of the scanning service, model and audit trail.

These exercise the whole decision path without an HTTP server, which is what
the framework-free service core is for.
"""

from __future__ import annotations

import numpy as np

from phishguard.adversarial.attacker import BudgetedAttacker, RawScoreSurface
from phishguard.eval.metrics import score_summary
from phishguard.schemas import BAND_ALLOW, BAND_BLOCK, BANDS
from phishguard.service.contracts import (
    AdversarialProbeRequest,
    BatchScanRequest,
    FeedbackRequest,
    UrlScanRequest,
)
from tests.helpers import (
    ham_message,
    phishing_message,
    scan_request,
    scan_service,
    split_corpus,
    trained_detector,
)


# --------------------------------------------------------------- the model
def test_detector_trains_and_separates_the_classes():
    detector, _ = trained_detector()
    _, _, test, y_test, _ = split_corpus()
    summary = score_summary(y_test, detector.predict_proba(test))
    assert summary["macro_f1"] > 0.85, summary
    assert summary["pr_auc"] > 0.90, summary


def test_detector_keeps_false_positives_low():
    detector, _ = trained_detector()
    _, _, test, y_test, _ = split_corpus()
    summary = score_summary(y_test, detector.predict_proba(test))
    assert summary["false_positive_rate"] <= 0.05, summary


def test_obvious_phishing_scores_above_obvious_legitimate_mail():
    detector, _ = trained_detector()
    phish = detector.assess(phishing_message())
    ham = detector.assess(ham_message())
    assert phish.score > ham.score
    assert phish.band == BAND_BLOCK
    assert ham.band == BAND_ALLOW


def test_verdict_carries_evidence_and_member_scores():
    detector, _ = trained_detector()
    verdict = detector.assess(phishing_message())
    assert verdict.band in BANDS
    assert verdict.evidence, "a blocked message must come with evidence"
    assert set(verdict.member_scores) == set(detector.member_names)
    assert all(0.0 <= v <= 1.0 for v in verdict.member_scores.values())
    assert verdict.latency_ms > 0


def test_evidence_is_human_readable_not_feature_names():
    detector, _ = trained_detector()
    titles = [e["title"] for e in detector.assess(phishing_message()).evidence]
    assert titles
    assert any(" " in t for t in titles), "evidence should be sentences"
    assert not any(t.startswith(("hdr_", "beh_", "url_")) for t in titles)


def test_missing_behavioral_context_is_reported_not_invented():
    from phishguard.schemas import BehavioralContext

    detector, _ = trained_detector()
    verdict = detector.assess(
        phishing_message(behavioral=BehavioralContext(available=False))
    )
    assert verdict.behavioral_available is False
    assert any("history" in e["title"].lower() or "context" in e["title"].lower()
               for e in verdict.evidence)


def test_predictions_are_deterministic():
    detector, _ = trained_detector()
    msg = phishing_message()
    scores = [detector.assess(msg, explain=False).score for _ in range(3)]
    assert len(set(round(s, 9) for s in scores)) == 1


def test_batch_and_single_scoring_agree():
    detector, _ = trained_detector()
    messages = [phishing_message(), ham_message()]
    batch = detector.predict_proba(messages)
    singles = [detector.predict_proba([m])[0] for m in messages]
    np.testing.assert_allclose(batch, singles, atol=1e-12)


def test_empty_batch_is_handled():
    detector, _ = trained_detector()
    assert detector.predict_proba([]).shape == (0,)


def test_model_persists_and_reloads_with_identical_scores(tmp_path=None):
    import tempfile
    from pathlib import Path

    from phishguard.models.registry import current_version, load_detector, save_detector
    from tests.helpers import make_settings

    detector, _ = trained_detector()
    settings = make_settings(
        artifacts_dir=Path(tempfile.mkdtemp(prefix="pg-registry-"))
    )
    record = save_detector(detector, settings=settings, metrics={"macro_f1": 0.9})
    assert current_version(settings=settings) == record.version

    reloaded, manifest = load_detector(settings=settings)
    assert reloaded.model_version == detector.model_version
    assert manifest["version"] == record.version
    msg = phishing_message()
    assert abs(
        reloaded.assess(msg, explain=False).score
        - detector.assess(msg, explain=False).score
    ) < 1e-12


# ------------------------------------------------------------- the service
def test_scan_records_a_decision_and_returns_a_band():
    service, store, _ = scan_service()
    before = store.count()
    response = service.scan(scan_request())
    assert response.band in BANDS
    assert response.decision_id.startswith("dec_")
    assert store.count() == before + 1


def test_audit_trail_stores_no_message_content():
    """Data minimisation is the point of the audit schema."""
    service, store, _ = scan_service()
    secret_subject = "Board pack Q3 - CONFIDENTIAL merger terms"
    secret_body = "The acquisition price is 41.5 million. http://x-verify.tk/login"
    response = service.scan(
        scan_request(subject=secret_subject, body=secret_body,
                     sender="Real Person <real.person@partner.example>")
    )
    row = store.get_decision(response.decision_id)
    assert row is not None
    blob = " ".join(str(v) for v in row.values())
    assert "CONFIDENTIAL" not in blob
    assert "41.5 million" not in blob
    assert "real.person@partner.example" not in blob
    # But it stays investigable.
    assert row["sender_domain"] == "partner.example"
    assert row["sender_px"].startswith("px_")
    assert row["subject_hash"]


def test_feedback_attaches_to_a_decision():
    service, _, _ = scan_service()
    response = service.scan(scan_request())
    feedback = service.submit_feedback(
        FeedbackRequest(decision_id=response.decision_id, analyst_label="phishing",
                        rationale="confirmed credential harvest")
    )
    assert feedback.decision_id == response.decision_id
    assert "never used to retrain" in feedback.note
    record = service.get_decision(response.decision_id)
    assert record is not None and record.feedback_label == "phishing"


def test_feedback_on_an_unknown_decision_is_rejected():
    service, _, _ = scan_service()
    try:
        service.submit_feedback(
            FeedbackRequest(decision_id="dec_does_not_exist", analyst_label="phishing")
        )
    except KeyError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected KeyError for an unknown decision id")


def test_decisions_are_listable_and_filterable():
    service, _, _ = scan_service()
    service.scan(scan_request())
    page = service.list_decisions(limit=10)
    assert page.total >= 1
    assert len(page.items) <= 10
    blocked = service.list_decisions(limit=10, band="BLOCK")
    assert all(item.band == "BLOCK" for item in blocked.items)


def test_batch_scan_returns_one_result_per_message():
    service, _, _ = scan_service()
    batch = service.scan_batch(
        BatchScanRequest(messages=[scan_request(), scan_request(subject="Lunch?",
                                                                body="See you at 1.")])
    )
    assert len(batch.results) == 2
    assert batch.total_latency_ms > 0


def test_url_scan_separates_impersonation_from_a_genuine_domain():
    service, _, _ = scan_service()
    bad = service.scan_url(UrlScanRequest(url="http://paypa1-secure.tk/account/login"))
    good = service.scan_url(UrlScanRequest(url="https://www.paypal.com/signin"))
    assert bad.risk_score > good.risk_score
    assert bad.registered_domain == "paypa1-secure.tk"
    assert good.band == BAND_ALLOW
    assert bad.reasons


def test_url_scan_unwraps_a_redirect():
    service, _, _ = scan_service()
    result = service.scan_url(
        UrlScanRequest(url="https://relay.example/r?url=https%3A%2F%2Fbad.tk%2Flogin")
    )
    assert "bad.tk" in result.canonical_url


def test_operational_stats_summarise_the_audit_trail():
    service, _, _ = scan_service()
    service.scan(scan_request())
    stats = service.operational_stats()
    assert stats["decisions"] >= 1
    assert "score_distribution" in stats
    assert sum(b["count"] for b in stats["score_distribution"]) >= 1


def test_model_info_exposes_the_taxonomy_and_defences():
    service, _, _ = scan_service()
    info = service.model_info()
    assert info["model_version"]
    assert len(info["attack_taxonomy"]) >= 6
    assert len(info["defense_catalogue"]) >= 6
    assert info["active_defense_ids"]


# --------------------------------------------------------- adversarial path
def test_adversarial_probe_runs_and_explains_itself():
    service, _, _ = scan_service()
    response = service.probe(AdversarialProbeRequest(message=scan_request(), budget=6))
    assert response.queries >= 1
    assert 0.0 <= response.final_score <= 1.0
    assert response.interpretation
    assert response.trajectory


def test_the_fusion_is_harder_to_evade_than_a_text_only_baseline():
    """The central claim of the project, asserted as a test."""
    from phishguard.models.baseline import TfidfBaseline

    detector, _ = trained_detector()
    train, y_train, test, y_test, _ = split_corpus()
    phish = [m for m, y in zip(test, y_test, strict=True) if y == 1][:40]

    baseline = TfidfBaseline().fit(train, y_train)

    class _Surface:
        def predict_proba(self, messages):
            return baseline.score(messages)

    fusion_results = BudgetedAttacker(
        RawScoreSurface(detector), budget=8, seed=3
    ).attack_many(phish)
    baseline_results = BudgetedAttacker(_Surface(), budget=8, seed=3).attack_many(phish)

    fusion_asr = float(np.mean([r.evaded for r in fusion_results]))
    baseline_asr = float(np.mean([r.evaded for r in baseline_results]))
    assert fusion_asr <= baseline_asr, (fusion_asr, baseline_asr)


def test_adversarial_training_augments_only_phishing():
    """Teaching the model that obfuscation is label-neutral would be a own goal."""
    from phishguard.models.detector import PhishGuardDetector
    from tests.helpers import make_settings

    train, y_train, _, _, _ = split_corpus()
    detector = PhishGuardDetector(settings=make_settings())
    augmented, augmented_y = detector._augment(train[:200], y_train[:200], seed=1)
    added = len(augmented) - 200
    assert added > 0
    assert all(y == 1 for y in augmented_y[200:])
