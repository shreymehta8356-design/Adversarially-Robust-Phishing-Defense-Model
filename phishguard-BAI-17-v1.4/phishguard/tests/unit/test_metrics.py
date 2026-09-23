"""Metrics, calibration and acceptance gates."""

from __future__ import annotations

import numpy as np

from phishguard.eval.acceptance import build_gates, evaluate_gates
from phishguard.eval.metrics import (
    banded_outcome,
    confusion,
    latency_stats,
    pr_auc,
    prf,
    roc_auc,
    threshold_for_target_fpr,
)
from phishguard.models.calibration import (
    Calibrator,
    brier_score,
    expected_calibration_error,
    reliability_curve,
)


def test_confusion_and_prf_on_a_known_case():
    y = np.array([1, 1, 0, 0, 1, 0])
    p = np.array([1, 0, 0, 1, 1, 0])
    tn, fp, fn, tp = confusion(y, p)
    assert (tn, fp, fn, tp) == (2, 1, 1, 2)
    stats = prf(y, p)
    # prf rounds to five decimals for report stability, so compare accordingly.
    assert abs(stats["recall_phish"] - 2 / 3) < 1e-4
    assert abs(stats["precision_phish"] - 2 / 3) < 1e-4
    assert 0.0 <= stats["macro_f1"] <= 1.0


def test_perfect_and_inverted_rankings():
    y = np.array([0, 0, 1, 1])
    assert roc_auc(y, np.array([0.1, 0.2, 0.8, 0.9])) == 1.0
    assert roc_auc(y, np.array([0.9, 0.8, 0.2, 0.1])) == 0.0
    assert abs(pr_auc(y, np.array([0.1, 0.2, 0.8, 0.9])) - 1.0) < 1e-9


def test_auc_handles_ties_without_bias():
    y = np.array([0, 1, 0, 1])
    assert roc_auc(y, np.array([0.5, 0.5, 0.5, 0.5])) == 0.5


def test_pr_auc_is_undefined_without_positives():
    assert pr_auc(np.array([0, 0, 0]), np.array([0.1, 0.2, 0.3])) == 0.0


def test_threshold_for_target_fpr_respects_the_budget():
    rng = np.random.default_rng(0)
    y = np.concatenate([np.zeros(800, dtype=int), np.ones(200, dtype=int)])
    scores = np.concatenate([rng.beta(2, 8, 800), rng.beta(8, 2, 200)])
    threshold = threshold_for_target_fpr(y, scores, 0.02)
    achieved = float(np.mean(scores[y == 0] >= threshold))
    assert achieved <= 0.03


def test_banded_outcome_excludes_the_review_band_from_auto_metrics():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.05, 0.55, 0.60, 0.95])  # two land in REVIEW
    out = banded_outcome(y, scores, review_threshold=0.4, block_threshold=0.8)
    assert out.allow == 1 and out.review == 2 and out.block == 1
    assert out.auto_decided == 2
    assert out.missed_phish == 0
    assert out.blocked_ham == 0
    assert out.ham_in_review == 1 and out.phish_in_review == 1


def test_banded_outcome_counts_the_outcomes_that_hurt():
    y = np.array([1, 0])
    scores = np.array([0.10, 0.95])  # a missed phish and a blocked legitimate message
    out = banded_outcome(y, scores, review_threshold=0.4, block_threshold=0.8)
    assert out.missed_phish == 1
    assert out.blocked_ham == 1


def test_calibration_error_is_zero_for_a_perfectly_calibrated_model():
    rng = np.random.default_rng(3)
    probs = rng.uniform(0, 1, 20000)
    labels = (rng.uniform(0, 1, 20000) < probs).astype(int)
    assert expected_calibration_error(probs, labels) < 0.02


def test_calibration_error_detects_overconfidence():
    probs = np.full(1000, 0.95)
    labels = np.zeros(1000, dtype=int)  # never actually phishing
    assert expected_calibration_error(probs, labels) > 0.9


def test_isotonic_calibrator_improves_a_skewed_score():
    rng = np.random.default_rng(5)
    n = 2000
    labels = rng.integers(0, 2, n)
    # Systematically overconfident raw scores.
    raw = np.clip(labels * 0.6 + 0.35 + rng.normal(0, 0.12, n), 0, 1)
    calibrator = Calibrator(method="isotonic").fit(raw, labels)
    report = calibrator.report(raw, labels)
    assert report["ece_after"] <= report["ece_before"] + 1e-9
    assert report["brier_after"] <= report["brier_before"] + 1e-9


def test_calibrator_falls_back_to_platt_on_small_samples():
    rng = np.random.default_rng(1)
    raw = rng.uniform(0, 1, 40)
    labels = (raw > 0.5).astype(int)
    calibrator = Calibrator(method="isotonic", min_isotonic_samples=250).fit(raw, labels)
    assert calibrator.fitted_method == "platt"


def test_calibrator_is_a_no_op_when_a_class_is_missing():
    calibrator = Calibrator().fit(np.array([0.2, 0.4]), np.array([0, 0]))
    assert calibrator.fitted_method == "none"
    np.testing.assert_allclose(calibrator.transform(np.array([0.3])), [0.3])


def test_reliability_curve_bins_cover_the_unit_interval():
    rows = reliability_curve(np.array([0.05, 0.5, 0.99]), np.array([0, 1, 1]), n_bins=10)
    assert len(rows) == 10
    assert rows[0]["bin_lower"] == 0.0 and rows[-1]["bin_upper"] == 1.0
    assert sum(r["count"] for r in rows) == 3


def test_brier_score_bounds():
    assert brier_score(np.array([1.0, 0.0]), np.array([1, 0])) == 0.0
    assert brier_score(np.array([0.0, 1.0]), np.array([1, 0])) == 1.0


def test_latency_percentiles_are_ordered():
    stats = latency_stats([float(i) for i in range(1, 101)])
    assert stats.p50_ms <= stats.p95_ms <= stats.p99_ms <= stats.max_ms
    assert stats.n == 100


def test_latency_of_an_empty_sample_is_safe():
    assert latency_stats([]).n == 0


def test_gates_pass_on_a_good_report_and_fail_on_a_bad_one():
    good = {
        "clean": {"macro_f1": 0.97, "pr_auc": 0.99, "false_positive_rate": 0.004},
        "calibration": {"ece": 0.02},
        "robustness": {"macro_f1_drop": 0.05, "attack_success_rate": 0.10},
        "latency": {"p95_ms": 40.0},
        "deltas": {"vs_rule_baseline_macro_f1": 0.05, "asr_advantage_vs_text_baseline": 0.12},
        "leakage": {"passed_numeric": 1.0},
    }
    assert evaluate_gates(good).passed

    bad = {**good, "clean": {**good["clean"], "false_positive_rate": 0.25}}
    result = evaluate_gates(bad)
    assert not result.passed
    assert any(f["id"] == "G3" for f in result.failures)


def test_a_missing_metric_fails_its_blocking_gate():
    result = evaluate_gates({"clean": {"macro_f1": 0.99}})
    assert not result.passed
    assert any(r["observed"] is None for r in result.results)


def test_every_gate_has_a_rationale():
    for gate in build_gates():
        assert gate.rationale, gate.id
        assert gate.direction in {"min", "max"}


def test_acceptance_renders_a_readable_summary():
    text = evaluate_gates({"clean": {"macro_f1": 0.99}}).render()
    assert "Acceptance gates" in text
    assert "NO-GO" in text


def test_threshold_for_target_fpr_handles_a_mass_point():
    """A quantile is wrong when the score distribution piles up on one value.

    A well-separated calibrated model scores most legitimate mail at exactly
    0.0. Taking the 98th percentile of that returns 0.0, and ``score >= 0.0``
    classifies the whole corpus as phishing.
    """
    y = np.concatenate([np.zeros(1000, dtype=int), np.ones(200, dtype=int)])
    negatives = np.concatenate([np.zeros(980), np.linspace(0.1, 0.6, 20)])
    scores = np.concatenate([negatives, np.linspace(0.85, 1.0, 200)])
    threshold = threshold_for_target_fpr(y, scores, 0.02)
    achieved = float(np.mean(scores[y == 0] >= threshold))
    assert achieved <= 0.02, (threshold, achieved)
    assert threshold > 0.0


def test_threshold_for_zero_tolerance_sits_above_every_negative():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.0, 0.3, 0.9, 1.0])
    threshold = threshold_for_target_fpr(y, scores, 0.0)
    assert float(np.mean(scores[y == 0] >= threshold)) == 0.0
