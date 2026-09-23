"""Metrics.

Implemented directly rather than pulled from ``sklearn.metrics`` wholesale for
two reasons: the operating-point analysis needs metrics *at a chosen threshold*
rather than at 0.5, and the banded decision policy needs metrics that account
for a three-way outcome where some messages are deliberately not auto-decided.

The headline numbers are the ones the project brief names: macro F1, PR-AUC,
robustness drop, calibration, false positives and inference speed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from phishguard.schemas import BAND_ALLOW, BAND_BLOCK, BAND_REVIEW


def confusion(y_true: np.ndarray, y_pred: np.ndarray) -> tuple[int, int, int, int]:
    """``(tn, fp, fn, tp)``."""
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    return tn, fp, fn, tp


def prf(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    """Per-class and macro precision / recall / F1."""
    tn, fp, fn, tp = confusion(y_true, y_pred)
    p_pos = tp / (tp + fp) if (tp + fp) else 0.0
    r_pos = tp / (tp + fn) if (tp + fn) else 0.0
    f_pos = 2 * p_pos * r_pos / (p_pos + r_pos) if (p_pos + r_pos) else 0.0
    p_neg = tn / (tn + fn) if (tn + fn) else 0.0
    r_neg = tn / (tn + fp) if (tn + fp) else 0.0
    f_neg = 2 * p_neg * r_neg / (p_neg + r_neg) if (p_neg + r_neg) else 0.0
    return {
        "precision_phish": round(p_pos, 5),
        "recall_phish": round(r_pos, 5),
        "f1_phish": round(f_pos, 5),
        "precision_ham": round(p_neg, 5),
        "recall_ham": round(r_neg, 5),
        "f1_ham": round(f_neg, 5),
        "macro_f1": round((f_pos + f_neg) / 2.0, 5),
        "accuracy": round((tp + tn) / max(tp + tn + fp + fn, 1), 5),
        "false_positive_rate": round(fp / (fp + tn), 5) if (fp + tn) else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 5) if (fn + tp) else 0.0,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def pr_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Average precision - the right summary under class imbalance.

    Computed as the step-wise sum used by ``average_precision_score`` rather
    than a trapezoidal interpolation, which is optimistically biased.
    """
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=np.float64)
    if y_true.size == 0 or y_true.sum() == 0:
        return 0.0
    order = np.argsort(-scores, kind="mergesort")
    y = y_true[order]
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    precision = tp / np.maximum(tp + fp, 1)
    recall = tp / max(int(y_true.sum()), 1)
    prev_recall = np.concatenate([[0.0], recall[:-1]])
    return float(np.sum((recall - prev_recall) * precision))


def roc_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    """AUC via the rank-sum identity, with tie correction."""
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=np.float64)
    n_pos, n_neg = int(y_true.sum()), int((1 - y_true).sum())
    if n_pos == 0 or n_neg == 0:
        return 0.5
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(scores.size, dtype=np.float64)
    ranks[order] = np.arange(1, scores.size + 1, dtype=np.float64)
    s = scores[order]
    i = 0
    while i < s.size:
        j = i
        while j + 1 < s.size and s[j + 1] == s[i]:
            j += 1
        if j > i:
            ranks[order[i : j + 1]] = (i + 1 + j + 1) / 2.0
        i = j + 1
    return float((ranks[y_true == 1].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def threshold_for_target_fpr(y_true: np.ndarray, scores: np.ndarray, target_fpr: float) -> float:
    """Lowest threshold whose false-positive rate stays within ``target_fpr``.

    This is how the operating point is actually chosen: a mail gateway's
    tolerance is expressed as "no more than N false positives per thousand
    legitimate messages", not as a probability cut-off.

    Implemented by searching the achieved false-positive rate directly rather
    than by taking a quantile of the negative scores. A quantile is wrong here
    whenever the score distribution has a mass point, which is the normal case
    for a well-separated calibrated model: if 98% of legitimate messages score
    exactly 0.0, the 98th percentile *is* 0.0, and a threshold of 0.0 with the
    ``>=`` comparison used everywhere else classifies the entire corpus as
    phishing - a reported false-positive rate of 1.0 while nominally targeting
    0.02. The search below returns the smallest threshold that genuinely
    achieves the budget, and steps just above the largest negative score when
    even that is not enough.
    """
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=np.float64)
    negatives = scores[y_true == 0]
    if negatives.size == 0:
        return 0.5

    allowed = int(np.floor(max(target_fpr, 0.0) * negatives.size))
    if allowed <= 0:
        # Zero tolerance: sit strictly above every legitimate message.
        return float(np.nextafter(negatives.max(), np.inf))

    # Candidate thresholds are the distinct negative scores; ``>=`` means a
    # threshold equal to a score still counts that message as a false positive,
    # so the smallest candidate meeting the budget is the answer.
    for candidate in np.unique(negatives):
        if int(np.count_nonzero(negatives >= candidate)) <= allowed:
            return float(candidate)
    return float(np.nextafter(negatives.max(), np.inf))


@dataclass(slots=True)
class BandedOutcome:
    """Metrics for the three-way ALLOW / REVIEW / BLOCK policy.

    Auto-decision metrics deliberately exclude the review band: a message a
    human is asked to look at is neither a false positive nor a missed
    detection until the human decides. Review volume is reported alongside so
    that the trade is visible rather than hidden.
    """

    n: int
    allow: int
    review: int
    block: int
    review_rate: float
    auto_decided: int
    auto_macro_f1: float
    auto_fpr: float
    auto_recall: float
    #: Phishing that was auto-allowed - the outcome that actually hurts.
    missed_phish: int
    #: Legitimate mail auto-blocked - the outcome that gets a filter switched off.
    blocked_ham: int
    #: Phishing routed to a human rather than blocked outright.
    phish_in_review: int
    ham_in_review: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "allow": self.allow,
            "review": self.review,
            "block": self.block,
            "review_rate": round(self.review_rate, 5),
            "auto_decided": self.auto_decided,
            "auto_macro_f1": round(self.auto_macro_f1, 5),
            "auto_false_positive_rate": round(self.auto_fpr, 5),
            "auto_recall": round(self.auto_recall, 5),
            "missed_phish": self.missed_phish,
            "blocked_ham": self.blocked_ham,
            "phish_in_review": self.phish_in_review,
            "ham_in_review": self.ham_in_review,
        }


def banded_outcome(
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    review_threshold: float,
    block_threshold: float,
    bands: Any = None,
) -> BandedOutcome:
    """What the decision policy does with a batch of messages.

    Pass ``bands`` whenever the system being measured can change a band
    without changing the score -- the deployed detector's abstention control
    escalates a message to REVIEW when its members disagree, however confident
    the fused score is. Thresholding ``scores`` alone in that case measures a
    detector with the control removed, which is not the one being shipped: an
    earlier revision of the dossier did exactly that and reported a 0.1% review
    rate in one section beside a 12% review load in another, for the same
    model on the same test set.
    """
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=np.float64)
    if bands is None:
        bands = np.where(
            scores >= block_threshold,
            BAND_BLOCK,
            np.where(scores >= review_threshold, BAND_REVIEW, BAND_ALLOW),
        )
    else:
        bands = np.asarray(list(bands))
        if bands.shape[0] != y_true.shape[0]:
            raise ValueError("bands and labels must be the same length")
    allow = bands == BAND_ALLOW
    review = bands == BAND_REVIEW
    block = bands == BAND_BLOCK
    auto = allow | block

    auto_pred = block[auto].astype(int)
    auto_true = y_true[auto]
    stats = (
        prf(auto_true, auto_pred)
        if auto.any()
        else {"macro_f1": 0.0, "false_positive_rate": 0.0, "recall_phish": 0.0}
    )
    return BandedOutcome(
        n=int(y_true.size),
        allow=int(allow.sum()),
        review=int(review.sum()),
        block=int(block.sum()),
        review_rate=float(review.mean()) if y_true.size else 0.0,
        auto_decided=int(auto.sum()),
        auto_macro_f1=float(stats["macro_f1"]),
        auto_fpr=float(stats["false_positive_rate"]),
        auto_recall=float(stats["recall_phish"]),
        missed_phish=int(np.sum(allow & (y_true == 1))),
        blocked_ham=int(np.sum(block & (y_true == 0))),
        phish_in_review=int(np.sum(review & (y_true == 1))),
        ham_in_review=int(np.sum(review & (y_true == 0))),
    )


@dataclass(slots=True)
class LatencyStats:
    n: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    throughput_per_s: float
    extras: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "mean_ms": round(self.mean_ms, 3),
            "p50_ms": round(self.p50_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
            "max_ms": round(self.max_ms, 3),
            "throughput_per_s": round(self.throughput_per_s, 1),
            **self.extras,
        }


def latency_stats(samples_ms: list[float]) -> LatencyStats:
    arr = np.asarray(samples_ms, dtype=np.float64)
    if arr.size == 0:
        return LatencyStats(0, 0, 0, 0, 0, 0, 0)
    return LatencyStats(
        n=int(arr.size),
        mean_ms=float(arr.mean()),
        p50_ms=float(np.percentile(arr, 50)),
        p95_ms=float(np.percentile(arr, 95)),
        p99_ms=float(np.percentile(arr, 99)),
        max_ms=float(arr.max()),
        throughput_per_s=float(1000.0 / arr.mean()) if arr.mean() > 0 else 0.0,
    )


def score_summary(
    y_true: np.ndarray, scores: np.ndarray, *, threshold: float = 0.5
) -> dict[str, Any]:
    """The standard block of numbers reported for any arm of the evaluation."""
    pred = (np.asarray(scores) >= threshold).astype(int)
    out = prf(y_true, pred)
    out["pr_auc"] = round(pr_auc(y_true, scores), 5)
    out["roc_auc"] = round(roc_auc(y_true, scores), 5)
    out["threshold"] = round(float(threshold), 5)
    out["n"] = int(np.asarray(y_true).size)
    out["positive_rate"] = round(float(np.mean(np.asarray(y_true))), 5)
    return out


# ---------------------------------------------------------------------------
# Curve points, stored in the report so figures regenerate without retraining
# ---------------------------------------------------------------------------
def curve_points(
    y_true: np.ndarray, scores: np.ndarray, *, fpr_floor: float = 1e-4
) -> dict[str, Any]:
    """ROC and precision-recall curves on fixed grids.

    The ROC curve is sampled on a **log-spaced false-positive grid**. For a
    detector this good, a linear-axis ROC curve is a right angle in the top-left
    corner and conveys nothing; every operating point a mail gateway would
    actually use sits below 1% FPR, which is exactly the region a linear axis
    compresses into a few pixels. Log-FPR is the standard presentation for
    security classifiers for that reason.

    Precision is reported as *interpolated* precision -- the best precision
    achievable at or above each recall -- which is the conventional,
    monotone form and the one PR-AUC summarises.
    """
    from sklearn.metrics import precision_recall_curve, roc_curve

    y = np.asarray(y_true).astype(int)
    s = np.asarray(scores, dtype=np.float64)
    if y.min() == y.max():
        return {"roc": {"fpr": [], "tpr": []}, "pr": {"recall": [], "precision": []}}

    fpr, tpr, _ = roc_curve(y, s)
    grid = np.concatenate([[0.0], np.logspace(np.log10(fpr_floor), 0.0, 140)])
    # Step interpolation: the TPR actually achievable at each FPR budget.
    tpr_at = np.array([tpr[fpr <= g].max() if np.any(fpr <= g) else 0.0 for g in grid])

    precision, recall, _ = precision_recall_curve(y, s)
    r_grid = np.linspace(0.0, 1.0, 101)
    p_at = np.array([precision[recall >= r].max() if np.any(recall >= r) else 0.0 for r in r_grid])

    return {
        "roc": {
            "fpr": [round(float(v), 6) for v in grid],
            "tpr": [round(float(v), 6) for v in tpr_at],
            "fpr_floor": fpr_floor,
            "n_negatives": int((y == 0).sum()),
        },
        "pr": {
            "recall": [round(float(v), 4) for v in r_grid],
            "precision": [round(float(v), 6) for v in p_at],
            "base_rate": round(float(y.mean()), 5),
        },
    }


def score_histogram(y_true: np.ndarray, scores: np.ndarray, *, bins: int = 40) -> dict[str, Any]:
    """Per-class score counts on a shared grid, for distribution figures."""
    y = np.asarray(y_true).astype(int)
    s = np.asarray(scores, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    return {
        "edges": [round(float(e), 4) for e in edges],
        "legitimate": np.histogram(s[y == 0], bins=edges)[0].astype(int).tolist(),
        "phishing": np.histogram(s[y == 1], bins=edges)[0].astype(int).tolist(),
    }
