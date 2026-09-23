"""Probability calibration and its measurement.

A phishing gateway's thresholds are policy decisions: "auto-block above 0.8"
only means anything if 0.8 really is an 80% chance of phishing. An uncalibrated
model whose scores pile up near 0 and 1 makes the REVIEW band meaningless and
silently changes the false-positive rate every time the model is retrained.

So calibration here is a first-class, measured, gated property:

* :class:`Calibrator` wraps the fusion output with isotonic regression fitted
  on a split that no member and no fusion weight has seen.
* :func:`expected_calibration_error` is checked against an acceptance gate, and
  :func:`reliability_curve` feeds the diagram in the evaluation dossier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression


def expected_calibration_error(
    probs: np.ndarray, labels: np.ndarray, *, n_bins: int = 15
) -> float:
    """Bin-weighted mean gap between confidence and observed frequency.

    Equal-width bins on [0, 1]; empty bins contribute nothing. This is the
    standard ECE, reported alongside the reliability curve so that a single
    scalar never has to be trusted on its own.
    """
    probs = np.clip(np.asarray(probs, dtype=np.float64), 0.0, 1.0)
    labels = np.asarray(labels, dtype=np.float64)
    if probs.size == 0:
        return 0.0
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(probs, edges[1:-1], right=False), 0, n_bins - 1)
    total = 0.0
    for b in range(n_bins):
        mask = idx == b
        n = int(mask.sum())
        if n == 0:
            continue
        total += (n / probs.size) * abs(probs[mask].mean() - labels[mask].mean())
    return float(total)


def maximum_calibration_error(
    probs: np.ndarray, labels: np.ndarray, *, n_bins: int = 15, min_count: int = 20
) -> float:
    """Worst-bin calibration gap, ignoring bins too small to be meaningful."""
    probs = np.clip(np.asarray(probs, dtype=np.float64), 0.0, 1.0)
    labels = np.asarray(labels, dtype=np.float64)
    if probs.size == 0:
        return 0.0
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(probs, edges[1:-1], right=False), 0, n_bins - 1)
    worst = 0.0
    for b in range(n_bins):
        mask = idx == b
        if int(mask.sum()) < min_count:
            continue
        worst = max(worst, abs(probs[mask].mean() - labels[mask].mean()))
    return float(worst)


def reliability_curve(
    probs: np.ndarray, labels: np.ndarray, *, n_bins: int = 15
) -> list[dict[str, float]]:
    """Rows for the reliability diagram: predicted vs observed per bin."""
    probs = np.clip(np.asarray(probs, dtype=np.float64), 0.0, 1.0)
    labels = np.asarray(labels, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(probs, edges[1:-1], right=False), 0, n_bins - 1)
    rows: list[dict[str, float]] = []
    for b in range(n_bins):
        mask = idx == b
        n = int(mask.sum())
        rows.append(
            {
                "bin_lower": round(float(edges[b]), 4),
                "bin_upper": round(float(edges[b + 1]), 4),
                "count": n,
                "mean_predicted": round(float(probs[mask].mean()), 5) if n else 0.0,
                "observed_frequency": round(float(labels[mask].mean()), 5) if n else 0.0,
            }
        )
    return rows


def brier_score(probs: np.ndarray, labels: np.ndarray) -> float:
    """Mean squared error of the probability - proper scoring rule."""
    probs = np.asarray(probs, dtype=np.float64)
    labels = np.asarray(labels, dtype=np.float64)
    return float(np.mean((probs - labels) ** 2)) if probs.size else 0.0


@dataclass(slots=True)
class Calibrator:
    """Isotonic (default) or Platt post-hoc calibration.

    Isotonic is the default because it is non-parametric and the fusion's raw
    scores are not reliably sigmoid-shaped once four heterogeneous members are
    stacked. It needs a few hundred held-out points to be stable, so the
    calibrator falls back to Platt scaling on small calibration sets and
    records which one it used.
    """

    method: Literal["isotonic", "platt", "none"] = "isotonic"
    min_isotonic_samples: int = 250
    _iso: IsotonicRegression | None = field(default=None, repr=False)
    _platt: LogisticRegression | None = field(default=None, repr=False)
    fitted_method: str = "none"
    fitted: bool = False

    def fit(self, scores: np.ndarray, labels: np.ndarray) -> Calibrator:
        scores = np.asarray(scores, dtype=np.float64).ravel()
        labels = np.asarray(labels, dtype=np.int64).ravel()
        if self.method == "none" or scores.size == 0 or len(np.unique(labels)) < 2:
            self.fitted_method = "none"
            self.fitted = True
            return self

        use_isotonic = self.method == "isotonic" and scores.size >= self.min_isotonic_samples
        if use_isotonic:
            self._iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
            self._iso.fit(scores, labels)
            self.fitted_method = "isotonic"
        else:
            self._platt = LogisticRegression(max_iter=1000, solver="lbfgs")
            self._platt.fit(scores.reshape(-1, 1), labels)
            self.fitted_method = "platt"
        self.fitted = True
        return self

    def transform(self, scores: np.ndarray) -> np.ndarray:
        scores = np.asarray(scores, dtype=np.float64).ravel()
        if not self.fitted or self.fitted_method == "none":
            return np.clip(scores, 0.0, 1.0)
        if self.fitted_method == "isotonic" and self._iso is not None:
            return np.clip(self._iso.predict(scores), 0.0, 1.0)
        if self._platt is not None:
            return self._platt.predict_proba(scores.reshape(-1, 1))[:, 1]
        return np.clip(scores, 0.0, 1.0)

    def report(self, scores: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
        """Before/after calibration quality, for the evaluation dossier."""
        cal = self.transform(scores)
        return {
            "method": self.fitted_method,
            "ece_before": round(expected_calibration_error(scores, labels), 5),
            "ece_after": round(expected_calibration_error(cal, labels), 5),
            "mce_after": round(maximum_calibration_error(cal, labels), 5),
            "brier_before": round(brier_score(scores, labels), 5),
            "brier_after": round(brier_score(cal, labels), 5),
            "reliability": reliability_curve(cal, labels),
        }
