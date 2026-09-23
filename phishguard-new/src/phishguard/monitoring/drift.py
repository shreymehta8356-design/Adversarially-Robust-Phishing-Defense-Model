"""Statistical drift detection: is incoming mail still what the model was built for?

A deployed classifier fails quietly. Its accuracy is only measurable with
labels, and labels arrive late or never; what *is* observable immediately is
the input distribution and the model's own outputs. This module compares both
against a reference captured at training time and raises an alarm when they
move.

Design decisions
----------------
**The reference is legitimate mail, not the training mix.** The training
corpus is ~42% phishing so that both classes are well represented; production
mail is overwhelmingly legitimate. Comparing live traffic to the training mix
would report severe drift on the first day purely from the base rate. The
reference is therefore built from the *legitimate* messages of the stacking
and calibration pools -- whole campaigns the members never fitted on, so their
member scores are the ones new mail will get -- which is what live traffic
mostly is. A phishing campaign arriving in volume then shows up as drift too,
which is exactly what an operator wants to know.

**Only what the audit store already holds.** Live quantities come from the
privacy-preserving audit trail: per-member scores, body length, recipient and
attachment counts, and whether behavioural context was available. No message
text is needed or read, so monitoring does not widen what the system retains.

**Population Stability Index, with a two-sample KS test beside it.** PSI is
the standard model-monitoring statistic (from credit-risk scorecards) and
reads as a magnitude; the Kolmogorov-Smirnov test adds a significance level.
The conventional PSI bands are used: below 0.10 stable, 0.10-0.25 a moderate
shift worth watching, above 0.25 a significant shift that warrants
investigation and usually a retrain.

**The alarm thresholds are calibrated, not assumed.** The textbook PSI bands
assume independent samples. Mail is not independent: it arrives in campaigns,
and one bulk newsletter can fill a tenth of a day's traffic. Measured on this
corpus over 30 stable 400-message weeks, the median worst-quantity PSI was
about 0.17 and one week in twenty exceeded 0.34, purely from campaign
lumpiness -- so the textbook bands (0.10 / 0.25) would raise an alarm most
weeks. The monitor therefore estimates the null distribution of its own
statistic, by holding whole campaigns out of the reference to fill one window
at a time, and sets its thresholds at that null's 95th and 99th percentiles
(never below the textbook values). An alarm then means "more shift than
stable, campaign-structured mail produces", which is the question an operator
is actually asking. See :func:`null_thresholds` for the two designs that were
measured and rejected on the way.

**The calibrated score is not monitored.** Isotonic calibration saturates on
this corpus -- almost everything is exactly 0 or 1 -- so its distribution
barely moves when the input shifts. The *member* scores are continuous and are
where drift is visible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

PSI_MODERATE = 0.10
PSI_SIGNIFICANT = 0.25
_EPS = 1e-4
_N_BINS = 10
_SAMPLE = 1000


def psi(expected: np.ndarray, actual: np.ndarray) -> float:
    """Population stability index between two binned distributions."""
    e = np.clip(np.asarray(expected, dtype=np.float64), _EPS, None)
    a = np.clip(np.asarray(actual, dtype=np.float64), _EPS, None)
    e, a = e / e.sum(), a / a.sum()
    return float(np.sum((a - e) * np.log(a / e)))


def _edges(values: np.ndarray, bins: int = _N_BINS) -> np.ndarray:
    """Quantile bin edges from the reference, open at both ends.

    Quantile edges give each bin roughly equal reference mass, which is what
    makes PSI comparable across quantities with very different scales. Ties
    (a score that is exactly 0.0 for a third of messages) collapse edges, so
    duplicates are dropped rather than producing empty zero-width bins.
    """
    qs = np.quantile(values, np.linspace(0, 1, bins + 1)[1:-1])
    inner = np.unique(qs)
    return np.concatenate([[-np.inf], inner, [np.inf]])


def _fractions(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    counts, _ = np.histogram(values, bins=edges)
    total = counts.sum()
    return counts / total if total else np.zeros_like(counts, dtype=np.float64)


def _severity(value: float) -> str:
    if value >= PSI_SIGNIFICANT:
        return "significant"
    if value >= PSI_MODERATE:
        return "moderate"
    return "stable"


@dataclass
class ReferenceProfile:
    """What legitimate mail looked like to the model at training time."""

    n: int = 0
    quantities: dict[str, dict[str, Any]] = field(default_factory=dict)
    band_shares: dict[str, float] = field(default_factory=dict)
    model_version: str = ""
    groups: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "model_version": self.model_version,
            "band_shares": self.band_shares,
            "quantities": {
                k: {kk: (vv.tolist() if isinstance(vv, np.ndarray) else vv) for kk, vv in q.items()}
                for k, q in self.quantities.items()
            },
        }


def _monitored(
    messages: list[Any], member_matrix: np.ndarray, member_names: tuple[str, ...]
) -> dict[str, np.ndarray]:
    """The quantities monitored, computed the way the audit store records them."""
    out: dict[str, np.ndarray] = {}
    for j, name in enumerate(member_names):
        out[f"member:{name}"] = np.asarray(member_matrix[:, j], dtype=np.float64)
    out["body length (log)"] = np.log1p([len(m.body) for m in messages])
    out["recipients"] = np.asarray(
        [len(m.to) or m.behavioral.recipient_count for m in messages], dtype=np.float64
    )
    out["attachments"] = np.asarray([len(m.attachments) for m in messages], dtype=np.float64)
    out["behavioural context available"] = np.asarray(
        [float(m.behavioral.available) for m in messages], dtype=np.float64
    )
    return out


def build_reference(
    detector: Any, messages: list[Any], labels: Any, *, seed: int = 7
) -> ReferenceProfile | None:
    """Capture the reference from held-out *legitimate* mail.

    ``messages`` should hold **whole campaigns**, as the detector's
    campaign-level calibration pool does. The null distribution is built by
    resampling the reference's campaigns, so a reference holding only
    fragments of campaigns (a random row sample) understates how lumpy live
    traffic is: measured on this corpus, that raised the false-alarm rate on
    stable weeks from a nominal 1% to 7-10%. Rebuilding fragments to their
    full size by duplicating their messages was tried and overshoots the
    other way -- the monitor then never fired, even on a genuine shift.
    """
    y = np.asarray(labels).astype(int)
    ham = [m for m, lab in zip(messages, y, strict=False) if lab == 0]
    if len(ham) < 50:
        return None
    Z = detector._member_matrix(ham)
    values = _monitored(ham, Z, detector.member_names)
    # Campaign ids let the null be drawn with the same clumping real traffic
    # has. Only integer codes are kept, so no sender or subject material is.
    groups = [m.group_key or f"row:{i}" for i, m in enumerate(ham)]
    return profile_from_values(
        values, groups, seed=seed, model_version=getattr(detector, "model_version", "")
    )


def profile_from_values(
    values: dict[str, np.ndarray], groups: Any = None, *, seed: int = 7, model_version: str = ""
) -> ReferenceProfile:
    """A reference profile from already-computed monitored quantities.

    ``groups`` gives the campaign of each row (any hashable labels); without
    it the monitor cannot calibrate its thresholds and falls back to the
    textbook bands, and says so.
    """
    n = max((len(v) for v in values.values()), default=0)
    rng = np.random.default_rng(seed)
    profile = ReferenceProfile(n=n, model_version=model_version)
    if groups is not None:
        # Only integer codes are kept -- never the keys themselves, which may
        # be derived from sender or subject material.
        _, profile.groups = np.unique(np.asarray(groups), return_inverse=True)
    for name, v in values.items():
        v = np.asarray(v, dtype=np.float64)
        edges = _edges(v)
        sample = v if v.size <= _SAMPLE else rng.choice(v, _SAMPLE, replace=False)
        profile.quantities[name] = {
            "edges": edges,
            "fractions": _fractions(v, edges),
            "sample": np.sort(sample),
            "mean": float(v.mean()),
            "values": np.asarray(v, dtype=np.float32),
        }
    return profile


def null_thresholds(
    profile: ReferenceProfile, window: int, *, n_boot: int = 400, seed: int = 0
) -> dict[str, float]:
    """PSI thresholds from the null distribution of the monitor's own statistic.

    Each bootstrap mimics one live comparison. Whole campaigns are held out of
    the reference, in random order and **without replacement**, until they
    fill one window of ``window`` messages; the bins are rebuilt from the
    remaining campaigns, and the worst PSI across all monitored quantities is
    recorded. Taking the worst across quantities inside the bootstrap is what
    accounts for monitoring several things at once.

    Two earlier designs were measured on this corpus and rejected. Holding out
    a fixed 35% of campaigns and drawing the window from them *with*
    replacement repeated campaigns inside a window, which made the null far
    lumpier than real traffic: the thresholds rose above 1.0 and a genuine
    shift never fired. A reference holding only *fragments* of campaigns (a
    row-level sample) did the opposite, understating lumpiness, and raised the
    false-alarm rate on stable weeks to several times its nominal level.
    """
    groups = getattr(profile, "groups", None)
    if groups is None or len(groups) == 0:
        return {
            "moderate": PSI_MODERATE,
            "significant": PSI_SIGNIFICANT,
            "source": "textbook (no campaign ids in this reference)",
        }
    groups = np.asarray(groups)
    rng = np.random.default_rng(seed)
    uniq = np.unique(groups)
    members = {g: np.flatnonzero(groups == g) for g in uniq.tolist()}
    names = [n for n, q in profile.quantities.items() if "values" in q]
    values = {n: np.asarray(profile.quantities[n]["values"], dtype=np.float64) for n in names}
    worst: list[float] = []
    for _ in range(n_boot):
        held: list[int] = []
        count = 0
        for g in rng.permutation(uniq).tolist():
            if count >= window:
                break
            held.append(g)
            count += members[g].size
        if count < window:
            continue  # the reference cannot fill a window and keep a remainder
        fit_mask = ~np.isin(groups, held)
        if fit_mask.sum() < max(30, window // 2):
            continue
        picked = np.concatenate([members[g] for g in held])[:window]
        w = 0.0
        for name in names:
            v = values[name]
            edges = _edges(v[fit_mask])
            w = max(w, psi(_fractions(v[fit_mask], edges), _fractions(v[picked], edges)))
        worst.append(w)
    if len(worst) < 20:
        return {
            "moderate": PSI_MODERATE,
            "significant": PSI_SIGNIFICANT,
            "source": (
                f"textbook (the reference of {profile.n} messages is too small to "
                f"calibrate windows of {window})"
            ),
        }
    arr = np.asarray(worst)
    return {
        "moderate": round(max(PSI_MODERATE, float(np.quantile(arr, 0.95))), 4),
        "significant": round(max(PSI_SIGNIFICANT, float(np.quantile(arr, 0.99))), 4),
        "null_median": round(float(np.median(arr)), 4),
        "source": (
            f"calibrated: 95th/99th percentile of the worst-quantity PSI of "
            f"{len(arr)} stable windows of {window} messages made of whole, "
            f"held-out campaigns"
        ),
    }


def drift_report(
    profile: ReferenceProfile | None, live: dict[str, np.ndarray], *, bands: list[str] | None = None
) -> dict[str, Any]:
    """Compare a window of live traffic with the reference."""
    if profile is None:
        return {
            "available": False,
            "reason": "this model has no drift reference; retrain it to capture one",
        }
    n_live = max((len(v) for v in live.values()), default=0)
    if n_live < 30:
        return {
            "available": False,
            "n_live": n_live,
            "reason": f"only {n_live} decisions in the window; at least 30 are needed",
        }

    from scipy.stats import ks_2samp

    # The null is computed at the window's actual size. An earlier version
    # rounded to the nearest power of two, which turned a 400-message window
    # into 512: a larger window has a *tighter* null, so the threshold came out
    # too strict and a stable week raised a false alarm. Computing it exactly
    # costs a fraction of a second on a monitoring endpoint.
    # A window larger than the reference can fill (while keeping enough of
    # itself to bin against) is calibrated at the largest size it can: PSI
    # noise shrinks as windows grow, so those thresholds are conservative.
    supported = max(30, int(profile.n) // 3)
    bucket = int(min(max(n_live, 30), supported))
    cache = getattr(profile, "_null_cache", None)
    if cache is None:
        cache = {}
        try:
            profile._null_cache = cache  # type: ignore[attr-defined]
        except AttributeError:
            pass
    thresholds = cache.get(bucket)
    if thresholds is None:
        thresholds = null_thresholds(profile, bucket)
        if bucket < n_live and thresholds["source"].startswith("calibrated"):
            thresholds = dict(
                thresholds,
                source=thresholds["source"]
                + (
                    f"; calibrated at {bucket}, the largest window this reference supports, "
                    f"which is conservative for this window of {n_live}"
                ),
            )
        cache[bucket] = thresholds
    moderate, significant = thresholds["moderate"], thresholds["significant"]

    def severity(value: float) -> str:
        if value >= significant:
            return "significant"
        if value >= moderate:
            return "moderate"
        return "stable"

    rows = []
    for name, ref in profile.quantities.items():
        values = live.get(name)
        if values is None or len(values) == 0:
            continue
        values = np.asarray(values, dtype=np.float64)
        value = psi(ref["fractions"], _fractions(values, np.asarray(ref["edges"])))
        ks = ks_2samp(np.asarray(ref["sample"]), values)
        rows.append(
            {
                "quantity": name,
                "psi": round(value, 4),
                "severity": severity(value),
                "ks_statistic": round(float(ks.statistic), 4),
                "ks_p_value": float(ks.pvalue),
                "reference_mean": round(float(ref["mean"]), 4),
                "live_mean": round(float(values.mean()), 4),
            }
        )
    rows.sort(key=lambda r: -r["psi"])
    worst = rows[0] if rows else None
    overall = severity(worst["psi"]) if worst else "stable"
    hint = None
    if bucket < n_live / 2:
        hint = (
            f"The reference holds {profile.n} legitimate messages, which can calibrate "
            f"windows of up to {bucket}; this window has {n_live}, so the alarm is "
            "conservative and may miss a moderate shift. Training on more data "
            "(for example --n 9000) gives a sharper monitor."
        )
    out: dict[str, Any] = {
        "available": True,
        "hint": hint,
        "n_reference": profile.n,
        "n_live": n_live,
        "status": overall,
        "worst": worst,
        "quantities": rows,
        "thresholds": thresholds,
        "textbook_thresholds": {"moderate": PSI_MODERATE, "significant": PSI_SIGNIFICANT},
        "note": (
            "Reference is held-out legitimate mail from training. A significant shift "
            "means incoming mail no longer looks like what the model was built for - "
            "a new sending pattern, a new campaign in volume, or an upstream change "
            "in how mail reaches the gateway."
        ),
    }
    if bands:
        shares = {b: bands.count(b) / len(bands) for b in ("ALLOW", "REVIEW", "BLOCK")}
        out["live_band_shares"] = {k: round(v, 4) for k, v in shares.items()}
    out["advice"] = {
        "stable": "No action needed.",
        "moderate": (
            "Watch the named quantities. If the shift persists for several "
            "windows, compare analyst feedback for the same period."
        ),
        "significant": (
            "Investigate the source of the shift, check analyst disagreement "
            "(`phishguard feedback`), and plan a retrain on recent data."
        ),
    }[overall]
    return out


def live_from_messages(detector: Any, messages: list[Any]) -> dict[str, np.ndarray]:
    """Monitored quantities for a batch of messages (for tests and simulation)."""
    Z = detector._member_matrix(messages)
    return _monitored(messages, Z, detector.member_names)


def live_from_audit_rows(
    rows: list[dict[str, Any]], member_names: tuple[str, ...]
) -> dict[str, np.ndarray]:
    """Monitored quantities rebuilt from audit-store rows -- no message text needed."""
    import json

    out: dict[str, list[float]] = {f"member:{n}": [] for n in member_names}
    out |= {
        "body length (log)": [],
        "recipients": [],
        "attachments": [],
        "behavioural context available": [],
    }
    for r in rows:
        try:
            ms = json.loads(r.get("member_scores") or "{}")
        except (TypeError, ValueError):
            ms = {}
        for n in member_names:
            if n in ms:
                out[f"member:{n}"].append(float(ms[n]))
        out["body length (log)"].append(float(np.log1p(int(r.get("body_length", 0)))))
        out["recipients"].append(float(r.get("recipient_count", 0)))
        out["attachments"].append(float(r.get("attachment_count", 0)))
        out["behavioural context available"].append(float(r.get("behavioral_available", 0)))
    return {k: np.asarray(v, dtype=np.float64) for k, v in out.items()}


def simulate_drift(
    detector: Any, *, weeks: int = 10, per_week: int = 400, shift_week: int = 6, seed: int = 31
) -> dict[str, Any]:
    """A demonstration: stable weeks of production-like mail, then a shift.

    Weeks before ``shift_week`` are drawn from the same generator as training,
    at a realistic 2% phishing prevalence. From ``shift_week`` on, a quarter of
    the traffic is replaced with PG-HARD-style mail -- a new sending pattern
    the model was not trained on. The monitor should stay quiet, then fire.
    """
    from phishguard.data.hardcases import build_hard_benchmark
    from phishguard.data.synthetic import generate_corpus

    hard, _, _ = build_hard_benchmark(variants_per_case=8, seed=seed)
    rng = np.random.default_rng(seed)
    profile = getattr(detector, "drift_reference", None)
    rows = []
    thresholds: dict[str, Any] = {}
    hint: str | None = None
    for week in range(1, weeks + 1):
        msgs, y = generate_corpus(per_week * 3, seed=seed + week, phish_ratio=0.02)
        msgs = list(msgs[:per_week])
        if week >= shift_week:
            k = per_week // 4
            picks = rng.choice(len(hard), k, replace=True)
            msgs[:k] = [hard[i] for i in picks]
        report = drift_report(profile, live_from_messages(detector, msgs))
        thresholds = report.get("thresholds") or thresholds
        hint = report.get("hint") or hint
        rows.append(
            {
                "week": week,
                "shifted": week >= shift_week,
                "status": report.get("status", "unavailable"),
                "worst_quantity": (report.get("worst") or {}).get("quantity"),
                "worst_psi": (report.get("worst") or {}).get("psi"),
                "psi": {q["quantity"]: q["psi"] for q in report.get("quantities", [])},
            }
        )
    return {
        "weeks": rows,
        "shift_week": shift_week,
        "per_week": per_week,
        "thresholds": thresholds,
        "hint": hint,
        "reference_available": profile is not None,
        "description": (
            f"{weeks} simulated weeks of {per_week} messages at 2% phishing; from week "
            f"{shift_week}, a quarter of traffic is PG-HARD-style mail the model was not "
            "trained on."
        ),
    }
