"""Drift monitoring: quiet on stable traffic, loud on a real shift, honest when it cannot tell.

The failure modes pinned here are the ones that make a drift monitor worse than
none: an alarm that fires every week on ordinary campaign lumpiness (so it gets
ignored), an alarm that cannot fire at all, a verdict issued on a handful of
messages, and a live view computed differently from the reference it is
compared against.
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

import numpy as np

from phishguard.monitoring.drift import (
    PSI_MODERATE,
    PSI_SIGNIFICANT,
    _edges,
    _fractions,
    drift_report,
    live_from_audit_rows,
    live_from_messages,
    null_thresholds,
    profile_from_values,
    psi,
)


def _campaign_traffic(
    n_campaigns: int, per: int = 8, *, shift: float = 0.0, seed: int = 0, spread: float = 0.35
):
    """Monitored quantities for mail that arrives in campaigns.

    Each campaign has its own offset (``spread``), so windows are lumpier than
    independent draws -- the property that breaks the textbook PSI bands.
    """
    rng = np.random.default_rng(seed)
    offsets = rng.normal(0.0, spread, n_campaigns)
    groups = np.repeat(np.arange(n_campaigns), per)
    values = {
        "member:a": offsets[groups] + rng.normal(0.0, 1.0, groups.size) + shift,
        "member:b": rng.exponential(1.0, groups.size) + max(shift, 0.0),
        "recipients": rng.integers(1, 4, groups.size).astype(float),
    }
    return values, groups


def _reference():
    values, groups = _campaign_traffic(150, seed=0)
    return profile_from_values(values, groups)


# ----------------------------------------------------------------- PSI itself
def test_psi_is_zero_for_identical_distributions_and_grows_with_shift():
    even = np.full(10, 0.1)
    assert psi(even, even) == 0.0
    mild = np.array([0.08, 0.08, 0.09, 0.1, 0.1, 0.1, 0.1, 0.11, 0.12, 0.12])
    strong = np.array([0.02, 0.03, 0.05, 0.08, 0.1, 0.1, 0.12, 0.15, 0.17, 0.18])
    assert 0 < psi(even, mild) < psi(even, strong)


def test_psi_is_finite_when_a_live_bin_is_empty():
    ref = np.full(10, 0.1)
    live = np.array([0.0, 0.0, 0.2, 0.2, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    value = psi(ref, live)
    assert np.isfinite(value) and value > 0


def test_tied_reference_values_share_one_bin_without_zero_width_bins():
    """A third of scores exactly 0.0 would otherwise collapse several edges."""
    values = np.concatenate([np.zeros(400), np.linspace(0.01, 1.0, 800)])
    edges = _edges(values)
    assert np.all(np.diff(edges) > 0)
    fr = _fractions(values, edges)
    assert abs(fr.sum() - 1.0) < 1e-9
    assert fr.max() >= 400 / 1200, "the tied zeros land together in one bin"


def test_a_value_never_seen_in_the_reference_is_still_detected():
    """A quantity that was constant at training -- behavioural context always
    present, say -- keeps an empty bin below its support, so a gateway that
    stops sending context is flagged rather than binned away."""
    ref = profile_from_values({"behavioural context available": np.ones(500)})
    live = {"behavioural context available": np.r_[np.ones(300), np.zeros(100)]}
    report = drift_report(ref, live)
    assert report["status"] == "significant"
    assert report["worst"]["live_mean"] == 0.75


# ----------------------------------------------------------------- thresholds
def test_thresholds_are_calibrated_and_never_below_the_textbook_bands():
    th = null_thresholds(_reference(), 400)
    assert th["source"].startswith("calibrated")
    assert "400 messages" in th["source"]
    assert th["moderate"] >= PSI_MODERATE
    assert th["significant"] >= PSI_SIGNIFICANT
    assert th["significant"] >= th["moderate"]


def test_without_campaign_ids_the_monitor_says_it_uses_textbook_bands():
    values, _ = _campaign_traffic(60, seed=1)
    th = null_thresholds(profile_from_values(values, groups=None), 400)
    assert (th["moderate"], th["significant"]) == (PSI_MODERATE, PSI_SIGNIFICANT)
    assert "textbook" in th["source"]


def test_the_null_is_computed_at_the_exact_window_size():
    """Rounding 400 up to 512 once made thresholds too strict (a larger window
    has a tighter null), which raised a false alarm on a stable week."""
    profile = _reference()
    live, _ = _campaign_traffic(50, seed=11)
    report = drift_report(profile, live)
    assert report["n_live"] == 400
    assert set(profile._null_cache) == {400}
    assert "400 messages" in report["thresholds"]["source"]


# ------------------------------------------------------------------ verdicts
def test_stable_traffic_is_quiet_and_a_real_shift_fires():
    profile = _reference()
    stable, _ = _campaign_traffic(50, seed=21)
    shifted, _ = _campaign_traffic(50, shift=1.0, seed=22)
    quiet = drift_report(profile, stable)
    loud = drift_report(profile, shifted)
    assert quiet["status"] != "significant"
    assert loud["status"] == "significant"
    assert loud["worst"]["quantity"] in {"member:a", "member:b"}
    assert loud["worst"]["live_mean"] > loud["worst"]["reference_mean"]
    assert loud["advice"].startswith("Investigate")


def test_false_alarm_rate_on_stable_windows_is_near_its_nominal_level():
    """'Significant' is the null's 99th percentile, so stable campaign-structured
    windows should almost never reach it; 'moderate' (95th) about 1 in 20."""
    profile = _reference()
    statuses = [
        drift_report(profile, _campaign_traffic(50, seed=100 + k)[0])["status"] for k in range(40)
    ]
    assert statuses.count("significant") <= 2
    assert statuses.count("significant") + statuses.count("moderate") <= 8


def test_textbook_bands_cry_wolf_on_lumpy_stable_mail_and_calibrated_ones_do_not():
    """The reason the thresholds are calibrated. When campaigns are large and
    distinct, sampling lumpiness alone pushes *stable* windows past the textbook
    0.10 most of the time; the calibrated monitor, measuring the same windows,
    stays below its significant level."""
    values, groups = _campaign_traffic(80, per=40, spread=2.0, seed=5)
    profile = profile_from_values(values, groups)
    reports = [
        drift_report(profile, _campaign_traffic(10, per=40, spread=2.0, seed=300 + k)[0])
        for k in range(20)
    ]
    textbook_alarms = sum(r["worst"]["psi"] >= PSI_MODERATE for r in reports)
    calibrated_alarms = sum(r["status"] == "significant" for r in reports)
    assert textbook_alarms >= 12
    assert calibrated_alarms <= 2
    assert reports[0]["thresholds"]["moderate"] > PSI_MODERATE


def test_no_reference_is_reported_as_unavailable_with_the_fix():
    report = drift_report(None, {"member:a": np.zeros(100)})
    assert report["available"] is False
    assert "retrain" in report["reason"]


def test_a_handful_of_decisions_is_not_a_verdict():
    report = drift_report(_reference(), {"member:a": np.zeros(12)})
    assert report["available"] is False
    assert report["n_live"] == 12


def test_live_band_shares_are_reported_when_bands_are_given():
    live, _ = _campaign_traffic(50, seed=31)
    bands = ["ALLOW"] * 380 + ["REVIEW"] * 15 + ["BLOCK"] * 5
    report = drift_report(_reference(), live, bands=bands)
    assert report["live_band_shares"] == {"ALLOW": 0.95, "REVIEW": 0.0375, "BLOCK": 0.0125}


# ------------------------------------------------------- audit-trail inputs
def test_audit_rows_rebuild_the_monitored_quantities_without_message_text():
    rows = [
        {
            "member_scores": json.dumps({"rules": 0.25, "wordtfidf": 0.75}),
            "body_length": 99,
            "recipient_count": 3,
            "attachment_count": 1,
            "behavioral_available": 1,
            "band": "REVIEW",
        },
        {
            "member_scores": "not json",
            "body_length": 0,
            "recipient_count": 1,
            "attachment_count": 0,
            "behavioral_available": 0,
            "band": "ALLOW",
        },
        {"member_scores": None, "band": "ALLOW"},
    ]
    live = live_from_audit_rows(rows, ("rules", "wordtfidf"))
    assert live["member:rules"].tolist() == [0.25]
    assert live["member:wordtfidf"].tolist() == [0.75]
    assert np.allclose(live["body length (log)"], np.log1p([99, 0, 0]))
    assert live["recipients"].tolist() == [3.0, 1.0, 0.0]
    assert live["attachments"].tolist() == [1.0, 0.0, 0.0]
    assert live["behavioural context available"].tolist() == [1.0, 0.0, 0.0]


def test_the_service_monitors_from_the_audit_trail_alone():
    """End to end: decisions recorded through the API path, drift computed
    from the audit store's content-free columns, one row per decision."""
    from phishguard.service.contracts import BatchScanRequest
    from phishguard.service.scanning import ScanService
    from phishguard.service.store import DecisionStore
    from tests.helpers import scan_request, trained_detector

    detector, settings = trained_detector()
    store = DecisionStore(Path(tempfile.mkdtemp(prefix="pg-drift-")) / "audit.db")
    service = ScanService(detector, store, settings)

    service.scan_batch(
        BatchScanRequest(
            messages=[
                scan_request(
                    body=f"Minutes from meeting {i}: the rota is attached.",
                    sender=f"c{i}@corp.example",
                )
                for i in range(12)
            ]
        )
    )
    early = service.drift(window_hours=1)
    assert early["available"] is False and early["n_live"] == 12

    service.scan_batch(
        BatchScanRequest(
            messages=[
                scan_request(
                    body=f"Please review draft {i} before Friday.", sender=f"d{i}@corp.example"
                )
                for i in range(30)
            ]
        )
    )
    rows = store.monitoring_rows(window_hours=1)
    assert len(rows) == 42
    report = service.drift(window_hours=1)
    assert report["available"] is True and report["n_live"] == 42
    assert {q["quantity"] for q in report["quantities"]} >= {
        f"member:{n}" for n in detector.member_names
    }
    assert report["window_hours"] == 1
    assert abs(sum(report["live_band_shares"].values()) - 1.0) < 1e-3


def test_monitored_member_scores_are_the_ones_the_detector_decided_with():
    from tests.helpers import corpus, trained_detector

    detector, _ = trained_detector()
    messages, _ = corpus()
    sample = list(messages[:25])
    live = live_from_messages(detector, sample)
    for i, m in enumerate(sample):
        verdict = detector.assess(m)
        for name in detector.member_names:
            assert abs(verdict.member_scores[name] - live[f"member:{name}"][i]) < 1e-9


# ---------------------------------------------------------------- the model
def test_training_captures_a_campaign_aware_reference_from_legitimate_mail():
    from tests.helpers import trained_detector

    detector, _ = trained_detector()
    ref = detector.drift_reference
    assert ref is not None and ref.n >= 50
    assert {f"member:{n}" for n in detector.member_names} <= set(ref.quantities)
    assert ref.groups is not None and len(ref.groups) == ref.n
    # Only integer campaign codes are retained, never sender or subject text.
    assert np.issubdtype(np.asarray(ref.groups).dtype, np.integer)


def test_a_model_saved_before_monitoring_loads_and_says_to_retrain():
    import joblib

    from tests.helpers import trained_detector

    shared, _ = trained_detector()
    old = copy.copy(shared)  # own __dict__: the cached detector stays intact
    old.__dict__.pop("drift_reference", None)
    path = Path(tempfile.mkdtemp(prefix="pg-old-")) / "old.joblib"
    joblib.dump(old, path)
    restored = joblib.load(path)
    assert restored.drift_reference is None
    report = drift_report(restored.drift_reference, {"member:a": np.zeros(100)})
    assert report["available"] is False and "retrain" in report["reason"]


def test_a_window_larger_than_the_reference_supports_is_flagged_as_conservative():
    values, groups = _campaign_traffic(30, seed=3)  # 240 reference messages
    profile = profile_from_values(values, groups)
    live, _ = _campaign_traffic(100, seed=4)  # 800 live messages
    report = drift_report(profile, live)
    assert report["available"] and report["hint"]
    assert "conservative" in report["hint"]
    assert "the largest window this reference supports" in report["thresholds"]["source"]
    small, _ = _campaign_traffic(5, seed=5)  # 40 live messages: no hint
    assert drift_report(profile, small)["hint"] is None
