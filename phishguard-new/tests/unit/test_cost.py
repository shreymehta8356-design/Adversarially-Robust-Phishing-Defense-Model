"""The expected-cost model behind the operating point.

These pin the properties a reader of the cost section relies on: that the
banding rule matches the deployed detector, that the model re-weights to the
deployment's prevalence instead of the corpus's, and that "optimal" means
optimal under the stated assumptions and nothing more.
"""

from __future__ import annotations

import numpy as np

from phishguard.eval.cost import (
    BAND_ALLOW,
    BAND_BLOCK,
    BAND_REVIEW,
    CostAssumptions,
    RateTable,
    ScoredSet,
    bands_for,
    class_rates,
    expected_cost,
    minimax_regret,
)


def _set(scores, labels, spread=None) -> ScoredSet:
    return ScoredSet(
        labels=np.asarray(labels),
        scores=np.asarray(scores),
        spread=np.asarray(spread) if spread is not None else np.zeros(0),
    )


def test_bands_follow_the_thresholds():
    s = _set([0.1, 0.5, 0.9], [0, 0, 1])
    assert list(bands_for(s, 0.4, 0.8, 9.0)) == [BAND_ALLOW, BAND_REVIEW, BAND_BLOCK]


def test_symmetric_abstention_escalates_a_contested_block():
    s = _set([0.95], [1], spread=[0.9])
    assert bands_for(s, 0.4, 0.8, 0.45, "symmetric")[0] == BAND_REVIEW


def test_escalate_only_abstention_never_downgrades_a_block():
    """Disagreement may make a decision more cautious, never less."""
    s = _set([0.95, 0.05], [1, 1], spread=[0.9, 0.9])
    bands = bands_for(s, 0.4, 0.8, 0.45, "escalate")
    assert bands[0] == BAND_BLOCK  # contested block stays blocked
    assert bands[1] == BAND_REVIEW  # contested allow is escalated


def test_cost_model_bands_match_the_deployed_detector():
    """The model must price the policy that actually ships, not an idealisation."""
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    det.review_threshold, det.block_threshold = 0.4, 0.8
    cases = [
        (0.9, {"a": 0.9, "b": 0.88, "c": 0.92}),  # agreed block
        (0.9, {"a": 0.95, "b": 0.1, "c": 0.9}),  # contested block
        (0.05, {"a": 0.9, "b": 0.02, "c": 0.03}),  # contested allow
        (0.5, {"a": 0.5, "b": 0.55, "c": 0.45}),  # plain review
    ]
    names = {BAND_ALLOW: "ALLOW", BAND_REVIEW: "REVIEW", BAND_BLOCK: "BLOCK"}
    for mode in ("symmetric", "escalate"):
        det.settings.abstain_mode = mode
        for score, members in cases:
            expected = det.band_with_abstention(score, members)[0]
            spread = max(members.values()) - min(members.values())
            got = bands_for(
                _set([score], [1], spread=[spread]),
                0.4,
                0.8,
                det.settings.abstain_disagreement,
                mode,
            )[0]
            assert names[int(got)] == expected, (mode, score, members)
    det.settings.abstain_mode = "symmetric"


def test_cost_reweights_to_deployment_prevalence():
    """A false alarm must not look nearly free just because the corpus is 46% phishing."""
    rates = {
        "phish_allow": 0.0,
        "phish_review": 0.0,
        "phish_block": 1.0,
        "ham_allow": 0.9,
        "ham_review": 0.0,
        "ham_block": 0.1,
    }
    rare = expected_cost(rates, None, CostAssumptions(phish_prevalence=0.01))
    common = expected_cost(rates, None, CostAssumptions(phish_prevalence=0.46))
    # The same false-block rate costs more when legitimate mail dominates.
    assert rare["false_block_per_1000"] > common["false_block_per_1000"]


def test_a_perfect_policy_costs_nothing():
    rates = {
        "phish_allow": 0.0,
        "phish_review": 0.0,
        "phish_block": 1.0,
        "ham_allow": 1.0,
        "ham_review": 0.0,
        "ham_block": 0.0,
    }
    assert expected_cost(rates, None, CostAssumptions())["per_1000"] == 0.0


def test_review_is_not_a_free_catch():
    """Analysts miss some reviewed phishing, so reviewing costs more than one unit."""
    a = CostAssumptions(analyst_miss_rate=0.05, miss_cost=200)
    rates = {
        "phish_allow": 0.0,
        "phish_review": 1.0,
        "phish_block": 0.0,
        "ham_allow": 1.0,
        "ham_review": 0.0,
        "ham_block": 0.0,
    }
    per_phish = expected_cost(rates, None, a)["per_1000"] / (1000 * a.phish_prevalence)
    assert abs(per_phish - (1 + 0.05 * 200)) < 1e-6


def test_the_optimum_is_optimal_on_its_own_grid():
    rng = np.random.default_rng(3)
    labels = np.r_[np.zeros(300), np.ones(100)]
    scores = np.r_[rng.beta(2, 6, 300), rng.beta(6, 2, 100)]
    s = _set(scores, labels)
    table = RateTable(s, None)
    a = CostAssumptions()
    best = table.best(a, use_hard=False)
    for pol, o in zip(table.policies, table.ordinary):
        assert expected_cost(o, None, a)["per_1000"] >= best["per_1000"] - 1e-9, pol


def test_higher_miss_cost_never_raises_the_optimal_review_threshold():
    """If missed phishing gets dearer, the policy should never get *more* permissive."""
    rng = np.random.default_rng(5)
    labels = np.r_[np.zeros(400), np.ones(150)]
    scores = np.r_[rng.beta(2, 7, 400), rng.beta(7, 2, 150)]
    table = RateTable(_set(scores, labels), None)
    cheap = table.best(CostAssumptions(miss_cost=20), allow_abstain=False, use_hard=False)
    dear = table.best(CostAssumptions(miss_cost=2000), allow_abstain=False, use_hard=False)
    assert dear["review"] <= cheap["review"]


def test_minimax_regret_is_never_worse_than_any_policy_it_beat():
    rng = np.random.default_rng(9)
    o = _set(
        np.r_[rng.beta(2, 7, 300), rng.beta(7, 2, 100)],
        np.r_[np.zeros(300), np.ones(100)],
        spread=rng.uniform(0, 0.9, 400),
    )
    h = _set(
        np.r_[rng.beta(3, 3, 60), rng.beta(3, 3, 60)],
        np.r_[np.zeros(60), np.ones(60)],
        spread=rng.uniform(0, 0.9, 120),
    )
    table = RateTable(o, h)
    mm = minimax_regret(table, CostAssumptions())
    assert mm["max_regret_per_1000"] >= 0
    assert all(r["regret_per_1000"] <= mm["max_regret_per_1000"] + 1e-9 for r in mm["by_profile"])


def test_class_rates_sum_to_one_per_label():
    s = _set([0.1, 0.5, 0.9, 0.2, 0.95], [0, 0, 0, 1, 1])
    r = class_rates(s, bands_for(s, 0.4, 0.8, 9.0))
    assert abs(r["ham_allow"] + r["ham_review"] + r["ham_block"] - 1) < 1e-12
    assert abs(r["phish_allow"] + r["phish_review"] + r["phish_block"] - 1) < 1e-12


def test_abstain_mode_rejects_a_typo():
    """A misspelt mode must fail loudly, not silently fall back to symmetric."""
    from phishguard.config import Settings

    try:
        Settings(abstain_mode="escalte")
    except Exception:  # noqa: BLE001 - pydantic's ValidationError
        return
    raise AssertionError("an invalid abstain_mode was accepted")
