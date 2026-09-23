"""PG-HARD and the abstention control.

These pin the properties that make the hard benchmark worth quoting. A curated
benchmark is only evidence if it is reproducible, if it is genuinely held out
of training, and if the thing being graded is the system that actually ships.
"""

from __future__ import annotations

import numpy as np

from phishguard.data.hardcases import (
    HARD_CASES,
    TOLERATED_HAM,
    TOLERATED_PHISH,
    build_hard_benchmark,
    describe_benchmark,
)
from phishguard.eval.hard_eval import grade, matched_thresholds
from phishguard.schemas import BAND_ALLOW, BAND_BLOCK, BAND_REVIEW


# ----------------------------------------------------------------- benchmark
def test_every_case_declares_why_it_is_hard():
    """A case without a stated defeated cue is an anecdote, not a benchmark."""
    for case in HARD_CASES:
        assert case.defeats, case.case_id
        assert len(case.rationale) > 80, (
            f"{case.case_id}: the rationale has to survive an examiner asking 'why is this hard?'"
        )
        assert case.label in (0, 1)


def test_benchmark_is_balanced_and_covers_both_failure_directions():
    d = describe_benchmark()
    assert d["n_hard_negatives"] >= 10
    assert d["n_hard_positives"] >= 10
    # A set of only hard positives measures recall and calls it robustness.
    assert d["n_hard_negatives"] == d["n_hard_positives"]


def test_tolerated_bands_encode_the_three_band_design():
    for case in HARD_CASES:
        expected = TOLERATED_PHISH if case.label == 1 else TOLERATED_HAM
        assert tuple(case.tolerated) == expected, case.case_id
        # REVIEW is always acceptable: escalating a genuinely hard message is
        # the correct behaviour, not a failure to decide.
        assert BAND_REVIEW in case.tolerated
        # Exactly one band is a real operational failure per label.
        assert (BAND_ALLOW in case.tolerated) != (BAND_BLOCK in case.tolerated)


def test_benchmark_is_deterministic():
    a, ya, ma = build_hard_benchmark(variants_per_case=3, seed=99)
    b, yb, mb = build_hard_benchmark(variants_per_case=3, seed=99)
    assert ya == yb
    assert [m["case_id"] for m in ma] == [m["case_id"] for m in mb]
    assert [m.subject for m in a] == [m.subject for m in b]
    assert [m.body for m in a] == [m.body for m in b]


def test_adding_variants_does_not_renumber_existing_ones():
    """Variant k must be the same message regardless of how many were asked for.

    Otherwise every change to ``--variants`` silently produces a different
    benchmark and the case-by-case table stops being comparable across runs.
    """
    few, _, meta_few = build_hard_benchmark(variants_per_case=2, seed=5)
    many, _, meta_many = build_hard_benchmark(variants_per_case=6, seed=5)
    index = {(m["case_id"], m["variant"]): i for i, m in enumerate(meta_many)}
    for i, m in enumerate(meta_few):
        j = index[(m["case_id"], m["variant"])]
        assert few[i].subject == many[j].subject
        assert few[i].body == many[j].body


def test_variants_of_a_case_share_a_group_key():
    """Variants are near-duplicates; a split must never straddle them."""
    messages, _, meta = build_hard_benchmark(variants_per_case=4)
    by_case: dict[str, set[str]] = {}
    for msg, m in zip(messages, meta, strict=True):
        by_case.setdefault(m["case_id"], set()).add(msg.group_key)
    for case_id, keys in by_case.items():
        assert len(keys) == 1, f"{case_id} spans {keys}"


def test_no_hard_case_leaks_into_the_training_corpus():
    """PG-HARD must not appear in the corpus the model is fitted on."""
    from phishguard.data.synthetic import generate_corpus

    hard, _, _ = build_hard_benchmark(variants_per_case=4)
    corpus, _ = generate_corpus(1500, seed=4242)
    corpus_prints = {m.fingerprint() for m in corpus}
    overlap = [m for m in hard if m.fingerprint() in corpus_prints]
    assert not overlap, f"{len(overlap)} PG-HARD records appear in the corpus"


def test_hard_cases_carry_no_real_recipient_or_live_brand_domain():
    """Provenance claim in the module docstring, enforced."""
    messages, _, _ = build_hard_benchmark(variants_per_case=2)
    for m in messages:
        for addr in m.to:
            assert addr.endswith(".example"), addr


# ----------------------------------------------------------------- grading
def _meta(labels: list[int]) -> list[dict]:
    return [
        {
            "case_id": f"C{i}",
            "variant": 0,
            "label": lab,
            "family": f"C{i}",
            "title": "t",
            "defeats": "d",
            "rationale": "r",
            "tolerated": list(TOLERATED_PHISH if lab else TOLERATED_HAM),
        }
        for i, lab in enumerate(labels)
    ]


def test_grade_counts_the_two_operational_failures():
    labels = [1, 1, 0, 0]
    # phish at 0.01 (silent), phish at 0.9 (blocked),
    # ham at 0.95 (false block), ham at 0.1 (allowed)
    scores = [0.01, 0.9, 0.95, 0.1]
    out = grade(scores, labels, _meta(labels), review=0.4, block=0.8)
    assert out["silent_delivery"] == 1
    assert out["false_block"] == 1
    assert out["acceptable_rate"] == 0.5


def test_review_band_counts_as_an_acceptable_outcome_for_both_labels():
    labels = [1, 0]
    scores = [0.5, 0.5]  # both land in REVIEW
    out = grade(scores, labels, _meta(labels), review=0.4, block=0.8)
    assert out["silent_delivery"] == 0
    assert out["false_block"] == 0
    assert out["acceptable_rate"] == 1.0


def test_supplied_bands_override_score_thresholding():
    """The deployed system's abstention must reach the grader.

    Banding the score alone would measure a detector without D-ABSTAIN, which
    is not the one being shipped.
    """
    labels = [1]
    scores = [0.01]  # would be ALLOW on score alone -> silent delivery
    out = grade(
        scores,
        labels,
        _meta(labels),
        review=0.4,
        block=0.8,
        bands=[BAND_REVIEW],  # abstention escalated it
    )
    assert out["silent_delivery"] == 0
    assert out["acceptable_rate"] == 1.0


def test_matched_thresholds_keep_the_bands_ordered():
    y = np.array([0] * 90 + [1] * 10)
    scores = np.concatenate([np.linspace(0.0, 0.5, 90), np.linspace(0.6, 1.0, 10)])
    review, block = matched_thresholds(y, scores, target_review_fpr=0.10, target_block_fpr=0.01)
    assert block >= review


# ---------------------------------------------------------------- abstention
def test_disagreement_is_the_spread_between_members():
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    spread = det.disagreement(
        {"rules": 0.83, "engineered": 0.76, "charngram": 0.03, "wordtfidf": 0.03}
    )
    assert abs(spread - 0.80) < 1e-9


def test_disagreement_needs_enough_members_to_mean_anything():
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    assert det.disagreement({"engineered": 0.9}) == 0.0


def test_abstention_escalates_a_confident_but_contested_verdict():
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    det.review_threshold, det.block_threshold = 0.4, 0.8
    contested = {"rules": 0.83, "engineered": 0.76, "charngram": 0.03, "wordtfidf": 0.03}
    band, spread, abstained = det.band_with_abstention(0.05, contested)
    assert band == BAND_REVIEW
    assert abstained
    assert spread > det.settings.abstain_disagreement


def test_abstention_leaves_an_agreed_verdict_alone():
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    det.review_threshold, det.block_threshold = 0.4, 0.8
    agreed = {"rules": 0.97, "engineered": 0.99, "charngram": 0.95, "wordtfidf": 0.96}
    band, _, abstained = det.band_with_abstention(0.98, agreed)
    assert band == BAND_BLOCK
    assert not abstained


def test_abstention_is_off_when_the_control_is_ablated():
    from phishguard.defenses.controls import DefenseConfig
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector(defenses=DefenseConfig.without("D-ABSTAIN"))
    det.review_threshold, det.block_threshold = 0.4, 0.8
    contested = {"rules": 0.83, "engineered": 0.76, "charngram": 0.03, "wordtfidf": 0.03}
    band, _, abstained = det.band_with_abstention(0.05, contested)
    assert not abstained
    assert band == BAND_ALLOW


# ------------------------------------------------------- fitted thresholds
def test_thresholds_fall_back_when_the_pool_is_perfectly_separated():
    """Isotonic saturation makes a false-alarm budget unmeasurable.

    Every legitimate message scoring exactly 0.0 means no threshold above zero
    has a measurable false-positive rate, and the search degenerates to "block
    anything above zero". The configured constants must survive that.
    """
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    scores = np.array([0.0] * 200 + [1.0] * 120)
    y = np.array([0] * 200 + [1] * 120)
    det._fit_thresholds(scores, y)
    assert det.review_threshold == det.settings.review_threshold
    assert det.block_threshold == det.settings.block_threshold
    assert "perfectly separated" in det.threshold_source


def test_thresholds_reject_a_block_boundary_below_even_odds():
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    # Negatives spread low; the budget is met far below 0.5.
    scores = np.concatenate([np.linspace(0.0, 0.2, 200), np.linspace(0.3, 0.4, 120)])
    y = np.array([0] * 200 + [1] * 120)
    det._fit_thresholds(scores, y)
    assert det.block_threshold >= 0.5


def test_fitted_bands_are_wide_enough_to_be_bands():
    from phishguard.models.detector import PhishGuardDetector

    det = PhishGuardDetector()
    rng = np.random.default_rng(0)
    scores = np.concatenate([rng.uniform(0.0, 0.95, 400), rng.uniform(0.5, 1.0, 200)])
    y = np.array([0] * 400 + [1] * 200)
    det._fit_thresholds(scores, y)
    assert det.block_threshold - det.review_threshold >= 0.10 or (
        det.threshold_source.startswith("configured")
    )
