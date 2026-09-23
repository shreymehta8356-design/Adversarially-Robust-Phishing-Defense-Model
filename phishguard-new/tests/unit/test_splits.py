"""Leakage-safe splitting - the guard that keeps every other number honest."""

from __future__ import annotations

import numpy as np

from phishguard.data.splits import (
    audit_leakage,
    find_near_duplicates,
    grouped_split,
    jaccard_from_signatures,
    minhash_signature,
    single_feature_auc,
    temporal_split,
)
from phishguard.features import FeatureAssembler
from tests.helpers import corpus


def test_minhash_estimates_similarity():
    a = minhash_signature("verify your account immediately or it will be closed")
    b = minhash_signature("verify your account immediately or it will be closed")
    c = minhash_signature("the quarterly warehouse audit is scheduled for Thursday")
    assert jaccard_from_signatures(a, b) == 1.0
    assert jaccard_from_signatures(a, c) < 0.4


def test_near_duplicates_are_found_across_two_sets():
    from phishguard.schemas import EmailMessage

    reference = [EmailMessage(subject="Verify your account", body="Click here now to verify")]
    candidates = [
        EmailMessage(subject="Verify your account", body="Click here now to verify"),
        EmailMessage(subject="Warehouse rota", body="The rota for next week is attached"),
    ]
    flagged = find_near_duplicates(reference, candidates, threshold=0.85)
    assert 0 in flagged and 1 not in flagged


def test_grouped_split_never_splits_a_campaign():
    messages, labels = corpus()
    split = grouped_split(messages, labels, test_size=0.25, seed=3)
    train_groups = {messages[i].group_key for i in split.train_idx}
    test_groups = {messages[i].group_key for i in split.test_idx}
    assert not (train_groups & test_groups)
    assert split.group_overlap == 0


def test_grouped_split_preserves_class_balance():
    messages, labels = corpus()
    split = grouped_split(messages, labels, test_size=0.25, seed=3)
    train_rate = float(np.mean([labels[i] for i in split.train_idx]))
    test_rate = float(np.mean([labels[i] for i in split.test_idx]))
    assert abs(train_rate - test_rate) < 0.08, (train_rate, test_rate)


def test_temporal_split_trains_on_the_past_only():
    messages, labels = corpus()
    split = temporal_split(messages, labels, test_size=0.25)
    latest_train = max(messages[i].received_at for i in split.train_idx)
    earliest_test = min(messages[i].received_at for i in split.test_idx)
    assert earliest_test >= latest_train


def test_leakage_audit_passes_on_a_correct_split():
    messages, labels = corpus()
    split = grouped_split(messages, labels, test_size=0.25, seed=3)
    assembler = FeatureAssembler()
    report = audit_leakage(
        messages,
        labels,
        split,
        features=assembler.transform(messages),
        feature_names=assembler.names,
    )
    assert report.passed, report.failures
    assert report.group_overlap == 0
    assert report.exact_duplicate_pairs == 0


def test_leakage_audit_catches_a_deliberately_broken_split():
    """A row-level split shares campaigns; the audit must refuse it."""
    from phishguard.data.splits import SplitResult

    messages, labels = corpus()
    n = len(messages)
    broken = SplitResult(
        train_idx=list(range(0, n, 2)),
        test_idx=list(range(1, n, 2)),
        strategy="deliberately-broken-row-level",
    )
    report = audit_leakage(messages, labels, broken)
    assert not report.passed
    assert report.group_overlap > 0


def test_leakage_audit_flags_a_planted_label_feature():
    messages, labels = corpus()
    split = grouped_split(messages, labels, test_size=0.25, seed=3)
    assembler = FeatureAssembler()
    features = assembler.transform(messages)
    # Plant the label as a feature: the audit exists to catch exactly this.
    poisoned = np.column_stack([features, np.asarray(labels, dtype=np.float64)])
    report = audit_leakage(
        messages,
        labels,
        split,
        features=poisoned,
        feature_names=(*assembler.names, "planted_label"),
    )
    assert not report.passed
    assert any(r["feature"] == "planted_label" for r in report.suspicious_features)


def test_no_single_feature_dominates_the_corpus():
    """If one feature separates the classes alone, the corpus is not a real task."""
    messages, labels = corpus()
    assembler = FeatureAssembler()
    features = assembler.transform(messages)
    y = np.asarray(labels)
    worst = max(single_feature_auc(features[:, j], y) for j in range(features.shape[1]))
    assert worst < 0.985, f"a single feature reaches AUC {worst:.4f}"


def test_single_feature_auc_handles_constants_and_perfect_separation():
    y = np.array([0, 0, 1, 1])
    assert single_feature_auc(np.array([1.0, 1.0, 1.0, 1.0]), y) == 0.5
    assert single_feature_auc(np.array([0.0, 0.0, 1.0, 1.0]), y) == 1.0


def test_training_pools_never_split_a_campaign():
    """The leak the grouped split closes must not reopen inside training.

    With row-level pools, a calibration message usually had a sibling in the
    member-fitting pool, so the calibration pool looked perfectly separated
    and the false-alarm budget could not be estimated from it.
    """
    from phishguard.models.detector import _campaign_pools

    messages, _ = corpus()
    n = len(messages)
    cal, stack, fit = _campaign_pools(
        messages, int(n * 0.18), int(n * 0.22), np.random.default_rng(0)
    )
    assert sorted(np.concatenate([cal, stack, fit]).tolist()) == list(range(n))
    keys = [messages[i].group_key for i in range(n)]
    pools = [{keys[i] for i in pool} for pool in (cal, stack, fit)]
    assert not (pools[0] & pools[1]) and not (pools[0] & pools[2]) and not (pools[1] & pools[2])
    # Whole campaigns overshoot the target by at most one campaign each.
    assert int(n * 0.18) <= len(cal) <= int(n * 0.18) + 60
    assert int(n * 0.22) <= len(stack) <= int(n * 0.22) + 60


def test_a_trained_detector_calibrated_on_campaigns_it_never_fitted():
    from tests.helpers import trained_detector

    detector, _ = trained_detector()
    report = detector.report
    assert report.n_cal > 0 and report.n_stack > 0 and report.n_fit > 0
    ref = detector.drift_reference
    # The drift reference is the stacking and calibration pools' legitimate mail.
    assert ref is not None and ref.n > 0
