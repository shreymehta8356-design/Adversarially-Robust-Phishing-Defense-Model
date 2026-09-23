"""Defensive controls that act at decision time, and the evidence they leave."""

from __future__ import annotations

from phishguard.adversarial.taxonomy import ATTACK_FAMILIES, FAMILY_BY_ID
from phishguard.defenses.controls import DEFENSE_IDS, apply_velocity_guard, describe_defenses

BURST = {
    "beh_context_available": 1.0,
    "beh_campaign_shape": 0.9,
    "beh_domain_reported": 0.0,
    "beh_display_name_reuse": 1.0,
}


def test_velocity_guard_raises_a_burst_campaign_within_its_bound():
    score, note = apply_velocity_guard(0.50, BURST)
    assert 0.50 < score <= 0.50 + 0.15
    assert note and note.startswith("velocity guard raised score by +")


def test_velocity_guard_never_lowers_a_score():
    """Regression: the 0.99 ceiling was applied unconditionally, so a message
    already scored 1.0 was lowered to 0.99 and the evidence read "raised score
    by -0.010" -- a monotone control that was not monotone."""
    for start in (0.991, 0.995, 1.0):
        score, note = apply_velocity_guard(start, BURST)
        assert score == start and note is None


def test_velocity_guard_stays_out_of_the_way_without_context_or_when_disabled():
    no_context = dict(BURST, beh_context_available=0.0)
    assert apply_velocity_guard(0.5, no_context) == (0.5, None)
    assert apply_velocity_guard(0.5, BURST, enabled=False) == (0.5, None)
    quiet = dict(BURST, beh_campaign_shape=0.0, beh_display_name_reuse=0.0)
    assert apply_velocity_guard(0.5, quiet) == (0.5, None)


def test_text_evidence_names_whole_words_not_character_fragments():
    from tests.helpers import phishing_message, trained_detector

    detector, _ = trained_detector()
    verdict = detector.assess(phishing_message(), explain=True)
    tokens = [e for e in verdict.evidence if e["kind"] == "token"]
    assert tokens, "a phishing message should carry text evidence"
    terms = [t.strip() for t in tokens[0]["detail"].split(",")]
    text = phishing_message().text.lower()
    # Every term is a word (or phrase) an analyst can find in the message.
    assert all(len(t) >= 3 for t in terms)
    assert all(any(part in text for part in t.split()) for t in terms), terms


def test_controls_and_attack_families_agree_on_who_counters_what():
    """Regression: the defence catalogue kept its own list of families per
    control, written before A-TRUST and A-CHANNEL existed, and it disagreed with
    the taxonomy's list for five of the six controls. The mapping now lives only
    in the taxonomy and the catalogue is derived from it."""
    rows = {row["id"]: row for row in describe_defenses()}
    assert set(rows) == set(DEFENSE_IDS)
    for family in ATTACK_FAMILIES:
        assert family.countered_by, f"{family.id} has no control against it"
        for control in family.countered_by:
            assert control in rows, f"{family.id} names unknown control {control}"
            assert family.id in rows[control]["counters"]
    for control, row in rows.items():
        assert row["counters"], f"{control} counters no attack family"
        for family_id in row["counters"]:
            assert control in FAMILY_BY_ID[family_id].countered_by
