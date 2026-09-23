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


def test_abstention_needs_a_contradiction_not_one_lukewarm_reader():
    """Regression: an ordinary message that arrives without sender history had
    one text member at 0.49 and the rest near zero -- a spread of 0.48 -- and
    was escalated. One reader shrugging is not two readers contradicting."""
    from tests.helpers import trained_detector

    det, _ = trained_detector()
    det.settings.abstain_requires_contradiction = True
    lukewarm = {"rules": 0.04, "engineered": 0.01, "charngram": 0.31, "wordtfidf": 0.49}
    band, spread, abstained = det.band_with_abstention(0.0, lukewarm)
    assert spread > det.settings.abstain_disagreement
    assert band == "ALLOW" and not abstained

    # Two readers alarmed against a calm one: a contradiction, escalate.
    hijack = {"rules": 0.04, "engineered": 0.01, "charngram": 0.60, "wordtfidf": 0.48}
    assert det.band_with_abstention(0.0, hijack) == ("REVIEW", 0.59, True)
    # One reader certain against a calm one: also a contradiction.
    clone = {"rules": 0.25, "engineered": 1.0, "charngram": 0.17, "wordtfidf": 0.12}
    assert det.band_with_abstention(0.11, clone)[2] is True
    # Everyone alarmed: no contradiction, the score decides.
    agreed = {"rules": 0.9, "engineered": 1.0, "charngram": 0.45, "wordtfidf": 0.5}
    assert det.band_with_abstention(0.99, agreed) == ("BLOCK", 0.55, False)

    det.settings.abstain_requires_contradiction = False
    assert det.band_with_abstention(0.0, lukewarm)[0] == "REVIEW"
    det.settings.abstain_requires_contradiction = True


def test_transformer_member_is_optional_and_travels_without_a_gpu():
    """The fifth reader is a guarded upgrade: absent torch, the detector builds
    its four core members; a saved member carries CPU weights and picks its
    device when it is next used, so a model trained on a GPU loads on a laptop."""
    import pickle

    from phishguard.config import Settings
    from phishguard.models.detector import PhishGuardDetector
    from phishguard.models.members import TransformerMember

    settings = Settings(environment="test", use_transformer=True)
    detector = PhishGuardDetector(settings=settings)
    if TransformerMember.available():  # pragma: no cover - depends on the machine
        assert "transformer" in detector.member_names
    else:
        assert "transformer" not in detector.member_names

    member = TransformerMember(model_name="x/y", epochs=3, max_train=99)
    member._state = {"w": [1, 2, 3]}
    member.fitted = True
    clone = pickle.loads(pickle.dumps(member))
    assert (clone.model_name, clone.epochs, clone.max_train, clone.fitted) == ("x/y", 3, 99, True)
    assert clone._state == {"w": [1, 2, 3]} and clone._pipeline is None
