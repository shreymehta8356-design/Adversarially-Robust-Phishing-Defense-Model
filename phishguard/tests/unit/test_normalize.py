"""Canonicalization - defensive control D-NORM."""

from __future__ import annotations

from phishguard.defenses.normalize import (
    canonicalize,
    collapse_runs,
    count_mixed_script_words,
    defeat_leetspeak,
    fold_confusables,
    obfuscation_signals,
    rejoin_separated,
    strip_diacritics,
    strip_invisible,
)


def test_folds_cyrillic_homoglyphs_to_ascii():
    # Cyrillic а, е and о render identically to their Latin counterparts.
    assert fold_confusables("pаypаl") == "paypal"
    assert fold_confusables("Urgеnt") == "Urgent"
    assert fold_confusables("micrоsоft") == "microsoft"


def test_strips_zero_width_characters():
    assert strip_invisible("pass​word") == "password"
    assert strip_invisible("ver‍ifyi⁠ng") == "verifying"


def test_strips_combining_diacritics():
    assert strip_diacritics("pásswörd") == "password"


def test_defeats_leetspeak_only_inside_word_like_tokens():
    assert defeat_leetspeak("p4ssw0rd") == "password"
    assert defeat_leetspeak("h3ll0") == "hello"
    # Too few letters to be confident it is a word, so left alone.
    assert defeat_leetspeak("l33t") == "l33t"
    # Genuine identifiers must survive. Folding "office365" would make the
    # canonical form of a real brand differ from the brand's own spelling.
    assert defeat_leetspeak("sha256") == "sha256"
    assert defeat_leetspeak("office365") == "office365"
    assert defeat_leetspeak("base64") == "base64"
    assert defeat_leetspeak("x509") == "x509"
    assert defeat_leetspeak("2FA") == "2FA"


def test_rejoins_separated_tokens():
    assert "password" in rejoin_separated("p-a-s-s-w-o-r-d reset")
    assert "verify" in rejoin_separated("v e r i f y now")


def test_collapses_character_runs():
    assert collapse_runs("urgeeeeent") == "urgeent"
    # Two repeats are legitimate in ordinary English and are preserved.
    assert collapse_runs("keep") == "keep"


def test_full_pipeline_normalises_a_layered_obfuscation():
    raw = "Urgеnt: verify your p4ssw0rd n​ow"
    assert canonicalize(raw) == "Urgent: verify your password now"


def test_canonicalize_is_idempotent():
    once = canonicalize("Urgеnt: p4ssw0rd n​ow")
    assert canonicalize(once) == once


def test_obfuscation_signals_quantify_evasion_effort():
    clean = obfuscation_signals("Please confirm your password")
    dirty = obfuscation_signals("Please cоnfirm your p4ssw0rd n​ow")
    assert clean["obf_zero_width_count"] == 0
    assert dirty["obf_zero_width_count"] == 1
    assert dirty["obf_confusable_ratio"] > clean["obf_confusable_ratio"]
    assert dirty["obf_leet_tokens"] >= 1


def test_mixed_script_words_are_counted():
    # "paypal" written with a Cyrillic 'а' mixes scripts inside one word.
    assert count_mixed_script_words("pаypal login") == 1
    assert count_mixed_script_words("paypal login") == 0


def test_empty_and_none_like_inputs_are_safe():
    assert canonicalize("") == ""
    assert strip_invisible("") == ""
    assert obfuscation_signals("")["obf_norm_edit_ratio"] == 0.0
