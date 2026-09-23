"""The three feature families and the assembler contract."""

from __future__ import annotations

import numpy as np

from phishguard.features.assembler import FEATURE_FAMILIES, FeatureAssembler
from phishguard.features.behavioral import behavioral_features
from phishguard.features.email import email_features, header_features
from phishguard.features.lexicons import damerau_levenshtein, nearest_brand_lookalike
from phishguard.schemas import Attachment, AuthResults, BehavioralContext
from tests.helpers import ham_message, phishing_message


def test_header_detects_display_name_brand_mismatch():
    msg = phishing_message()
    f = header_features(msg)
    assert f["hdr_display_brand_domain_mismatch"] == 1.0
    assert f["hdr_replyto_domain_mismatch"] == 1.0
    assert f["hdr_spf_fail"] == 1.0


def test_header_is_clean_for_legitimate_internal_mail():
    f = header_features(ham_message())
    assert f["hdr_display_brand_domain_mismatch"] == 0.0
    assert f["hdr_auth_score"] == 1.0


def test_attachment_double_extension_is_detected():
    f = email_features(phishing_message())
    assert f["att_double_extension"] >= 1.0
    assert f["att_executable"] >= 1.0


def test_body_lexicons_separate_pressure_from_ordinary_mail():
    phish = email_features(phishing_message())
    ham = email_features(ham_message())
    assert phish["body_lex_credential"] > ham["body_lex_credential"]
    assert phish["body_lex_threat"] > ham["body_lex_threat"]
    assert phish["body_generic_greeting"] >= 1.0


def test_html_password_field_is_detected():
    assert email_features(phishing_message())["html_password_input"] == 1.0


def test_behavioral_absence_is_a_first_class_signal():
    """The model must be told when it is flying blind, not fed silent zeros."""
    with_ctx = behavioral_features(
        phishing_message(), BehavioralContext(available=True, prior_messages_from_sender=40)
    )
    without = behavioral_features(
        phishing_message(), BehavioralContext(available=False)
    )
    assert with_ctx["beh_context_available"] == 1.0
    assert without["beh_context_available"] == 0.0
    assert with_ctx["beh_relationship_strength"] > without["beh_relationship_strength"]


def test_relationship_strength_saturates_with_history():
    weak = behavioral_features(
        ham_message(), BehavioralContext(available=True, prior_messages_from_sender=1)
    )["beh_relationship_strength"]
    strong = behavioral_features(
        ham_message(),
        BehavioralContext(
            available=True, prior_messages_from_sender=200, prior_replies_to_sender=150
        ),
    )["beh_relationship_strength"]
    assert 0.0 <= weak < strong <= 1.0


def test_trust_deficit_is_bounded_and_ordered():
    high = behavioral_features(phishing_message())["beh_trust_deficit"]
    low = behavioral_features(ham_message())["beh_trust_deficit"]
    assert 0.0 <= low < high <= 1.0


def test_assembler_produces_a_stable_named_vector():
    assembler = FeatureAssembler()
    fv = assembler.extract(phishing_message())
    assert fv.values.shape == (assembler.n_features,)
    assert len(assembler.names) == len(set(assembler.names))
    assert np.isfinite(fv.values).all()


def test_assembler_families_can_be_ablated():
    full = FeatureAssembler().n_features
    sizes = [FeatureAssembler(families=(f,)).n_features for f in FEATURE_FAMILIES]
    assert sum(sizes) == full
    assert all(s > 0 for s in sizes)


def test_assembler_rejects_an_unknown_family():
    try:
        FeatureAssembler(families=("email", "telepathy"))
    except ValueError as exc:
        assert "telepathy" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for an unknown family")


def test_feature_contract_mismatch_is_a_hard_failure():
    """A model served against a different feature layout produces confident nonsense."""
    assembler = FeatureAssembler()
    contract = assembler.contract()
    contract["names"] = list(contract["names"]) + ["a_feature_that_does_not_exist"]
    try:
        assembler.verify(contract)
    except RuntimeError as exc:
        assert "contract mismatch" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError on a contract mismatch")


def test_transform_matrix_matches_row_by_row_extraction():
    assembler = FeatureAssembler()
    messages = [phishing_message(), ham_message()]
    matrix = assembler.transform(messages)
    assert matrix.shape == (2, assembler.n_features)
    np.testing.assert_allclose(matrix[0], assembler.extract(messages[0]).values)


def test_empty_message_produces_a_valid_vector():
    from phishguard.schemas import EmailMessage

    fv = FeatureAssembler().extract(EmailMessage())
    assert np.isfinite(fv.values).all()


def test_edit_distance_and_brand_lookalikes():
    assert damerau_levenshtein("paypal.com", "paypal.com") == 0
    assert damerau_levenshtein("paypa1.com", "paypal.com") == 1
    assert damerau_levenshtein("ppyaal.com", "paypal.com") <= 3
    domain, distance = nearest_brand_lookalike("paypa1.com")
    assert domain == "paypal.com" and distance == 1
    assert nearest_brand_lookalike("northgate-industries.example")[1] == 99


def test_auth_results_map_onto_a_score():
    from phishguard.schemas import EmailMessage

    all_pass = header_features(
        EmailMessage(sender="a@b.com", auth=AuthResults("pass", "pass", "pass"))
    )
    none_pass = header_features(
        EmailMessage(sender="a@b.com", auth=AuthResults("fail", "fail", "fail"))
    )
    assert all_pass["hdr_auth_score"] == 1.0
    assert none_pass["hdr_auth_score"] == 0.0


def test_attachment_extension_parsing():
    assert Attachment("report.PDF").extension == "pdf"
    assert Attachment("archive.tar.gz").extension == "gz"
    assert Attachment("noextension").extension == ""
