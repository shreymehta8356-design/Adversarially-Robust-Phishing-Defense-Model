"""Loading real public corpora, and auditing them before training.

Every test here corresponds to a specific way real phishing corpora quietly
corrupt a model: a charset decoded wrongly, a subject left encoded, an HTML-only
body with no text, a forged authentication header trusted, a label convention
misread, spam relabelled as phishing, or -- the one that matters most -- two
classes collected in different decades.
"""

from __future__ import annotations

import email
import email.policy

from phishguard.data.loaders import (
    UNDATED,
    LoadReport,
    _message_from_rfc822,
    html_to_text,
    load_any,
    load_csv,
    load_eml_dir,
    load_mbox,
    resolve_label_convention,
)
from phishguard.schemas import LABEL_HAM, LABEL_PHISH
from tests import realmail


# ------------------------------------------------------------ decoding
def test_windows_1252_is_decoded_with_its_declared_charset():
    raw = email.message_from_bytes(realmail.windows_1252_message(), policy=email.policy.default)
    report = LoadReport()
    msg = _message_from_rfc822(raw, "t", "", report)
    assert "We’ve" in msg.body and "“final”" in msg.body
    assert "�" not in msg.body, "decoding as UTF-8 would have produced U+FFFD"
    assert report.decode_replacements == 0


def test_rfc2047_encoded_subjects_are_decoded_in_mbox():
    """mbox is parsed with compat32, which leaves encoded-words in place."""
    d = realmail.tmpdir()
    path = realmail.modern_phishing_mbox(d, n=6)
    report = LoadReport()
    messages, _ = load_mbox(path, label=LABEL_PHISH, report=report)
    assert report.encoded_subjects == 3
    for m in messages:
        assert "=?utf-8?" not in m.subject.lower()
        assert m.subject.startswith("Acti")
    # The homoglyph survives decoding, where the normaliser (D-NORM) can see it.
    assert any("\u043e" in m.subject for m in messages)


def test_html_only_mail_gets_a_text_body():
    d = realmail.tmpdir()
    path = realmail.modern_phishing_mbox(d, n=6)
    report = LoadReport()
    messages, _ = load_mbox(path, label=LABEL_PHISH, report=report)
    assert report.html_only_converted >= 1
    for m in messages:
        assert m.body.strip(), "every message must reach the text models with a body"
        assert "<" not in m.body, "tags must not leak into the text rendering"


def test_html_to_text_drops_script_and_keeps_link_text():
    html = (
        "<html><head><style>p{color:red}</style></head><body>"
        "<script>track()</script><p>Verify&nbsp;your <b>account</b></p>"
        "<a href='http://x.example'>Click here</a></body></html>"
    )
    text = html_to_text(html)
    assert "track()" not in text and "color:red" not in text
    assert "Verify your account" in text and "Click here" in text


# ------------------------------------------------------------ auth
def test_authentication_results_parsed_including_softfail():
    d = realmail.tmpdir()
    path = realmail.modern_phishing_mbox(d, n=3)
    messages, _ = load_mbox(path, label=LABEL_PHISH)
    for m in messages:
        assert (m.auth.spf, m.auth.dkim, m.auth.dmarc) == ("softfail", "none", "fail")


def test_only_the_topmost_authentication_header_is_trusted():
    """Lower headers travelled with the message and can be forged by the sender."""
    raw = email.message_from_bytes(realmail.forged_auth_message(), policy=email.policy.default)
    msg = _message_from_rfc822(raw, "t", "")
    assert (msg.auth.spf, msg.auth.dkim, msg.auth.dmarc) == ("fail", "fail", "fail")


def test_received_spf_is_used_when_authentication_results_is_absent():
    raw = email.message_from_bytes(
        b"Received-SPF: pass (mx.example: domain of a@b.example designates 1.2.3.4)\r\n"
        b"From: a@b.example\r\nSubject: hi\r\nDate: Mon, 03 Jun 2002 10:00:00 +0000\r\n\r\nhello\r\n",
        policy=email.policy.default,
    )
    msg = _message_from_rfc822(raw, "t", "")
    assert msg.auth.spf == "pass"
    assert msg.auth.dmarc == "none"


# ------------------------------------------------------------ layout
def test_spamassassin_cmds_file_is_not_loaded_as_mail():
    d = realmail.tmpdir()
    root = realmail.spamassassin_dir(d, n=5)
    report = LoadReport()
    messages, _ = load_eml_dir(root, label=LABEL_HAM, report=report)
    assert len(messages) == 5
    assert report.read == 5


def test_nazario_files_without_an_extension_load_as_mbox():
    d = realmail.tmpdir()
    path = realmail.modern_phishing_mbox(d, n=4)
    assert path.suffix == ""
    messages, labels = load_any(f"{path}#phish")
    assert len(messages) == 4 and set(labels) == {LABEL_PHISH}


def test_undated_mail_gets_a_fixed_sentinel_not_the_current_time():
    raw = email.message_from_bytes(
        b"From: a@b.example\r\nSubject: hi\r\n\r\nbody\r\n", policy=email.policy.default
    )
    first = _message_from_rfc822(raw, "t", "")
    second = _message_from_rfc822(raw, "t", "")
    assert first.received_at == UNDATED == second.received_at


# ------------------------------------------------------------ labels
def test_uci_minus_one_means_phishing():
    convention, mapping = resolve_label_convention(["-1", "1", "1", "-1"])
    assert "uci" in convention
    assert mapping["-1"] == LABEL_PHISH and mapping["1"] == LABEL_HAM


def test_binary_one_means_phishing():
    _, mapping = resolve_label_convention(["0", "1", "0"])
    assert mapping["1"] == LABEL_PHISH and mapping["0"] == LABEL_HAM


def test_uci_csv_loads_with_the_right_polarity():
    d = realmail.tmpdir()
    path = realmail.csv_file(
        d,
        "uci.csv",
        [
            {"url": "http://phish-1.example/login", "Result": "-1"},
            {"url": "https://www.bank.example/", "Result": "1"},
            {"url": "http://phish-2.example/verify", "Result": "-1"},
        ],
    )
    report = LoadReport()
    messages, labels = load_csv(path, label_column="Result", report=report)
    assert labels == [LABEL_PHISH, LABEL_HAM, LABEL_PHISH]
    assert "uci" in report.label_convention


def test_named_labels_from_kaggle_style_csvs():
    d = realmail.tmpdir()
    path = realmail.csv_file(
        d,
        "named.csv",
        [
            {"Email Text": "Verify your account now", "Email Type": "Phishing Email"},
            {"Email Text": "Lunch on Friday?", "Email Type": "Safe Email"},
        ],
    )
    messages, labels = load_csv(path, label_column="Email Type")
    assert labels == [LABEL_PHISH, LABEL_HAM]


def test_spam_is_not_silently_relabelled_as_phishing():
    d = realmail.tmpdir()
    path = realmail.csv_file(
        d,
        "mixed.csv",
        [
            {"text": "Cheap watches!!!", "label": "spam"},
            {"text": "Verify your password", "label": "phishing"},
            {"text": "See you at 3", "label": "ham"},
        ],
    )
    report = LoadReport()
    _, labels = load_csv(path, report=report)
    assert labels == [LABEL_PHISH, LABEL_HAM]
    assert report.skipped_spam == 1
    _, labels_phish = load_csv(path, spam_as="phish")
    assert labels_phish == [LABEL_PHISH, LABEL_PHISH, LABEL_HAM]


def test_an_unknown_label_is_refused_not_defaulted_to_legitimate():
    d = realmail.tmpdir()
    path = realmail.csv_file(
        d,
        "odd.csv",
        [
            {"text": "Verify your password", "label": "phishing"},
            {"text": "Something", "label": "maybe?"},
        ],
    )
    report = LoadReport()
    _, labels = load_csv(path, report=report)
    assert labels == [LABEL_PHISH]
    assert report.skipped_unknown_label == 1
    assert report.unknown_label_values == {"maybe?": 1}


# ------------------------------------------------------------ the audit
def test_audit_flags_the_classic_era_confound():
    """Nazario-era phishing + Enron-era ham: separable by date alone.

    This is the confound most published results on these corpora never check
    for, and the audit must refuse the corpus rather than let it through.
    """
    from phishguard.data.verify import audit_corpus

    d = realmail.tmpdir()
    phish = realmail.modern_phishing_mbox(d, n=30, year=2023)
    ham = realmail.old_ham_maildir(d, n=30, year=2001)
    audit, _, _ = audit_corpus([f"{phish}#phish", f"{ham}#ham"])
    assert audit.verdict == "NOT READY"
    checks = {f.check for f in audit.findings if f.level == "fail"}
    assert "era mismatch" in checks
    assert any(c.startswith("confound: receipt year") for c in checks)
    # DMARC did not exist in 2001, so its presence predicts phishing perfectly.
    dmarc = next(r for r in audit.confounds if r["feature"] == "has a DMARC verdict")
    assert dmarc["auc"] >= 0.95


def test_audit_accepts_a_same_era_corpus():
    from phishguard.data.verify import audit_corpus

    d = realmail.tmpdir()
    phish = realmail.modern_phishing_mbox(d, n=30, year=2023)
    ham = realmail.modern_ham_maildir(d, n=30, year=2023)
    audit, _, _ = audit_corpus([f"{phish}#phish", f"{ham}#ham"])
    checks = {f.check for f in audit.findings if f.level == "fail"}
    assert "era mismatch" not in checks
    assert not any(c.startswith("confound: receipt year") for c in checks)


def test_audit_catches_the_same_message_under_both_labels():
    from phishguard.data.verify import audit_corpus

    d = realmail.tmpdir()
    phish = realmail.modern_phishing_mbox(d, n=10, year=2023)
    audit, _, _ = audit_corpus([f"{phish}#phish", f"{phish}#ham"])
    assert any(f.check == "label noise" and f.level == "fail" for f in audit.findings)


def test_audit_warns_that_public_corpora_have_no_behavioural_context():
    from phishguard.data.verify import audit_corpus

    d = realmail.tmpdir()
    audit, _, _ = audit_corpus(
        [
            f"{realmail.modern_phishing_mbox(d, n=12)}#phish",
            f"{realmail.modern_ham_maildir(d, n=12)}#ham",
        ]
    )
    assert audit.coverage["behavioural_context"] == 0
    assert any(f.check == "behavioural context" for f in audit.findings)
