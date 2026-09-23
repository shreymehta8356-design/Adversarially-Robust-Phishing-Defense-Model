"""Dataset versions: stable where they should be, sensitive where they must be."""

from __future__ import annotations

from dataclasses import replace

from phishguard.data.fingerprint import dataset_fingerprint


def test_the_same_corpus_has_the_same_version_whatever_its_order():
    from phishguard.data.synthetic import generate_corpus

    messages, labels = generate_corpus(300, seed=5)
    a = dataset_fingerprint(messages, labels)
    reversed_pairs = list(zip(messages, labels, strict=True))[::-1]
    b = dataset_fingerprint([m for m, _ in reversed_pairs], [y for _, y in reversed_pairs])
    again, again_y = generate_corpus(300, seed=5)  # regenerated from the recipe
    assert a == b == dataset_fingerprint(again, again_y)
    assert len(a["sha256"]) == 64 and a["version"] == a["sha256"][:12]
    assert a["n"] == 300 and a["n_phishing"] == sum(labels)


def test_one_flipped_label_or_one_edited_body_changes_the_version():
    from phishguard.data.synthetic import generate_corpus

    messages, labels = generate_corpus(120, seed=6)
    base = dataset_fingerprint(messages, labels)["sha256"]
    flipped = list(labels)
    flipped[7] = 1 - flipped[7]
    assert dataset_fingerprint(messages, flipped)["sha256"] != base
    edited = list(messages)
    edited[3] = replace(edited[3], body=edited[3].body + " ")
    assert dataset_fingerprint(edited, labels)["sha256"] != base


def test_a_fingerprint_contains_no_message_text():
    from tests.helpers import phishing_message

    msg = phishing_message(subject="Payroll for Anita Desai")
    fp = dataset_fingerprint([msg], [1])
    assert "Anita" not in str(fp) and "Payroll" not in str(fp)
