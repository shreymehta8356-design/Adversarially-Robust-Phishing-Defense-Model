"""Adversarial transforms and the validity constraints that keep them honest."""

from __future__ import annotations

import numpy as np

from phishguard.adversarial.taxonomy import ATTACK_FAMILIES, OUT_OF_SCOPE
from phishguard.adversarial.transforms import (
    TRANSFORM_BY_ID,
    TRANSFORMS,
    payload_preserved,
    random_perturbation,
    transforms_for,
)
from phishguard.features.urls import canonicalize_url, extract_links, parse_url
from tests.helpers import phishing_message

RNG = np.random.default_rng(11)


def test_every_transform_has_a_known_family():
    families = {f.id for f in ATTACK_FAMILIES}
    for t in TRANSFORMS:
        assert t.family in families, t.id
    assert len(TRANSFORM_BY_ID) == len(TRANSFORMS), "duplicate transform ids"


def test_every_family_has_at_least_one_transform():
    covered = {t.family for t in TRANSFORMS}
    assert covered == {f.id for f in ATTACK_FAMILIES}


def test_no_transform_raises_on_a_realistic_message():
    msg = phishing_message()
    for t in TRANSFORMS:
        t.fn(msg, RNG)  # must return a message or None, never raise


def test_transforms_do_not_mutate_the_original_message():
    msg = phishing_message()
    before = (msg.subject, msg.body, msg.html_body, msg.sender, msg.behavioral.hour_local)
    for t in TRANSFORMS:
        t.fn(msg, RNG)
    after = (msg.subject, msg.body, msg.html_body, msg.sender, msg.behavioral.hour_local)
    assert before == after


def test_valid_perturbations_keep_the_victim_reachable():
    """An 'attack' that deletes the payload is a broken email, not an evasion.

    "Reachable" is not the same as "has a URL". The A-CHANNEL family moves the
    payload off email entirely -- a number to dial, a code to scan -- which is
    a real and effective attack precisely because no URL survives it. The
    invariant is that *some* route to the attacker remains, so the check is
    for a link or an out-of-band carrier, not for a link alone.
    """
    import re

    out_of_band = re.compile(r"(\+?\d[\d ()\-]{7,}\d)|(\[QR code image\])|(cid:qr-)", re.I)
    msg = phishing_message()
    for t in TRANSFORMS:
        candidate = t.fn(msg, RNG)
        if candidate is None or not payload_preserved(msg, candidate):
            continue
        links = extract_links(candidate.body, candidate.html_body)
        carrier = out_of_band.search(f"{candidate.body} {candidate.html_body}")
        assert links or carrier, f"{t.id} produced a valid candidate the victim cannot act on"


def test_payload_check_rejects_a_message_with_the_link_removed():
    msg = phishing_message()
    gutted = msg.copy(body="Hello.", html_body="")
    assert not payload_preserved(msg, gutted)


def test_payload_check_rejects_an_emptied_message():
    msg = phishing_message()
    assert not payload_preserved(msg, msg.copy(body="", html_body="", subject=""))


def test_payload_check_accepts_shortener_wrapping():
    """The victim still lands on the page, so this is a real evasion."""
    msg = phishing_message()
    wrapped = TRANSFORM_BY_ID["A-URL-01"].fn(msg, RNG)
    assert wrapped is not None
    assert payload_preserved(msg, wrapped)


def test_payload_check_accepts_the_text_as_image_attack():
    """It empties the text part while keeping the lure fully intact in HTML."""
    msg = phishing_message()
    imaged = TRANSFORM_BY_ID["A-STR-03"].fn(msg, RNG)
    assert imaged is not None
    assert payload_preserved(msg, imaged)


def test_open_redirect_preserves_the_destination():
    msg = phishing_message()
    original_hosts = {
        parse_url(canonicalize_url(h)).registered_domain
        for h, _ in extract_links(msg.body, msg.html_body)
    }
    redirected = TRANSFORM_BY_ID["A-URL-02"].fn(msg, RNG)
    assert redirected is not None
    new_hosts = {
        parse_url(canonicalize_url(h)).registered_domain
        for h, _ in extract_links(redirected.body, redirected.html_body)
    }
    assert original_hosts & new_hosts, "canonicalization should recover the target"


def test_behavioral_transforms_touch_only_attacker_controlled_state():
    """The attacker cannot fabricate the victim's correspondence history."""
    msg = phishing_message(
        behavioral=phishing_message().behavioral.__class__(
            available=True,
            prior_messages_from_sender=17,
            prior_replies_to_sender=9,
            domain_age_days=1200,
            domain_report_count=4,
            hour_local=3,
            burst_count_1h=300,
            recipient_count=90,
            display_name_alias_count=7,
        )
    )
    for t in transforms_for(("A-BEH",)):
        candidate = t.fn(msg, RNG)
        if candidate is None:
            continue
        b = candidate.behavioral
        assert b.prior_messages_from_sender == 17, t.id
        assert b.prior_replies_to_sender == 9, t.id
        assert b.domain_age_days == 1200, t.id
        assert b.domain_report_count == 4, t.id


def test_header_transforms_cannot_move_to_the_brands_real_domain():
    """Sending from paypal.com is domain compromise - out of scope, not an attack."""
    msg = phishing_message()
    for t in transforms_for(("A-HDR",)):
        candidate = t.fn(msg, RNG)
        if candidate is None:
            continue
        assert candidate.sender_domain == msg.sender_domain, t.id


def test_lexical_transforms_change_the_text():
    msg = phishing_message()
    for tid in ("A-LEX-01", "A-LEX-04", "A-UNI-01", "A-UNI-02"):
        candidate = TRANSFORM_BY_ID[tid].fn(msg, RNG)
        assert candidate is not None, tid
        assert candidate.text != msg.text, tid


def test_normalization_undoes_the_unicode_family():
    """D-NORM exists precisely to collapse A-UNI back onto the canonical form."""
    from phishguard.defenses.normalize import canonicalize

    msg = phishing_message()
    for tid in ("A-UNI-01", "A-UNI-02", "A-UNI-05"):
        attacked = TRANSFORM_BY_ID[tid].fn(msg, RNG)
        assert attacked is not None
        original = canonicalize(msg.body)
        recovered = canonicalize(attacked.body)
        # Not necessarily identical, but far closer than the raw forms.
        assert _similarity(recovered, original) > _similarity(attacked.body, msg.body)


def _similarity(a: str, b: str) -> float:
    sa, sb = set(a.lower().split()), set(b.lower().split())
    return len(sa & sb) / max(len(sa | sb), 1)


def test_random_perturbation_returns_a_valid_message():
    msg = phishing_message()
    for seed in range(6):
        out = random_perturbation(msg, np.random.default_rng(seed))
        assert payload_preserved(msg, out)


def test_out_of_scope_threats_are_documented():
    assert len(OUT_OF_SCOPE) >= 3
    for entry in OUT_OF_SCOPE:
        assert entry["threat"] and entry["why"] and entry["mitigation_elsewhere"]


# ------------------------------------------- A-TRUST and A-CHANNEL families
def test_relocation_transforms_keep_the_attack_valid():
    """Re-hosting is a real attacker move, not a degenerate one.

    ``payload_preserved`` normally requires the original destination host to
    survive, which stops "delete the link" being scored as an evasion. Payload
    relocation deliberately changes the host: the victim still lands on a page
    the attacker controls, it just sits on infrastructure with genuine
    reputation. If the validity rule rejected this, the dominant
    credential-phishing pattern of recent years would be excluded from the
    robustness measurement.
    """
    import numpy as np

    from phishguard.adversarial.transforms import apply_transform, payload_preserved
    from tests.helpers import phishing_message

    rng = np.random.default_rng(11)
    base = phishing_message()
    for tid in ("A-TRUST-01", "A-TRUST-02", "A-TRUST-03"):
        out = apply_transform(tid, base, rng)
        assert out is not None, tid
        assert payload_preserved(base, out), tid


def test_out_of_band_transforms_remove_every_url_but_stay_valid():
    import numpy as np

    from phishguard.adversarial.transforms import apply_transform, payload_preserved
    from phishguard.features.urls import extract_links
    from tests.helpers import phishing_message

    rng = np.random.default_rng(12)
    base = phishing_message()
    for tid in ("A-CHAN-01", "A-CHAN-02"):
        out = apply_transform(tid, base, rng)
        assert out is not None, tid
        assert not extract_links(out.body, out.html_body), (
            f"{tid} must leave no extractable URL - that is the whole point"
        )
        assert payload_preserved(base, out), tid


def test_emptying_the_body_is_still_not_a_valid_attack():
    """The relocation carve-outs must not open a hole in the validity rule."""
    from phishguard.adversarial.transforms import payload_preserved
    from tests.helpers import phishing_message

    base = phishing_message()
    assert not payload_preserved(base, base.copy(body="", html_body=""))
    assert not payload_preserved(base, base.copy(body="ok", html_body=""))


def test_every_transform_has_its_own_implementation():
    """Regression: a second function defined with the same name silently
    replaced the first, so A-URL-02 ran A-TRUST-02's code and the query-string
    redirect was never tested. Found by static analysis (ruff F811)."""
    from phishguard.adversarial.transforms import TRANSFORMS

    by_fn: dict[object, list[str]] = {}
    for t in TRANSFORMS:
        by_fn.setdefault(t.fn, []).append(t.id)
    shared = {ids[0]: ids for ids in by_fn.values() if len(ids) > 1}
    assert not shared, f"transforms sharing one implementation: {shared}"


def test_open_redirect_chaining_carries_the_target_in_a_query_parameter():
    from urllib.parse import parse_qs, urlparse

    from phishguard.features.urls import extract_links

    msg = phishing_message()
    out = TRANSFORM_BY_ID["A-URL-02"].fn(msg, RNG)
    assert out is not None
    hrefs = [h for h, _ in extract_links(out.body, out.html_body)]
    assert any("url" in parse_qs(urlparse(h).query) for h in hrefs), hrefs
