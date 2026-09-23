"""Analyst evidence cards.

Feature names are for the model; analysts need sentences. This module turns
attributions into an ordered list of evidence items an analyst can act on
without knowing anything about the model, which is what makes the human-
oversight requirement real rather than decorative.

Each item carries:

``kind``       rule | feature | member | token | defense | context
``title``      one line, plain English
``detail``     the specific value that triggered it
``direction``  ``phishing`` or ``legitimate`` - mitigating evidence is shown
               too, because a reviewer needs to see both sides
``weight``     comparable magnitude for ordering
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from phishguard.defenses.normalize import canonicalize
from phishguard.explain.attributions import (
    disagreement,
    engineered_attributions,
    fusion_attributions,
)
from phishguard.features.urls import canonicalize_url, extract_links, parse_url
from phishguard.models.baseline import RuleBaseline
from phishguard.models.members import EngineeredMember, TextMember
from phishguard.schemas import EmailMessage

if TYPE_CHECKING:  # pragma: no cover
    from phishguard.models.detector import PhishGuardDetector

#: Templates keyed by feature name. ``{v}`` is the observed value.
_FEATURE_PHRASES: dict[str, str] = {
    "hdr_display_brand_domain_mismatch": "Display name claims a brand the sending domain does not own",
    "hdr_is_lookalike": "Sending domain is a near-miss imitation of a well-known domain",
    "hdr_lookalike_distance": "Sending domain is {v} character edits from a well-known domain",
    "hdr_replyto_domain_mismatch": "Replies would go to a different domain than the sender",
    "hdr_returnpath_domain_mismatch": "Envelope sender does not match the From header",
    "hdr_spf_fail": "SPF check failed",
    "hdr_dmarc_fail": "DMARC check failed",
    "hdr_dkim_fail": "DKIM signature did not verify",
    "hdr_auth_score": "{v} of the three authentication checks passed",
    "hdr_sender_high_risk_tld": "Sending domain uses a top-level domain with high abuse rates",
    "hdr_sender_disposable": "Sending domain is a disposable mail provider",
    "hdr_sender_freemail": "Sent from a free consumer mail provider",
    "hdr_sender_free_hosting": "Sending domain is on free hosting infrastructure",
    "hdr_local_is_noreply": "Sent from a no-reply style mailbox",
    "link_any_brand_impersonation": "A link impersonates a brand it does not belong to",
    "link_any_brand_squat": "A link's domain contains a brand name it does not own",
    "link_any_brand_lookalike": "A link's domain is a typosquat of a real brand domain",
    "link_text_shows_url_mismatch": "A link's visible text points somewhere other than its destination",
    "link_text_href_mismatch": "Link text names a brand the destination does not belong to",
    "link_any_ip_host": "A link points at a bare IP address instead of a hostname",
    "link_any_shortener": "A link is hidden behind a URL shortener",
    "link_any_free_hosting": "A link is hosted on free, anonymous infrastructure",
    "link_any_redirect_param": "A link redirects through another site",
    "link_any_punycode": "A link uses an internationalised domain that can imitate ASCII",
    "link_count": "Message contains {v} link(s)",
    "link_unique_domains": "Links point at {v} distinct domains",
    "url_high_risk_tld__max": "A link uses a high-abuse top-level domain",
    "url_num_subdomains__max": "A link's host is padded with {v} subdomain levels",
    "url_suspicious_token_count__max": "A link's path contains {v} credential-page keyword(s)",
    "url_host_entropy__max": "A link's hostname looks machine-generated",
    "link_official_brand_ratio": "Links point at genuine brand domains",
    "body_lex_credential": "Body asks for credentials ({v} references)",
    "body_lex_threat": "Body threatens consequences ({v} references)",
    "body_lex_urgency": "Body applies time pressure ({v} references)",
    "body_lex_financial": "Body concerns money or payment ({v} references)",
    "body_lex_reward": "Body offers a reward or prize ({v} references)",
    "body_lex_authority": "Body invokes authority ({v} references)",
    "body_lex_secrecy": "Body asks for secrecy ({v} references)",
    "body_urgency_phrases": "Body uses {v} explicit deadline phrase(s)",
    "body_generic_greeting": "Generic greeting rather than the recipient's name",
    "body_imperative_starts": "{v} line(s) start with a direct instruction",
    "body_unsubscribe_present": "Message carries an unsubscribe footer",
    "body_signature_present": "Message has a conventional sign-off",
    "subj_urgency_phrases": "Subject applies time pressure",
    "subj_all_caps_words": "Subject shouts in capitals ({v} words)",
    "subj_exclamations": "Subject uses {v} exclamation mark(s)",
    "html_password_input": "HTML contains a password entry field",
    "html_form_count": "HTML contains {v} form(s)",
    "html_hidden_style_count": "HTML contains {v} hidden or zero-size element(s)",
    "html_image_only": "Message body is an image with almost no text",
    "html_entity_density": "HTML uses an unusual density of character entities",
    "att_executable": "{v} executable attachment(s)",
    "att_macro_enabled": "{v} macro-enabled document attachment(s)",
    "att_double_extension": "{v} attachment(s) use a double extension",
    "att_archive": "{v} archive attachment(s)",
    "obf_zero_width_count": "Text contains {v} invisible character(s)",
    "obf_mixed_script_words": "{v} word(s) mix character scripts (homoglyph obfuscation)",
    "obf_confusable_ratio": "Text contains look-alike characters from other alphabets",
    "obf_leet_tokens": "{v} word(s) use digit-for-letter substitution",
    "obf_separated_tokens": "{v} word(s) are split with punctuation or spaces",
    "obf_norm_edit_ratio": "Text changed substantially under normalisation",
    "beh_sender_first_seen": "First message ever received from this sender",
    "beh_relationship_strength": "Established correspondence history with this sender",
    "beh_prior_messages": "{v} previous message(s) from this sender",
    "beh_young_domain": "Sending domain was registered recently",
    "beh_domain_age_days": "Sending domain is {v} days old",
    "beh_off_hours": "Received outside normal working hours",
    "beh_campaign_shape": "Arrived as part of a burst from an unfamiliar sender",
    "beh_burst_count_1h": "{v} message(s) from this domain in the last hour",
    "beh_display_name_reuse": "This display name has been used by several different addresses",
    "beh_domain_reported": "Users have previously reported this sending domain",
    "beh_mass_mailing": "Sent to a large recipient list",
    "beh_trust_deficit": "Overall unearned-trust score {v}",
    "beh_cold_contact_with_ask": "An unknown sender is making a request",
    "beh_young_domain_and_ask": "A newly registered domain is making a request",
    "beh_context_available": "Sender history was available for this assessment",
}

_TOKEN_CLEAN = re.compile(r"\s+")
_WORD = re.compile(r"[\w@./-]+")


def _readable_terms(tokens: list[str], member: TextMember, message: EmailMessage) -> list[str]:
    """What an analyst can read: words and phrases, not character fragments.

    The character model scores 3-5 character fragments of the canonical text,
    such as "ypa"; shown raw they explain nothing. Each fragment is replaced by
    the word it came from ("paypal"), and repeats are dropped.
    """
    cleaned = [_TOKEN_CLEAN.sub(" ", t).strip() for t in tokens]
    if member.analyzer == "word":
        return [t for t in cleaned if t]
    words = _WORD.findall(canonicalize(message.text))
    out: list[str] = []
    for fragment in cleaned:
        word = next((w for w in words if fragment and fragment in w), fragment)
        if word and word not in out:
            out.append(word)
    return out


def humanize_feature(name: str, value: float) -> str:
    """Plain-English description of one feature observation."""
    template = _FEATURE_PHRASES.get(name)
    if template is None:
        pretty = name.replace("__max", " (worst link)").replace("__mean", " (average link)")
        pretty = pretty.replace("hdr_", "header: ").replace("body_", "body: ")
        pretty = pretty.replace("subj_", "subject: ").replace("html_", "HTML: ")
        pretty = pretty.replace("att_", "attachment: ").replace("beh_", "behaviour: ")
        pretty = pretty.replace("url_", "link: ").replace("link_", "link: ")
        pretty = pretty.replace("obf_", "obfuscation: ").replace("_", " ")
        return f"{pretty} = {value:g}"
    formatted = f"{value:g}" if value != int(value) else f"{int(value)}"
    return template.replace("{v}", formatted)


def build_evidence(
    detector: PhishGuardDetector,
    message: EmailMessage,
    score: float,
    member_scores: dict[str, float],
    *,
    max_items: int = 12,
) -> list[dict[str, Any]]:
    """Assemble the ordered evidence list shown to the analyst."""
    items: list[dict[str, Any]] = []

    # --- destination summary: the single thing an analyst checks first ---
    links = extract_links(message.body, message.html_body)
    if links:
        first = canonicalize_url(links[0][0])
        parsed = parse_url(first)
        items.append(
            {
                "kind": "context",
                "id": "destination",
                "title": f"Primary link resolves to {parsed.registered_domain or parsed.host}",
                "detail": first[:200],
                "direction": "neutral",
                "weight": 0.0,
            }
        )

    # --- rule checklist (transparent, always available) ---
    rules = detector.members.get("rules")
    if isinstance(rules, RuleBaseline):
        _, fired = rules.explain_one(message)
        for rule in fired[:6]:
            items.append(
                {
                    "kind": "rule",
                    "id": rule["id"],
                    "title": rule["description"],
                    "detail": f"{rule['feature']} = {rule['value']:g}",
                    "direction": "phishing" if rule["weight"] > 0 else "legitimate",
                    "weight": round(abs(float(rule["weight"])) / 2.0, 4),
                }
            )

    # --- engineered feature counterfactuals ---
    engineered = detector.members.get("engineered")
    if isinstance(engineered, EngineeredMember) and engineered.fitted:
        fv = engineered.assembler.extract(message)
        for attr in engineered_attributions(engineered, fv, top_k=6):
            items.append(
                {
                    "kind": "feature",
                    "id": attr["feature"],
                    "title": humanize_feature(attr["feature"], attr["value"]),
                    "detail": (
                        f"score would change by {-attr['contribution']:+.3f} if this were normal"
                    ),
                    "direction": attr["direction"],
                    "weight": round(abs(float(attr["contribution"])), 4),
                }
            )

    # --- text evidence ---
    # The word model first: its terms are readable as they are. The character
    # model is the fallback, with its fragments mapped back to whole words.
    for name in ("wordtfidf", "charngram"):
        member = detector.members.get(name)
        if isinstance(member, TextMember) and member.fitted:
            tokens = member.token_contributions(message, top_k=4)
            phrase = [t["token"] for t in tokens if t["contribution"] > 0 and len(t["token"]) > 2][
                :4
            ]
            if phrase:
                items.append(
                    {
                        "kind": "token",
                        "id": name,
                        "title": "Wording most associated with phishing in this message",
                        "detail": ", ".join(_readable_terms(phrase, member, message)),
                        "direction": "phishing",
                        "weight": round(
                            min(
                                sum(t["contribution"] for t in tokens if t["contribution"] > 0), 1.0
                            ),
                            4,
                        ),
                    }
                )
            break

    # --- ensemble agreement ---
    if detector.fusion is not None and len(member_scores) > 1:
        spread = disagreement(member_scores)
        top_members = fusion_attributions(
            detector.member_names,
            detector.fusion.coef_[0],
            member_scores,
            float(detector.fusion.intercept_[0]),
        )[:2]
        items.append(
            {
                "kind": "member",
                "id": "ensemble",
                "title": (
                    "Detection views disagree - possible evasion attempt"
                    if spread > 0.25
                    else "Detection views agree"
                ),
                "detail": "; ".join(
                    f"{m['member']}={m['score']:.2f}"
                    for m in top_members
                    if m["member"] != "(intercept)"
                ),
                "direction": "phishing" if spread > 0.25 else "neutral",
                "weight": round(float(spread), 4),
            }
        )

    # --- missing context is itself evidence ---
    if not message.behavioral.available:
        items.append(
            {
                "kind": "context",
                "id": "no_behavioral_context",
                "title": "No sender history was supplied with this message",
                "detail": (
                    "Assessment used email and URL evidence only; behavioural signals "
                    "were unavailable, which widens the uncertainty on this verdict."
                ),
                "direction": "neutral",
                "weight": 0.0,
            }
        )

    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in sorted(items, key=lambda d: -float(d["weight"])):
        key = (item["kind"], str(item["id"]))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    # Context items carry zero weight by design - "no sender history was
    # supplied", "the link resolves to X" - so ranking by weight alone would
    # push exactly the caveats an analyst most needs off the end of the list.
    # They are pinned, and the remaining slots go to the strongest evidence.
    context = [i for i in deduped if i["kind"] == "context"]
    scored = [i for i in deduped if i["kind"] != "context"]
    keep = max(max_items - len(context), 1)
    return context + scored[:keep]
