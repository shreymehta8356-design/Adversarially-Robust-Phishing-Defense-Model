"""Email family - header, subject, body, HTML and attachment signals.

Split into four blocks so that each can be reasoned about, tested and ablated
on its own:

``header_features``      who the message claims to be from, and whether the
                         envelope agrees with the display name
``subject_features``     the lure, compressed into one line
``body_features``        social-engineering pressure, structure and obfuscation
``attachment_features``  payload delivery risk

All text signals are computed on the *canonicalized* string (defence
``D-NORM``) while the obfuscation deltas between raw and canonical text are
themselves kept as features -- so an attacker cannot get a cleaner feature
vector merely by making the message harder to read.
"""

from __future__ import annotations

import re

from phishguard.defenses.normalize import canonicalize, obfuscation_signals
from phishguard.features.lexicons import (
    ARCHIVE_EXTENSIONS,
    DISPOSABLE_DOMAINS,
    DOC_EXTENSIONS,
    EXEC_EXTENSIONS,
    FREEMAIL_DOMAINS,
    GENERIC_GREETING,
    LEXICONS,
    MACRO_EXTENSIONS,
    URGENCY_PHRASES,
    lexicon_counts,
    nearest_brand_lookalike,
    phrase_hits,
    tokenize,
)
from phishguard.features.urls import (
    BRAND_TOKENS,
    FREE_HOSTING_SUFFIXES,
    HIGH_RISK_TLDS,
    shannon_entropy,
    split_public_suffix,
)
from phishguard.schemas import Attachment, EmailMessage

_SENTENCE_RE = re.compile(r"[.!?]+")
_HTML_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b")
_HIDDEN_STYLE_RE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0"
    r"|width\s*:\s*0|height\s*:\s*0|color\s*:\s*#?f{3,6}\b)",
    re.I,
)
_INPUT_PASSWORD_RE = re.compile(r"<input[^>]*type\s*=\s*[\"']?password", re.I)
_HTML_ENTITY_RE = re.compile(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z]{2,8});")
_TAG_STRIP_RE = re.compile(r"<[^>]+>")
_CURRENCY_RE = re.compile(r"[$£€₹¥]|\b(?:usd|eur|gbp|inr|rs\.?|dollars?|rupees?|euros?)\b", re.I)
_NUM_RE = re.compile(r"\b\d[\d,]*(?:\.\d+)?\b")


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
HEADER_FEATURE_NAMES: tuple[str, ...] = (
    "hdr_has_sender", "hdr_display_name_present", "hdr_display_name_length",
    "hdr_display_has_brand", "hdr_display_brand_domain_mismatch",
    "hdr_display_contains_address", "hdr_display_address_mismatch",
    "hdr_replyto_present", "hdr_replyto_domain_mismatch",
    "hdr_returnpath_present", "hdr_returnpath_domain_mismatch",
    "hdr_sender_freemail", "hdr_sender_disposable",
    "hdr_sender_domain_length", "hdr_sender_domain_digits",
    "hdr_sender_domain_hyphens", "hdr_sender_domain_entropy",
    "hdr_sender_subdomain_depth", "hdr_sender_high_risk_tld",
    "hdr_sender_free_hosting", "hdr_sender_brand_token",
    "hdr_lookalike_distance", "hdr_is_lookalike",
    "hdr_local_length", "hdr_local_digit_ratio", "hdr_local_entropy",
    "hdr_local_is_noreply", "hdr_local_has_plus_tag",
    "hdr_spf_fail", "hdr_dkim_fail", "hdr_dmarc_fail", "hdr_auth_score",
    "hdr_received_hops", "hdr_recipient_count", "hdr_to_empty",
)


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(".") if "@" in (addr or "") else ""


def _auth_flag(value: str, failing: tuple[str, ...] = ("fail", "softfail")) -> float:
    return 1.0 if (value or "none").lower() in failing else 0.0


def header_features(msg: EmailMessage) -> dict[str, float]:
    """Envelope-consistency and sender-reputation signals."""
    display = canonicalize(msg.sender_display, aggressive=False)
    addr = msg.sender_address
    domain = msg.sender_domain
    sub, reg, suffix = split_public_suffix(domain)
    local = addr.split("@", 1)[0] if "@" in addr else ""

    display_tokens = set(re.split(r"[^a-z0-9]+", display.lower()))
    display_brands = display_tokens & BRAND_TOKENS
    reg_root = reg.split(".")[0] if reg else ""
    domain_brands = {b for b in BRAND_TOKENS if b and b in domain}

    # "PayPal Support <billing@secure-alerts.tk>" -> brand claimed, not owned.
    display_brand_mismatch = bool(display_brands) and not (display_brands & domain_brands)

    embedded_addr = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", msg.sender_display or "")
    display_addr_mismatch = 0.0
    if embedded_addr:
        display_addr_mismatch = (
            1.0 if _domain_of(embedded_addr.group(0).lower()) != domain else 0.0
        )

    reply_dom = _domain_of(msg.reply_to_address)
    ret_dom = _domain_of(msg.return_path_address)
    lookalike_domain, lookalike_dist = nearest_brand_lookalike(reg)

    auth = msg.auth
    spf_fail = _auth_flag(auth.spf)
    dkim_fail = _auth_flag(auth.dkim, ("fail",))
    dmarc_fail = _auth_flag(auth.dmarc, ("fail",))
    passes = sum(
        1.0
        for v in (auth.spf, auth.dkim, auth.dmarc)
        if (v or "none").lower() == "pass"
    )

    return {
        "hdr_has_sender": 1.0 if addr else 0.0,
        "hdr_display_name_present": 1.0 if display else 0.0,
        "hdr_display_name_length": float(len(display)),
        "hdr_display_has_brand": float(len(display_brands)),
        "hdr_display_brand_domain_mismatch": 1.0 if display_brand_mismatch else 0.0,
        "hdr_display_contains_address": 1.0 if embedded_addr else 0.0,
        "hdr_display_address_mismatch": display_addr_mismatch,
        "hdr_replyto_present": 1.0 if reply_dom else 0.0,
        "hdr_replyto_domain_mismatch": 1.0 if reply_dom and reply_dom != domain else 0.0,
        "hdr_returnpath_present": 1.0 if ret_dom else 0.0,
        "hdr_returnpath_domain_mismatch": 1.0 if ret_dom and ret_dom != domain else 0.0,
        "hdr_sender_freemail": 1.0 if domain in FREEMAIL_DOMAINS else 0.0,
        "hdr_sender_disposable": 1.0 if domain in DISPOSABLE_DOMAINS else 0.0,
        "hdr_sender_domain_length": float(len(domain)),
        "hdr_sender_domain_digits": float(sum(c.isdigit() for c in domain)),
        "hdr_sender_domain_hyphens": float(domain.count("-")),
        "hdr_sender_domain_entropy": shannon_entropy(reg_root),
        "hdr_sender_subdomain_depth": float(len([p for p in sub.split(".") if p])),
        "hdr_sender_high_risk_tld": (
            1.0 if suffix.rsplit(".", 1)[-1] in HIGH_RISK_TLDS else 0.0
        ),
        "hdr_sender_free_hosting": 1.0 if suffix in FREE_HOSTING_SUFFIXES else 0.0,
        "hdr_sender_brand_token": float(len(domain_brands)),
        "hdr_lookalike_distance": float(min(lookalike_dist, 9)),
        "hdr_is_lookalike": 1.0 if 0 < lookalike_dist <= 2 else 0.0,
        "hdr_local_length": float(len(local)),
        "hdr_local_digit_ratio": (
            sum(c.isdigit() for c in local) / len(local) if local else 0.0
        ),
        "hdr_local_entropy": shannon_entropy(local),
        "hdr_local_is_noreply": (
            1.0 if any(t in local for t in ("noreply", "no-reply", "donotreply")) else 0.0
        ),
        "hdr_local_has_plus_tag": 1.0 if "+" in local else 0.0,
        "hdr_spf_fail": spf_fail,
        "hdr_dkim_fail": dkim_fail,
        "hdr_dmarc_fail": dmarc_fail,
        "hdr_auth_score": passes / 3.0,
        "hdr_received_hops": float(msg.received_hops),
        "hdr_recipient_count": float(len(msg.to)),
        "hdr_to_empty": 1.0 if not msg.to else 0.0,
    }


# --------------------------------------------------------------------------
# Subject
# --------------------------------------------------------------------------
SUBJECT_FEATURE_NAMES: tuple[str, ...] = (
    "subj_length", "subj_word_count", "subj_upper_ratio", "subj_all_caps_words",
    "subj_exclamations", "subj_questions", "subj_digit_count",
    "subj_currency_symbols", "subj_non_ascii_ratio", "subj_reply_prefix",
    "subj_forward_prefix", "subj_bracket_tag", "subj_urgency_phrases",
    "subj_has_brand", "subj_emoji_count",
) + tuple(f"subj_lex_{name}" for name in LEXICONS)


_EMOJI_RE = re.compile(
    "[\U0001f300-\U0001faff\U00002600-\U000027bf\U0001f1e6-\U0001f1ff]"
)


def subject_features(msg: EmailMessage) -> dict[str, float]:
    raw = msg.subject or ""
    canon = canonicalize(raw)
    tokens = tokenize(canon)
    n = max(len(raw), 1)
    letters = [c for c in raw if c.isalpha()]
    counts = lexicon_counts(tokens)

    out = {
        "subj_length": float(len(raw)),
        "subj_word_count": float(len(tokens)),
        "subj_upper_ratio": (
            sum(c.isupper() for c in letters) / len(letters) if letters else 0.0
        ),
        "subj_all_caps_words": float(
            sum(1 for t in raw.split() if len(t) > 2 and t.isupper())
        ),
        "subj_exclamations": float(raw.count("!")),
        "subj_questions": float(raw.count("?")),
        "subj_digit_count": float(sum(c.isdigit() for c in raw)),
        "subj_currency_symbols": float(len(_CURRENCY_RE.findall(raw))),
        "subj_non_ascii_ratio": sum(1 for c in raw if ord(c) > 127) / n,
        "subj_reply_prefix": 1.0 if re.match(r"^\s*re\s*:", raw, re.I) else 0.0,
        "subj_forward_prefix": 1.0 if re.match(r"^\s*(fwd?|fw)\s*:", raw, re.I) else 0.0,
        "subj_bracket_tag": 1.0 if re.match(r"^\s*[\[(]", raw) else 0.0,
        "subj_urgency_phrases": float(phrase_hits(canon, URGENCY_PHRASES)),
        "subj_has_brand": float(len(set(tokens) & BRAND_TOKENS)),
        "subj_emoji_count": float(len(_EMOJI_RE.findall(raw))),
    }
    for name in LEXICONS:
        out[f"subj_lex_{name}"] = float(counts[name])
    return out


# --------------------------------------------------------------------------
# Body + HTML
# --------------------------------------------------------------------------
BODY_FEATURE_NAMES: tuple[str, ...] = (
    "body_length", "body_word_count", "body_unique_word_ratio",
    "body_avg_word_length", "body_sentence_count", "body_avg_sentence_length",
    "body_upper_ratio", "body_exclamation_density", "body_digit_ratio",
    "body_currency_mentions", "body_number_mentions", "body_non_ascii_ratio",
    "body_generic_greeting", "body_has_greeting", "body_urgency_phrases",
    "body_brand_mentions", "body_first_person_plural", "body_second_person",
    "body_imperative_starts", "body_signature_present", "body_unsubscribe_present",
    "body_phone_numbers", "body_email_addresses", "body_is_empty",
    "html_present", "html_tag_count", "html_tag_diversity", "html_text_ratio",
    "html_image_count", "html_image_only", "html_form_count",
    "html_password_input", "html_hidden_style_count", "html_script_count",
    "html_iframe_count", "html_entity_density", "html_anchor_count",
    "html_external_css",
) + tuple(f"body_lex_{name}" for name in LEXICONS) + (
    "obf_zero_width_count", "obf_bidi_count", "obf_confusable_ratio",
    "obf_diacritic_ratio", "obf_nonascii_ratio", "obf_separated_tokens",
    "obf_leet_tokens", "obf_norm_edit_ratio", "obf_mixed_script_words",
)


def body_features(msg: EmailMessage) -> dict[str, float]:
    raw_body = msg.body or ""
    html = msg.html_body or ""
    combined_raw = f"{msg.subject}\n{raw_body}"
    canon = canonicalize(combined_raw)
    tokens = tokenize(canon)
    counts = lexicon_counts(tokens)

    n_chars = max(len(raw_body), 1)
    n_tokens = max(len(tokens), 1)
    letters = [c for c in raw_body if c.isalpha()]
    sentences = [s for s in _SENTENCE_RE.split(raw_body) if s.strip()]
    lower_canon = canon.lower()

    text_only = _TAG_STRIP_RE.sub(" ", html) if html else ""
    tags = _HTML_TAG_RE.findall(html) if html else []
    tag_names = [t.lower() for t in tags]

    out: dict[str, float] = {
        "body_length": float(len(raw_body)),
        "body_word_count": float(len(tokens)),
        "body_unique_word_ratio": len(set(tokens)) / n_tokens,
        "body_avg_word_length": sum(len(t) for t in tokens) / n_tokens,
        "body_sentence_count": float(len(sentences)),
        "body_avg_sentence_length": (
            sum(len(s.split()) for s in sentences) / len(sentences) if sentences else 0.0
        ),
        "body_upper_ratio": (
            sum(c.isupper() for c in letters) / len(letters) if letters else 0.0
        ),
        "body_exclamation_density": raw_body.count("!") / n_chars * 100.0,
        "body_digit_ratio": sum(c.isdigit() for c in raw_body) / n_chars,
        "body_currency_mentions": float(len(_CURRENCY_RE.findall(raw_body))),
        "body_number_mentions": float(len(_NUM_RE.findall(raw_body))),
        "body_non_ascii_ratio": sum(1 for c in raw_body if ord(c) > 127) / n_chars,
        "body_generic_greeting": float(
            sum(1 for g in GENERIC_GREETING if g in lower_canon)
        ),
        "body_has_greeting": (
            1.0
            if re.match(r"^\s*(dear|hello|hi|greetings|good\s+(morning|afternoon|evening))",
                        raw_body, re.I)
            else 0.0
        ),
        "body_urgency_phrases": float(phrase_hits(canon, URGENCY_PHRASES)),
        "body_brand_mentions": float(len(set(tokens) & BRAND_TOKENS)),
        "body_first_person_plural": float(
            sum(1 for t in tokens if t in {"we", "our", "us", "ours"})
        ),
        "body_second_person": float(
            sum(1 for t in tokens if t in {"you", "your", "yours", "yourself"})
        ),
        "body_imperative_starts": float(
            sum(
                1
                for line in raw_body.splitlines()
                if re.match(
                    r"^\s*(click|verify|confirm|update|download|call|reply|login|"
                    r"sign|open|submit|act|do not|don't)\b",
                    line, re.I,
                )
            )
        ),
        "body_signature_present": (
            1.0
            if re.search(r"(regards|sincerely|thanks|best wishes|yours truly)",
                         raw_body, re.I)
            else 0.0
        ),
        "body_unsubscribe_present": (
            1.0 if re.search(r"unsubscribe|opt.?out|manage preferences", raw_body, re.I) else 0.0
        ),
        "body_phone_numbers": float(
            len(re.findall(r"(?:\+\d{1,3}[\s-]?)?(?:\d[\s-]?){8,13}\d", raw_body))
        ),
        "body_email_addresses": float(len(re.findall(r"[\w.\-+]+@[\w.\-]+\.\w+", raw_body))),
        "body_is_empty": 1.0 if not raw_body.strip() else 0.0,
        "html_present": 1.0 if html.strip() else 0.0,
        "html_tag_count": float(len(tags)),
        "html_tag_diversity": float(len(set(tag_names))),
        "html_text_ratio": (
            len(text_only.strip()) / max(len(html), 1) if html else 0.0
        ),
        "html_image_count": float(tag_names.count("img")),
        "html_image_only": (
            1.0 if html and tag_names.count("img") >= 1 and len(text_only.split()) < 15 else 0.0
        ),
        "html_form_count": float(tag_names.count("form")),
        "html_password_input": 1.0 if _INPUT_PASSWORD_RE.search(html) else 0.0,
        "html_hidden_style_count": float(len(_HIDDEN_STYLE_RE.findall(html))),
        "html_script_count": float(tag_names.count("script")),
        "html_iframe_count": float(tag_names.count("iframe")),
        "html_entity_density": (
            len(_HTML_ENTITY_RE.findall(html)) / max(len(html), 1) * 100.0 if html else 0.0
        ),
        "html_anchor_count": float(tag_names.count("a")),
        "html_external_css": float(len(re.findall(r"<link[^>]+stylesheet", html, re.I))),
    }
    for name in LEXICONS:
        out[f"body_lex_{name}"] = float(counts[name])
    out.update(obfuscation_signals(combined_raw))
    return out


# --------------------------------------------------------------------------
# Attachments
# --------------------------------------------------------------------------
ATTACHMENT_FEATURE_NAMES: tuple[str, ...] = (
    "att_count", "att_total_bytes", "att_max_bytes", "att_executable",
    "att_macro_enabled", "att_archive", "att_document", "att_double_extension",
    "att_extension_mismatch", "att_name_max_length", "att_rtl_override",
    "att_unknown_type",
)


def attachment_features(attachments: list[Attachment]) -> dict[str, float]:
    out = dict.fromkeys(ATTACHMENT_FEATURE_NAMES, 0.0)
    if not attachments:
        return out

    sizes = [max(a.size_bytes, 0) for a in attachments]
    out["att_count"] = float(len(attachments))
    out["att_total_bytes"] = float(sum(sizes))
    out["att_max_bytes"] = float(max(sizes) if sizes else 0)

    for a in attachments:
        ext = a.extension
        name = (a.filename or "").lower()
        if ext in EXEC_EXTENSIONS:
            out["att_executable"] += 1.0
        elif ext in MACRO_EXTENSIONS:
            out["att_macro_enabled"] += 1.0
        elif ext in ARCHIVE_EXTENSIONS:
            out["att_archive"] += 1.0
        elif ext in DOC_EXTENSIONS:
            out["att_document"] += 1.0
        else:
            out["att_unknown_type"] += 1.0
        # "invoice.pdf.exe" - classic double extension
        parts = name.split(".")
        if len(parts) >= 3 and parts[-2] in (DOC_EXTENSIONS | ARCHIVE_EXTENSIONS):
            out["att_double_extension"] += 1.0
        # Declared MIME does not match the extension.
        ct = (a.content_type or "").lower()
        if ct and ext:
            if ext == "pdf" and "pdf" not in ct:
                out["att_extension_mismatch"] += 1.0
            elif ext in {"zip", "rar", "7z"} and not any(
                k in ct for k in ("zip", "compressed", "octet", "rar", "7z")
            ):
                out["att_extension_mismatch"] += 1.0
        out["att_name_max_length"] = max(out["att_name_max_length"], float(len(name)))
        if any(c in name for c in "‮‭‫‪"):
            out["att_rtl_override"] += 1.0
    return out


#: Full ordered name list for the email family.
EMAIL_FEATURE_NAMES: tuple[str, ...] = (
    HEADER_FEATURE_NAMES + SUBJECT_FEATURE_NAMES + BODY_FEATURE_NAMES
    + ATTACHMENT_FEATURE_NAMES
)


def email_features(msg: EmailMessage) -> dict[str, float]:
    """All email-family features for one message."""
    out: dict[str, float] = {}
    out.update(header_features(msg))
    out.update(subject_features(msg))
    out.update(body_features(msg))
    out.update(attachment_features(msg.attachments))
    return out
