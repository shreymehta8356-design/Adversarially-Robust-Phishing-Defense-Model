"""Behavioral family - relationship, timing and campaign-shape signals.

These are the features a mail gateway can compute but a static corpus cannot:
whether this sender has ever written to this recipient before, whether the
message arrived at 03:12 on a Sunday, whether the same display name has been
seen behind four different addresses this week.

Why this family matters for *robustness*
----------------------------------------
Text and URL features live in the space an attacker directly controls: they can
rewrite the sentence and re-register the domain. Behavioral features live in a
space the attacker only partially controls -- forging "we have exchanged 40
emails over 2 years" requires actually having done so. That asymmetry is why
the fusion model degrades far more gracefully under attack than a text-only
classifier, and the ablation study in the evaluation dossier quantifies it.

Every feature has a defined value when context is absent, and
``beh_context_available`` tells the model whether to trust the rest of the
block -- the model learns "no context" as its own regime instead of being fed
misleading zeros.
"""

from __future__ import annotations

import math

from phishguard.schemas import BehavioralContext, EmailMessage

BEHAVIORAL_FEATURE_NAMES: tuple[str, ...] = (
    "beh_context_available",
    "beh_sender_first_seen",
    "beh_prior_messages",
    "beh_prior_messages_log",
    "beh_prior_replies",
    "beh_reply_ratio",
    "beh_relationship_strength",
    "beh_thread_depth",
    "beh_is_new_thread",
    "beh_cold_contact_with_ask",
    "beh_hour_local",
    "beh_off_hours",
    "beh_is_weekend",
    "beh_odd_hour_and_urgent",
    "beh_recipient_count",
    "beh_bcc_count",
    "beh_bcc_ratio",
    "beh_mass_mailing",
    "beh_external_sender",
    "beh_external_and_financial",
    "beh_domain_report_count",
    "beh_domain_reported",
    "beh_domain_click_rate",
    "beh_burst_count_1h",
    "beh_burst_log",
    "beh_campaign_shape",
    "beh_display_name_alias_count",
    "beh_display_name_reuse",
    "beh_domain_age_days",
    "beh_domain_age_log",
    "beh_young_domain",
    "beh_young_domain_and_ask",
    "beh_trust_deficit",
)

#: Outside 07:00-21:00 local is "off hours" for a normal business recipient.
_BUSINESS_START, _BUSINESS_END = 7, 21
#: A domain younger than this is effectively disposable infrastructure.
_YOUNG_DOMAIN_DAYS = 90


def behavioral_features(
    msg: EmailMessage,
    ctx: BehavioralContext | None = None,
    *,
    email_signals: dict[str, float] | None = None,
) -> dict[str, float]:
    """Compute the behavioral block.

    ``email_signals`` lets a few cross-family interaction terms be built (an
    off-hours message is unremarkable; an off-hours message from a two-week-old
    domain asking for credentials is not). Passing it is optional so the family
    stays independently testable.
    """
    ctx = ctx or msg.behavioral
    sig = email_signals or {}

    prior = max(int(ctx.prior_messages_from_sender), 0)
    replies = max(int(ctx.prior_replies_to_sender), 0)
    reply_ratio = replies / prior if prior else 0.0

    # Relationship strength: saturating function of two-way history. One prior
    # message is weak evidence; forty with replies is strong.
    relationship = (
        (1.0 - math.exp(-prior / 8.0)) * 0.6 + min(reply_ratio, 1.0) * 0.4 if ctx.available else 0.0
    )

    hour = int(ctx.hour_local) % 24
    off_hours = 1.0 if (hour < _BUSINESS_START or hour >= _BUSINESS_END) else 0.0

    burst = max(int(ctx.burst_count_1h), 1)
    aliases = max(int(ctx.display_name_alias_count), 1)
    age = max(int(ctx.domain_age_days), 0)
    young = 1.0 if (ctx.available and 0 <= age < _YOUNG_DOMAIN_DAYS) else 0.0

    recipients = max(int(ctx.recipient_count), len(msg.to), 1)
    bcc = max(int(ctx.bcc_count), 0)

    # Cross-family interactions. These are the terms an attacker cannot rewrite
    # away by editing text alone.
    ask_pressure = (
        sig.get("body_lex_credential", 0.0)
        + sig.get("body_lex_financial", 0.0)
        + sig.get("body_urgency_phrases", 0.0)
    )
    urgent = sig.get("subj_urgency_phrases", 0.0) + sig.get("body_lex_urgency", 0.0)

    first_seen = 1.0 if (ctx.sender_first_seen or not ctx.available) else 0.0

    # A single scalar an analyst can read: how much unearned trust is being
    # asked for. High = stranger, new domain, off hours, making a request.
    trust_deficit = (
        first_seen * 0.25
        + young * 0.25
        + off_hours * 0.10
        + (1.0 - relationship) * 0.20
        + min(ask_pressure / 6.0, 1.0) * 0.20
    )

    return {
        "beh_context_available": 1.0 if ctx.available else 0.0,
        "beh_sender_first_seen": first_seen,
        "beh_prior_messages": float(prior),
        "beh_prior_messages_log": math.log1p(prior),
        "beh_prior_replies": float(replies),
        "beh_reply_ratio": reply_ratio,
        "beh_relationship_strength": relationship,
        "beh_thread_depth": float(max(int(ctx.thread_depth), 0)),
        "beh_is_new_thread": 1.0 if int(ctx.thread_depth) <= 0 else 0.0,
        "beh_cold_contact_with_ask": first_seen * min(ask_pressure / 4.0, 1.0),
        "beh_hour_local": float(hour),
        "beh_off_hours": off_hours,
        "beh_is_weekend": 1.0 if ctx.is_weekend else 0.0,
        "beh_odd_hour_and_urgent": off_hours * min(urgent / 3.0, 1.0),
        "beh_recipient_count": float(recipients),
        "beh_bcc_count": float(bcc),
        "beh_bcc_ratio": bcc / (recipients + bcc) if (recipients + bcc) else 0.0,
        "beh_mass_mailing": 1.0 if recipients >= 25 or bcc >= 25 else 0.0,
        "beh_external_sender": 1.0 if ctx.external_sender else 0.0,
        "beh_external_and_financial": (
            (1.0 if ctx.external_sender else 0.0)
            * min(sig.get("body_lex_financial", 0.0) / 4.0, 1.0)
        ),
        "beh_domain_report_count": float(max(int(ctx.domain_report_count), 0)),
        "beh_domain_reported": 1.0 if int(ctx.domain_report_count) > 0 else 0.0,
        "beh_domain_click_rate": float(min(max(ctx.domain_click_rate, 0.0), 1.0)),
        "beh_burst_count_1h": float(burst),
        "beh_burst_log": math.log1p(burst),
        # Campaign shape: many messages from one domain in an hour, to many
        # recipients, from a sender nobody has corresponded with.
        "beh_campaign_shape": min(math.log1p(burst) / 4.0, 1.0) * first_seen,
        "beh_display_name_alias_count": float(aliases),
        "beh_display_name_reuse": 1.0 if aliases > 1 else 0.0,
        "beh_domain_age_days": float(age),
        "beh_domain_age_log": math.log1p(age),
        "beh_young_domain": young,
        "beh_young_domain_and_ask": young * min(ask_pressure / 4.0, 1.0),
        "beh_trust_deficit": round(min(max(trust_deficit, 0.0), 1.0), 6),
    }
