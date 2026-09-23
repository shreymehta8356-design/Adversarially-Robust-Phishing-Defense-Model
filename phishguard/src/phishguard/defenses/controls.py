"""The defensive-control registry.

Every hardening measure in the system is registered here with an ID, a
description, the attack families it is intended to blunt, and its cost. This is
what turns "we added some normalization" into a defensible security argument:
each control can be switched off independently, and the ablation study reports
the robustness that is actually attributable to it.

Controls
--------
``D-NORM``      Unicode / homoglyph / leet / separator canonicalization
``D-URL``       URL unwrapping and canonicalization
``D-ADVTRAIN``  Adversarially augmented training data
``D-ENSEMBLE``  Multi-view fusion (an attack must beat every member at once)
``D-ABSTAIN``   Confidence bands routing uncertain mail to a human
``D-VELOCITY``  Campaign-burst guard applied at decision time
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

DEFENSE_IDS: tuple[str, ...] = (
    "D-NORM",
    "D-URL",
    "D-ADVTRAIN",
    "D-ENSEMBLE",
    "D-ABSTAIN",
    "D-VELOCITY",
)

#: id -> (human name, what it does, attack families it counters, cost note)
DEFENSE_CATALOGUE: dict[str, dict[str, Any]] = {
    "D-NORM": {
        "name": "Text canonicalization",
        "description": (
            "NFKC normalization, zero-width and bidi stripping, confusable folding, "
            "diacritic removal, leetspeak folding, separator rejoining and run collapsing "
            "applied before any text feature is computed. The obfuscation deltas are "
            "retained as features so evasion effort is itself evidence."
        ),
        "counters": ["A-LEX", "A-UNI"],
        "cost": "~0.15 ms/message; no measurable clean-accuracy loss",
        "residual": (
            "Confusables outside the curated table, and paraphrase attacks that use no "
            "obfuscation at all, pass through unchanged."
        ),
    },
    "D-URL": {
        "name": "URL canonicalization",
        "description": (
            "Percent-decoding, punycode decoding, homoglyph folding in the host and "
            "recursive unwrapping of open-redirect / shortener parameters, so that the "
            "feature extractor scores the destination the victim actually reaches."
        ),
        "counters": ["A-URL"],
        "cost": "~0.1 ms/URL; strictly offline, no DNS or HTTP lookups",
        "residual": (
            "A shortener whose target is not embedded in the query string cannot be "
            "resolved offline; the wrapper itself remains a feature."
        ),
    },
    "D-ADVTRAIN": {
        "name": "Adversarial training",
        "description": (
            "Each phishing training example is augmented with attacked variants drawn "
            "from the full transform suite, so the decision boundary is fitted on the "
            "perturbed manifold rather than only on pristine corpus text."
        ),
        "counters": ["A-LEX", "A-UNI", "A-URL", "A-STRUCT"],
        "cost": "training set grows by the augmentation multiplier; inference unchanged",
        "residual": (
            "Generalizes to unseen transforms only to the extent that they resemble the "
            "training perturbations; a genuinely novel attack family is out of scope."
        ),
    },
    "D-ENSEMBLE": {
        "name": "Multi-view fusion",
        "description": (
            "A calibrated stacker over rule, engineered-feature, character-n-gram and "
            "word-n-gram members. The members read different views of the message, so a "
            "perturbation that lowers one member's score often raises another's."
        ),
        "counters": ["A-LEX", "A-UNI", "A-STRUCT", "A-HDR"],
        "cost": "~4x single-model inference; still sub-10 ms/message on CPU",
        "residual": (
            "Members share the text channel, so a strong semantic paraphrase moves them "
            "together. Behavioral features are the decorrelating leg."
        ),
    },
    "D-ABSTAIN": {
        "name": "Confidence banding / abstention",
        "description": (
            "Three-way decision: ALLOW below the review threshold, BLOCK above the block "
            "threshold, and REVIEW in between where the message is queued for an analyst "
            "instead of being auto-decided."
        ),
        "counters": ["A-LEX", "A-UNI", "A-URL", "A-STRUCT", "A-HDR", "A-BEH"],
        "cost": "analyst time proportional to the review-band width",
        "residual": (
            "An attack that pushes a message all the way below the review threshold still "
            "evades silently; banding converts some evasions into review load, not zero."
        ),
    },
    "D-VELOCITY": {
        "name": "Campaign-burst guard",
        "description": (
            "A decision-time escalation that raises the effective score when the same "
            "sender domain arrives in an unusual burst from an unknown contact, using the "
            "behavioral block rather than message content."
        ),
        "counters": ["A-BEH", "A-LEX"],
        "cost": "one bounded arithmetic adjustment; no extra model call",
        "residual": (
            "Low-and-slow, individually targeted spear-phishing produces no burst and is "
            "unaffected."
        ),
    },
}


@dataclass(slots=True)
class DefenseConfig:
    """Which controls are active. Used for both serving and ablation."""

    norm: bool = True
    url_canon: bool = True
    adv_train: bool = True
    ensemble: bool = True
    abstain: bool = True
    velocity: bool = True

    @classmethod
    def none(cls) -> DefenseConfig:
        """All controls off - the undefended baseline arm of the ablation."""
        return cls(
            norm=False,
            url_canon=False,
            adv_train=False,
            ensemble=False,
            abstain=False,
            velocity=False,
        )

    @classmethod
    def without(cls, defense_id: str) -> DefenseConfig:
        """Full stack minus one control - the leave-one-out ablation arm."""
        mapping = {
            "D-NORM": "norm",
            "D-URL": "url_canon",
            "D-ADVTRAIN": "adv_train",
            "D-ENSEMBLE": "ensemble",
            "D-ABSTAIN": "abstain",
            "D-VELOCITY": "velocity",
        }
        key = mapping.get(defense_id.upper())
        if key is None:
            raise ValueError(f"unknown defense id {defense_id!r}; expected one of {DEFENSE_IDS}")
        cfg = cls()
        setattr(cfg, key, False)
        return cfg

    @property
    def active_ids(self) -> list[str]:
        flags = {
            "D-NORM": self.norm,
            "D-URL": self.url_canon,
            "D-ADVTRAIN": self.adv_train,
            "D-ENSEMBLE": self.ensemble,
            "D-ABSTAIN": self.abstain,
            "D-VELOCITY": self.velocity,
        }
        return [k for k, v in flags.items() if v]

    def as_dict(self) -> dict[str, bool]:
        return asdict(self)


def describe_defenses() -> list[dict[str, Any]]:
    """Catalogue rows for the model card and the ``/api/v1/model`` endpoint."""
    return [{"id": did, **DEFENSE_CATALOGUE[did]} for did in DEFENSE_IDS]


def apply_velocity_guard(
    score: float, behavioral: dict[str, float], *, enabled: bool = True
) -> tuple[float, str | None]:
    """Defensive control ``D-VELOCITY``.

    Raises the score for messages that look like part of a burst campaign from
    an unfamiliar sender. Bounded and monotone: it can only push a score up, by
    at most 0.15, and never past 0.99 -- so it can add review load but cannot
    on its own manufacture a block from a clean message.
    """
    if not enabled:
        return score, None
    if not behavioral.get("beh_context_available", 0.0):
        return score, None

    campaign = behavioral.get("beh_campaign_shape", 0.0)
    reported = behavioral.get("beh_domain_reported", 0.0)
    alias_reuse = behavioral.get("beh_display_name_reuse", 0.0)

    bump = 0.10 * campaign + 0.04 * reported + 0.03 * alias_reuse
    bump = min(bump, 0.15)
    if bump <= 0.005:
        return score, None
    adjusted = min(score + bump * (1.0 - score), 0.99)
    reason = (
        f"velocity guard raised score by {adjusted - score:+.3f} "
        f"(campaign={campaign:.2f}, reported={reported:.0f}, alias_reuse={alias_reuse:.0f})"
    )
    return adjusted, reason
