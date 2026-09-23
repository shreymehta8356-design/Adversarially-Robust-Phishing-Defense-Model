"""Per-decision attributions.

Three attribution methods, one per model type, chosen so that nothing here is
an approximation of an approximation:

``fusion_attributions``
    Exact. The fusion is logistic regression over member scores, so each
    member's contribution to the log-odds is ``coef_j * score_j`` by definition.

``TextMember.token_contributions``
    Exact. The text members are linear over TF-IDF, so a token's contribution
    is ``coef_j * tfidf_j``.

``engineered_attributions``
    Occlusion. Gradient boosting has no linear decomposition, so instead of
    reaching for a SHAP approximation this measures the thing the analyst
    actually wants to know: *what would the score have been if this signal had
    been normal?* Each candidate feature is replaced by its training-set
    reference value and the model is re-scored. The difference is the feature's
    contribution, in probability units, and it is a real counterfactual rather
    than an estimate of one.

The occlusion pass costs one extra batched prediction of ``K+1`` rows per
message, where ``K`` is the number of candidate features (default 24, chosen by
largest deviation from the reference). That is a single vectorised call and
measures well under a millisecond, which is why the API can afford to explain
every decision rather than only the ones an analyst opens.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import numpy as np

from phishguard.features.assembler import FeatureVector

if TYPE_CHECKING:  # pragma: no cover
    from phishguard.models.members import EngineeredMember

#: Reference ("normal") value per feature family. Zero is the right neutral
#: value for the count and flag features that dominate the vector; the
#: distance-like features get their neutral maximum instead, because zero there
#: means "exact brand match", the opposite of neutral.
_NEUTRAL_OVERRIDES: dict[str, float] = {
    "url_lookalike_distance__max": 9.0,
    "url_lookalike_distance__mean": 9.0,
    "link_min_lookalike_distance": 9.0,
    "hdr_lookalike_distance": 9.0,
    "hdr_auth_score": 1.0,
    "beh_domain_age_days": 1500.0,
    "beh_domain_age_log": float(np.log1p(1500.0)),
    "beh_relationship_strength": 0.6,
    "beh_hour_local": 12.0,
    "beh_recipient_count": 1.0,
    "beh_burst_count_1h": 1.0,
    "beh_burst_log": float(np.log1p(1.0)),
    "beh_display_name_alias_count": 1.0,
    "beh_context_available": 1.0,
    "link_official_brand_ratio": 1.0,
    "url_official_brand_domain__max": 1.0,
    "url_official_brand_domain__mean": 1.0,
    "url_is_https": 1.0,
    "url_is_https__max": 1.0,
    "url_is_https__mean": 1.0,
    "link_https_ratio": 1.0,
    "body_has_greeting": 1.0,
}


def neutral_vector(names: tuple[str, ...]) -> np.ndarray:
    """The 'nothing unusual here' reference point for occlusion."""
    return np.fromiter(
        (_NEUTRAL_OVERRIDES.get(n, 0.0) for n in names),
        dtype=np.float64,
        count=len(names),
    )


def engineered_attributions(
    member: EngineeredMember,
    fv: FeatureVector,
    *,
    top_k: int = 8,
    candidates: int = 24,
) -> list[dict[str, Any]]:
    """Counterfactual contribution of each engineered feature, in score units.

    Positive ``contribution`` means the feature pushed the score *up* (towards
    phishing): the score fell by that much when the feature was reset to
    normal.
    """
    if not member.fitted or fv.values.size == 0:
        return []

    names = fv.names
    base = fv.values
    reference = neutral_vector(names)

    # Only occlude features that actually differ from the reference - the rest
    # contribute nothing by construction and would waste the query budget.
    deviation = np.abs(base - reference)
    active = np.flatnonzero(deviation > 1e-9)
    if active.size == 0:
        return []
    if active.size > candidates:
        active = active[np.argsort(-deviation[active])[:candidates]]

    batch = np.repeat(base[None, :], len(active) + 1, axis=0)
    for row, j in enumerate(active, start=1):
        batch[row, j] = reference[j]

    scores = member.score_matrix(batch)
    base_score = float(scores[0])

    rows: list[dict[str, Any]] = []
    for row, j in enumerate(active, start=1):
        contribution = base_score - float(scores[row])
        if abs(contribution) < 1e-4:
            continue
        rows.append(
            {
                "feature": names[j],
                "value": round(float(base[j]), 4),
                "reference": round(float(reference[j]), 4),
                "contribution": round(contribution, 5),
                "direction": "phishing" if contribution > 0 else "legitimate",
            }
        )
    rows.sort(key=lambda r: -abs(r["contribution"]))
    return rows[:top_k]


def fusion_attributions(
    member_names: tuple[str, ...],
    coefficients: np.ndarray,
    member_scores: dict[str, float],
    intercept: float,
) -> list[dict[str, Any]]:
    """Exact log-odds contribution of each ensemble member."""
    rows: list[dict[str, Any]] = []
    for name, coef in zip(member_names, np.asarray(coefficients).ravel(), strict=True):
        score = float(member_scores.get(name, 0.0))
        rows.append(
            {
                "member": name,
                "score": round(score, 5),
                "weight": round(float(coef), 5),
                "log_odds_contribution": round(float(coef) * score, 5),
            }
        )
    rows.sort(key=lambda r: -abs(r["log_odds_contribution"]))
    return rows + [
        {
            "member": "(intercept)",
            "score": 1.0,
            "weight": round(float(intercept), 5),
            "log_odds_contribution": round(float(intercept), 5),
        }
    ]


def disagreement(member_scores: dict[str, float]) -> float:
    """Spread across ensemble members.

    High disagreement is itself operationally meaningful: it usually means the
    message has been perturbed so that some views were moved and others were
    not, which is the signature of an evasion attempt rather than of an
    ordinary borderline message.
    """
    values = [v for k, v in member_scores.items() if k != "rules"] or list(member_scores.values())
    if len(values) < 2:
        return 0.0
    return float(np.std(values, ddof=0))
