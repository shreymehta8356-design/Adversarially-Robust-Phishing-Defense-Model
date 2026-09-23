"""Robustness measurement and the residual-risk register.

Three outputs, each answering a different stakeholder's question.

**Robustness drop** (the engineer's question): rebuild the test set with every
phishing message replaced by its best adversarial variant, then recompute the
headline metrics. The gap between clean and adversarial macro F1 is the number
the acceptance gate checks, and it is the honest way to state robustness -
"attack success rate" alone hides what happens to the legitimate half.

**Per-family effectiveness** (the defender's question): which attack families
actually move the score, so that defensive effort goes where the risk is.

**Residual-risk register** (the risk owner's question): for each family, what
remains after the controls are applied, scored on likelihood and impact, with
the compensating control that covers the gap. This is the artefact a security
review asks for and the one a model card is incomplete without.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

import numpy as np

from phishguard.adversarial.attacker import AttackResult, BudgetedAttacker, Scorer
from phishguard.adversarial.taxonomy import ATTACK_FAMILIES, FAMILY_BY_ID, OUT_OF_SCOPE
from phishguard.defenses.controls import DEFENSE_CATALOGUE
from phishguard.eval.metrics import score_summary
from phishguard.schemas import EmailMessage

#: Likelihood bands for the residual-risk register, keyed on the measured
#: post-defence attack success rate for that family.
_LIKELIHOOD_BANDS: tuple[tuple[float, str], ...] = (
    (0.40, "High"),
    (0.15, "Medium"),
    (0.05, "Low"),
    (0.00, "Very low"),
)

#: Impact is a property of the family, not of the measurement: what does a
#: successful evasion of this kind actually cost the organisation?
_FAMILY_IMPACT: dict[str, tuple[str, str]] = {
    "A-LEX": ("High", "Credential harvest delivered to the inbox with no warning"),
    "A-UNI": ("High", "Same as A-LEX; obfuscation also defeats human proof-reading"),
    "A-URL": ("High", "Victim reaches the landing page; the lure text is unchanged"),
    "A-STRUCT": ("High", "Lure renders normally while carrying no analysable text"),
    "A-HDR": ("Medium", "Improves credibility but does not by itself deliver the payload"),
    "A-BEH": ("Medium", "Costs the attacker reach; effective only for targeted sending"),
}


def _band(rate: float) -> str:
    for threshold, label in _LIKELIHOOD_BANDS:
        if rate >= threshold:
            return label
    return "Very low"


def attack_summary(
    results: list[AttackResult],
    *,
    block_threshold: float = 0.80,
    review_threshold: float = 0.40,
) -> dict[str, Any]:
    """Aggregate statistics over a batch of attacks.

    Two success definitions, because they mean different things operationally
    and reporting only one is misleading:

    ``attack_success_rate``
        The message ends below the **block** threshold. It is no longer
        auto-quarantined; at best it lands in an analyst's review queue. This
        is the headline number, and it is the sensitive one - an attacker who
        drags a score from 0.99 to 0.79 has achieved something real, and a
        measure anchored at 0.5 would score that as a total failure.

    ``silent_delivery_rate``
        The message ends below the **review** threshold: it reaches the
        recipient's inbox with no human ever seeing it. Rarer, and much worse.

    The attacker's own stopping condition is the review threshold, because
    silent delivery is what they actually want; both outcomes are then read off
    the final scores.
    """
    if not results:
        return {
            "n": 0, "attack_success_rate": 0.0, "silent_delivery_rate": 0.0,
            "mean_score_drop": 0.0, "median_score_drop": 0.0, "max_score_drop": 0.0,
            "mean_queries": 0.0, "median_queries_to_evade": 0.0,
            "mean_steps_to_evade": 0.0, "family_usage": [], "transform_usage": [],
        }
    finals = np.array([r.final_score for r in results], dtype=np.float64)
    escaped_block = finals < block_threshold
    silent = finals < review_threshold
    evaded = escaped_block
    drops = np.array([r.score_drop for r in results], dtype=np.float64)
    queries = np.array([r.queries for r in results], dtype=np.float64)
    evade_queries = queries[evaded]
    steps = np.array([len(r.steps) for r in results], dtype=np.float64)

    fam = Counter(f for r in results for f in set(r.families_used))
    tr = Counter(s for r in results for s in r.steps)
    return {
        "n": len(results),
        "attack_success_rate": round(float(escaped_block.mean()), 5),
        "silent_delivery_rate": round(float(silent.mean()), 5),
        "n_escaped_block": int(escaped_block.sum()),
        "n_silent_delivery": int(silent.sum()),
        "block_threshold": block_threshold,
        "review_threshold": review_threshold,
        "mean_final_score": round(float(finals.mean()), 5),
        "mean_score_drop": round(float(drops.mean()), 5),
        "median_score_drop": round(float(np.median(drops)), 5),
        "max_score_drop": round(float(drops.max()), 5),
        "mean_queries": round(float(queries.mean()), 2),
        "median_queries_to_evade": (
            round(float(np.median(evade_queries)), 2) if evade_queries.size else 0.0
        ),
        "mean_steps_to_evade": (
            round(float(steps[evaded].mean()), 2) if evaded.any() else 0.0
        ),
        "family_usage": [
            {"family": k, "messages": v, "share": round(v / len(results), 4)}
            for k, v in fam.most_common()
        ],
        "transform_usage": [
            {"transform_id": k, "uses": v} for k, v in tr.most_common(12)
        ],
    }


def per_family_attack(
    scorer: Scorer,
    messages: list[EmailMessage],
    *,
    budget: int = 10,
    evasion_threshold: float = 0.40,
    block_threshold: float = 0.80,
    seed: int = 7,
) -> dict[str, dict[str, Any]]:
    """Run the budgeted attack once per family, in isolation.

    Restricting the attacker to a single family is what makes the residual-risk
    register per-family rather than a single undifferentiated number.
    """
    out: dict[str, dict[str, Any]] = {}
    for family in ATTACK_FAMILIES:
        attacker = BudgetedAttacker(
            scorer, budget=budget, evasion_threshold=evasion_threshold,
            families=(family.id,), seed=seed,
        )
        results = attacker.attack_many(messages)
        out[family.id] = attack_summary(
            results, block_threshold=block_threshold, review_threshold=evasion_threshold
        )
    return out


def adversarial_metrics(
    scorer: Scorer,
    messages: list[EmailMessage],
    y_true: np.ndarray,
    *,
    results: list[AttackResult],
    phish_positions: list[int],
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Metrics on a test set where every phish is replaced by its attacked form.

    Legitimate messages are left untouched, which is the correct construction:
    an attacker perturbs their own mail, not the victim's. The resulting macro
    F1 is directly comparable with the clean number, and their difference is
    the robustness drop.
    """
    y_true = np.asarray(y_true).astype(int)
    perturbed: list[EmailMessage] = list(messages)
    for pos, res in zip(phish_positions, results, strict=True):
        if res.message is not None:
            perturbed[pos] = res.message
    scores = scorer.predict_proba(perturbed)
    return score_summary(y_true, scores, threshold=threshold)


def residual_risk_register(
    family_results: dict[str, dict[str, Any]],
    *,
    defenses_active: list[str],
) -> list[dict[str, Any]]:
    """The register: what risk remains after the controls are applied."""
    rows: list[dict[str, Any]] = []
    for family in ATTACK_FAMILIES:
        summary = family_results.get(family.id, {})
        asr = float(summary.get("attack_success_rate", 0.0))
        drop = float(summary.get("mean_score_drop", 0.0))
        impact, impact_note = _FAMILY_IMPACT.get(family.id, ("Medium", ""))
        applied = [d for d in family.countered_by if d in defenses_active]
        missing = [d for d in family.countered_by if d not in defenses_active]
        rows.append(
            {
                "family_id": family.id,
                "family": family.name,
                "measured_attack_success_rate": round(asr, 5),
                "measured_mean_score_drop": round(drop, 5),
                "median_queries_to_evade": summary.get("median_queries_to_evade", 0.0),
                "likelihood": _band(asr),
                "impact": impact,
                "impact_rationale": impact_note,
                "controls_applied": applied,
                "controls_not_applied": missing,
                "attacker_cost": family.attacker_cost,
                "residual_risk": _residual_level(_band(asr), impact),
                "residual_description": (
                    DEFENSE_CATALOGUE.get(applied[0], {}).get("residual", "")
                    if applied else "No control from this family's set is active."
                ),
                "compensating_control": _compensating(family.id, applied),
            }
        )
    rows.sort(key=lambda r: -r["measured_attack_success_rate"])
    return rows


_RISK_MATRIX: dict[tuple[str, str], str] = {
    ("High", "High"): "High",
    ("High", "Medium"): "Medium",
    ("Medium", "High"): "Medium",
    ("Medium", "Medium"): "Medium",
    ("Low", "High"): "Low",
    ("Low", "Medium"): "Low",
    ("Very low", "High"): "Low",
    ("Very low", "Medium"): "Very low",
}


def _residual_level(likelihood: str, impact: str) -> str:
    return _RISK_MATRIX.get((likelihood, impact), "Medium")


def _compensating(family_id: str, applied: list[str]) -> str:
    """What catches what the model does not."""
    base = {
        "A-LEX": (
            "The REVIEW band routes uncertain messages to an analyst rather than "
            "auto-allowing them, and user reporting feeds the domain-report signal."
        ),
        "A-UNI": (
            "Obfuscation effort is retained as a feature, so heavy folding raises the "
            "score even when the folded text looks benign."
        ),
        "A-URL": (
            "URL rewriting and click-time protection at the gateway, plus the "
            "behavioural family, which URL edits cannot move."
        ),
        "A-STRUCT": (
            "The URL and behavioural families are unaffected by markup changes; an "
            "image-only message with a single link is itself a scored signal."
        ),
        "A-HDR": (
            "Behavioural history cannot be forged by header edits; DMARC enforcement "
            "at the boundary limits what alignment buys the attacker."
        ),
        "A-BEH": (
            "Low-and-slow sending sharply reduces campaign reach, so the attacker "
            "pays for the evasion in delivered volume."
        ),
    }.get(family_id, "Analyst review of the REVIEW band.")
    if not applied:
        return f"NO PRIMARY CONTROL ACTIVE. Relying entirely on: {base}"
    return base


def robustness_report(
    scorer: Scorer,
    test_messages: list[EmailMessage],
    y_true: np.ndarray,
    *,
    clean_summary: dict[str, Any],
    budget: int = 10,
    evasion_threshold: float = 0.40,
    block_threshold: float = 0.80,
    threshold: float = 0.5,
    defenses_active: list[str] | None = None,
    max_attacked: int = 250,
    per_family: bool = True,
    seed: int = 7,
    restarts: int = 1,
) -> dict[str, Any]:
    """Full robustness section of the evaluation dossier.

    ``evasion_threshold`` is the attacker's goal (silent delivery);
    ``block_threshold`` is what the deployed policy auto-quarantines at, and is
    what the headline attack-success rate is measured against.
    """
    y_true = np.asarray(y_true).astype(int)
    phish_positions = [int(i) for i in np.flatnonzero(y_true == 1)][:max_attacked]
    phish = [test_messages[i] for i in phish_positions]

    attacker = BudgetedAttacker(
        scorer, budget=budget, evasion_threshold=evasion_threshold,
        restarts=restarts, seed=seed,
    )
    results = attacker.attack_many(phish)
    composed = attack_summary(
        results, block_threshold=block_threshold, review_threshold=evasion_threshold
    )

    adversarial = adversarial_metrics(
        scorer, test_messages, y_true,
        results=results, phish_positions=phish_positions, threshold=threshold,
    )

    clean_f1 = float(clean_summary.get("macro_f1", 0.0))
    adv_f1 = float(adversarial.get("macro_f1", 0.0))
    clean_recall = float(clean_summary.get("recall_phish", 0.0))
    adv_recall = float(adversarial.get("recall_phish", 0.0))

    family_results = (
        per_family_attack(
            scorer, phish, budget=budget, evasion_threshold=evasion_threshold,
            block_threshold=block_threshold, seed=seed,
        )
        if per_family
        else {}
    )

    report: dict[str, Any] = {
        "attacked_messages": len(phish),
        "budget": budget,
        "evasion_threshold": evasion_threshold,
        "attack_success_rate": composed["attack_success_rate"],
        "silent_delivery_rate": composed["silent_delivery_rate"],
        "block_threshold": block_threshold,
        "success_definition": (
            f"a message whose score falls below the deployed block threshold "
            f"({block_threshold}) is no longer auto-quarantined; below the review "
            f"threshold ({evasion_threshold}) it is delivered with no human review"
        ),
        "composed_attack": composed,
        "clean_macro_f1": round(clean_f1, 5),
        "adversarial_macro_f1": round(adv_f1, 5),
        "macro_f1_drop": round(max(clean_f1 - adv_f1, 0.0), 5),
        "clean_recall": round(clean_recall, 5),
        "adversarial_recall": round(adv_recall, 5),
        "recall_drop": round(max(clean_recall - adv_recall, 0.0), 5),
        "adversarial_metrics": adversarial,
        "per_family": family_results,
    }
    if family_results:
        report["residual_risk_register"] = residual_risk_register(
            family_results, defenses_active=defenses_active or []
        )
    # What the decision policy actually does with the attacked traffic. Macro F1
    # alone hides the shift from BLOCK into REVIEW, which is where the analyst
    # workload lands and where an attacker's effort actually shows up.
    from phishguard.eval.metrics import banded_outcome

    perturbed = list(test_messages)
    for pos, res in zip(phish_positions, results, strict=True):
        if res.message is not None:
            perturbed[pos] = res.message
    adv_scores = scorer.predict_proba(perturbed)
    clean_scores = scorer.predict_proba(test_messages)
    report["banded_under_attack"] = {
        "clean": banded_outcome(
            y_true, clean_scores,
            review_threshold=evasion_threshold, block_threshold=block_threshold,
        ).as_dict(),
        "adversarial": banded_outcome(
            y_true, adv_scores,
            review_threshold=evasion_threshold, block_threshold=block_threshold,
        ).as_dict(),
    }
    report["out_of_scope"] = [dict(o) for o in OUT_OF_SCOPE]
    return report


def compare_robustness(
    arms: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Side-by-side robustness table across models or defence configurations."""
    rows: list[dict[str, Any]] = []
    for name, rep in arms.items():
        rows.append(
            {
                "arm": name,
                "clean_macro_f1": rep.get("clean_macro_f1", 0.0),
                "adversarial_macro_f1": rep.get("adversarial_macro_f1", 0.0),
                "macro_f1_drop": rep.get("macro_f1_drop", 0.0),
                "attack_success_rate": rep.get("attack_success_rate", 0.0),
                "median_queries_to_evade": rep.get("composed_attack", {}).get(
                    "median_queries_to_evade", 0.0
                ),
            }
        )
    rows.sort(key=lambda r: r["attack_success_rate"])
    return rows


def family_effectiveness_table(
    family_results: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Flat table of family effectiveness for the dossier."""
    rows: list[dict[str, Any]] = []
    for fid, summary in family_results.items():
        family = FAMILY_BY_ID.get(fid)
        rows.append(
            {
                "family_id": fid,
                "family": family.name if family else fid,
                "attack_success_rate": summary.get("attack_success_rate", 0.0),
                "silent_delivery_rate": summary.get("silent_delivery_rate", 0.0),
                "mean_score_drop": summary.get("mean_score_drop", 0.0),
                "median_queries_to_evade": summary.get("median_queries_to_evade", 0.0),
                "attacker_cost": family.attacker_cost if family else "",
            }
        )
    rows.sort(key=lambda r: -r["attack_success_rate"])
    return rows


def aggregate_by_family(results: list[AttackResult]) -> dict[str, int]:
    """How often each family appears in a successful composed attack."""
    counts: dict[str, int] = defaultdict(int)
    for r in results:
        if not r.evaded:
            continue
        for f in set(r.families_used):
            counts[f] += 1
    return dict(counts)
