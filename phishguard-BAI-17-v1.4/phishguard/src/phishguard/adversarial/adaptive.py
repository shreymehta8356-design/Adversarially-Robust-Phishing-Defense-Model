"""Adaptive attacks and the robustness-versus-budget curve.

Why this module exists
----------------------
The first version of the robustness evaluation had two weaknesses that a
reader who knows the adversarial-ML literature would find in minutes:

1. **The targets were easy.** It attacked the phishing messages of the ordinary
   test set, which the model scores at ~0.998. Driving 0.998 below 0.80 with a
   handful of edits is close to impossible for any semantic-preserving attack,
   so an attack success rate of 0.000 said more about the choice of targets
   than about the defence.
2. **The attacker did not know about the defence.** It minimised the fused
   score. But the deployed decision is not "fused score below 0.40" -- the
   abstention control (D-ABSTAIN) escalates any message whose ensemble members
   disagree, however low the fused score falls. An attacker that ignores the
   control is being measured against a system that does not exist, which is the
   classic failure the literature calls evaluating against a non-adaptive
   adversary (Athalye, Carlini and Wagner, ICML 2018; Tramer et al., NeurIPS
   2020: "an adaptive attack is the only meaningful evaluation of a defence").

This module fixes both:

* Targets are PG-HARD's hard positives, which start near or inside the review
  band, so an attacker has a real chance.
* :class:`AdaptiveDecisionSurface` is an attacker objective that *knows* about
  abstention. To be delivered silently, every member must read the message as
  safe -- not just their average -- so the adaptive objective is the most
  alarmed member's score, not the fused score.
* Robustness is reported as a **curve over query budget**, the form the
  literature uses, rather than one number at one arbitrary budget.

What "success" means
--------------------
Success is measured on the **deployed decision**, never on a score: an attacked
message counts as a silent delivery only if the full deployed policy --
calibrated score, then abstention -- returns ALLOW for it. Each attacker
optimises its own surrogate objective, but all of them are graded by the same
judge, which is the only way numbers from different attackers are comparable.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

import numpy as np

from phishguard.adversarial.attacker import BudgetedAttacker, RawScoreSurface
from phishguard.adversarial.taxonomy import ATTACK_FAMILIES
from phishguard.schemas import BAND_ALLOW, EmailMessage


class AdaptiveDecisionSurface:
    """Attacker objective that accounts for the abstention control.

    The deployed policy delivers a message silently only when the fused score
    is below the review threshold *and* no member contradicts the others by
    more than the abstention limit. Both conditions are satisfied when every
    member's score is low, so an attacker who wants silent delivery should
    minimise the highest member score -- the reader most likely to object --
    rather than the average the fusion computes.

    Returning ``max(fused, max member)`` gives the greedy search exactly that
    target: it can only make progress by quieting the most alarmed reader, and
    it reaches the evasion threshold only when all of them are quiet together.
    """

    def __init__(self, detector: Any) -> None:
        self.detector = detector

    def predict_proba(self, messages: list[EmailMessage]) -> np.ndarray:
        if not messages:
            return np.zeros(0, dtype=np.float64)
        Z = self.detector._member_matrix(messages)
        fused = self.detector._fusion_raw(Z)
        return np.maximum(fused, Z.max(axis=1))


class ScoreSurface:
    """Adapt any object with ``score(messages)`` to the attacker protocol."""

    def __init__(self, model: Any) -> None:
        self.model = model

    def predict_proba(self, messages: list[EmailMessage]) -> np.ndarray:
        return np.asarray(self.model.score(messages), dtype=np.float64)


def _final_messages(
    originals: Sequence[EmailMessage], results: Sequence[Any]
) -> list[EmailMessage]:
    return [
        (r.message if getattr(r, "message", None) is not None else m)
        for m, r in zip(originals, results, strict=True)
    ]


def silent_rate(bands: Sequence[str]) -> float:
    bands = list(bands)
    return sum(1 for b in bands if b == BAND_ALLOW) / len(bands) if bands else 0.0


def budget_sweep(
    *,
    targets: list[EmailMessage],
    attacker_surface: Any,
    judge: Callable[[list[EmailMessage]], list[str]],
    evasion_threshold: float,
    budgets: Sequence[int] = (0, 10, 40, 120),
    families: tuple[str, ...] | None = None,
    restarts: int = 1,
    seed: int = 7,
) -> list[dict[str, Any]]:
    """Silent-delivery rate after attack, at each query budget.

    ``attacker_surface`` is what the attacker optimises; ``judge`` is the
    deployed decision that grades the result. Budget 0 is the unattacked
    baseline, so every curve starts from the system's clean behaviour on the
    same targets and the rise is attributable to the attack alone.
    """
    rows: list[dict[str, Any]] = []
    for budget in budgets:
        started = time.perf_counter()
        if budget <= 0:
            final = list(targets)
            queries = [0] * len(targets)
        else:
            attacker = BudgetedAttacker(
                attacker_surface,
                budget=budget,
                evasion_threshold=evasion_threshold,
                families=families,
                restarts=restarts,
                seed=seed,
            )
            results = attacker.attack_many(targets)
            final = _final_messages(targets, results)
            queries = [int(getattr(r, "queries", 0)) for r in results]
        bands = judge(final)
        rows.append(
            {
                "budget": int(budget),
                "n": len(targets),
                "silent_delivery_rate": round(silent_rate(bands), 4),
                "silent_delivered": sum(1 for b in bands if b == BAND_ALLOW),
                # The attacker can succeed in two different senses and the
                # report must keep them apart: making the system *less sure*
                # (BLOCK -> REVIEW moves the cost onto an analyst) is a real
                # effect, but it is not the same as reaching the victim
                # unwarned (-> ALLOW). Collapsing both into one "attack success
                # rate" either overstates the danger or hides the workload.
                "auto_blocked_rate": round(sum(1 for b in bands if b == "BLOCK") / len(bands), 4)
                if bands
                else 0.0,
                "bands": {b: list(bands).count(b) for b in ("ALLOW", "REVIEW", "BLOCK")},
                "mean_queries_used": round(float(np.mean(queries)) if queries else 0.0, 2),
                "seconds": round(time.perf_counter() - started, 2),
            }
        )
    return rows


def run_adaptive_robustness(
    detector: Any,
    *,
    targets: list[EmailMessage],
    baseline: Any | None = None,
    baseline_review_threshold: float | None = None,
    budgets: Sequence[int] = (0, 10, 40, 120),
    per_family_budget: int = 40,
    per_family: bool = True,
    seed: int = 7,
) -> dict[str, Any]:
    """Naive and adaptive attacks on hard positives, graded by the deployed policy.

    Three curves share one judge per system:

    * ``naive``    -- minimises PhishGuard's fused score (the original attacker)
    * ``adaptive`` -- minimises the most alarmed member (knows about D-ABSTAIN)
    * ``text_only``-- the conventional filter under the same attacker; it has no
      abstention control, so its naive and adaptive attacks coincide.
    """
    review = float(detector.review_threshold)

    def pg_judge(msgs: list[EmailMessage]) -> list[str]:
        return detector.bands(msgs)

    out: dict[str, Any] = {
        "targets": len(targets),
        "budgets": list(budgets),
        "judge": (
            "the deployed decision: calibrated score, then abstention on member "
            "disagreement. A message counts as a silent delivery only if that "
            "policy returns ALLOW for it."
        ),
        "curves": {},
    }

    out["curves"]["naive"] = {
        "label": "PhishGuard vs a score-minimising attacker",
        "rows": budget_sweep(
            targets=targets,
            attacker_surface=RawScoreSurface(detector),
            judge=pg_judge,
            evasion_threshold=review,
            budgets=budgets,
            seed=seed,
        ),
    }
    out["curves"]["adaptive"] = {
        "label": "PhishGuard vs an attacker that knows about abstention",
        "rows": budget_sweep(
            targets=targets,
            attacker_surface=AdaptiveDecisionSurface(detector),
            judge=pg_judge,
            evasion_threshold=review,
            budgets=budgets,
            seed=seed,
        ),
    }

    if baseline is not None:
        thr = review if baseline_review_threshold is None else float(baseline_review_threshold)

        def text_judge(msgs: list[EmailMessage]) -> list[str]:
            scores = np.asarray(baseline.score(msgs), dtype=np.float64)
            return ["ALLOW" if s < thr else "REVIEW" for s in scores]

        out["curves"]["text_only"] = {
            "label": "Text-only filter vs the same attacker",
            "review_threshold": round(thr, 6),
            "rows": budget_sweep(
                targets=targets,
                attacker_surface=ScoreSurface(baseline),
                judge=text_judge,
                evasion_threshold=thr,
                budgets=budgets,
                seed=seed,
            ),
        }

    # Which readers the strongest attack could and could not move. This is
    # the mechanism behind the headline number: if the zero comes from one
    # member the attacker simply cannot reach, the report should say which.
    strongest = max(b for b in budgets) if budgets else 0
    if strongest > 0:
        attacker = BudgetedAttacker(
            AdaptiveDecisionSurface(detector),
            budget=strongest,
            evasion_threshold=review,
            restarts=1,
            seed=seed,
        )
        final = _final_messages(targets, attacker.attack_many(targets))
        z0 = detector._member_matrix(targets)
        z1 = detector._member_matrix(final)
        out["member_movement"] = {
            "budget": int(strongest),
            "members": [
                {
                    "member": name,
                    "mean_before": round(float(z0[:, j].mean()), 4),
                    "mean_after": round(float(z1[:, j].mean()), 4),
                    "mean_drop": round(float(z0[:, j].mean() - z1[:, j].mean()), 4),
                }
                for j, name in enumerate(detector.member_names)
            ],
        }

    if per_family:
        fam_rows: list[dict[str, Any]] = []
        for family in ATTACK_FAMILIES:
            row: dict[str, Any] = {"family_id": family.id, "family": family.name}
            pg = budget_sweep(
                targets=targets,
                attacker_surface=AdaptiveDecisionSurface(detector),
                judge=pg_judge,
                evasion_threshold=review,
                budgets=(per_family_budget,),
                families=(family.id,),
                seed=seed,
            )[0]
            row["phishguard_silent_delivery_rate"] = pg["silent_delivery_rate"]
            row["phishguard_auto_blocked_rate"] = pg["auto_blocked_rate"]
            if baseline is not None:
                thr = (
                    review
                    if baseline_review_threshold is None
                    else float(baseline_review_threshold)
                )

                def tj(msgs: list[EmailMessage], _thr: float = thr) -> list[str]:
                    scores = np.asarray(baseline.score(msgs), dtype=np.float64)
                    return ["ALLOW" if s < _thr else "REVIEW" for s in scores]

                tx = budget_sweep(
                    targets=targets,
                    attacker_surface=ScoreSurface(baseline),
                    judge=tj,
                    evasion_threshold=thr,
                    budgets=(per_family_budget,),
                    families=(family.id,),
                    seed=seed,
                )[0]
                row["text_only_silent_delivery_rate"] = tx["silent_delivery_rate"]
            fam_rows.append(row)
        out["per_family"] = {"budget": per_family_budget, "rows": fam_rows}

    return out
