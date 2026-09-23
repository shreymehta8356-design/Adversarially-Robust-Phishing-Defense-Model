"""Budgeted black-box attacker.

The threat model (see :mod:`phishguard.adversarial.taxonomy`) grants the
adversary the detector's *score* for a candidate message and a query budget.
This module implements the search they would run.

Search strategy
---------------
Greedy hill-climbing with a query budget, which is what a real operator does
when testing a kit against a scanner:

1. score the original message;
2. generate one candidate per applicable transform;
3. discard candidates that fail :func:`payload_preserved`;
4. score the survivors in a single batch and keep the one that lowers the score
   most;
5. repeat until the message is classified as benign, the budget is exhausted,
   or no transform improves the score.

Two refinements matter for honesty:

* **Composition is allowed.** Each step builds on the previous winner, so the
  attacker can stack homoglyphs *and* redirect chaining *and* business-hours
  delivery. Testing transforms only in isolation would badly understate risk.
* **Random restarts.** Greedy search gets stuck in local optima, which would
  flatter the defence. ``restarts`` reruns the search from a randomly perturbed
  starting point and keeps the best result found.

Queries are counted honestly - every scored candidate is one query - so
"queries to evade" is a meaningful attacker-cost metric.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import numpy as np

from phishguard.adversarial.transforms import (
    TRANSFORMS,
    Transform,
    payload_preserved,
    transforms_for,
)
from phishguard.schemas import EmailMessage


class Scorer(Protocol):
    """Anything that maps messages to P(phishing)."""

    def predict_proba(self, messages: list[EmailMessage]) -> np.ndarray: ...


class RawScoreSurface:
    """Expose a detector's pre-calibration score as the attack surface.

    See :meth:`PhishGuardDetector.predict_proba_raw` for why: a saturated
    calibrator reports zero attack success because it gives the attacker no
    gradient, which flatters the defence rather than measuring it. Attacking
    the raw score grants a finer oracle than the deployed API exposes, so the
    resulting numbers are an upper bound on real-world attacker success.
    """

    def __init__(self, detector: Any) -> None:
        self.detector = detector

    def predict_proba(self, messages: list[EmailMessage]) -> np.ndarray:
        return self.detector.predict_proba_raw(messages)


@dataclass(slots=True)
class AttackResult:
    """Outcome of attacking one message."""

    original_score: float
    final_score: float
    evaded: bool
    queries: int
    steps: list[str] = field(default_factory=list)
    families_used: list[str] = field(default_factory=list)
    message: EmailMessage | None = None
    #: Score after each accepted step, for the attack-trajectory plot.
    trajectory: list[float] = field(default_factory=list)

    @property
    def score_drop(self) -> float:
        return self.original_score - self.final_score

    def as_dict(self) -> dict[str, Any]:
        return {
            "original_score": round(self.original_score, 5),
            "final_score": round(self.final_score, 5),
            "score_drop": round(self.score_drop, 5),
            "evaded": self.evaded,
            "queries": self.queries,
            "steps": list(self.steps),
            "families_used": sorted(set(self.families_used)),
            "trajectory": [round(s, 5) for s in self.trajectory],
        }


class BudgetedAttacker:
    """Greedy, budget-limited, decision-based evasion search."""

    def __init__(
        self,
        scorer: Scorer,
        *,
        budget: int = 10,
        evasion_threshold: float = 0.5,
        families: tuple[str, ...] | None = None,
        transforms: tuple[Transform, ...] | None = None,
        restarts: int = 0,
        seed: int = 7,
        max_candidates_per_step: int = 32,
    ) -> None:
        self.scorer = scorer
        self.budget = budget
        self.evasion_threshold = evasion_threshold
        self.transforms = transforms or transforms_for(families)
        self.restarts = restarts
        self.rng = np.random.default_rng(seed)
        self.max_candidates_per_step = max_candidates_per_step

    # ------------------------------------------------------------------ api
    def attack(self, message: EmailMessage) -> AttackResult:
        """Attack one message, keeping the best result across restarts."""
        best = self._greedy(message)
        for r in range(self.restarts):
            if best.evaded:
                break
            start = self._random_start(message, seed_offset=r)
            candidate = self._greedy(start, original=message)
            candidate.queries += best.queries
            if candidate.final_score < best.final_score:
                candidate.queries = candidate.queries
                best = candidate
        return best

    def attack_many(
        self,
        messages: list[EmailMessage],
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> list[AttackResult]:
        results: list[AttackResult] = []
        for i, m in enumerate(messages):
            results.append(self.attack(m))
            if progress is not None and (i + 1) % 25 == 0:
                progress(i + 1, len(messages))
        return results

    # ------------------------------------------------------------- internals
    def _random_start(self, message: EmailMessage, *, seed_offset: int) -> EmailMessage:
        rng = np.random.default_rng(int(self.rng.integers(0, 2**31)) + seed_offset)
        order = rng.permutation(len(self.transforms))
        for i in order:
            t = self.transforms[int(i)]
            try:
                candidate = t.fn(message, rng)
            except Exception:  # noqa: BLE001, S112 - an inapplicable transform is skipped, not fatal
                continue
            if candidate is not None and payload_preserved(message, candidate):
                return candidate
        return message

    def _greedy(self, start: EmailMessage, *, original: EmailMessage | None = None) -> AttackResult:
        reference = original or start
        current = start
        queries = 1
        current_score = float(self.scorer.predict_proba([current])[0])
        origin_score = float(
            self.scorer.predict_proba([reference])[0] if original is not None else current_score
        )
        if original is not None:
            queries += 1

        steps: list[str] = []
        families: list[str] = []
        trajectory: list[float] = [current_score]
        used: set[str] = set()

        while queries < self.budget and current_score >= self.evasion_threshold:
            candidates: list[tuple[Transform, EmailMessage]] = []
            for t in self.transforms:
                if t.id in used:
                    continue  # applying the same primitive twice rarely helps
                try:
                    cand = t.fn(current, self.rng)
                except Exception:  # noqa: BLE001, S112 - an inapplicable transform is skipped, not fatal
                    continue
                if cand is None or not payload_preserved(reference, cand):
                    continue
                candidates.append((t, cand))
                if len(candidates) >= self.max_candidates_per_step:
                    break
            if not candidates:
                break

            remaining = self.budget - queries
            if remaining <= 0:
                break
            candidates = candidates[:remaining]
            scores = self.scorer.predict_proba([c for _, c in candidates])
            queries += len(candidates)

            best_i = int(np.argmin(scores))
            best_score = float(scores[best_i])
            if best_score >= current_score - 1e-6:
                break  # no transform helps: local optimum

            transform, current = candidates[best_i][0], candidates[best_i][1]
            current_score = best_score
            used.add(transform.id)
            steps.append(transform.id)
            families.append(transform.family)
            trajectory.append(current_score)

        return AttackResult(
            original_score=origin_score,
            final_score=current_score,
            evaded=current_score < self.evasion_threshold,
            queries=queries,
            steps=steps,
            families_used=families,
            message=current,
            trajectory=trajectory,
        )


def single_transform_sweep(
    scorer: Scorer,
    messages: list[EmailMessage],
    *,
    transforms: tuple[Transform, ...] = TRANSFORMS,
    evasion_threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """Effectiveness of each transform applied on its own.

    Complements the composed attack: the greedy search says how bad a
    determined attacker can make things, while this says *which primitive* is
    doing the damage, which is what tells you where to spend defensive effort.
    """
    if not messages:
        return []
    rng = np.random.default_rng(11)
    base = scorer.predict_proba(messages)
    rows: list[dict[str, Any]] = []

    for t in transforms:
        perturbed: list[EmailMessage] = []
        keep: list[int] = []
        for i, m in enumerate(messages):
            try:
                cand = t.fn(m, rng)
            except Exception:  # noqa: BLE001
                cand = None
            if cand is not None and payload_preserved(m, cand):
                perturbed.append(cand)
                keep.append(i)
        if not perturbed:
            rows.append(
                {
                    "transform_id": t.id,
                    "family": t.family,
                    "name": t.name,
                    "channel": t.channel,
                    "applicable": 0,
                    "applicability_rate": 0.0,
                    "mean_score_drop": 0.0,
                    "evasion_rate": 0.0,
                    "max_score_drop": 0.0,
                }
            )
            continue
        after = scorer.predict_proba(perturbed)
        before = base[keep]
        drops = before - after
        evaded = int(np.sum((before >= evasion_threshold) & (after < evasion_threshold)))
        at_risk = int(np.sum(before >= evasion_threshold))
        rows.append(
            {
                "transform_id": t.id,
                "family": t.family,
                "name": t.name,
                "channel": t.channel,
                "applicable": len(perturbed),
                "applicability_rate": round(len(perturbed) / len(messages), 4),
                "mean_score_drop": round(float(np.mean(drops)), 5),
                "max_score_drop": round(float(np.max(drops)), 5),
                "evasion_rate": round(evaded / at_risk, 4) if at_risk else 0.0,
            }
        )
    rows.sort(key=lambda r: -r["mean_score_drop"])
    return rows
