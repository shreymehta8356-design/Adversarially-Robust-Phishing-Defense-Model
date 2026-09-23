"""An expected-cost model for the operating point.

The problem this solves
-----------------------
The deployed policy has three knobs -- the review threshold, the block
threshold and the abstention limit -- and until now all three were policy
constants chosen by judgement. An examiner is entitled to ask *why 0.40, why
0.80, why 0.45*. "They seemed reasonable" is not an answer; "they minimise
expected cost under these stated assumptions, and here is how far the optimum
moves when the assumptions change" is.

What is and is not assumed
--------------------------
Costs are expressed in **analyst reviews**: one message sent to a human costs
1 unit. The two other costs are then ratios to that, which is the only form in
which they can be stated honestly without inventing a currency figure:

    miss_cost          a phishing message delivered with no warning
    false_block_cost   a legitimate message quarantined

The defaults are illustrative assumptions, labelled as such everywhere they
appear, and the report is built so that no conclusion rests on them alone:
every result comes with a sensitivity sweep across two orders of magnitude of
each ratio. An organisation substitutes its own figures -- from incident
history, helpdesk tickets, analyst time -- and the model re-runs.

Two further assumptions matter more than people expect:

* **The base rate.** A synthetic evaluation corpus is ~46% phishing so that
  both classes are well represented; real inbound mail is overwhelmingly
  legitimate. The model estimates class-conditional behaviour from the test
  data and then *re-weights to a deployment prevalence*, which is the standard
  correction for prior shift. Scoring the policy at the corpus's own 46% would
  make every false alarm look nearly free.
* **The hard-case share.** Real phishing is a mixture of commodity campaigns
  and a minority of targeted, hard messages. The model mixes the ordinary test
  set's behaviour with PG-HARD's at a stated share, because the value of the
  abstention control lives almost entirely in that minority -- on easy mail it
  is pure cost.

Analyst error is included: a message sent to review is not a guaranteed catch.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np

BAND_ALLOW, BAND_REVIEW, BAND_BLOCK = 0, 1, 2


@dataclass(slots=True)
class CostAssumptions:
    """Every number the cost model depends on, in one place."""

    #: Cost of a phishing message delivered with no warning, in analyst reviews.
    miss_cost: float = 200.0
    #: Cost of quarantining a legitimate message, in analyst reviews.
    false_block_cost: float = 10.0
    #: Cost of one message sent to human review.
    review_cost: float = 1.0
    #: Probability an analyst lets a reviewed phishing message through anyway.
    analyst_miss_rate: float = 0.05
    #: Probability an analyst wrongly quarantines a reviewed legitimate message.
    analyst_false_block_rate: float = 0.01
    #: Share of inbound mail that is phishing in the deployment.
    phish_prevalence: float = 0.02
    #: Share of phishing that is hard / targeted (behaves like PG-HARD).
    hard_phish_share: float = 0.10
    #: Share of legitimate mail that is hard-negative-like. Held equal to the
    #: phishing share by default so that one number -- "how much of our
    #: traffic is hard" -- drives the model everywhere: the CLI, the dossier
    #: and the break-even search all use the same single share.
    hard_ham_share: float = 0.10

    def as_dict(self) -> dict[str, float]:
        return {k: float(v) for k, v in asdict(self).items()}


@dataclass(slots=True)
class ScoredSet:
    """Per-message quantities a policy needs, computed once and swept cheaply."""

    labels: np.ndarray
    scores: np.ndarray
    #: Spread between the most and least alarmed member; zeros when the system
    #: has no ensemble (a baseline), which disables abstention for it.
    spread: np.ndarray = field(default_factory=lambda: np.zeros(0))

    def __post_init__(self) -> None:
        self.labels = np.asarray(self.labels).astype(int)
        self.scores = np.asarray(self.scores, dtype=np.float64)
        if self.spread.size == 0:
            self.spread = np.zeros_like(self.scores)
        else:
            self.spread = np.asarray(self.spread, dtype=np.float64)


def score_set(detector: Any, messages: list[Any], labels: Any) -> ScoredSet:
    """Calibrated scores and member spread from the deployed detector."""
    # Scores after every score-modifying control (the velocity guard), exactly
    # as the API reports them; abstention is then re-applied per policy by
    # ``bands_for``, which mirrors ``band_with_abstention``.
    decisions = detector._decisions(messages)
    scores = np.array([d.score for d in decisions], dtype=np.float64)
    spread = (
        np.array([d.spread for d in decisions], dtype=np.float64)
        if len(detector.member_names) >= detector.settings.abstain_min_members
        else np.zeros(len(messages))
    )
    return ScoredSet(labels=np.asarray(labels), scores=scores, spread=spread)


ABSTAIN_MODES = ("symmetric", "escalate")


def bands_for(
    s: ScoredSet, review: float, block: float, abstain: float, mode: str = "symmetric"
) -> np.ndarray:
    """The deployed banding rule, vectorised: thresholds, then abstention.

    ``symmetric`` abstention (the deployed rule) sends any contested message to
    review, including one the score alone would have blocked. ``escalate``
    abstention only ever makes the decision *more* cautious: a contested ALLOW
    becomes REVIEW, a contested BLOCK stays BLOCK. The two differ exactly when a
    confident block is contested -- symmetric mode rescues a hard legitimate
    message from a false block there, escalate mode refuses to hand a probable
    phish to an analyst who might wave it through.
    """
    bands = np.where(
        s.scores >= block, BAND_BLOCK, np.where(s.scores >= review, BAND_REVIEW, BAND_ALLOW)
    )
    contested = s.spread >= abstain
    if mode == "escalate":
        return np.where(contested & (bands == BAND_ALLOW), BAND_REVIEW, bands)
    return np.where(contested, BAND_REVIEW, bands)


def class_rates(s: ScoredSet, bands: np.ndarray) -> dict[str, float]:
    """P(band | label) for both labels."""
    out: dict[str, float] = {}
    for label, name in ((1, "phish"), (0, "ham")):
        mask = s.labels == label
        n = int(mask.sum())
        for code, band in ((BAND_ALLOW, "allow"), (BAND_REVIEW, "review"), (BAND_BLOCK, "block")):
            out[f"{name}_{band}"] = float((bands[mask] == code).sum() / n) if n else 0.0
    return out


def expected_cost(
    ordinary: dict[str, float], hard: dict[str, float] | None, a: CostAssumptions
) -> dict[str, float]:
    """Expected cost per message, re-weighted to deployment prevalence.

    Returned per 1,000 messages alongside its decomposition, so a reader can
    see which failure mode is driving the total.
    """

    def per_phish(r: dict[str, float]) -> tuple[float, float, float]:
        miss = r["phish_allow"] * a.miss_cost
        review = r["phish_review"] * (a.review_cost + a.analyst_miss_rate * a.miss_cost)
        return miss, review, 0.0

    def per_ham(r: dict[str, float]) -> tuple[float, float, float]:
        fb = r["ham_block"] * a.false_block_cost
        review = r["ham_review"] * (a.review_cost + a.analyst_false_block_rate * a.false_block_cost)
        return 0.0, review, fb

    hp = a.hard_phish_share if hard else 0.0
    hn = a.hard_ham_share if hard else 0.0
    p = a.phish_prevalence

    om, orv, _ = per_phish(ordinary)
    _, orh, ofb = per_ham(ordinary)
    if hard:
        hm, hrv, _ = per_phish(hard)
        _, hrh, hfb = per_ham(hard)
    else:
        hm = hrv = hrh = hfb = 0.0

    miss = p * ((1 - hp) * om + hp * hm)
    review = p * ((1 - hp) * orv + hp * hrv) + (1 - p) * ((1 - hn) * orh + hn * hrh)
    false_block = (1 - p) * ((1 - hn) * ofb + hn * hfb)
    total = miss + review + false_block
    return {
        "per_1000": round(1000 * total, 4),
        "missed_phishing_per_1000": round(1000 * miss, 4),
        "review_per_1000": round(1000 * review, 4),
        "false_block_per_1000": round(1000 * false_block, 4),
    }


def _review_load(
    ordinary: dict[str, float], hard: dict[str, float] | None, a: CostAssumptions
) -> float:
    """Messages sent to a human per 1,000 inbound, at deployment prevalence."""
    hp = a.hard_phish_share if hard else 0.0
    hn = a.hard_ham_share if hard else 0.0
    p = a.phish_prevalence
    hard = hard or {"phish_review": 0.0, "ham_review": 0.0}
    phish = (1 - hp) * ordinary["phish_review"] + hp * hard["phish_review"]
    ham = (1 - hn) * ordinary["ham_review"] + hn * hard["ham_review"]
    return 1000 * (p * phish + (1 - p) * ham)


def evaluate_policy(
    ordinary: ScoredSet,
    hard: ScoredSet | None,
    a: CostAssumptions,
    review: float,
    block: float,
    abstain: float,
    mode: str = "symmetric",
) -> dict[str, Any]:
    o = class_rates(ordinary, bands_for(ordinary, review, block, abstain, mode))
    h = (
        class_rates(hard, bands_for(hard, review, block, abstain, mode))
        if hard is not None
        else None
    )
    cost = expected_cost(o, h, a)
    cost["reviews_per_1000"] = round(_review_load(o, h, a), 3)
    return {
        "review": round(review, 4),
        "block": round(block, 4),
        "abstain": round(abstain, 4) if abstain <= 1.0 else None,
        "abstain_mode": mode if abstain <= 1.0 else None,
        **cost,
    }


GRID = np.round(np.arange(0.05, 0.96, 0.05), 2)
ABSTAIN_GRID = np.round(np.concatenate([np.arange(0.25, 0.86, 0.05), [9.0]]), 2)


class RateTable:
    """Class-conditional band rates for every policy on the grid, computed once.

    Expected cost is linear in these rates for fixed assumptions, so the
    sensitivity sweep and the break-even search -- dozens of assumption sets --
    re-price one table instead of re-banding every message thousands of times.
    """

    def __init__(self, ordinary: ScoredSet, hard: ScoredSet | None) -> None:
        self.policies: list[tuple[float, float, float, str]] = []
        self.ordinary: list[dict[str, float]] = []
        self.hard: list[dict[str, float] | None] = []
        for ab in ABSTAIN_GRID:
            # With abstention off the two modes are identical; enumerate once.
            modes = ABSTAIN_MODES if ab <= 1.0 else ("symmetric",)
            for mode in modes:
                for rv in GRID:
                    for bl in GRID:
                        if bl < rv:
                            continue
                        pol = (float(rv), float(bl), float(ab), mode)
                        self.policies.append(pol)
                        self.ordinary.append(class_rates(ordinary, bands_for(ordinary, *pol)))
                        self.hard.append(
                            class_rates(hard, bands_for(hard, *pol)) if hard is not None else None
                        )

    def best(
        self, a: CostAssumptions, *, allow_abstain: bool = True, use_hard: bool = True
    ) -> dict[str, Any]:
        best: dict[str, Any] | None = None
        for pol, o, h in zip(self.policies, self.ordinary, self.hard, strict=True):
            if not allow_abstain and pol[2] <= 1.0:
                continue
            cost = expected_cost(o, h if use_hard else None, a)
            if best is None or cost["per_1000"] < best["per_1000"] - 1e-12:
                cost["reviews_per_1000"] = round(_review_load(o, h if use_hard else None, a), 3)
                best = {
                    "review": round(pol[0], 4),
                    "block": round(pol[1], 4),
                    "abstain": round(pol[2], 4) if pol[2] <= 1.0 else None,
                    "abstain_mode": pol[3] if pol[2] <= 1.0 else None,
                    **cost,
                }
        return best or {}


def optimise(
    ordinary: ScoredSet,
    hard: ScoredSet | None,
    a: CostAssumptions,
    *,
    allow_abstain: bool = True,
    table: RateTable | None = None,
) -> dict[str, Any]:
    """Exhaustive search over the policy grid."""
    table = table or RateTable(ordinary, hard)
    return table.best(a, allow_abstain=allow_abstain, use_hard=hard is not None)


def cost_curve(
    ordinary: ScoredSet,
    hard: ScoredSet | None,
    a: CostAssumptions,
    *,
    review: float,
    abstain: float,
    mode: str = "symmetric",
) -> list[dict[str, Any]]:
    """Expected cost as the block threshold moves, other knobs held fixed."""
    rows = []
    for bl in np.round(np.arange(max(review, 0.05), 1.0001, 0.025), 3):
        rows.append(evaluate_policy(ordinary, hard, a, review, float(bl), abstain, mode))
    return rows


#: Four organisation profiles spanning the realistic range of the two cost
#: ratios. They are illustrative, like the defaults, and exist so that the
#: default policy can be chosen by a stated decision rule rather than by feel.
ORG_PROFILES: tuple[tuple[str, dict[str, float]], ...] = (
    ("Lean IT team", {"miss_cost": 200.0, "false_block_cost": 10.0}),
    ("Finance / legal - invoices matter", {"miss_cost": 500.0, "false_block_cost": 200.0}),
    ("Staffed SOC, high stakes", {"miss_cost": 2000.0, "false_block_cost": 100.0}),
    ("Regulated, zero tolerance", {"miss_cost": 5000.0, "false_block_cost": 500.0}),
)


def minimax_regret(
    table: RateTable,
    base: CostAssumptions,
    *,
    prefer: tuple[float, float, float, str] | None = None,
) -> dict[str, Any]:
    """The policy whose worst-case excess cost across ORG_PROFILES is smallest.

    Minimax regret is the textbook rule for choosing when the costs are
    uncertain: it does not need to know which profile applies, only that one
    of them does. Ties are broken towards ``prefer`` (the current default), so
    the rule never changes a setting that makes no difference.
    """
    profiles = [CostAssumptions(**{**base.as_dict(), **kw}) for _, kw in ORG_PROFILES]
    best_costs = [table.best(a)["per_1000"] for a in profiles]
    ranked = []
    for pol, o, h in zip(table.policies, table.ordinary, table.hard, strict=True):
        costs = [expected_cost(o, h, a)["per_1000"] for a in profiles]
        regrets = [c - b for c, b in zip(costs, best_costs, strict=False)]
        distance = (
            0.0
            if prefer is None
            else sum(abs(x - y) for x, y in zip(pol[:3], prefer[:3], strict=False))
            + (pol[3] != prefer[3])
        )
        ranked.append((round(max(regrets), 6), distance, pol, costs, regrets))
    ranked.sort(key=lambda r: (r[0], r[1]))
    regret, _, pol, costs, regrets = ranked[0]
    return {
        "review": pol[0],
        "block": pol[1],
        "abstain": pol[2] if pol[2] <= 1.0 else None,
        "abstain_mode": pol[3] if pol[2] <= 1.0 else None,
        "max_regret_per_1000": round(regret, 3),
        "by_profile": [
            {
                "profile": name,
                "cost_per_1000": round(c, 3),
                "regret_per_1000": round(r, 3),
                "best_possible_per_1000": round(b, 3),
            }
            for (name, _), c, r, b in zip(ORG_PROFILES, costs, regrets, best_costs, strict=False)
        ],
    }


def policy_regret(
    table: RateTable,
    base: CostAssumptions,
    pol: tuple[float, float, float, str],
    ordinary: ScoredSet,
    hard: ScoredSet,
) -> float:
    """Worst-case regret of one given policy across ORG_PROFILES."""
    worst = 0.0
    for _, kw in ORG_PROFILES:
        a = CostAssumptions(**{**base.as_dict(), **kw})
        c = evaluate_policy(ordinary, hard, a, *pol)["per_1000"]
        worst = max(worst, c - table.best(a)["per_1000"])
    return round(worst, 3)


def robustness_of_policies(
    detector: Any,
    targets: list[Any],
    policies: dict[str, tuple[float, float, float, str]],
    *,
    budgets: tuple[int, ...] = (0, 40, 120),
    seed: int = 7,
) -> dict[str, Any]:
    """Silent delivery under the adaptive attack, for each candidate policy.

    The cost model prices *benign* traffic. An attacker adapts to whatever
    policy is deployed, so a policy that is cheap on ordinary mail can be cheap
    precisely because it leaves room for an attacker. This check measures that
    directly: same targets, same adaptive attacker, one run per policy.
    """
    import copy

    from phishguard.adversarial.adaptive import AdaptiveDecisionSurface, budget_sweep

    out: dict[str, Any] = {}
    for name, (review, block, abstain, mode) in policies.items():
        d = copy.copy(detector)
        d.settings = copy.copy(detector.settings)
        d.review_threshold, d.block_threshold = review, block
        d.settings.abstain_disagreement = abstain if abstain <= 1.0 else 9.0
        d.settings.abstain_mode = mode
        rows = budget_sweep(
            targets=targets,
            attacker_surface=AdaptiveDecisionSurface(d),
            judge=d.bands,
            evasion_threshold=review,
            budgets=budgets,
            seed=seed,
        )
        out[name] = {
            "policy": {
                "review": review,
                "block": block,
                "abstain": abstain if abstain <= 1.0 else None,
                "abstain_mode": mode,
            },
            "rows": [
                {
                    "budget": r["budget"],
                    "silent_delivery_rate": r["silent_delivery_rate"],
                    "silent_delivered": r.get("silent_delivered"),
                    "auto_blocked_rate": r["auto_blocked_rate"],
                }
                for r in rows
            ],
            "worst_silent_delivery_rate": max(r["silent_delivery_rate"] for r in rows),
            # Counts as well as rates: with a few dozen targets, one record is
            # several percentage points, and the narrative must know that.
            "worst_silent_delivered": max(int(r.get("silent_delivered") or 0) for r in rows),
            "n_targets": len(targets),
        }
    return out


def run_cost_analysis(
    *,
    detector: Any,
    ordinary_messages: list[Any],
    ordinary_labels: Any,
    hard_messages: list[Any],
    hard_labels: Any,
    text_baseline: Any | None = None,
    assumptions: CostAssumptions | None = None,
    attack_targets: list[Any] | None = None,
    attack_budgets: tuple[int, ...] = (0, 40, 120),
) -> dict[str, Any]:
    """The full analysis: deployed policy, optimum, sensitivity, break-even,
    minimax-regret choice, and -- when attack targets are supplied -- how each
    candidate policy holds up against the adaptive attacker."""
    a = assumptions or CostAssumptions()
    ordinary = score_set(detector, ordinary_messages, ordinary_labels)
    hard = score_set(detector, hard_messages, hard_labels)

    deployed_params = (
        float(detector.review_threshold),
        float(detector.block_threshold),
        float(detector.settings.abstain_disagreement) if detector.defenses.abstain else 9.0,
        getattr(detector.settings, "abstain_mode", "symmetric"),
    )
    table = RateTable(ordinary, hard)
    deployed = evaluate_policy(ordinary, hard, a, *deployed_params)
    optimum = table.best(a)
    no_abstain = table.best(a, allow_abstain=False)

    # Same analysis on ordinary mail alone: what abstention looks like if the
    # hard minority is ignored. The gap between the two optima is the finding.
    ordinary_only = table.best(a, use_hard=False)
    ordinary_only_no_abstain = table.best(a, allow_abstain=False, use_hard=False)

    out: dict[str, Any] = {
        "assumptions": a.as_dict(),
        "assumptions_note": (
            "Costs are in units of one analyst review. The defaults are "
            "illustrative assumptions, not measurements; every conclusion "
            "below is re-derived across a sensitivity sweep."
        ),
        "deployed": deployed,
        "optimum": optimum,
        "optimum_without_abstention": no_abstain,
        "ordinary_mail_only": {
            "optimum": ordinary_only,
            "optimum_without_abstention": ordinary_only_no_abstain,
        },
        "deployed_regret_per_1000": round(deployed["per_1000"] - optimum["per_1000"], 4),
        "abstention_saving_per_1000": round(no_abstain["per_1000"] - optimum["per_1000"], 4),
        "curve": cost_curve(
            ordinary,
            hard,
            a,
            review=deployed_params[0],
            abstain=deployed_params[2],
            mode=deployed_params[3],
        ),
    }

    # --- the text-only filter, optimised under the same assumptions
    if text_baseline is not None:
        o_tx = ScoredSet(labels=ordinary.labels, scores=text_baseline.score(ordinary_messages))
        h_tx = ScoredSet(labels=hard.labels, scores=text_baseline.score(hard_messages))
        tx_opt = RateTable(o_tx, h_tx).best(a, allow_abstain=False)
        out["text_only"] = {
            "optimum": tx_opt,
            "note": "Optimised over the same threshold grid; it has no abstention control.",
        }
        out["saving_vs_text_only_per_1000"] = round(tx_opt["per_1000"] - optimum["per_1000"], 4)

    # --- sensitivity: how the optimum and the value of abstention move
    sens = []
    for ratio in (20.0, 50.0, 100.0, 200.0, 500.0, 1000.0):
        for hp in (0.0, 0.02, 0.05, 0.10, 0.25):
            aa = CostAssumptions(**{**a.as_dict(), "miss_cost": ratio, "hard_phish_share": hp})
            opt = table.best(aa)
            flat = table.best(aa, allow_abstain=False)
            dep = evaluate_policy(ordinary, hard, aa, *deployed_params)
            sens.append(
                {
                    "miss_cost": ratio,
                    "hard_phish_share": hp,
                    "optimum_review": opt["review"],
                    "optimum_block": opt["block"],
                    "optimum_abstain": opt["abstain"],
                    "optimum_per_1000": opt["per_1000"],
                    "deployed_per_1000": dep["per_1000"],
                    "no_abstention_per_1000": flat["per_1000"],
                    "abstention_pays": opt["abstain"] is not None,
                }
            )
    out["sensitivity"] = sens

    # --- break-even: the smallest share of *hard traffic* at which abstention
    # pays. One share is applied to both classes: an earlier version varied
    # only the phishing share while holding hard legitimate mail at 5%, which
    # credited abstention with a benefit that came from the other class and
    # reported a meaningless break-even of 0%.
    breakeven = None
    for h in np.round(np.arange(0.0, 0.301, 0.0025), 4):
        aa = CostAssumptions(
            **{**a.as_dict(), "hard_phish_share": float(h), "hard_ham_share": float(h)}
        )
        with_ab = table.best(aa)
        without = table.best(aa, allow_abstain=False)
        if with_ab["per_1000"] < without["per_1000"] - 1e-9:
            breakeven = float(h)
            break
    out["abstention_breakeven_hard_share"] = breakeven

    # --- the frontier: what each policy trades between safety and workload.
    # A single "optimum" hides that it is an optimum *for one cost ratio*; the
    # frontier shows every policy a different organisation might rationally
    # choose, and where the deployed default sits on it.
    points = []
    for pol, o, h in zip(table.policies, table.ordinary, table.hard, strict=True):
        cst = expected_cost(o, h, a)
        points.append(
            {
                "review": pol[0],
                "block": pol[1],
                "abstain": pol[2] if pol[2] <= 1.0 else None,
                "abstain_mode": pol[3] if pol[2] <= 1.0 else None,
                "reviews_per_1000": round(_review_load(o, h, a), 3),
                "missed_phishing_per_1000": round(
                    1000
                    * a.phish_prevalence
                    * (
                        (1 - a.hard_phish_share) * o["phish_allow"]
                        + a.hard_phish_share * (h or o)["phish_allow"]
                    ),
                    5,
                ),
                "false_blocks_per_1000": round(
                    1000
                    * (1 - a.phish_prevalence)
                    * (
                        (1 - a.hard_ham_share) * o["ham_block"]
                        + a.hard_ham_share * (h or o)["ham_block"]
                    ),
                    5,
                ),
                "cost_per_1000": cst["per_1000"],
            }
        )
    frontier = []
    for pt in sorted(points, key=lambda r: (r["reviews_per_1000"], r["missed_phishing_per_1000"])):
        if (
            not frontier
            or pt["missed_phishing_per_1000"] < frontier[-1]["missed_phishing_per_1000"] - 1e-9
        ):
            frontier.append(pt)
    out["frontier"] = frontier
    out["deployed_point"] = next(
        (
            pt
            for pt in points
            if abs(pt["review"] - deployed_params[0]) < 1e-9
            and abs(pt["block"] - deployed_params[1]) < 1e-9
            and (
                (pt["abstain"] is None and deployed_params[2] > 1.0)
                or (
                    pt["abstain"] is not None
                    and abs(pt["abstain"] - deployed_params[2]) < 1e-9
                    and pt.get("abstain_mode") == deployed_params[3]
                )
            )
        ),
        {
            "review": deployed_params[0],
            "block": deployed_params[1],
            "abstain": deployed_params[2] if deployed_params[2] <= 1.0 else None,
            "reviews_per_1000": deployed["reviews_per_1000"],
            "missed_phishing_per_1000": None,
            "cost_per_1000": deployed["per_1000"],
        },
    )
    # Recompute the deployed point's rates exactly, in case it is off-grid.
    o_d = class_rates(ordinary, bands_for(ordinary, *deployed_params))
    h_d = class_rates(hard, bands_for(hard, *deployed_params))
    out["deployed_point"].update(
        {
            "reviews_per_1000": round(_review_load(o_d, h_d, a), 3),
            "missed_phishing_per_1000": round(
                1000
                * a.phish_prevalence
                * (
                    (1 - a.hard_phish_share) * o_d["phish_allow"]
                    + a.hard_phish_share * h_d["phish_allow"]
                ),
                5,
            ),
            "false_blocks_per_1000": round(
                1000
                * (1 - a.phish_prevalence)
                * ((1 - a.hard_ham_share) * o_d["ham_block"] + a.hard_ham_share * h_d["ham_block"]),
                5,
            ),
        }
    )

    # --- which policy each kind of organisation should pick
    out["by_miss_cost"] = []
    for ratio in (20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 5000.0):
        aa = CostAssumptions(**{**a.as_dict(), "miss_cost": ratio})
        best = table.best(aa)
        out["by_miss_cost"].append({"miss_cost": ratio, **best})

    # --- choosing a default without knowing the organisation
    mm = minimax_regret(table, a, prefer=deployed_params)
    out["minimax_regret"] = mm

    def point_for(pol: tuple[float, float, float, str]) -> dict[str, Any]:
        """Workload / safety coordinates of one policy, computed directly.

        A cost optimum need not lie on the two-axis frontier (cost also counts
        false blocks), so candidates are placed by their own rates rather than
        looked up on the frontier.
        """
        o_ = class_rates(ordinary, bands_for(ordinary, *pol))
        h_ = class_rates(hard, bands_for(hard, *pol))
        return {
            "review": pol[0],
            "block": pol[1],
            "abstain": pol[2] if pol[2] <= 1.0 else None,
            "abstain_mode": pol[3] if pol[2] <= 1.0 else None,
            "reviews_per_1000": round(_review_load(o_, h_, a), 3),
            "missed_phishing_per_1000": round(
                1000
                * a.phish_prevalence
                * (
                    (1 - a.hard_phish_share) * o_["phish_allow"]
                    + a.hard_phish_share * h_["phish_allow"]
                ),
                5,
            ),
            "false_blocks_per_1000": round(
                1000
                * (1 - a.phish_prevalence)
                * ((1 - a.hard_ham_share) * o_["ham_block"] + a.hard_ham_share * h_["ham_block"]),
                5,
            ),
        }

    def as_pol(r: dict[str, Any]) -> tuple[float, float, float, str]:
        return (
            r["review"],
            r["block"],
            r["abstain"] if r.get("abstain") is not None else 9.0,
            r.get("abstain_mode") or "symmetric",
        )

    out["candidate_points"] = {
        "deployed": point_for(deployed_params),
        "minimax_regret": point_for(as_pol(mm)),
        "cost_optimal": point_for(as_pol(optimum)),
    }
    out["candidate_costs"] = {
        "deployed": deployed["per_1000"],
        "minimax_regret": evaluate_policy(ordinary, hard, a, *as_pol(mm))["per_1000"],
        "cost_optimal": optimum["per_1000"],
    }
    out["deployed_max_regret_per_1000"] = policy_regret(table, a, deployed_params, ordinary, hard)
    out["profiles"] = [{"profile": name, **kw} for name, kw in ORG_PROFILES]

    # --- ...and the question the cost model cannot answer on its own
    if attack_targets:
        candidates = {
            "deployed": deployed_params,
            "minimax_regret": (
                mm["review"],
                mm["block"],
                mm["abstain"] if mm["abstain"] is not None else 9.0,
                mm["abstain_mode"] or "symmetric",
            ),
            "cost_optimal": (
                optimum["review"],
                optimum["block"],
                optimum["abstain"] if optimum["abstain"] is not None else 9.0,
                optimum.get("abstain_mode") or "symmetric",
            ),
        }
        # Identical policies need measuring once.
        seen: dict[tuple, str] = {}
        unique = {}
        for name, pol in candidates.items():
            if pol in seen:
                continue
            seen[pol] = name
            unique[name] = pol
        rob = robustness_of_policies(detector, attack_targets, unique, budgets=attack_budgets)
        for name, pol in candidates.items():
            if name not in rob:
                rob[name] = rob[seen[pol]]
        out["under_attack"] = rob
    return out


def _policy_label(r: dict[str, Any]) -> str:
    if r.get("abstain") is None:
        return "off"
    return f"{r['abstain']:.2f} ({r.get('abstain_mode') or 'symmetric'})"


def _candidate_finding(c: dict[str, Any], costs: dict[str, float], ua: dict[str, Any]) -> str:
    """What the candidate table shows, stated at the resolution the data has.

    With a few dozen attacked records, a difference of one or two records is
    several percentage points and is not a finding; it is reported as
    unresolved rather than as a ranking.
    """
    dep = ua.get("deployed") or {}
    n = dep.get("n_targets")
    names = {
        "minimax_regret": "the minimax-regret choice",
        "cost_optimal": "the cost-optimal policy",
    }
    tol = 2  # records

    def k(key: str) -> int | None:
        x = ua.get(key) or {}
        return x.get("worst_silent_delivered") if n else None

    parts: list[str] = []
    for key in ("cost_optimal", "minimax_regret"):
        if key not in ua or not dep:
            continue
        alt, d = ua[key], dep
        cheaper = costs.get(key) is not None and costs[key] < costs["deployed"]
        if n and k(key) is not None and k("deployed") is not None:
            diff = k(key) - k("deployed")
            counts = f"{k(key)} of {n} against {k('deployed')} for the deployed default"
        else:
            diff = round(
                (alt["worst_silent_delivery_rate"] - d["worst_silent_delivery_rate"]) * 100
            )
            counts = (
                f"{alt['worst_silent_delivery_rate']:.0%} against "
                f"{d['worst_silent_delivery_rate']:.0%} for the deployed default"
            )
        if diff > tol:
            parts.append(
                f"{names[key].capitalize()} is "
                + (
                    "cheaper on benign traffic partly because it leaves an attacker room: "
                    if cheaper
                    else "worse under attack: "
                )
                + f"it delivers {alt['worst_silent_delivery_rate']:.0%} of hard phishing under the "
                f"adaptive attack ({counts})."
            )
        elif diff < -tol:
            parts.append(
                f"{names[key].capitalize()} delivers less under attack ({counts})"
                + (" and is also cheaper on benign traffic" if cheaper else "")
                + ", so on this run it is the stronger policy."
            )
        else:
            parts.append(
                f"{names[key].capitalize()} is within {tol} records of the deployed default under "
                f"attack ({counts})"
                + (
                    f" and costs {costs[key]:.0f} rather than {costs['deployed']:.0f} per 1,000 on "
                    "benign traffic"
                    if costs.get(key) is not None
                    else ""
                )
                + "; a difference this run cannot resolve."
            )
    pts = c.get("candidate_points") or {}
    dep_fb = (pts.get("deployed") or {}).get("false_blocks_per_1000")
    mm_fb = (pts.get("minimax_regret") or {}).get("false_blocks_per_1000")
    profiles = c.get("profiles") or []
    if dep_fb is not None and mm_fb is not None and dep_fb > mm_fb and profiles:
        dearest = max(profiles, key=lambda pr: pr["false_block_cost"])
        parts.append(
            f"Most of the gap in worst-case regret is false blocks: at the stated share of hard "
            f"traffic the deployed default quarantines {dep_fb:.1f} legitimate messages per "
            f"1,000 against {mm_fb:.1f} for the minimax-regret choice, and the "
            f"{dearest['profile']} profile prices each at {dearest['false_block_cost']:.0f} "
            "reviews. Because every PG-HARD case stands for a slice of real traffic, one case "
            "that is blocked in all its variants moves this figure on its own (section 4 names it)."
        )
    parts.append(
        "The default is **not** re-tuned from this table: the candidates are chosen on the "
        "same test mail and PG-HARD records they are scored on, so adopting one here would "
        "tune the policy to the benchmark. The way to move it is `phishguard cost --attack` "
        "on an organisation's own traffic. The deployed default's price on benign traffic "
        f"is stated either way: a worst-case regret of {c.get('deployed_max_regret_per_1000', 0):.0f} "
        "cost units per 1,000 messages across the four profiles below."
    )
    return "**The finding.** " + " ".join(parts) + "\n"


def render_cost_markdown(c: dict[str, Any]) -> str:
    a = c["assumptions"]
    d, o, n = c["deployed"], c["optimum"], c["optimum_without_abstention"]
    dp = c.get("deployed_point", {})
    lines = ["## Operating point — an expected-cost justification\n"]
    lines.append(
        "Costs are in units of **one analyst review**. Assumed, illustratively — an "
        "organisation substitutes its own: a phish delivered with no warning costs "
        f"**{a['miss_cost']:.0f}** reviews, a wrongly quarantined legitimate message "
        f"**{a['false_block_cost']:.0f}**; analysts miss {a['analyst_miss_rate']:.0%} of "
        f"the phishing they review. Traffic: {a['phish_prevalence']:.1%} of inbound mail "
        f"is phishing; {a['hard_phish_share']:.0%} of phishing and "
        f"{a['hard_ham_share']:.0%} of legitimate mail behaves like PG-HARD. Class "
        "behaviour is measured on the test data and re-weighted to that prevalence.\n"
    )
    lines.append(
        "| Policy | Review ≥ | Block ≥ | Abstain at spread ≥ | Cost / 1,000 | "
        "Sent to a human / 1,000 |"
    )
    lines.append("|---|---|---|---|---|---|")

    def row(name: str, r: dict[str, Any]) -> str:
        return (
            f"| {name} | {r['review']:.2f} | {r['block']:.2f} | {_policy_label(r)} | "
            f"**{r['per_1000']:.1f}** | {r['reviews_per_1000']:.1f} |"
        )

    lines.append(row("**Deployed**", d))
    lines.append(row("Cost-optimal under these assumptions", o))
    lines.append(row("Cost-optimal, abstention disabled", n))
    if "text_only" in c:
        lines.append(row("Text-only filter, cost-optimal", c["text_only"]["optimum"]))
    lines.append("")

    if dp and dp.get("missed_phishing_per_1000") is not None:
        opt_pts = [
            pt
            for pt in c.get("frontier", [])
            if abs(pt["reviews_per_1000"] - o["reviews_per_1000"]) < 1e-6
        ]
        opt_miss = (
            opt_pts[0]["missed_phishing_per_1000"]
            if opt_pts
            else o["missed_phishing_per_1000"] / max(a["miss_cost"], 1e-9)
        )
        lines.append(
            "**What the two policies trade.** The deployed policy is the safety-first end "
            f"of the frontier: {dp['missed_phishing_per_1000']:.3f} silently delivered phish "
            f"per 1,000 messages, at the price of sending {dp['reviews_per_1000']:.0f} in "
            "every 1,000 to a human. The cost-optimal policy cuts that review load to "
            f"{o['reviews_per_1000']:.0f} per 1,000 and accepts "
            f"{opt_miss:.3f} silent deliveries per 1,000 in exchange. Neither is 'correct': "
            "the choice depends on what a missed phish costs *this* organisation, which is "
            "why the next table exists.\n"
        )
    mm = c.get("minimax_regret")
    ua = c.get("under_attack")
    if mm and ua:
        lines.append("### Candidate defaults, priced and attacked\n")
        lines.append(
            "Three candidate defaults, priced on benign traffic and then attacked. "
            "*Worst-case regret* is how much more a policy costs than the best "
            "possible policy, for whichever of four organisation profiles it fares "
            "worst on. *Under attack* is the share of hard phishing the adaptive "
            "attacker gets delivered with no warning.\n"
        )
        lines.append(
            "| Candidate | Review / block / abstain | Cost / 1,000 | Worst-case regret / 1,000 "
            "| Delivered under attack (worst budget) |"
        )
        lines.append("|---|---|---|---|---|")
        costs = {
            "deployed": c["deployed"]["per_1000"],
            "cost_optimal": c["optimum"]["per_1000"],
            **(c.get("candidate_costs") or {}),
        }
        cand = [
            ("deployed", "Deployed default", c["deployed"], c.get("deployed_max_regret_per_1000")),
            ("minimax_regret", "Minimax-regret choice", mm, mm.get("max_regret_per_1000")),
            ("cost_optimal", "Cost-optimal at the stated assumptions", c["optimum"], None),
        ]
        for key, name, pol, regret in cand:
            attack = ua.get(key)
            reg = "—" if regret is None else f"{regret:.1f}"
            cost_txt = "—" if costs.get(key) is None else f"{costs[key]:.1f}"
            if not attack:
                atk = "—"
            else:
                atk = f"**{attack['worst_silent_delivery_rate']:.1%}**"
                if attack.get("n_targets"):
                    atk += f" ({attack['worst_silent_delivered']} of {attack['n_targets']})"
            lines.append(
                f"| {name} | {pol['review']:.2f} / {pol['block']:.2f} / "
                f"{_policy_label(pol)} | {cost_txt} | {reg} | {atk} |"
            )
        lines.append("")
        lines.append(_candidate_finding(c, costs, ua))
        lines.append("Profiles used for the regret calculation (illustrative):\n")
        for prof in c.get("profiles", []):
            lines.append(
                f"- **{prof['profile']}** — missed phish {prof['miss_cost']:.0f}, "
                f"false block {prof['false_block_cost']:.0f} reviews"
            )
        lines.append("")

    lines.append("### Which policy for which organisation\n")
    lines.append(
        "| If a missed phish costs … reviews | Review ≥ | Block ≥ | Abstain | "
        "Cost / 1,000 | Sent to a human / 1,000 |"
    )
    lines.append("|---|---|---|---|---|---|")
    for r in c.get("by_miss_cost", []):
        lines.append(
            f"| {r['miss_cost']:.0f} | {r['review']:.2f} | {r['block']:.2f} | "
            f"{_policy_label(r)} | {r['per_1000']:.1f} | {r['reviews_per_1000']:.1f} |"
        )
    lines.append("")
    be = c.get("abstention_breakeven_hard_share")
    oo = c["ordinary_mail_only"]
    lines.append(
        "**Where abstention earns its place.** On ordinary mail alone the cost-optimal "
        "policy "
        + ("disables abstention" if oo["optimum"]["abstain"] is None else "still keeps abstention")
        + " — on easy mail, escalation is mostly cost. "
        + (
            f"It pays for itself once **{be:.1%}** of traffic (in both classes) is hard."
            if be is not None
            else "Under these assumptions it never pays for itself."
        )
        + "\n"
    )
    sv = c.get("saving_vs_text_only_per_1000")
    if sv is not None and sv >= 0:
        lines.append(
            f"Against the best the text-only filter can do under the same assumptions, "
            f"PhishGuard at its cost-optimal policy saves **{sv:.1f}** cost units per "
            "1,000 messages.\n"
        )
    elif sv is not None:
        tx = c.get("text_only_under_attack") or {}
        lines.append(
            "Under these assumptions the text-only filter, at its own cost-optimal policy, "
            f"is **cheaper** on benign traffic, by {-sv:.1f} cost units per 1,000 messages. "
            "That price leaves out the attacker"
            + (
                f": under the adaptive attack the text-only filter delivers "
                f"{tx['silent_delivery_rate']:.0%} of hard phishing unwarned at budget "
                f"{tx['budget']} (section 4)."
                if tx
                else "."
            )
            + "\n"
        )
    lines.append("### Sensitivity\n")
    lines.append(
        "| Miss cost | Hard share | Optimal review / block / abstain | Optimal cost | "
        "Deployed cost | Abstention pays? |"
    )
    lines.append("|---|---|---|---|---|---|")
    for srow in c["sensitivity"]:
        ab = "off" if srow["optimum_abstain"] is None else f"{srow['optimum_abstain']:.2f}"
        lines.append(
            f"| {srow['miss_cost']:.0f} | {srow['hard_phish_share']:.0%} | "
            f"{srow['optimum_review']:.2f} / {srow['optimum_block']:.2f} / {ab} | "
            f"{srow['optimum_per_1000']:.1f} | {srow['deployed_per_1000']:.1f} | "
            f"{'yes' if srow['abstention_pays'] else 'no'} |"
        )
    lines.append("")
    return "\n".join(lines)
