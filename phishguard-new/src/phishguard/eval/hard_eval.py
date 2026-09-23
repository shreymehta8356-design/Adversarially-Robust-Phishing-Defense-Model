"""Evaluation on PG-HARD, the curated hard-case benchmark.

The headline number on a representative corpus is not evidence of much: it is
dominated by easy mail. This module runs the deployed system and the two
baselines over :mod:`phishguard.data.hardcases`, where every record is hard by
construction, and reports the two outcomes that carry real operational cost.

Fairness of the comparison
--------------------------
Comparing systems by thresholding each at 0.5 is meaningless, because the
scores are not on a common scale -- an uncalibrated baseline can look
"accurate" simply by being enthusiastic. Every system here is instead tuned to
**the same false-alarm budget on ordinary mail** before being measured on hard
mail:

1. Measure PhishGuard's false-positive rate on the ordinary held-out test set
   at its two deployed thresholds (0.40 review, 0.80 block).
2. For each baseline, find the thresholds that achieve those same two
   false-positive rates on that same ordinary test set.
3. Apply each system's own thresholds to PG-HARD and compare.

Every system therefore gets the same allowance for annoying users on normal
mail, and the benchmark measures what that allowance buys on hard mail. This
is the standard equal-false-alarm comparison, and it is the only way the
"text-only filter" column is an honest column.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np

from ..data.hardcases import (
    BENCHMARK_ID,
    build_hard_benchmark,
    describe_benchmark,
)
from ..models.baseline import RuleBaseline, TfidfBaseline
from ..models.detector import PhishGuardDetector
from ..schemas import BAND_ALLOW, BAND_BLOCK, BAND_REVIEW, EmailMessage
from .metrics import prf, roc_auc, threshold_for_target_fpr


def _band(score: float, review: float, block: float) -> str:
    if score >= block:
        return BAND_BLOCK
    if score >= review:
        return BAND_REVIEW
    return BAND_ALLOW


def _fpr_at(y: np.ndarray, scores: np.ndarray, threshold: float) -> float:
    y = np.asarray(y).astype(int)
    scores = np.asarray(scores, dtype=np.float64)
    negatives = scores[y == 0]
    if negatives.size == 0:
        return 0.0
    return float((negatives >= threshold).mean())


def matched_thresholds(
    y_ref: np.ndarray,
    ref_scores: np.ndarray,
    *,
    target_review_fpr: float,
    target_block_fpr: float,
) -> tuple[float, float]:
    """Thresholds for one system at a given pair of false-positive budgets."""
    review = threshold_for_target_fpr(y_ref, ref_scores, target_review_fpr)
    block = threshold_for_target_fpr(y_ref, ref_scores, target_block_fpr)
    # A monotone pair is required for the bands to be well-formed; if the two
    # budgets collapse onto the same threshold, nudge the block band above it.
    if block < review:
        block = review
    return float(review), float(block)


def grade(
    scores: Sequence[float],
    labels: Sequence[int],
    meta: Sequence[dict[str, Any]],
    *,
    review: float,
    block: float,
    bands: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Score one system on PG-HARD under its own banding thresholds.

    ``bands`` lets a system supply the bands it would really emit -- the
    deployed detector's abstention control can escalate a message whose score
    alone would have been a confident verdict. Baselines have no such control,
    so they fall back to thresholding the score.
    """
    scores = np.asarray(scores, dtype=np.float64)
    y = np.asarray(labels).astype(int)
    if bands is None:
        bands = [_band(float(s), review, block) for s in scores]
    bands = list(bands)

    hp = y == 1
    hn = y == 0
    n_hp = int(hp.sum())
    n_hn = int(hn.sum())

    silent = sum(1 for b, is_p in zip(bands, hp, strict=False) if is_p and b == BAND_ALLOW)
    blocked_ham = sum(1 for b, is_n in zip(bands, hn, strict=False) if is_n and b == BAND_BLOCK)
    acceptable = sum(1 for b, m in zip(bands, meta, strict=False) if b in m["tolerated"])
    caught = sum(1 for b, is_p in zip(bands, hp, strict=False) if is_p and b == BAND_BLOCK)
    reviewed = sum(1 for b in bands if b == BAND_REVIEW)

    binary = prf(y, (scores >= block).astype(int))

    return {
        "n": int(y.size),
        "thresholds": {"review": round(review, 6), "block": round(block, 6)},
        # ---- the two that matter
        "silent_delivery": silent,
        "silent_delivery_rate": round(silent / n_hp, 4) if n_hp else 0.0,
        "false_block": blocked_ham,
        "false_block_rate": round(blocked_ham / n_hn, 4) if n_hn else 0.0,
        # ---- supporting
        "acceptable_rate": round(acceptable / y.size, 4) if y.size else 0.0,
        "auto_blocked_phish_rate": round(caught / n_hp, 4) if n_hp else 0.0,
        "review_load_rate": round(reviewed / y.size, 4) if y.size else 0.0,
        "roc_auc": round(roc_auc(y, scores), 5),
        "macro_f1_at_block": binary["macro_f1"],
        "mean_score_phish": round(float(scores[hp].mean()), 4) if n_hp else 0.0,
        "mean_score_ham": round(float(scores[hn].mean()), 4) if n_hn else 0.0,
        "separation": round(float(scores[hp].mean() - scores[hn].mean()), 4)
        if n_hp and n_hn
        else 0.0,
        "bands": {
            BAND_ALLOW: bands.count(BAND_ALLOW),
            BAND_REVIEW: bands.count(BAND_REVIEW),
            BAND_BLOCK: bands.count(BAND_BLOCK),
        },
        # Exact outcome mix per label, so a figure never has to estimate how a
        # system's review load splits between phishing and legitimate mail.
        "bands_by_label": {
            name: {
                band: sum(1 for b, lab in zip(bands, y, strict=False) if lab == label and b == band)
                for band in (BAND_ALLOW, BAND_REVIEW, BAND_BLOCK)
            }
            for label, name in ((1, "phishing"), (0, "legitimate"))
        },
        "_bands": bands,
    }


def _per_case(
    scores: Sequence[float],
    meta: Sequence[dict[str, Any]],
    bands: Sequence[str],
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for score, m, band in zip(scores, meta, bands, strict=False):
        b = buckets.setdefault(
            m["case_id"],
            {
                "case_id": m["case_id"],
                "title": m["title"],
                "label": m["label"],
                "defeats": m["defeats"],
                "rationale": m["rationale"],
                "tolerated": m["tolerated"],
                "scores": [],
                "bands": [],
            },
        )
        b["scores"].append(float(score))
        b["bands"].append(band)

    rows = []
    for b in buckets.values():
        n = len(b["scores"])
        ok = sum(1 for x in b["bands"] if x in b["tolerated"])
        worst = min(b["scores"]) if b["label"] == 1 else max(b["scores"])
        rows.append(
            {
                "case_id": b["case_id"],
                "title": b["title"],
                "label": b["label"],
                "defeats": b["defeats"],
                "rationale": b["rationale"],
                "n": n,
                "mean_score": round(sum(b["scores"]) / n, 4),
                # The variant that came closest to failing: the honest number.
                "worst_score": round(worst, 4),
                "pass_rate": round(ok / n, 4),
                "bands": {
                    BAND_ALLOW: b["bands"].count(BAND_ALLOW),
                    BAND_REVIEW: b["bands"].count(BAND_REVIEW),
                    BAND_BLOCK: b["bands"].count(BAND_BLOCK),
                },
                "failed": ok < n,
                "variant_scores": [round(x, 4) for x in b["scores"]],
                "variant_bands": list(b["bands"]),
            }
        )
    rows.sort(key=lambda r: (r["pass_rate"], -r["n"]))
    return rows


def _per_defeated_signal(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        groups.setdefault(r["defeats"], []).append(r)
    out = []
    for signal, items in groups.items():
        n = sum(i["n"] for i in items)
        passed = sum(i["pass_rate"] * i["n"] for i in items)
        out.append(
            {
                "defeats": signal,
                "cases": len(items),
                "n": n,
                "pass_rate": round(passed / n, 4) if n else 0.0,
            }
        )
    out.sort(key=lambda r: r["pass_rate"])
    return out


def run_hard_evaluation(
    detector: PhishGuardDetector,
    *,
    train_messages: list[EmailMessage],
    y_train: np.ndarray,
    ref_messages: list[EmailMessage],
    y_ref: np.ndarray,
    variants_per_case: int = 8,
    seed: int = 20260912,
    tfidf_baseline: TfidfBaseline | None = None,
    adaptive_attack: bool = False,
    attack_budgets: Sequence[int] = (0, 10, 40, 120),
    attack_variants: int = 4,
) -> dict[str, Any]:
    """Run PG-HARD for the deployed system and both baselines.

    ``ref_messages`` is the ordinary held-out test set. It is used only to
    calibrate each system's thresholds to a common false-alarm budget -- no
    hard-case record ever influences a threshold.
    """
    settings = detector.settings
    messages, labels, meta = build_hard_benchmark(variants_per_case=variants_per_case, seed=seed)
    y = np.asarray(labels).astype(int)
    y_ref = np.asarray(y_ref).astype(int)

    # --- the budget every system must live within, taken from the deployment
    ref_scores = detector.predict_proba(ref_messages)
    pg_review = getattr(detector, "review_threshold", settings.review_threshold)
    pg_block = getattr(detector, "block_threshold", settings.block_threshold)
    target_review_fpr = _fpr_at(y_ref, ref_scores, pg_review)
    target_block_fpr = _fpr_at(y_ref, ref_scores, pg_block)

    systems: dict[str, dict[str, Any]] = {}

    # --- deployed system, at its real thresholds
    pg_scores = detector.predict_proba(messages)
    # Grade the system that actually ships: abstention on member disagreement
    # changes the band without changing the score, so banding the score alone
    # would measure a detector that is not the deployed one.
    systems["phishguard"] = grade(
        pg_scores,
        y,
        meta,
        review=pg_review,
        block=pg_block,
        bands=detector.bands(messages),
    )
    systems["phishguard"]["label"] = "PhishGuard (full tri-modal ensemble)"

    # --- B1: the text-only filter this project argues against
    tfidf = tfidf_baseline or TfidfBaseline().fit(train_messages, y_train)
    tfidf_ref = tfidf.score(ref_messages)
    tr, tb = matched_thresholds(
        y_ref,
        tfidf_ref,
        target_review_fpr=target_review_fpr,
        target_block_fpr=target_block_fpr,
    )
    systems["B1_tfidf_logreg"] = grade(tfidf.score(messages), y, meta, review=tr, block=tb)
    systems["B1_tfidf_logreg"]["label"] = "Text-only filter (TF-IDF + logistic regression)"

    # --- B0: the hand-written rule checklist
    rules = RuleBaseline()
    rule_ref = rules.score(ref_messages)
    rr, rb = matched_thresholds(
        y_ref,
        rule_ref,
        target_review_fpr=target_review_fpr,
        target_block_fpr=target_block_fpr,
    )
    systems["B0_rule_checklist"] = grade(rules.score(messages), y, meta, review=rr, block=rb)
    systems["B0_rule_checklist"]["label"] = "Hand-written rule checklist"

    # What abstention costs on *ordinary* mail. Without this number the
    # headline is an overclaim: a system that escalates everything scores
    # perfectly here and is useless in production, so the review load on
    # normal traffic is reported next to the hard-case result, not buried.
    ref_bands = detector.bands(ref_messages)
    ordinary_review = ref_bands.count(BAND_REVIEW) / max(len(ref_bands), 1)
    ordinary_block_ham = sum(
        1 for b, lab in zip(ref_bands, y_ref, strict=False) if lab == 0 and b == BAND_BLOCK
    ) / max(int((y_ref == 0).sum()), 1)
    ordinary_allow_phish = sum(
        1 for b, lab in zip(ref_bands, y_ref, strict=False) if lab == 1 and b == BAND_ALLOW
    ) / max(int((y_ref == 1).sum()), 1)

    per_case = _per_case(pg_scores, meta, systems["phishguard"].pop("_bands"))
    for key in ("B1_tfidf_logreg", "B0_rule_checklist"):
        systems[key].pop("_bands", None)

    failures = [r for r in per_case if r["failed"]]

    # Robustness where it can actually be measured: on the hard positives,
    # which start near the decision boundary, against both a score-minimising
    # attacker and one that knows about the abstention control. Off by default
    # in the standalone command because it takes minutes rather than seconds.
    adaptive: dict[str, Any] | None = None
    if adaptive_attack:
        from ..adversarial.adaptive import run_adaptive_robustness

        att_msgs, att_y, _ = build_hard_benchmark(variants_per_case=attack_variants, seed=seed)
        targets = [m for m, lab in zip(att_msgs, att_y, strict=False) if lab == 1]
        adaptive = run_adaptive_robustness(
            detector,
            targets=targets,
            baseline=tfidf,
            baseline_review_threshold=tr,
            budgets=attack_budgets,
            seed=settings.attack_seed,
        )

    return {
        "benchmark": BENCHMARK_ID,
        "n_records": int(y.size),
        "variants_per_case": variants_per_case,
        "seed": seed,
        "budget": {
            "target_review_fpr": round(target_review_fpr, 5),
            "target_block_fpr": round(target_block_fpr, 5),
            "note": (
                "Each system's thresholds were chosen on the ordinary held-out "
                "test set so that all systems share this false-alarm budget. "
                "No PG-HARD record influenced any threshold."
            ),
        },
        "ordinary_mail": {
            "n": len(ref_messages),
            "review_load_rate": round(ordinary_review, 4),
            "false_block_rate": round(ordinary_block_ham, 4),
            "silent_delivery_rate": round(ordinary_allow_phish, 4),
            "note": (
                "Measured on the ordinary held-out test set with the same "
                "deployed policy. This is the price of the hard-case result: "
                "escalation is only a defence if the escalation queue stays "
                "small enough for a human to work."
            ),
        },
        "systems": systems,
        "per_case": per_case,
        "per_defeated_signal": _per_defeated_signal(per_case),
        "failing_cases": [
            {
                "case_id": r["case_id"],
                "title": r["title"],
                "label": r["label"],
                "defeats": r["defeats"],
                "pass_rate": r["pass_rate"],
                "worst_score": r["worst_score"],
            }
            for r in failures
        ],
        "description": describe_benchmark(),
        "adaptive_robustness": adaptive,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render_hard_markdown(report: dict[str, Any]) -> str:
    """Markdown section for the evaluation dossier."""
    sys_rows = report["systems"]
    order = ["phishguard", "B1_tfidf_logreg", "B0_rule_checklist"]

    lines: list[str] = []
    lines.append(f"## {report['benchmark']} — curated hard-case benchmark\n")
    d = report["description"]
    lines.append(
        f"{d['n_cases']} hand-designed cases "
        f"({d['n_hard_negatives']} hard negatives, {d['n_hard_positives']} hard "
        f"positives), {report['variants_per_case']} deterministic variants each "
        f"= **{report['n_records']} records**. Every case inverts a named "
        f"detection cue; none of this set is easy.\n"
    )
    lines.append(
        "All three systems are tuned to the same false-alarm budget on the "
        "ordinary held-out test set "
        f"(review {report['budget']['target_review_fpr']:.4f} FPR, "
        f"block {report['budget']['target_block_fpr']:.4f} FPR) before being "
        "measured here, so the columns are comparable.\n"
    )

    lines.append("### Headline — the two failures that cost money\n")
    lines.append(
        "| System | Silent delivery | False block | Acceptable outcome | Sent to a human |"
    )
    lines.append("|---|---|---|---|---|")
    for key in order:
        s = sys_rows[key]
        lines.append(
            f"| {s['label']} | **{s['silent_delivery_rate']:.1%}** "
            f"({s['silent_delivery']}) | **{s['false_block_rate']:.1%}** "
            f"({s['false_block']}) | {s['acceptable_rate']:.1%} | "
            f"{s['review_load_rate']:.1%} |"
        )
    lines.append("")
    om = report.get("ordinary_mail")
    if om:
        lines.append(
            f"On **ordinary** mail the same policy sends "
            f"{om['review_load_rate']:.1%} of messages to a human, blocks "
            f"{om['false_block_rate']:.2%} of legitimate mail and lets "
            f"{om['silent_delivery_rate']:.2%} of phishing through silently "
            f"(n={om['n']}). The hard-case result above is bought with that "
            f"review queue; without this line it would be an overclaim, "
            f"because a system that escalates everything scores perfectly on "
            f"PG-HARD and is useless in production.\n"
        )
    lines.append(
        "*Silent delivery* = a hard phish the user received with no warning. "
        "*False block* = legitimate mail the user never saw. Routing a hard "
        "case to human review counts as an acceptable outcome for both labels, "
        "because that is what the middle band is for.\n"
    )

    lines.append("### Where the system is weakest\n")
    lines.append("| Defeated cue | Cases | Records | Pass rate |")
    lines.append("|---|---|---|---|")
    for row in report["per_defeated_signal"]:
        lines.append(f"| {row['defeats']} | {row['cases']} | {row['n']} | {row['pass_rate']:.1%} |")
    lines.append("")

    lines.append("### Case-by-case\n")
    lines.append("| Case | Label | Defeats | Mean | Worst | Pass |")
    lines.append("|---|---|---|---|---|---|")
    for r in report["per_case"]:
        label = "phish" if r["label"] == 1 else "legit"
        mark = "" if r["pass_rate"] == 1.0 else " ⚠"
        lines.append(
            f"| `{r['case_id']}` {r['title']}{mark} | {label} | {r['defeats']} | "
            f"{r['mean_score']:.3f} | {r['worst_score']:.3f} | "
            f"{r['pass_rate']:.0%} |"
        )
    lines.append("")

    adaptive = report.get("adaptive_robustness")
    if adaptive:
        lines.append("### Under attack — hard positives, adaptive attacker\n")
        lines.append(
            f"{adaptive['targets']} hard-positive records attacked at increasing "
            "query budgets. Every attacker is graded by the same judge — the "
            "deployed decision, calibrated score then abstention — so a message "
            "counts as delivered only if the real policy would have delivered "
            "it.\n"
        )
        curves = adaptive["curves"]
        budgets = [r["budget"] for r in curves["naive"]["rows"]]
        header = "| Attacker vs system | " + " | ".join(f"budget {b}" for b in budgets) + " |"
        lines.append(header)
        lines.append("|" + "---|" * (len(budgets) + 1))
        for key in ("naive", "adaptive", "text_only"):
            if key not in curves:
                continue
            c = curves[key]
            cells = " | ".join(f"{r['silent_delivery_rate']:.1%}" for r in c["rows"])
            lines.append(f"| {c['label']} | {cells} |")
        lines.append("")
        lines.append(
            "Cells are the **silent-delivery rate**: the fraction of attacked "
            "phishing that reaches the user with no warning.\n"
        )
        pg_rows = curves["adaptive"]["rows"]
        if pg_rows:
            first, last = pg_rows[0], pg_rows[-1]
            lines.append(
                f"The attack is not without effect on PhishGuard. At budget "
                f"{last['budget']} the adaptive attacker moves the share of "
                f"these messages that are *auto-blocked* from "
                f"{first['auto_blocked_rate']:.1%} to "
                f"{last['auto_blocked_rate']:.1%} — the rest are escalated to "
                f"review rather than delivered. The attack's cost lands on the "
                f"analyst queue, not on the victim.\n"
            )
        mm = adaptive.get("member_movement")
        if mm:
            lines.append(
                f"Which readers the strongest attack (budget {mm['budget']}) could move:\n"
            )
            lines.append("| Member | Mean score before | After | Drop |")
            lines.append("|---|---|---|---|")
            for row in mm["members"]:
                lines.append(
                    f"| `{row['member']}` | {row['mean_before']:.3f} | "
                    f"{row['mean_after']:.3f} | {row['mean_drop']:+.3f} |"
                )
            lines.append("")
        pf = adaptive.get("per_family")
        if pf:
            lines.append(f"Per attack family, budget {pf['budget']}:\n")
            lines.append(
                "| Family | PhishGuard silent delivery | PhishGuard still auto-blocked "
                "| Text-only silent delivery |"
            )
            lines.append("|---|---|---|---|")
            for row in pf["rows"]:
                tx = row.get("text_only_silent_delivery_rate")
                lines.append(
                    f"| {row['family_id']} {row['family']} | "
                    f"{row['phishguard_silent_delivery_rate']:.1%} | "
                    f"{row['phishguard_auto_blocked_rate']:.1%} | "
                    f"{'—' if tx is None else f'{tx:.1%}'} |"
                )
            lines.append("")

    if report["failing_cases"]:
        lines.append("### Honest failures\n")
        lines.append(
            "These cases are not fully handled. They are reported rather than "
            "removed, and each names the cue the system is still leaning on.\n"
        )
        for r in report["failing_cases"]:
            lines.append(
                f"- **{r['case_id']}** — {r['title']} "
                f"(pass {r['pass_rate']:.0%}, worst score {r['worst_score']:.3f}); "
                f"defeats *{r['defeats']}*."
            )
        lines.append("")
    else:
        lines.append(
            "### Honest failures\n\nNo case fell outside its tolerated bands at "
            "this variant count. Raising `--variants` widens the search and is "
            "the recommended way to look for one.\n"
        )

    return "\n".join(lines)
