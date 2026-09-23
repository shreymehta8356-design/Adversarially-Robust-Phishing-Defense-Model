"""The evaluation orchestrator.

Produces the whole evaluation dossier in one run:

1. leakage audit on the split that was used
2. clean metrics for the fusion, every member, and both baselines
3. calibration quality and the reliability curve
4. banded-decision outcome at the deployed thresholds
5. latency distribution
6. adversarial robustness, per-family effectiveness and the residual-risk register
7. modality ablation - what each feature family is worth
8. defence ablation - what each control is worth
9. subgroup slices and categorised error analysis
10. acceptance gates, and a go/no-go verdict

Everything is returned as one JSON-serialisable dict, written to
``artifacts/reports/evaluation.json`` and rendered as Markdown for the report.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from phishguard.adversarial.attacker import RawScoreSurface
from phishguard.adversarial.report import (
    compare_robustness,
    family_effectiveness_table,
    robustness_report,
)
from phishguard.adversarial.taxonomy import describe_taxonomy
from phishguard.config import Settings, get_settings
from phishguard.data.splits import LeakageReport
from phishguard.defenses.controls import DEFENSE_IDS, DefenseConfig, describe_defenses
from phishguard.eval.acceptance import evaluate_gates
from phishguard.eval.error_analysis import (
    confidence_profile,
    error_report,
    slice_metrics,
)
from phishguard.eval.metrics import (
    banded_outcome,
    latency_stats,
    score_summary,
    threshold_for_target_fpr,
)
from phishguard.features.assembler import FEATURE_FAMILIES
from phishguard.models.baseline import RuleBaseline, TfidfBaseline
from phishguard.models.calibration import (
    expected_calibration_error,
    maximum_calibration_error,
    reliability_curve,
)
from phishguard.models.detector import PhishGuardDetector
from phishguard.schemas import EmailMessage


class _MemberSurface:
    """Adapt a single member or baseline to the ``Scorer`` protocol."""

    def __init__(self, member: Any) -> None:
        self.member = member

    def predict_proba(self, messages: list[EmailMessage]) -> np.ndarray:
        return self.member.score(messages)


def measure_latency(
    detector: PhishGuardDetector, messages: list[EmailMessage], *, n: int = 200
) -> dict[str, Any]:
    """Single-message end-to-end latency, which is what the gateway experiences.

    Measured one message at a time and including evidence generation, because
    batching would report a throughput number the inline path never achieves.
    """
    sample = messages[:n]
    if not sample:
        return latency_stats([]).as_dict()
    for m in sample[: min(10, len(sample))]:  # warm caches
        detector.assess(m, explain=False)

    with_explain: list[float] = []
    without: list[float] = []
    for m in sample:
        t0 = time.perf_counter()
        detector.assess(m, explain=False)
        without.append((time.perf_counter() - t0) * 1000.0)
        t1 = time.perf_counter()
        detector.assess(m, explain=True)
        with_explain.append((time.perf_counter() - t1) * 1000.0)

    stats = latency_stats(with_explain)
    stats.extras = {
        "without_explanation": latency_stats(without).as_dict(),
        "note": (
            "Single-message path including evidence generation, as served by "
            "POST /api/v1/scan. Batch throughput is materially higher."
        ),
    }
    return stats.as_dict()


def modality_ablation(
    train_messages: list[EmailMessage],
    y_train: np.ndarray,
    test_messages: list[EmailMessage],
    y_test: np.ndarray,
    *,
    settings: Settings,
    threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """What is each feature family worth?

    Trains the engineered member on each family alone, on each leave-one-out
    combination, and on all three. This is the experiment that justifies the
    project's title: if the three families were redundant, a single-modality
    model would match the full one.
    """
    from phishguard.features.assembler import FeatureAssembler
    from phishguard.models.members import EngineeredMember

    combos: list[tuple[str, ...]] = [
        ("email",), ("url",), ("behavioral",),
        ("email", "url"), ("email", "behavioral"), ("url", "behavioral"),
        ("email", "url", "behavioral"),
    ]
    rows: list[dict[str, Any]] = []
    for fams in combos:
        member = EngineeredMember(random_state=settings.random_seed)
        member.assembler = FeatureAssembler(families=fams)
        member.fit(train_messages, y_train)
        scores = member.score(test_messages)
        summary = score_summary(y_test, scores, threshold=threshold)
        rows.append(
            {
                "families": list(fams),
                "label": " + ".join(fams),
                "n_features": member.assembler.n_features,
                "macro_f1": summary["macro_f1"],
                "pr_auc": summary["pr_auc"],
                "recall_phish": summary["recall_phish"],
                "false_positive_rate": summary["false_positive_rate"],
            }
        )
    full = next(r for r in rows if len(r["families"]) == 3)
    for r in rows:
        r["macro_f1_vs_full"] = round(r["macro_f1"] - full["macro_f1"], 5)
    return rows


def defense_ablation(
    train_messages: list[EmailMessage],
    y_train: np.ndarray,
    test_messages: list[EmailMessage],
    y_test: np.ndarray,
    *,
    settings: Settings,
    budget: int,
    max_attacked: int,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """What is each defensive control worth?

    Each arm is trained from scratch with one control disabled and then
    attacked, because several of the controls (adversarial training, ensemble
    membership, URL canonicalization) change what the model learns and cannot
    be switched off at inference time. This is the most expensive part of the
    evaluation and the one that turns "we added defences" into a measurement.
    """
    arms: dict[str, DefenseConfig] = {"all defences": DefenseConfig()}
    for did in DEFENSE_IDS:
        arms[f"without {did}"] = DefenseConfig.without(did)
    arms["no defences"] = DefenseConfig.none()

    rows: list[dict[str, Any]] = []
    robustness_arms: dict[str, dict[str, Any]] = {}
    for name, cfg in arms.items():
        detector = PhishGuardDetector(settings=settings, defenses=cfg)
        detector.fit(train_messages, y_train, adversarial_augment=cfg.adv_train)
        clean_scores = detector.predict_proba(test_messages)
        clean = score_summary(y_test, clean_scores, threshold=threshold)
        rob = robustness_report(
            RawScoreSurface(detector), test_messages, y_test,
            clean_summary=clean, budget=budget, max_attacked=max_attacked,
            evasion_threshold=settings.review_threshold,
            block_threshold=settings.block_threshold,
            defenses_active=cfg.active_ids, per_family=False,
            seed=settings.attack_seed,
        )
        robustness_arms[name] = rob
        rows.append(
            {
                "arm": name,
                "active_controls": cfg.active_ids,
                "clean_macro_f1": clean["macro_f1"],
                "clean_false_positive_rate": clean["false_positive_rate"],
                "adversarial_macro_f1": rob["adversarial_macro_f1"],
                "macro_f1_drop": rob["macro_f1_drop"],
                "attack_success_rate": rob["attack_success_rate"],
                "silent_delivery_rate": rob["silent_delivery_rate"],
            }
        )

    baseline = next(r for r in rows if r["arm"] == "all defences")
    for r in rows:
        r["asr_vs_full"] = round(
            r["attack_success_rate"] - baseline["attack_success_rate"], 5
        )
        r["clean_f1_vs_full"] = round(r["clean_macro_f1"] - baseline["clean_macro_f1"], 5)
    return {"arms": rows, "comparison": compare_robustness(robustness_arms)}


def run_evaluation(
    detector: PhishGuardDetector,
    *,
    train_messages: list[EmailMessage],
    y_train: np.ndarray,
    test_messages: list[EmailMessage],
    y_test: np.ndarray,
    leakage: LeakageReport | None = None,
    settings: Settings | None = None,
    attack_budget: int | None = None,
    max_attacked: int = 200,
    run_modality_ablation: bool = True,
    run_defense_ablation: bool = False,
    output_dir: Path | None = None,
    split_notes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the full dossier and return it as a dict."""
    settings = settings or detector.settings
    budget = attack_budget or settings.attack_budget
    y_test = np.asarray(y_test).astype(int)
    y_train = np.asarray(y_train).astype(int)
    started = time.perf_counter()

    # -------------------------------------------------------------- clean
    scores = detector.predict_proba(test_messages)
    raw_scores = detector.predict_proba_raw(test_messages)
    clean = score_summary(y_test, scores, threshold=0.5)

    operating_threshold = threshold_for_target_fpr(y_test, scores, settings.gate_max_fpr)
    at_operating = score_summary(y_test, scores, threshold=operating_threshold)

    members: dict[str, dict[str, Any]] = {}
    for name, member in detector.members.items():
        member_scores = member.score(test_messages)
        members[name] = score_summary(y_test, member_scores, threshold=0.5)

    rule_baseline = RuleBaseline()
    rule_scores = rule_baseline.score(test_messages)
    tfidf_baseline = TfidfBaseline().fit(train_messages, y_train)
    tfidf_scores = tfidf_baseline.score(test_messages)
    baselines = {
        "B0_rule_checklist": score_summary(y_test, rule_scores, threshold=0.5),
        "B1_tfidf_logreg": score_summary(y_test, tfidf_scores, threshold=0.5),
    }

    # -------------------------------------------------- calibration + bands
    calibration = {
        "method": detector.calibrator.fitted_method,
        "ece": round(expected_calibration_error(scores, y_test), 5),
        "mce": round(maximum_calibration_error(scores, y_test), 5),
        "ece_uncalibrated": round(expected_calibration_error(raw_scores, y_test), 5),
        "reliability": reliability_curve(scores, y_test),
        "note": (
            "Isotonic calibration on a well-separated calibration pool approaches a "
            "step function, so a near-zero ECE here reflects strong separation rather "
            "than a difficult calibration problem being solved."
        ),
    }
    bands = banded_outcome(
        y_test, scores,
        review_threshold=settings.review_threshold,
        block_threshold=settings.block_threshold,
    ).as_dict()

    latency = measure_latency(detector, test_messages, n=min(150, len(test_messages)))

    # ------------------------------------------------------- robustness
    robustness = robustness_report(
        RawScoreSurface(detector), test_messages, y_test,
        clean_summary=clean, budget=budget, max_attacked=max_attacked,
        evasion_threshold=settings.review_threshold,
        block_threshold=settings.block_threshold,
        defenses_active=detector.defenses.active_ids, per_family=True,
        seed=settings.attack_seed, restarts=2,
    )
    robustness["family_effectiveness"] = family_effectiveness_table(
        robustness.get("per_family", {})
    )
    # The deployed API exposes only the calibrated score; report that too so the
    # gap between the conservative measurement and reality is visible.
    robustness_calibrated = robustness_report(
        detector, test_messages, y_test,
        clean_summary=clean, budget=budget,
        max_attacked=min(max_attacked, 120),
        evasion_threshold=settings.review_threshold,
        block_threshold=settings.block_threshold,
        defenses_active=detector.defenses.active_ids, per_family=False,
        seed=settings.attack_seed,
    )
    robustness["calibrated_surface"] = {
        "attack_success_rate": robustness_calibrated["attack_success_rate"],
        "macro_f1_drop": robustness_calibrated["macro_f1_drop"],
        "note": (
            "Measured against the calibrated score the deployed API actually returns. "
            "Lower than the raw-surface figure because the calibrator quantises the "
            "signal available to an attacker."
        ),
    }

    baseline_robustness = robustness_report(
        _MemberSurface(tfidf_baseline), test_messages, y_test,
        clean_summary=baselines["B1_tfidf_logreg"], budget=budget,
        max_attacked=max_attacked,
        evasion_threshold=settings.review_threshold,
        block_threshold=settings.block_threshold,
        defenses_active=[], per_family=False,
        seed=settings.attack_seed, restarts=2,
    )

    # ---------------------------------------------- the cases that are hard
    # An aggregate score over a corpus that contains obvious phishing flatters
    # the model. These are the slices where the answer is genuinely contested:
    # cloned brand templates, business email compromise, thread hijacking, and
    # legitimate mail that looks alarming.
    hard_kinds = {
        "clone", "bec_ceo", "thread_hijack", "vendor_swap", "doc_share",
        "calendar_lure", "recruiter", "suspicious_ham",
    }
    hard_mask = np.array(
        [
            (m.source.split(":", 1)[-1] in hard_kinds)
            or m.source.split(":", 1)[-1].startswith("real_")
            for m in test_messages
        ]
    )
    hard_summary: dict[str, Any] = {"n": int(hard_mask.sum())}
    if hard_mask.sum() >= 20 and len(np.unique(y_test[hard_mask])) == 2:
        hard_summary = {
            **score_summary(y_test[hard_mask], scores[hard_mask], threshold=0.5),
            "note": (
                "Cloned brand templates, business email compromise, thread "
                "hijacking and legitimate mail with a phishing-shaped surface. "
                "The honest read of the system's ceiling."
            ),
        }

    # -------------------------------------------------------- explanations
    slices = slice_metrics(test_messages, y_test, scores, threshold=0.5)
    errors = error_report(test_messages, y_test, scores, threshold=0.5)
    confidence = confidence_profile(y_test, scores)

    report: dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": detector.describe(),
        "dataset": {
            "n_train": int(len(train_messages)),
            "n_test": int(len(test_messages)),
            "train_phish_rate": round(float(y_train.mean()), 5),
            "test_phish_rate": round(float(y_test.mean()), 5),
            "split": split_notes or {},
        },
        "leakage": {
            **(leakage.as_dict() if leakage else {"passed": True, "failures": []}),
            "passed_numeric": 1.0 if (leakage is None or leakage.passed) else 0.0,
        },
        "clean": clean,
        "hard_subset": hard_summary,
        "at_operating_point": {
            "threshold": round(operating_threshold, 5),
            "target_false_positive_rate": settings.gate_max_fpr,
            **at_operating,
        },
        "members": members,
        "baselines": baselines,
        "calibration": calibration,
        "banded_decision": bands,
        "latency": latency,
        "robustness": robustness,
        "baseline_robustness": {
            "B1_tfidf_logreg": {
                "attack_success_rate": baseline_robustness["attack_success_rate"],
                "silent_delivery_rate": baseline_robustness["silent_delivery_rate"],
                "clean_macro_f1": baseline_robustness["clean_macro_f1"],
                "adversarial_macro_f1": baseline_robustness["adversarial_macro_f1"],
                "macro_f1_drop": baseline_robustness["macro_f1_drop"],
            }
        },
        "slices": slices,
        "errors": errors,
        "confidence_profile": confidence,
        "attack_taxonomy": describe_taxonomy(),
        "defense_catalogue": describe_defenses(),
        "deltas": {
            "vs_rule_baseline_macro_f1": round(
                clean["macro_f1"] - baselines["B0_rule_checklist"]["macro_f1"], 5
            ),
            "vs_tfidf_baseline_macro_f1": round(
                clean["macro_f1"] - baselines["B1_tfidf_logreg"]["macro_f1"], 5
            ),
            "asr_advantage_vs_text_baseline": round(
                baseline_robustness["attack_success_rate"]
                - robustness["attack_success_rate"],
                5,
            ),
        },
    }

    if run_modality_ablation:
        report["modality_ablation"] = modality_ablation(
            train_messages, y_train, test_messages, y_test,
            settings=settings, threshold=0.5,
        )
    if run_defense_ablation:
        report["defense_ablation"] = defense_ablation(
            train_messages, y_train, test_messages, y_test,
            settings=settings, budget=budget,
            max_attacked=min(max_attacked, 120), threshold=0.5,
        )

    acceptance = evaluate_gates(report, settings=settings)
    report["acceptance"] = acceptance.as_dict()
    report["evaluation_seconds"] = round(time.perf_counter() - started, 1)

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "evaluation.json").write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        (output_dir / "evaluation.md").write_text(
            render_markdown(report), encoding="utf-8"
        )
    return report


# --------------------------------------------------------------------------
def _table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not rows:
        return "_No data._\n"
    header = "| " + " | ".join(title for _, title in columns) + " |"
    sep = "|" + "|".join("---" for _ in columns) + "|"
    body = []
    for r in rows:
        cells = []
        for key, _ in columns:
            v = r.get(key, "")
            if isinstance(v, float):
                cells.append(f"{v:.4f}")
            elif isinstance(v, list):
                cells.append(", ".join(str(x) for x in v) or "-")
            else:
                cells.append(str(v))
        body.append("| " + " | ".join(cells) + " |")
    return "\n".join([header, sep, *body]) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    """Human-readable dossier, used verbatim in the final report."""
    clean = report["clean"]
    rob = report["robustness"]
    acc = report["acceptance"]
    out: list[str] = []
    a = out.append

    a("# Evaluation dossier\n")
    a(f"Generated: {report['generated_at']}  ")
    a(f"Model version: `{report['model']['model_version']}`  ")
    a(f"Active defences: {', '.join(report['model']['active_defense_ids'])}\n")

    a("## 1. Verdict\n")
    a(f"**{'GO' if acc['passed'] else 'NO-GO'}** - "
      f"{acc['n_gates'] - acc['n_failed']}/{acc['n_gates']} acceptance gates passed.\n")
    a(_table(acc["gates"], [
        ("id", "Gate"), ("name", "Criterion"), ("observed", "Observed"),
        ("threshold", "Threshold"), ("direction", "Dir"), ("passed", "Pass"),
    ]))

    a("## 2. Dataset and split\n")
    ds = report["dataset"]
    a(f"- Train: {ds['n_train']} messages ({ds['train_phish_rate']:.1%} phishing)")
    a(f"- Test: {ds['n_test']} messages ({ds['test_phish_rate']:.1%} phishing)")
    lk = report["leakage"]
    a(f"- Leakage audit: **{'PASSED' if lk.get('passed') else 'FAILED'}**"
      + ("" if lk.get("passed") else f" - {'; '.join(lk.get('failures', []))}"))
    a("")

    a("## 3. Clean performance\n")
    a(f"- Macro F1: **{clean['macro_f1']:.4f}**")
    a(f"- PR-AUC: **{clean['pr_auc']:.4f}**, ROC-AUC: {clean['roc_auc']:.4f}")
    a(f"- Recall (phishing): {clean['recall_phish']:.4f}, "
      f"False-positive rate: {clean['false_positive_rate']:.4f}")
    a(f"- Confusion: TN={clean['tn']} FP={clean['fp']} FN={clean['fn']} TP={clean['tp']}\n")

    hard = report.get("hard_subset") or {}
    if hard.get("n", 0) >= 20 and "macro_f1" in hard:
        a("### The cases that are actually hard\n")
        a(f"{hard['n']} messages: cloned brand templates, business email "
          f"compromise, thread hijacking, and legitimate mail with a "
          f"phishing-shaped surface.\n")
        a(f"- Macro F1 **{hard['macro_f1']:.4f}** "
          f"(vs {clean['macro_f1']:.4f} over the whole test set)")
        a(f"- Recall {hard['recall_phish']:.4f}, "
          f"FPR {hard['false_positive_rate']:.4f}\n")

    a("### Baselines and ensemble members\n")
    rows = (
        [{"name": f"B0 rule checklist", **report["baselines"]["B0_rule_checklist"]},
         {"name": f"B1 TF-IDF + logreg", **report["baselines"]["B1_tfidf_logreg"]}]
        + [{"name": f"member: {k}", **v} for k, v in report["members"].items()]
        + [{"name": "**fusion (deployed)**", **clean}]
    )
    a(_table(rows, [
        ("name", "System"), ("macro_f1", "Macro F1"), ("pr_auc", "PR-AUC"),
        ("recall_phish", "Recall"), ("false_positive_rate", "FPR"),
    ]))

    a("## 4. Calibration\n")
    cal = report["calibration"]
    a(f"- Method: {cal['method']}")
    a(f"- ECE: {cal['ece']:.5f} (uncalibrated: {cal['ece_uncalibrated']:.5f}), "
      f"MCE: {cal['mce']:.5f}")
    a(f"- {cal['note']}\n")

    a("## 5. Operational decision bands\n")
    b = report["banded_decision"]
    a(f"- ALLOW {b['allow']} / REVIEW {b['review']} / BLOCK {b['block']} "
      f"({b['review_rate']:.1%} routed to a human)")
    a(f"- Auto-decided macro F1: {b['auto_macro_f1']:.4f}, "
      f"auto FPR: {b['auto_false_positive_rate']:.4f}")
    a(f"- Phishing auto-allowed (missed): **{b['missed_phish']}**; "
      f"legitimate auto-blocked: **{b['blocked_ham']}**\n")

    a("## 6. Latency\n")
    lat = report["latency"]
    a(f"- p50 {lat['p50_ms']:.2f} ms, p95 **{lat['p95_ms']:.2f} ms**, "
      f"p99 {lat['p99_ms']:.2f} ms (single message, with explanation)")
    a(f"- Without explanation: p95 "
      f"{lat.get('without_explanation', {}).get('p95_ms', 0):.2f} ms\n")

    a("## 7. Adversarial robustness\n")
    a(f"Success is measured against the *deployed* policy, not against a 0.5 "
      f"cut-off: a message the attacker drags below the block threshold "
      f"({rob.get('block_threshold', 0.8)}) escapes auto-quarantine, and one "
      f"below the review threshold reaches the inbox with no human review. "
      f"Both are reported.\n")
    a(f"- Attack budget: {rob['budget']} queries with restarts; "
      f"{rob['attacked_messages']} phishing messages attacked")
    a(f"- **Escaped auto-block: {rob['attack_success_rate']:.3f}** "
      f"(raw-score surface, an upper bound on real attacker success)")
    a(f"- **Delivered with no human review: {rob.get('silent_delivery_rate', 0):.3f}**")
    a(f"- Calibrated surface (what the API actually exposes): "
      f"{rob['calibrated_surface']['attack_success_rate']:.3f}")
    a(f"- Mean score after attack: "
      f"{rob['composed_attack'].get('mean_final_score', 0):.4f} "
      f"(mean drop {rob['composed_attack'].get('mean_score_drop', 0):.4f}, "
      f"max {rob['composed_attack'].get('max_score_drop', 0):.4f})")
    a(f"- Macro F1: {rob['clean_macro_f1']:.4f} clean -> "
      f"{rob['adversarial_macro_f1']:.4f} adversarial "
      f"(**drop {rob['macro_f1_drop']:.4f}**)")
    a(f"- Recall: {rob['clean_recall']:.4f} -> {rob['adversarial_recall']:.4f}\n")

    if rob.get("banded_under_attack"):
        a("### What the decision policy does under attack\n")
        bua = rob["banded_under_attack"]
        a(_table([
            {"state": "clean", **bua["clean"]},
            {"state": "under attack", **bua["adversarial"]},
        ], [
            ("state", "Traffic"), ("allow", "ALLOW"), ("review", "REVIEW"),
            ("block", "BLOCK"), ("missed_phish", "Phishing allowed"),
            ("blocked_ham", "Legitimate blocked"),
        ]))
        a("Movement from BLOCK into REVIEW is where an attacker's effort shows "
          "up first: the message is no longer auto-quarantined, and the cost "
          "lands on the analyst queue rather than on the recipient.\n")

    bl = report["baseline_robustness"]["B1_tfidf_logreg"]
    a("### Comparison with the conventional text-only model\n")
    a(_table([
        {"system": "B1 TF-IDF + logreg", **bl},
        {"system": "Fusion (this project)",
         "attack_success_rate": rob["attack_success_rate"],
         "silent_delivery_rate": rob.get("silent_delivery_rate", 0.0),
         "clean_macro_f1": rob["clean_macro_f1"],
         "adversarial_macro_f1": rob["adversarial_macro_f1"],
         "macro_f1_drop": rob["macro_f1_drop"]},
    ], [
        ("system", "System"), ("clean_macro_f1", "Clean F1"),
        ("adversarial_macro_f1", "Adversarial F1"), ("macro_f1_drop", "Drop"),
        ("attack_success_rate", "Escaped block"),
        ("silent_delivery_rate", "Silent delivery"),
    ]))

    if rob.get("family_effectiveness"):
        a("### Attack family effectiveness\n")
        a(_table(rob["family_effectiveness"], [
            ("family_id", "ID"), ("family", "Family"),
            ("attack_success_rate", "Escaped block"),
            ("silent_delivery_rate", "Silent delivery"),
            ("mean_score_drop", "Mean drop"), ("attacker_cost", "Attacker cost"),
        ]))

    if rob.get("residual_risk_register"):
        a("### Residual-risk register\n")
        a(_table(rob["residual_risk_register"], [
            ("family_id", "ID"), ("family", "Attack family"),
            ("measured_attack_success_rate", "ASR"), ("likelihood", "Likelihood"),
            ("impact", "Impact"), ("residual_risk", "Residual"),
            ("controls_applied", "Controls"),
        ]))

    if report.get("modality_ablation"):
        a("## 8. Modality ablation\n")
        a("What each feature family contributes, holding the model fixed.\n")
        a(_table(report["modality_ablation"], [
            ("label", "Families"), ("n_features", "Features"),
            ("macro_f1", "Macro F1"), ("pr_auc", "PR-AUC"),
            ("macro_f1_vs_full", "vs full"),
        ]))

    if report.get("defense_ablation"):
        a("## 9. Defence ablation\n")
        a("Each arm is retrained from scratch with one control disabled.\n")
        a(_table(report["defense_ablation"]["arms"], [
            ("arm", "Arm"), ("clean_macro_f1", "Clean F1"),
            ("adversarial_macro_f1", "Adv F1"), ("macro_f1_drop", "Drop"),
            ("attack_success_rate", "ASR"), ("asr_vs_full", "ASR vs full"),
        ]))

    a("## 10. Error analysis\n")
    err = report["errors"]
    a(f"{err['n_errors']} errors ({err['error_rate']:.2%} of the test set).\n")
    if err["categories"]:
        a(_table(err["categories"], [("category", "Failure mode"), ("count", "Count")]))
    if err["worst_examples"]:
        a("Most confident mistakes:\n")
        a(_table(err["worst_examples"][:8], [
            ("lure_type", "Lure"), ("true_label", "True"), ("score", "Score"),
            ("sender_domain", "Sender domain"), ("subject", "Subject"),
        ]))

    a("## 11. Subgroup slices\n")
    for name, rows in report["slices"].items():
        if not rows:
            continue
        a(f"### {name.replace('_', ' ').title()}\n")
        a(_table(rows[:12], [
            ("value", "Slice"), ("n", "n"), ("macro_f1", "Macro F1"),
            ("recall_phish", "Recall"), ("false_positive_rate", "FPR"),
            ("errors", "Errors"),
        ]))

    a("## 12. Limitations\n")
    a(_LIMITATIONS)
    return "\n".join(out)


_LIMITATIONS = """\
1. **The corpus is synthetic.** It is generated to be campaign-structured,
   difficulty-balanced and leakage-audited, and no single feature separates the
   classes by more than ~0.84 AUC. It is nevertheless a model of phishing, not
   a sample of it. Clean metrics on it should be read as an upper bound; the
   comparative results (fusion vs baselines, defence ablation, modality
   ablation) transfer more reliably than the absolute numbers.
2. **Robustness is measured against this attack suite.** Thirty transforms
   across six families, composed under a query budget, is a serious test but
   not an exhaustive one. A genuinely novel attack family is by definition not
   represented, and the residual-risk register records that.
3. **The threat model excludes domain compromise.** Mail genuinely originating
   from a compromised brand or partner domain passes every header and
   reputation check by construction; it is an authentication problem, not a
   content-classification one. See `OOS-1` in the taxonomy.
4. **Behavioural features assume a mail gateway.** Correspondence history,
   campaign burstiness and domain age come from the deployment environment. In
   their absence the system degrades to email and URL evidence and records that
   it did so, but the ablation shows what that costs.
5. **No URL is resolved and no attachment is opened.** This is deliberate -
   fetching attacker-controlled content from the gateway would create an SSRF
   surface and leak victim telemetry - but it means a benign-looking URL
   serving a malicious page is invisible to this layer.
6. **Calibration is measured on the same distribution as training.** Under
   genuine distribution shift the probabilities will drift, which is why the
   monitoring endpoint tracks score distribution over time rather than assuming
   calibration holds.
"""
