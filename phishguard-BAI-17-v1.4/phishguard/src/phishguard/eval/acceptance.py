"""Go / no-go acceptance gates.

A capstone brief that says "measurable acceptance thresholds" means a machine
must be able to answer "does this build ship?" without a human squinting at a
table. Every gate here is checked automatically, in CI, and a failure is a
non-zero exit code.

The thresholds are deliberately not set to whatever the current model happens
to score. They encode the operational requirement:

``macro_f1``            overall quality on a balanced view of both classes
``pr_auc``              ranking quality where the positive class is the minority
``false_positive_rate`` the number that decides whether the filter stays on
``ece``                 the thresholds are policy, so the probabilities must mean something
``robustness_drop``     how much macro F1 the adversarial suite can take away
``attack_success_rate`` how often a budgeted attacker gets a phish through
``p95_latency_ms``      the gateway's per-message budget

The false-positive gate is the strictest of them on purpose. A phishing filter
that blocks legitimate mail is switched off by the business within a week, at
which point its recall is zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from phishguard.config import Settings, get_settings


@dataclass(slots=True)
class Gate:
    """One acceptance criterion."""

    id: str
    name: str
    metric_path: str
    threshold: float
    direction: Literal["min", "max"]
    rationale: str
    blocking: bool = True

    def check(self, value: float | None) -> dict[str, Any]:
        if value is None:
            return {
                "id": self.id,
                "name": self.name,
                "metric": self.metric_path,
                "threshold": self.threshold,
                "direction": self.direction,
                "observed": None,
                "passed": not self.blocking,
                "blocking": self.blocking,
                "note": "metric not produced by this run",
                "rationale": self.rationale,
            }
        passed = value >= self.threshold if self.direction == "min" else value <= self.threshold
        return {
            "id": self.id,
            "name": self.name,
            "metric": self.metric_path,
            "threshold": self.threshold,
            "direction": self.direction,
            "observed": round(float(value), 5),
            "passed": bool(passed),
            "blocking": self.blocking,
            "rationale": self.rationale,
        }


def build_gates(settings: Settings | None = None) -> list[Gate]:
    s = settings or get_settings()
    return [
        Gate(
            id="G1",
            name="Detection quality",
            metric_path="clean.macro_f1",
            threshold=s.gate_macro_f1,
            direction="min",
            rationale=(
                "Macro F1 weights both classes equally, so a model cannot pass by "
                "ignoring the minority class."
            ),
        ),
        Gate(
            id="G2",
            name="Ranking quality",
            metric_path="clean.pr_auc",
            threshold=s.gate_pr_auc,
            direction="min",
            rationale=(
                "PR-AUC is threshold-independent and is the honest summary when the "
                "positive class is a minority of live traffic."
            ),
        ),
        Gate(
            id="G3",
            name="False positives",
            metric_path="clean.false_positive_rate",
            threshold=s.gate_max_fpr,
            direction="max",
            rationale=(
                "The operational constraint that matters most: a filter that blocks "
                "legitimate mail gets switched off, after which its recall is zero."
            ),
        ),
        Gate(
            id="G4",
            name="Calibration",
            metric_path="calibration.ece",
            threshold=s.gate_max_ece,
            direction="max",
            rationale=(
                "The ALLOW/REVIEW/BLOCK thresholds are policy decisions, so the "
                "probabilities they are compared against have to mean what they say."
            ),
        ),
        Gate(
            id="G5",
            name="Adversarial robustness",
            metric_path="robustness.macro_f1_drop",
            threshold=s.gate_max_robustness_drop,
            direction="max",
            rationale=(
                "The distinguishing requirement of this project: quality must survive "
                "an attacker who is allowed to rewrite the message."
            ),
        ),
        Gate(
            id="G6",
            name="Attack success (escapes auto-block)",
            metric_path="robustness.attack_success_rate",
            threshold=s.gate_max_attack_success_rate,
            direction="max",
            rationale=(
                "Fraction of phishing a budgeted black-box attacker drags below the "
                "deployed block threshold, so it is no longer auto-quarantined. "
                "Measured against the raw score, which upper-bounds real attacker "
                "success, and anchored at the operating point rather than at 0.5 "
                "because 0.99 -> 0.79 is a real gain for the attacker."
            ),
        ),
        Gate(
            id="G7",
            name="Inference latency",
            metric_path="latency.p95_ms",
            threshold=s.gate_p95_latency_ms,
            direction="max",
            rationale=(
                "A mail gateway assesses inline. p95 rather than mean, because the "
                "tail is what causes queue backlog."
            ),
        ),
        Gate(
            id="G8",
            name="Beats the manual baseline",
            metric_path="deltas.vs_rule_baseline_macro_f1",
            threshold=0.01,
            direction="min",
            rationale=(
                "The learned system has to beat the analyst checklist it replaces by a "
                "margin that justifies its operational cost."
            ),
        ),
        Gate(
            id="G9",
            name="Robustness advantage over the text-only baseline",
            metric_path="deltas.asr_advantage_vs_text_baseline",
            threshold=0.0,
            direction="min",
            rationale=(
                "The tri-modal design is justified by robustness, not by clean "
                "accuracy. Its attack success rate must be lower than the "
                "conventional text-only model's."
            ),
        ),
        Gate(
            id="G10",
            name="No data leakage",
            metric_path="leakage.passed_numeric",
            threshold=1.0,
            direction="min",
            rationale=(
                "Group overlap, duplicates or a single near-perfect feature invalidate "
                "every other number in the report."
            ),
        ),
    ]


def _resolve(report: dict[str, Any], path: str) -> float | None:
    node: Any = report
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    try:
        return float(node)
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class AcceptanceResult:
    passed: bool
    results: list[dict[str, Any]] = field(default_factory=list)

    @property
    def failures(self) -> list[dict[str, Any]]:
        return [r for r in self.results if not r["passed"] and r["blocking"]]

    @property
    def warnings(self) -> list[dict[str, Any]]:
        return [r for r in self.results if not r["passed"] and not r["blocking"]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "n_gates": len(self.results),
            "n_failed": len(self.failures),
            "gates": self.results,
        }

    def render(self) -> str:
        lines = ["", "Acceptance gates", "=" * 78]
        for r in self.results:
            mark = "PASS" if r["passed"] else ("FAIL" if r["blocking"] else "WARN")
            obs = "n/a" if r["observed"] is None else f"{r['observed']:.4f}"
            op = ">=" if r["direction"] == "min" else "<="
            lines.append(
                f"  [{mark}] {r['id']:<4} {r['name']:<42} {obs:>9} {op} {r['threshold']:.4f}"
            )
        lines.append("=" * 78)
        lines.append(
            f"  RESULT: {'GO' if self.passed else 'NO-GO'} "
            f"({len(self.results) - len(self.failures)}/{len(self.results)} gates passed)"
        )
        return "\n".join(lines)


def evaluate_gates(report: dict[str, Any], *, settings: Settings | None = None) -> AcceptanceResult:
    """Check every gate against an evaluation report."""
    gates = build_gates(settings)
    results = [g.check(_resolve(report, g.metric_path)) for g in gates]
    passed = all(r["passed"] for r in results if r["blocking"])
    return AcceptanceResult(passed=passed, results=results)
