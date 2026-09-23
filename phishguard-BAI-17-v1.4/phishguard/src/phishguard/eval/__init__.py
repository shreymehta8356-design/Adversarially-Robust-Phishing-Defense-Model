"""Evaluation: metrics, error analysis, ablation and acceptance gates."""

from phishguard.eval.acceptance import AcceptanceResult, build_gates, evaluate_gates
from phishguard.eval.error_analysis import error_report, slice_metrics
from phishguard.eval.metrics import (
    banded_outcome,
    latency_stats,
    pr_auc,
    prf,
    roc_auc,
    score_summary,
)

__all__ = [
    "AcceptanceResult",
    "banded_outcome",
    "build_gates",
    "error_report",
    "evaluate_gates",
    "latency_stats",
    "pr_auc",
    "prf",
    "roc_auc",
    "score_summary",
    "slice_metrics",
]
