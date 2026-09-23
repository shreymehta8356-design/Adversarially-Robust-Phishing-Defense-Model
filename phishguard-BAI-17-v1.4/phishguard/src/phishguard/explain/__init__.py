"""Explanation layer: attributions and analyst-readable evidence cards."""

from phishguard.explain.attributions import (
    engineered_attributions,
    fusion_attributions,
)
from phishguard.explain.evidence import build_evidence, humanize_feature

__all__ = [
    "build_evidence",
    "engineered_attributions",
    "fusion_attributions",
    "humanize_feature",
]
