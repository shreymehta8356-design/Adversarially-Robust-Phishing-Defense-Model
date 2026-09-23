"""Models: baselines, fusion members, the detector, calibration and the registry."""

from phishguard.models.baseline import RULES, RuleBaseline, TfidfBaseline
from phishguard.models.calibration import (
    Calibrator,
    expected_calibration_error,
    reliability_curve,
)
from phishguard.models.detector import PhishGuardDetector, TrainingReport
from phishguard.models.registry import (
    current_version,
    list_models,
    load_detector,
    promote,
    save_detector,
)

__all__ = [
    "Calibrator",
    "PhishGuardDetector",
    "RULES",
    "RuleBaseline",
    "TfidfBaseline",
    "TrainingReport",
    "current_version",
    "expected_calibration_error",
    "list_models",
    "load_detector",
    "promote",
    "reliability_curve",
    "save_detector",
]
