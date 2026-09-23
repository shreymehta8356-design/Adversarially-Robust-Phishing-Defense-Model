"""Model persistence and the model registry.

Saving a detector is not just pickling an estimator. What has to survive is the
*whole decision system*: members, fusion weights, calibrator, the defensive
configuration that was active during training, and above all the feature
contract. A model loaded against a different feature layout will happily
produce numbers that look plausible and are wrong, so the contract is verified
on load and a mismatch is a hard failure rather than a warning.

Layout on disk::

    artifacts/models/
        <version>/
            detector.joblib     members, fusion, calibrator
            manifest.json       version, contract, metrics, provenance
        current -> <version>    pointer file naming the active version

Provenance in the manifest is what makes a result reproducible six months
later: the corpus seed and size, the split strategy, the library versions and
the defence set. ``phishguard train`` writes it; the model card reads it.
"""

from __future__ import annotations

import json
import platform
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn

from phishguard import __version__
from phishguard.config import Settings, get_settings
from phishguard.models.detector import PhishGuardDetector

_CURRENT_POINTER = "current"
_DETECTOR_FILE = "detector.joblib"
_MANIFEST_FILE = "manifest.json"

#: Bumped whenever a change to *training* means a model trained earlier would
#: give different results from one trained now. ``start.py`` reads it from the
#: manifest and retrains an older model once, so a user who updates the code
#: never runs it against a model the documentation no longer describes.
#: 1 - original; 2 - campaign-drawn training pools and a drift reference.
TRAINING_FORMAT = 2


@dataclass(slots=True)
class ModelRecord:
    """One saved model version."""

    version: str
    path: Path
    manifest: dict[str, Any]

    @property
    def created_at(self) -> str:
        return str(self.manifest.get("created_at", ""))

    @property
    def metrics(self) -> dict[str, Any]:
        return dict(self.manifest.get("metrics", {}))


def _environment() -> dict[str, str]:
    return {
        "phishguard": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
    }


def save_detector(
    detector: PhishGuardDetector,
    *,
    settings: Settings | None = None,
    metrics: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    make_current: bool = True,
) -> ModelRecord:
    """Persist a trained detector and its manifest."""
    if not detector.is_trained:
        raise ValueError("refusing to save an untrained detector")
    settings = settings or detector.settings
    settings.ensure_dirs()

    version = detector.model_version
    target = settings.models_path / version
    target.mkdir(parents=True, exist_ok=True)

    joblib.dump(detector, target / _DETECTOR_FILE, compress=3)

    manifest: dict[str, Any] = {
        "version": version,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "trained_at": detector.trained_at,
        "environment": _environment(),
        "members": list(detector.member_names),
        "feature_families": list(detector.families),
        "defenses": detector.defenses.as_dict(),
        "active_defense_ids": detector.defenses.active_ids,
        "training_format": TRAINING_FORMAT,
        # The thresholds this model will actually use, which may have been
        # fitted to the false-alarm budget rather than taken from settings.
        "thresholds": {
            "review": float(getattr(detector, "review_threshold", settings.review_threshold)),
            "block": float(getattr(detector, "block_threshold", settings.block_threshold)),
            "source": getattr(detector, "threshold_source", "configured"),
        },
        "drift_reference": getattr(detector, "drift_reference", None) is not None,
        "calibration_method": detector.calibrator.fitted_method,
        "training": detector.report.as_dict() if detector.report else {},
        "metrics": metrics or {},
        "provenance": provenance or {},
    }
    (target / _MANIFEST_FILE).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if make_current:
        (settings.models_path / _CURRENT_POINTER).write_text(version, encoding="utf-8")
    return ModelRecord(version=version, path=target, manifest=manifest)


def load_detector(
    version: str | None = None, *, settings: Settings | None = None
) -> tuple[PhishGuardDetector, dict[str, Any]]:
    """Load a saved detector and verify its feature contract."""
    settings = settings or get_settings()
    version = version or current_version(settings=settings)
    if not version:
        raise FileNotFoundError(
            f"no trained model found under {settings.models_path}. Run 'phishguard train' first."
        )
    target = settings.models_path / version
    detector_file = target / _DETECTOR_FILE
    if not detector_file.exists():
        raise FileNotFoundError(f"model version {version!r} not found at {detector_file}")

    detector: PhishGuardDetector = joblib.load(detector_file)
    manifest: dict[str, Any] = {}
    manifest_file = target / _MANIFEST_FILE
    if manifest_file.exists():
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Hard-fail on a feature-contract mismatch. A model served against a
    # different feature layout produces confident nonsense.
    from phishguard.models.members import EngineeredMember

    engineered = detector.members.get("engineered")
    contract = (manifest.get("training") or {}).get("feature_contract") or {}
    if isinstance(engineered, EngineeredMember) and contract.get("names"):
        engineered.assembler.verify(contract)

    # Runtime settings win over the training-time copy so that thresholds can be
    # retuned operationally without retraining.
    detector.settings = settings
    return detector, manifest


def current_version(*, settings: Settings | None = None) -> str | None:
    settings = settings or get_settings()
    pointer = settings.models_path / _CURRENT_POINTER
    if pointer.exists():
        version = pointer.read_text(encoding="utf-8").strip()
        if version and (settings.models_path / version / _DETECTOR_FILE).exists():
            return version
    # Fall back to the most recently created version directory.
    candidates = [
        d for d in settings.models_path.glob("*") if d.is_dir() and (d / _DETECTOR_FILE).exists()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime).name


def list_models(*, settings: Settings | None = None) -> list[ModelRecord]:
    settings = settings or get_settings()
    records: list[ModelRecord] = []
    if not settings.models_path.exists():
        return records
    for d in sorted(settings.models_path.glob("*")):
        if not d.is_dir() or not (d / _DETECTOR_FILE).exists():
            continue
        manifest = {}
        mf = d / _MANIFEST_FILE
        if mf.exists():
            try:
                manifest = json.loads(mf.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest = {"version": d.name, "error": "unreadable manifest"}
        records.append(ModelRecord(version=d.name, path=d, manifest=manifest))
    records.sort(key=lambda r: r.created_at, reverse=True)
    return records


def promote(version: str, *, settings: Settings | None = None) -> None:
    """Make ``version`` the model the service loads."""
    settings = settings or get_settings()
    if not (settings.models_path / version / _DETECTOR_FILE).exists():
        raise FileNotFoundError(f"model version {version!r} not found")
    (settings.models_path / _CURRENT_POINTER).write_text(version, encoding="utf-8")


def prune(keep: int = 5, *, settings: Settings | None = None) -> list[str]:
    """Delete all but the newest ``keep`` versions, never the current one."""
    settings = settings or get_settings()
    active = current_version(settings=settings)
    records = list_models(settings=settings)
    removed: list[str] = []
    for record in records[keep:]:
        if record.version == active:
            continue
        shutil.rmtree(record.path, ignore_errors=True)
        removed.append(record.version)
    return removed
