"""Optional experiment tracking with MLflow.

The evaluation already writes a complete, versioned record of every run to
``artifacts/reports``; MLflow adds what a file cannot: a browsable history of
runs side by side, with their parameters, metrics and artefacts, which is how
a team compares this week's model with last month's.

It is optional on purpose. The core install stays small and offline, and
nothing breaks without it: ``phishguard train --mlflow`` and
``phishguard evaluate --mlflow`` log a run when MLflow is installed
(``pip install -e ".[tracking]"``) and say how to install it when it is not.
Runs go to a local ``mlruns/`` folder unless ``MLFLOW_TRACKING_URI`` points
elsewhere; ``mlflow ui`` then shows them at http://127.0.0.1:5000.

Only parameters, metrics and the report files are logged -- never messages.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

EXPERIMENT = "phishguard"


class TrackingUnavailable(RuntimeError):
    """MLflow is not installed."""


def _flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping):
            out.update(_flatten(value, name + "."))
        else:
            out[name] = value
    return out


def _numeric(data: Mapping[str, Any]) -> dict[str, float]:
    return {
        k: float(v)
        for k, v in _flatten(data).items()
        if isinstance(v, (int, float)) and not isinstance(v, bool)
    }


def log_run(
    *,
    run_name: str,
    params: Mapping[str, Any],
    metrics: Mapping[str, Any],
    artifacts: Iterable[Path] = (),
    tags: Mapping[str, str] | None = None,
    tracking_uri: str | None = None,
    default_root: Path | None = None,
) -> str:
    """Log one run and return its id. Raises :class:`TrackingUnavailable`."""
    try:
        import mlflow
    except ImportError as exc:
        raise TrackingUnavailable(
            'MLflow is not installed. Add it with:  pip install -e ".[tracking]"'
        ) from exc

    uri = tracking_uri or os.environ.get("MLFLOW_TRACKING_URI")
    if not uri:
        root = (default_root or Path.cwd()) / "mlruns"
        root.mkdir(parents=True, exist_ok=True)
        uri = root.resolve().as_uri()
    mlflow.set_tracking_uri(uri)
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=run_name) as run:
        mlflow.set_tags({"project": "BAI-17 PhishGuard", **dict(tags or {})})
        # MLflow limits parameter values to 500 characters.
        mlflow.log_params({k: str(v)[:500] for k, v in _flatten(params).items()})
        mlflow.log_metrics(_numeric(metrics))
        for path in artifacts:
            path = Path(path)
            if path.is_dir():
                mlflow.log_artifacts(str(path), artifact_path=path.name)
            elif path.is_file():
                mlflow.log_artifact(str(path))
        return str(run.info.run_id)


def evaluation_metrics(report: Mapping[str, Any]) -> dict[str, float]:
    """The headline numbers of an evaluation, under stable metric names."""
    hard = ((report.get("pg_hard") or {}).get("systems") or {}).get("phishguard") or {}
    rob = report.get("robustness") or {}
    acc = report.get("acceptance") or {}
    return _numeric(
        {
            "clean.macro_f1": (report.get("clean") or {}).get("macro_f1"),
            "clean.pr_auc": (report.get("clean") or {}).get("pr_auc"),
            "clean.false_positive_rate": (report.get("clean") or {}).get("false_positive_rate"),
            "calibration.ece": (report.get("calibration") or {}).get("ece"),
            "robustness.macro_f1_drop": rob.get("macro_f1_drop"),
            "robustness.attack_success_rate": rob.get("attack_success_rate"),
            "latency.p95_ms": (report.get("latency") or {}).get("p95_ms"),
            "bands.review_rate": (report.get("banded_decision") or {}).get("review_rate"),
            "pg_hard.silent_delivery": hard.get("silent_delivery"),
            "pg_hard.false_block": hard.get("false_block"),
            "gates.passed": acc.get("n_gates", 0) - acc.get("n_failed", 0) if acc else None,
        }
    )
