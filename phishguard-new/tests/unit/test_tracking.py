"""MLflow tracking: optional, content-free, and exercised with a stand-in."""

from __future__ import annotations

import sys
import tempfile
import types
from pathlib import Path

from phishguard import tracking


class _FakeRun:
    def __init__(self, calls):
        self.calls = calls
        self.info = types.SimpleNamespace(run_id="run-123")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append(("end",))
        return False


def _fake_mlflow(calls):
    mod = types.ModuleType("mlflow")
    mod.set_tracking_uri = lambda uri: calls.append(("uri", uri))
    mod.set_experiment = lambda name: calls.append(("experiment", name))
    mod.start_run = lambda run_name=None: (calls.append(("start", run_name)), _FakeRun(calls))[1]
    mod.set_tags = lambda tags: calls.append(("tags", tags))
    mod.log_params = lambda params: calls.append(("params", params))
    mod.log_metrics = lambda metrics: calls.append(("metrics", metrics))
    mod.log_artifact = lambda path: calls.append(("artifact", path))
    mod.log_artifacts = lambda path, artifact_path=None: calls.append(
        ("artifacts", path, artifact_path)
    )
    return mod


def test_a_run_logs_flattened_params_numeric_metrics_and_files():
    calls: list = []
    sys.modules["mlflow"] = _fake_mlflow(calls)
    try:
        root = Path(tempfile.mkdtemp(prefix="pg-mlflow-"))
        report = root / "evaluation.json"
        report.write_text("{}", encoding="utf-8")
        (root / "figures").mkdir()
        run_id = tracking.log_run(
            run_name="evaluate pg-x",
            params={"model_version": "pg-x", "split": {"strategy": "grouped", "seed": 11}},
            metrics={"clean": {"macro_f1": 0.99, "note": "text"}, "flag": True, "n": 3},
            artifacts=[report, root / "figures", root / "missing.md"],
            default_root=root,
        )
    finally:
        del sys.modules["mlflow"]
    assert run_id == "run-123"
    kinds = [c[0] for c in calls]
    assert kinds[:3] == ["uri", "experiment", "start"] and kinds[-1] == "end"
    params = next(c[1] for c in calls if c[0] == "params")
    assert params == {"model_version": "pg-x", "split.strategy": "grouped", "split.seed": "11"}
    metrics = next(c[1] for c in calls if c[0] == "metrics")
    assert metrics == {"clean.macro_f1": 0.99, "n": 3.0}  # text and booleans are not metrics
    assert ("artifact", str(report)) in calls
    assert any(c[0] == "artifacts" and c[2] == "figures" for c in calls)
    assert next(c[1] for c in calls if c[0] == "uri").startswith("file:")


def test_without_mlflow_the_caller_is_told_how_to_install_it():
    saved = sys.modules.pop("mlflow", None)
    sys.modules["mlflow"] = None  # makes "import mlflow" raise ImportError
    try:
        tracking.log_run(run_name="x", params={}, metrics={})
    except tracking.TrackingUnavailable as exc:
        assert ".[tracking]" in str(exc)
    else:
        raise AssertionError("expected TrackingUnavailable")
    finally:
        del sys.modules["mlflow"]
        if saved is not None:
            sys.modules["mlflow"] = saved


def test_evaluation_metrics_picks_the_headline_numbers():
    report = {
        "clean": {"macro_f1": 0.98, "pr_auc": 0.99, "false_positive_rate": 0.002},
        "calibration": {"ece": 0.01},
        "robustness": {"macro_f1_drop": 0.0, "attack_success_rate": 0.0},
        "latency": {"p95_ms": 15.0},
        "banded_decision": {"review_rate": 0.16},
        "pg_hard": {"systems": {"phishguard": {"silent_delivery": 0, "false_block": 8}}},
        "acceptance": {"n_gates": 10, "n_failed": 0},
    }
    m = tracking.evaluation_metrics(report)
    assert m["gates.passed"] == 10.0 and m["pg_hard.false_block"] == 8.0
    assert set(m) >= {"clean.macro_f1", "latency.p95_ms", "bands.review_rate"}
