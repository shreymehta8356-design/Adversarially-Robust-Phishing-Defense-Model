"""Environment preflight - ``phishguard doctor``.

The purpose is narrow and worth stating: when this project does not work on
somebody's machine, they should get a *diagnosis*, not a traceback. Every check
here answers one question, reports a status, and — when it fails — says what to
do about it.

Nothing in this module imports the API stack or loads a model at import time,
so ``doctor`` keeps working precisely in the situations where everything else
has stopped working.
"""

from __future__ import annotations

import importlib
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Status = Literal["ok", "warn", "fail", "info"]

#: Minimum interpreter this project supports, matching ``requires-python``.
MIN_PYTHON = (3, 10)
#: Above this the project is untested; it is a warning, never a refusal.
MAX_TESTED_PYTHON = (3, 13)

#: Import name -> (pip name, minimum version, what breaks without it)
CORE_PACKAGES: dict[str, tuple[str, str, str]] = {
    "numpy": ("numpy", "1.24", "everything"),
    "scipy": ("scipy", "1.10", "the text models"),
    "sklearn": ("scikit-learn", "1.3", "all model training and inference"),
    "joblib": ("joblib", "1.3", "saving and loading models"),
    "pydantic": ("pydantic", "2.5", "input validation and the API contracts"),
    "pydantic_settings": ("pydantic-settings", "2.1", "configuration loading"),
}
API_PACKAGES: dict[str, tuple[str, str, str]] = {
    "fastapi": ("fastapi", "0.110", "the HTTP API and the analyst console"),
    "uvicorn": ("uvicorn", "0.27", "serving the API"),
}
OPTIONAL_PACKAGES: dict[str, tuple[str, str, str]] = {
    "torch": ("torch", "2.1", "the optional transformer member (off by default)"),
    "transformers": ("transformers", "4.38", "the optional transformer member"),
    "mlflow": ("mlflow", "2.10", "optional experiment tracking"),
    "pytest": ("pytest", "7.4", "running the test suite with pytest"),
}


@dataclass(slots=True)
class Check:
    """One diagnostic result."""

    name: str
    status: Status
    detail: str
    fix: str = ""

    @property
    def symbol(self) -> str:
        return {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "info": "--  "}[self.status]


@dataclass(slots=True)
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: Status, detail: str, fix: str = "") -> None:
        self.checks.append(Check(name, status, detail, fix))

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == "fail"]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == "warn"]

    @property
    def ok(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "n_checks": len(self.checks),
            "n_failed": len(self.failures),
            "n_warnings": len(self.warnings),
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "fix": c.fix}
                for c in self.checks
            ],
        }

    def render(self) -> str:
        width = max((len(c.name) for c in self.checks), default=10)
        lines = ["", "PhishGuard environment check", "=" * 74]
        for c in self.checks:
            lines.append(f"  [{c.symbol}] {c.name:<{width}}  {c.detail}")
            if c.fix and c.status in {"fail", "warn"}:
                lines.append(f"           {'':<{width}}  -> {c.fix}")
        lines.append("=" * 74)
        if self.failures:
            lines.append(
                f"  {len(self.failures)} problem(s) will stop PhishGuard from working. "
                "Fix the items marked FAIL above."
            )
        elif self.warnings:
            lines.append(
                f"  Ready. {len(self.warnings)} warning(s) - the system will run, but "
                "read them before relying on it."
            )
        else:
            lines.append("  Ready. Everything this project needs is present and working.")
        return "\n".join(lines)


# --------------------------------------------------------------------------
def _version_tuple(raw: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in str(raw).split(".")[:3]:
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _check_packages(
    report: Report, group: dict[str, tuple[str, str, str]], *, required: bool
) -> None:
    for module_name, (pip_name, minimum, purpose) in group.items():
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            report.add(
                pip_name,
                "fail" if required else "info",
                (
                    f"not installed - needed for {purpose}"
                    if required
                    else f"not installed (optional: {purpose})"
                ),
                f"pip install '{pip_name}>={minimum}'" if required else "",
            )
            if required and not isinstance(exc, ImportError):
                report.checks[-1].detail += f" ({type(exc).__name__})"
            continue
        found = getattr(module, "__version__", "unknown")
        if found != "unknown" and _version_tuple(found) < _version_tuple(minimum):
            report.add(
                pip_name,
                "warn",
                f"{found} installed, {minimum}+ expected - needed for {purpose}",
                f"pip install --upgrade '{pip_name}>={minimum}'",
            )
        else:
            report.add(pip_name, "ok", str(found))


def _writable(path: Path) -> tuple[bool, str]:
    """Can we actually create and delete a file here?"""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".phishguard-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _available_memory_mb() -> float | None:
    """Best-effort available memory, without adding a dependency."""
    try:  # Linux
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    try:  # POSIX generally
        pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and page_size > 0:
            return pages * page_size / (1024.0 * 1024.0)
    except (ValueError, OSError, AttributeError):
        pass
    return None


def _cgroup_memory_limit_mb() -> float | None:
    """Container memory limit, which is what actually kills a training run."""
    for path, transform in (
        ("/sys/fs/cgroup/memory.max", str),  # cgroup v2
        ("/sys/fs/cgroup/memory/memory.limit_in_bytes", str),  # cgroup v1
    ):
        try:
            raw = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if raw in {"max", ""}:
            return None
        try:
            value = int(transform(raw))
        except ValueError:
            continue
        # cgroup v1 reports an enormous sentinel when unlimited.
        if value >= 1 << 62:
            return None
        return value / (1024.0 * 1024.0)
    return None


# --------------------------------------------------------------------------
def run_checks(*, verbose: bool = False) -> Report:
    """Run every preflight check and return the report."""
    report = Report()

    # ---------------------------------------------------------- interpreter
    v = sys.version_info
    version_str = f"{v.major}.{v.minor}.{v.micro} ({platform.python_implementation()})"
    if (v.major, v.minor) < MIN_PYTHON:
        report.add(
            "python",
            "fail",
            f"{version_str} - this project needs {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer",
            f"install Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ and recreate the virtualenv",
        )
    elif (v.major, v.minor) > MAX_TESTED_PYTHON:
        report.add(
            "python",
            "warn",
            f"{version_str} - newer than the tested range "
            f"(3.10-{MAX_TESTED_PYTHON[0]}.{MAX_TESTED_PYTHON[1]})",
            "it will probably work; run 'phishguard doctor --self-test' to confirm",
        )
    else:
        report.add("python", "ok", version_str)

    report.add(
        "platform", "info", f"{platform.system()} {platform.release()} ({platform.machine()})"
    )

    # ------------------------------------------------------------- packages
    _check_packages(report, CORE_PACKAGES, required=True)
    _check_packages(report, API_PACKAGES, required=True)
    if verbose:
        _check_packages(report, OPTIONAL_PACKAGES, required=False)

    # -------------------------------------------------------------- sqlite
    try:
        conn = sqlite3.connect(":memory:")
        mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        conn.close()
        # An in-memory database cannot use WAL, so this confirms the pragma is
        # understood rather than that WAL is active.
        report.add("sqlite3", "ok", f"{sqlite3.sqlite_version} (journal pragma: {mode[0]})")
    except Exception as exc:  # noqa: BLE001
        report.add(
            "sqlite3",
            "fail",
            f"unusable: {type(exc).__name__}: {exc}",
            "the audit trail needs SQLite; reinstall Python with sqlite support",
        )

    # ------------------------------------------------------- writable paths
    from phishguard.config import get_settings

    settings = get_settings()
    writable, why = _writable(settings.artifacts_dir)
    if writable:
        report.add("artifacts dir", "ok", str(settings.artifacts_dir))
    else:
        report.add(
            "artifacts dir",
            "fail",
            f"{settings.artifacts_dir} is not writable - {why}",
            "set PG_ARTIFACTS_DIR to a directory you can write to, "
            "e.g. PG_ARTIFACTS_DIR=~/phishguard-data",
        )

    tmp_ok, tmp_why = _writable(Path(tempfile.gettempdir()))
    report.add(
        "temp dir",
        "ok" if tmp_ok else "fail",
        tempfile.gettempdir() if tmp_ok else f"not writable - {tmp_why}",
        "" if tmp_ok else "set TMPDIR to a writable location",
    )

    # ------------------------------------------------------------ resources
    limit = _cgroup_memory_limit_mb()
    available = _available_memory_mb()
    # Measured peak for `train --n 12000` is ~380 MB; 1 GB is a comfortable floor.
    budget = min([x for x in (limit, available) if x is not None], default=None)
    if budget is None:
        report.add("memory", "info", "could not be determined on this platform")
    elif budget < 700:
        report.add(
            "memory",
            "fail",
            f"{budget:.0f} MB available - training needs roughly 400 MB free",
            "close other applications, or raise the container memory limit; "
            "'phishguard train --n 4000' also works in less",
        )
    elif budget < 1200:
        report.add(
            "memory",
            "warn",
            f"{budget:.0f} MB available - enough, but not much headroom",
            "use --n 6000 if training is killed",
        )
    else:
        report.add("memory", "ok", f"{budget:.0f} MB available")

    try:
        free_gb = shutil.disk_usage(settings.artifacts_dir.parent).free / (1024**3)
        if free_gb < 0.5:
            report.add(
                "disk",
                "fail",
                f"{free_gb:.1f} GB free - a model needs about 50 MB, "
                "and the corpus and reports need more",
                "free some space, or point PG_ARTIFACTS_DIR at a larger volume",
            )
        elif free_gb < 2:
            report.add("disk", "warn", f"{free_gb:.1f} GB free")
        else:
            report.add("disk", "ok", f"{free_gb:.1f} GB free")
    except OSError as exc:
        report.add("disk", "info", f"could not be determined: {exc}")

    # --------------------------------------------------------- console asset
    from phishguard.config import find_console_asset

    asset = find_console_asset()
    if asset is not None:
        report.add("analyst console", "ok", str(asset))
    else:
        report.add(
            "analyst console",
            "warn",
            "index.html not found - the API will work, the browser console will not",
            "set PG_UI_PATH to the path of src/phishguard/static/index.html",
        )

    # ---------------------------------------------------------------- model
    try:
        from phishguard.models.registry import current_version, list_models

        version = current_version(settings=settings)
        if version:
            report.add(
                "trained model",
                "ok",
                f"{version} ({len(list_models(settings=settings))} version(s) registered)",
            )
        else:
            report.add(
                "trained model",
                "warn",
                "none registered - scanning will return 503",
                "run 'phishguard train --save' (about 40 seconds)",
            )
    except Exception as exc:  # noqa: BLE001
        report.add(
            "trained model",
            "warn",
            f"registry unreadable: {type(exc).__name__}: {exc}",
            "run 'phishguard train --save' to create one",
        )

    # ----------------------------------------------------------- API config
    try:
        keys = settings.resolved_api_keys()
        if not keys:
            report.add(
                "API keys",
                "fail",
                f"none configured and environment is '{settings.environment}'",
                "set PG_API_KEYS='analyst:<key>,admin:<key>'",
            )
        elif not settings.api_keys.strip():
            report.add(
                "API keys",
                "warn",
                "using the built-in development keys",
                "set PG_API_KEYS before exposing this beyond localhost",
            )
        else:
            roles = sorted(set(keys.values()))
            report.add(
                "API keys", "ok", f"{len(keys)} key(s) configured, roles: {', '.join(roles)}"
            )
    except Exception as exc:  # noqa: BLE001
        report.add(
            "API keys",
            "fail",
            f"{type(exc).__name__}: {exc}",
            "check PG_API_KEYS formatting: 'analyst:<key>,admin:<key>'",
        )

    if (
        settings.pseudonymization_salt == "phishguard-dev-salt"
        or "change-me" in settings.pseudonymization_salt
    ):
        report.add(
            "audit salt",
            "warn",
            "still the default value",
            "set PG_PSEUDONYMIZATION_SALT to a random string before production use",
        )
    else:
        report.add("audit salt", "ok", "configured")

    # --------------------------------------------------- console encoding
    encoding = (sys.stdout.encoding or "").lower()
    if encoding and "utf" not in encoding:
        report.add(
            "console encoding",
            "warn",
            f"{sys.stdout.encoding} - non-UTF-8 terminals can mangle output",
            "on Windows: set PYTHONUTF8=1, or run 'chcp 65001'",
        )
    else:
        report.add("console encoding", "ok", sys.stdout.encoding or "unknown")

    return report


def self_test() -> Report:
    """Exercise the real pipeline end to end on a tiny corpus.

    ``run_checks`` proves the environment *looks* right. This proves it
    actually works: it generates data, extracts features, trains, scores and
    attacks, which is the fastest way to catch a subtly incompatible library
    version that imports cleanly and then misbehaves.
    """
    report = Report()

    def step(name: str, fn: Callable[[], str]) -> Any:
        try:
            report.add(name, "ok", fn())
        except Exception as exc:  # noqa: BLE001
            report.add(
                name,
                "fail",
                f"{type(exc).__name__}: {exc}",
                "run with --verbose, or open an issue with this message",
            )
            raise

    try:
        from phishguard.data.splits import grouped_split
        from phishguard.data.synthetic import generate_corpus
        from phishguard.features import FeatureAssembler

        state: dict[str, Any] = {}

        def gen() -> str:
            msgs, labels = generate_corpus(400, seed=1)
            state["msgs"], state["labels"] = msgs, labels
            return f"{len(msgs)} messages, {sum(labels)} phishing"

        step("corpus generation", gen)

        def feats() -> str:
            assembler = FeatureAssembler()
            X = assembler.transform(state["msgs"][:50])
            state["n_features"] = assembler.n_features
            return f"{X.shape[1]} features extracted"

        step("feature extraction", feats)

        def split() -> str:
            sp = grouped_split(state["msgs"], state["labels"], test_size=0.3, seed=2)
            state["split"] = sp
            return f"{len(sp.train_idx)} train / {len(sp.test_idx)} test, no campaign overlap"

        step("leakage-safe split", split)

        def train() -> str:
            import numpy as np

            from phishguard.models.detector import PhishGuardDetector

            sp = state["split"]
            tr = [state["msgs"][i] for i in sp.train_idx]
            y = np.asarray([state["labels"][i] for i in sp.train_idx])
            det = PhishGuardDetector()
            det.fit(tr, y, adversarial_augment=False)
            state["detector"] = det
            return f"model {det.model_version} trained on {len(tr)} messages"

        step("model training", train)

        def score_real() -> str:
            det = state["detector"]
            sp = state["split"]
            te = [state["msgs"][i] for i in sp.test_idx][:40]
            probs = det.predict_proba(te)
            verdict = det.assess(te[0])
            return (
                f"{len(probs)} scored, range "
                f"{probs.min():.3f}-{probs.max():.3f}; "
                f"evidence items: {len(verdict.evidence)}"
            )

        step("scoring and explanation", score_real)

        def attack() -> str:
            from phishguard.adversarial.attacker import BudgetedAttacker, RawScoreSurface

            det = state["detector"]
            phish = [state["msgs"][i] for i in state["split"].test_idx if state["labels"][i] == 1][
                :5
            ]
            if not phish:
                return "no phishing messages in the test split to attack"
            results = BudgetedAttacker(RawScoreSurface(det), budget=4, seed=1).attack_many(phish)
            return f"{len(results)} messages attacked, suite functional"

        step("adversarial suite", attack)

        def store() -> str:
            from phishguard.service.store import DecisionStore

            path = Path(tempfile.mkdtemp(prefix="pg-doctor-")) / "probe.db"
            db = DecisionStore(path)
            db.record_decision(
                decision_id="dec_selftest",
                request_id="req_selftest",
                verdict={
                    "score": 0.5,
                    "band": "REVIEW",
                    "label": 0,
                    "model_version": "selftest",
                    "evidence": [],
                    "member_scores": {},
                    "latency_ms": 1.0,
                },
                redacted={
                    "subject_hash": "x",
                    "sender_px": "y",
                    "sender_domain": "example.com",
                    "recipient_count": 1,
                    "body_length": 10,
                    "attachment_count": 0,
                },
            )
            count = db.count()
            db.close()
            return f"audit trail read/write works ({count} record)"

        step("audit store", store)
    except Exception:  # noqa: BLE001, S110 - already recorded by step()
        pass

    return report
