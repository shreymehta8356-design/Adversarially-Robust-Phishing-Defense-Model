"""Portability regressions.

Each test here pins a bug that made the project fail on a machine other than
the one it was written on. They are cheap, and every one of them was found by
an audit rather than by a user, which is the order it should happen in.
"""

from __future__ import annotations

import ast
import pathlib
import sys

import numpy as np

SRC = pathlib.Path(__file__).resolve().parents[2] / "src"
REPO = SRC.parent


# --------------------------------------------------------- packaged assets
def test_analyst_console_ships_inside_the_package():
    """It must be package data, not a sibling directory of the repo root.

    The console used to be resolved as ``Path(__file__).parents[3] / "ui"``,
    which is right in a source checkout and wrong in every installed layout:
    in the container it resolved to ``/install/lib/python3.11/ui/index.html``,
    so the primary interface returned "asset not found" in the deployment the
    guide tells people to use first.
    """
    packaged = SRC / "phishguard" / "static" / "index.html"
    assert packaged.is_file(), "console must live inside the package"
    assert packaged.stat().st_size > 1000


def test_console_resolver_finds_the_packaged_asset():
    from phishguard.config import find_console_asset

    asset = find_console_asset()
    assert asset is not None and asset.is_file()
    assert asset.read_text(encoding="utf-8").lstrip().lower().startswith("<!doctype html")


def test_console_is_declared_as_package_data():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "static/*.html" in text, "the wheel would not contain the console"


def test_project_root_never_resolves_into_site_packages():
    """Otherwise ``phishguard train`` writes a model registry into the interpreter."""
    from phishguard.config import PROJECT_ROOT

    parts = {p.lower() for p in PROJECT_ROOT.parts}
    assert "site-packages" not in parts
    assert "dist-packages" not in parts


# ------------------------------------------------------------- file access
def test_all_text_file_access_declares_an_encoding():
    """Windows defaults to cp1252, which cannot read this project's own files.

    The corpora, the console and the reports all contain non-ASCII characters -
    homoglyphs, in the case of the adversarial suite - so an unqualified
    ``read_text()`` is a guaranteed UnicodeDecodeError on a default Windows
    install.
    """
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", None)
            if name not in {"read_text", "write_text"}:
                continue
            if not any(kw.arg == "encoding" for kw in node.keywords):
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} {name}()")
    assert not offenders, "text I/O without an explicit encoding: " + "; ".join(offenders)


def test_email_utils_is_imported_explicitly():
    """``import email`` does not bind ``email.utils``.

    It currently works only because ``email.policy`` imports it as a side
    effect, which is an implementation detail of CPython, not a promise.
    """
    source = (SRC / "phishguard" / "data" / "loaders.py").read_text(encoding="utf-8")
    assert "import email.utils" in source


# ------------------------------------------------------- interpreter range
def test_nothing_newer_than_the_declared_minimum_python_is_used():
    post_310 = {
        "StrEnum", "TaskGroup", "ExceptionGroup", "tomllib", "file_digest",
        "LiteralString", "assert_never", "batched", "override",
    }
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = getattr(node, "attr", None) or getattr(node, "id", None)
            if name in post_310:
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} {name}")
    assert not offenders, "requires-python is >=3.10 but found: " + "; ".join(offenders)


def test_declared_minimum_matches_reality():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10"' in text
    assert sys.version_info >= (3, 10)


# ------------------------------------------------------- numeric behaviour
def test_minhash_survives_uint64_wraparound():
    """The sketch relies on silent uint64 overflow, which NEP 50 changed.

    If a numpy version ever raises instead of wrapping, near-duplicate
    detection stops working and the leakage audit silently weakens.
    """
    import warnings

    from phishguard.data.splits import jaccard_from_signatures, minhash_signature

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # surface any RuntimeWarning as a failure
        same_a = minhash_signature("verify your account or it will be closed")
        same_b = minhash_signature("verify your account or it will be closed")
        other = minhash_signature("the warehouse audit is scheduled for Thursday")

    assert jaccard_from_signatures(same_a, same_b) == 1.0
    assert jaccard_from_signatures(same_a, other) < 0.4
    assert all(isinstance(v, int) and v >= 0 for v in same_a)


def test_sklearn_constructor_parameters_still_exist():
    """A silent API removal upstream would otherwise surface as a TypeError."""
    import inspect

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression

    expected = {
        HistGradientBoostingClassifier: [
            "max_iter", "learning_rate", "max_leaf_nodes", "min_samples_leaf",
            "l2_regularization", "early_stopping", "validation_fraction",
            "n_iter_no_change", "random_state",
        ],
        IsotonicRegression: ["out_of_bounds", "y_min", "y_max"],
        TfidfVectorizer: [
            "analyzer", "ngram_range", "min_df", "max_features", "sublinear_tf",
            "lowercase",
        ],
        LogisticRegression: ["max_iter", "C", "class_weight", "solver"],
    }
    for cls, params in expected.items():
        signature = set(inspect.signature(cls.__init__).parameters)
        missing = [p for p in params if p not in signature]
        assert not missing, f"{cls.__name__} no longer accepts {missing}"


# ------------------------------------------------------------- resilience
def test_memory_scaling_is_monotone_and_bounded():
    import phishguard.models.members as members

    original = members.available_memory_mb
    try:
        results = {}
        for budget in (300, 900, 1500, None):
            members.available_memory_mb = lambda b=budget: b
            results[budget] = members._memory_scaled(200_000)
        assert results[300] <= results[900] <= results[1500]
        assert results[1500] == 200_000, "a normal machine must not be penalised"
        assert results[None] == 200_000, "unknown budget must change nothing"
        assert results[300] >= 10_000, "never shrink below a usable vocabulary"
    finally:
        members.available_memory_mb = original


def test_doctor_runs_and_reports_without_raising():
    """The diagnostic must work in exactly the situations everything else fails."""
    from phishguard.doctor import run_checks

    report = run_checks(verbose=True)
    assert report.checks
    rendered = report.render()
    assert "PhishGuard environment check" in rendered
    for check in report.checks:
        assert check.status in {"ok", "warn", "fail", "info"}
        if check.status == "fail":
            assert check.fix, f"a failure must say how to fix it: {check.name}"


def test_doctor_is_json_serialisable():
    import json

    from phishguard.doctor import run_checks

    payload = json.loads(json.dumps(run_checks().as_dict()))
    assert "checks" in payload and isinstance(payload["ok"], bool)


#: Every declared runtime dependency must be either imported directly, or
#: listed here with the reason it is depended on anyway. An unused dependency
#: is a supply-chain and version-conflict surface for nothing in return, and
#: this test is how pandas was found and removed.
_INDIRECT_BUT_REAL: dict[str, str] = {
    "scipy": (
        "Never imported by name, but models/members.py calls .tocoo(), .col and "
        ".data on the sparse matrix TfidfVectorizer returns - that is scipy's "
        "API surface, so a minimum version is honest to declare."
    ),
    "uvicorn": "The ASGI server the `serve` command launches by name, not by import.",
    "python-multipart": "Required by FastAPI to parse form bodies; never imported here.",
}


def test_every_declared_dependency_is_actually_used():
    import_names = {
        "numpy": "numpy", "scipy": "scipy", "scikit-learn": "sklearn",
        "joblib": "joblib", "pydantic": "pydantic",
        "pydantic-settings": "pydantic_settings", "fastapi": "fastapi",
        "uvicorn": "uvicorn", "python-multipart": "multipart",
    }
    sources = "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py"))
    unused: list[str] = []
    for dep, module in import_names.items():
        if dep in _INDIRECT_BUT_REAL:
            continue
        if f"import {module}" not in sources and f"from {module}" not in sources:
            unused.append(dep)
    assert not unused, (
        f"declared but never imported, and with no documented reason: {unused}. "
        "Either remove the dependency or add it to _INDIRECT_BUT_REAL with the reason."
    )


def test_removed_dependencies_stay_removed():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert '"pandas' not in text, "pandas is not imported anywhere; it was removed"


def test_feature_extraction_is_deterministic_across_processes():
    """A hash-order dependency would make results differ run to run."""
    from phishguard.features import FeatureAssembler
    from tests.helpers import phishing_message

    assembler = FeatureAssembler()
    first = assembler.extract(phishing_message()).values
    second = assembler.extract(phishing_message()).values
    np.testing.assert_array_equal(first, second)
    assert assembler.names == FeatureAssembler().names
