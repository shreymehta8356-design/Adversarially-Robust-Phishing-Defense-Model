#!/usr/bin/env python3
"""Dependency-free test collector.

``pytest`` is the supported way to run this suite (``pytest -q``). This script
exists so the suite can also run somewhere pytest is not installed - a minimal
container, a locked-down build agent - without changing a line of the tests.

The test files use plain functions and plain ``assert`` statements with no
fixtures, so both runners see the same thing. Anything pytest-specific (a
``tmp_path`` argument, a marker) is handled here or skipped with a reason.

Usage::

    python scripts/run_tests.py                 # everything
    python scripts/run_tests.py unit            # one directory
    python scripts/run_tests.py -k normalize    # match by name
    python scripts/run_tests.py -v              # show every test
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

GREEN, RED, YELLOW, DIM, RESET = (
    ("\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m")
    if sys.stdout.isatty() else ("", "", "", "", "")
)


def load_module(path: Path):
    name = "phishguard_tests_" + path.relative_to(ROOT).as_posix().replace("/", "_")[:-3]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def collect(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        if p.is_file() and p.name.startswith("test_"):
            files.append(p)
        elif p.is_dir():
            files.extend(sorted(p.rglob("test_*.py")))
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run the PhishGuard test suite")
    parser.add_argument("targets", nargs="*", default=[],
                        help="directories or files under tests/ (default: all)")
    parser.add_argument("-k", dest="pattern", default="",
                        help="only run tests whose name contains this substring")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("-x", dest="exitfirst", action="store_true",
                        help="stop after the first failure")
    args = parser.parse_args(argv)

    tests_root = ROOT / "tests"
    targets = [
        (tests_root / t if not Path(t).is_absolute() else Path(t))
        for t in (args.targets or ["."])
    ]
    files = collect([t if t.exists() else tests_root / t.name for t in targets])
    if not files:
        print(f"{RED}no test files found{RESET}")
        return 1

    passed = failed = skipped = 0
    failures: list[tuple[str, str]] = []
    started = time.perf_counter()

    for file in files:
        rel = file.relative_to(ROOT)
        try:
            module = load_module(file)
        except Exception:
            failed += 1
            failures.append((str(rel), traceback.format_exc()))
            print(f"{RED}ERROR{RESET} importing {rel}")
            continue

        functions = [
            (name, obj)
            for name, obj in vars(module).items()
            if name.startswith("test_") and inspect.isfunction(obj)
        ]
        if args.pattern:
            functions = [(n, f) for n, f in functions if args.pattern in n]
        if not functions:
            continue

        print(f"\n{DIM}{rel}{RESET}")
        for name, fn in functions:
            # Supply pytest's tmp_path where a test declares it.
            kwargs = {}
            params = inspect.signature(fn).parameters
            if "tmp_path" in params:
                import tempfile

                kwargs["tmp_path"] = Path(tempfile.mkdtemp(prefix="pg-tmp-"))
            t0 = time.perf_counter()
            try:
                fn(**kwargs)
            except Exception as exc:
                if exc.__class__.__name__ in {"Skipped", "SkipTest"}:
                    skipped += 1
                    print(f"  {YELLOW}skip{RESET} {name}  {DIM}{exc}{RESET}")
                    continue
                failed += 1
                failures.append((f"{rel}::{name}", traceback.format_exc()))
                print(f"  {RED}FAIL{RESET} {name}")
                if args.exitfirst:
                    _report(failures, passed, failed, skipped, started)
                    return 1
            else:
                passed += 1
                elapsed = (time.perf_counter() - t0) * 1000
                if args.verbose:
                    print(f"  {GREEN}ok{RESET}   {name} {DIM}({elapsed:.0f} ms){RESET}")
                elif elapsed > 2000:
                    print(f"  {GREEN}ok{RESET}   {name} {DIM}({elapsed / 1000:.1f} s){RESET}")

    return _report(failures, passed, failed, skipped, started)


def _report(failures, passed, failed, skipped, started) -> int:
    if failures:
        print(f"\n{RED}{'=' * 74}{RESET}")
        for name, tb in failures:
            print(f"{RED}FAILED{RESET} {name}")
            print(tb.rstrip())
            print("-" * 74)
    elapsed = time.perf_counter() - started
    colour = RED if failed else GREEN
    print(
        f"\n{colour}{passed} passed, {failed} failed, {skipped} skipped{RESET} "
        f"in {elapsed:.1f}s"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
