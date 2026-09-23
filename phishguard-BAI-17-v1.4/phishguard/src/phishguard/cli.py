"""Command-line interface.

Every result in the report is reproducible from one of these commands, which is
what the "runs from documented setup instructions on a clean machine"
acceptance gate requires.

::

    phishguard data      --n 12000                  build and inspect the corpus
    phishguard train     --n 12000 --save           train and register a model
    phishguard evaluate  --defense-ablation         produce the evaluation dossier
    phishguard attack    --budget 10                run the adversarial suite alone
    phishguard scan      --file message.json        score one message
    phishguard models    --list                     inspect the model registry
    phishguard serve     --port 8000                run the API
    phishguard doctor    --self-test                check this machine can run it
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

from phishguard import __version__
from phishguard.config import get_settings


def _load_corpus(args: argparse.Namespace) -> tuple[list[Any], list[int], str]:
    """Build or load the corpus named by the CLI arguments."""
    if args.data_source and args.data_source != "synthetic":
        from phishguard.data.loaders import load_any

        messages: list[Any] = []
        labels: list[int] = []
        specs = [x.strip() for x in args.data_source.split(",") if x.strip()]
        # ``synthetic`` may appear alongside real corpora: the real mail teaches
        # the text members a vocabulary no generator produces, and the synthetic
        # campaigns keep the behavioural family and the hard cases in the pool.
        # Real corpora carry no sender history, so on their own they would
        # train a model that has never seen the behavioural block populated.
        if "synthetic" in specs:
            from phishguard.data.synthetic import generate_corpus

            specs = [x for x in specs if x != "synthetic"]
            n = int(getattr(args, "synthetic_n", 0) or args.n)
            m, y = generate_corpus(n, seed=args.seed, phish_ratio=args.phish_ratio)
            print(f"  generated {len(m)} synthetic messages (seed {args.seed})")
            messages.extend(m)
            labels.extend(y)
        for spec in specs:
            from phishguard.data.loaders import LoadReport

            report = LoadReport()
            m, y = load_any(
                spec,
                limit=getattr(args, "limit", None),
                spam_as=getattr(args, "spam_as", "skip"),
                report=report,
            )
            skipped = report.read - report.kept
            print(
                f"  loaded {report.kept} from {spec}"
                + (
                    f" ({skipped} skipped - run 'phishguard data --verify' to see why)"
                    if skipped
                    else ""
                )
            )
            messages.extend(m)
            labels.extend(y)
        if not messages:
            raise SystemExit(f"no messages loaded from {args.data_source!r}")
        return messages, labels, args.data_source

    from phishguard.data.synthetic import generate_corpus

    messages, labels = generate_corpus(args.n, seed=args.seed, phish_ratio=args.phish_ratio)
    return messages, labels, f"synthetic(n={args.n}, seed={args.seed})"


def _split(args: argparse.Namespace, messages: list[Any], labels: list[int]):
    from phishguard.data.splits import grouped_split, temporal_split

    if args.split == "temporal":
        return temporal_split(messages, labels, test_size=args.test_size)
    return grouped_split(messages, labels, test_size=args.test_size, seed=args.split_seed)


# --------------------------------------------------------------------------
def cmd_data(args: argparse.Namespace) -> int:
    from collections import Counter

    from phishguard.data.splits import audit_leakage
    from phishguard.features import FeatureAssembler

    if getattr(args, "verify", False):
        import json

        from phishguard.data.verify import audit_corpus, render_audit

        if not args.data_source or args.data_source == "synthetic":
            print("--verify audits a real corpus. Point it at one, for example:")
            print(
                "  phishguard data --verify --data-source "
                "data/phishing-2024#phish,data/enron-maildir#ham"
            )
            return 2
        specs = [x.strip() for x in args.data_source.split(",") if x.strip()]
        audit, _, _ = audit_corpus(specs, limit=args.limit, spam_as=args.spam_as)
        print(render_audit(audit))
        settings = get_settings()
        settings.ensure_dirs()
        out = settings.reports_path / "corpus-audit.json"
        out.write_text(json.dumps(audit.as_dict(), indent=2, default=str), encoding="utf-8")
        print(f"\nwritten: {out}")
        return 1 if audit.verdict == "NOT READY" else 0

    messages, labels, provenance = _load_corpus(args)
    split = _split(args, messages, labels)
    print(f"corpus: {provenance}")
    print(f"  messages         {len(messages)}")
    print(f"  phishing rate    {sum(labels) / len(labels):.4f}")
    print(f"  campaigns        {len({m.group_key for m in messages})}")
    print(f"  lure types       {len({m.source for m in messages})}")
    print(f"\nsplit ({split.strategy}):")
    print(f"  train            {len(split.train_idx)}")
    print(f"  test             {len(split.test_idx)}")
    print(f"  near-duplicates dropped from test: {split.dropped_near_duplicates}")
    for k, v in split.notes.items():
        print(f"  {k:16s} {v}")

    assembler = FeatureAssembler()
    X = assembler.transform(messages)
    report = audit_leakage(messages, labels, split, features=X, feature_names=assembler.names)
    print(f"\nleakage audit: {'PASSED' if report.passed else 'FAILED'}")
    for failure in report.failures:
        print(f"  ! {failure}")
    for row in report.suspicious_features[:5]:
        print(f"  suspicious: {row['feature']} (AUC {row['single_feature_auc']})")

    print(f"\nfeature contract: {assembler.n_features} features")
    for family, size in assembler.contract()["family_sizes"].items():
        print(f"  {family:12s} {size}")

    if args.show_kinds:
        print("\nlure types:")
        for (kind, label), n in Counter(
            (m.source.split(":")[-1], y) for m, y in zip(messages, labels, strict=True)
        ).most_common():
            print(f"  {kind:24s} label={label} n={n}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from phishguard.data.splits import audit_leakage
    from phishguard.eval.metrics import score_summary
    from phishguard.features import FeatureAssembler
    from phishguard.models.detector import PhishGuardDetector
    from phishguard.models.registry import save_detector

    settings = get_settings()
    settings.ensure_dirs()
    messages, labels, provenance = _load_corpus(args)
    split = _split(args, messages, labels)

    train = [messages[i] for i in split.train_idx]
    y_train = np.asarray([labels[i] for i in split.train_idx], dtype=np.int64)
    test = [messages[i] for i in split.test_idx]
    y_test = np.asarray([labels[i] for i in split.test_idx], dtype=np.int64)

    assembler = FeatureAssembler()
    leakage = audit_leakage(
        messages,
        labels,
        split,
        features=assembler.transform(messages),
        feature_names=assembler.names,
    )
    if not leakage.passed and not args.allow_leakage:
        print("LEAKAGE AUDIT FAILED - refusing to train:", file=sys.stderr)
        for failure in leakage.failures:
            print(f"  ! {failure}", file=sys.stderr)
        print("  (override with --allow-leakage if this is understood)", file=sys.stderr)
        return 2

    print(f"corpus: {provenance}")
    print(f"training on {len(train)} messages, testing on {len(test)}")
    detector = PhishGuardDetector(
        settings=settings,
        member_names=tuple(args.members.split(",")) if args.members else None,
    )
    if args.with_transformer and "transformer" not in detector.member_names:
        from phishguard.models.members import TransformerMember

        if not TransformerMember.available():
            print(
                "transformer extra not installed; continuing without it "
                "(pip install '.[transformer]')",
                file=sys.stderr,
            )
        else:
            settings.use_transformer = True
            detector = PhishGuardDetector(
                settings=settings,
                member_names=tuple(args.members.split(",")) if args.members else None,
            )

    started = time.perf_counter()
    report = detector.fit(train, y_train, adversarial_augment=not args.no_adv_train)
    print(f"trained in {time.perf_counter() - started:.1f}s")
    print(f"  members          {', '.join(report.members)}")
    print(f"  fusion weights   {report.fusion_weights}")
    print(f"  adv-augmented    +{report.n_adversarial_augmented} messages")
    print(f"  calibration      {report.calibration.get('method')}")

    scores = detector.predict_proba(test)
    summary = score_summary(y_test, scores)
    print(
        f"\nheld-out: macro F1 {summary['macro_f1']:.4f}  "
        f"PR-AUC {summary['pr_auc']:.4f}  FPR {summary['false_positive_rate']:.4f}"
    )

    if args.save:
        from phishguard.data.fingerprint import dataset_fingerprint

        record = save_detector(
            detector,
            settings=settings,
            metrics=summary,
            provenance={
                "corpus": provenance,
                "corpus_version": dataset_fingerprint(messages, labels),
                "train_version": dataset_fingerprint(train, y_train),
                "split_strategy": split.strategy,
                "split_notes": split.notes,
                "leakage_passed": leakage.passed,
                "n_train": len(train),
                "n_test": len(test),
            },
        )
        print(f"\nsaved model {record.version} -> {record.path}")
        print("  (now the current model for the API)")
    if getattr(args, "mlflow", False):
        _log_to_mlflow(
            run_name=f"train {detector.model_version}",
            params={
                "kind": "train",
                "corpus": provenance,
                "n_train": len(train),
                "members": ",".join(report.members),
                "adv_train": not args.no_adv_train,
                "split": split.strategy,
                "seed": settings.random_seed,
            },
            metrics={"heldout": summary, "fusion_weights": report.fusion_weights},
            artifacts=[settings.models_path / detector.model_version / "manifest.json"],
            settings=settings,
        )
    return 0


def _log_to_mlflow(*, run_name, params, metrics, artifacts, settings) -> None:  # noqa: ANN001
    from phishguard.tracking import TrackingUnavailable, log_run

    try:
        run_id = log_run(
            run_name=run_name,
            params=params,
            metrics=metrics,
            artifacts=[Path(a) for a in artifacts],
            default_root=settings.artifacts_dir.parent,
        )
        print(f"MLflow: logged run {run_id} (view with: mlflow ui)")
    except TrackingUnavailable as exc:
        print(f"MLflow: not logged - {exc}", file=sys.stderr)


def cmd_evaluate(args: argparse.Namespace) -> int:
    from phishguard.data.splits import audit_leakage
    from phishguard.eval.acceptance import evaluate_gates
    from phishguard.eval.run_eval import run_evaluation
    from phishguard.features import FeatureAssembler
    from phishguard.models.detector import PhishGuardDetector
    from phishguard.models.registry import load_detector, save_detector

    settings = get_settings()
    settings.ensure_dirs()
    messages, labels, provenance = _load_corpus(args)
    split = _split(args, messages, labels)
    train = [messages[i] for i in split.train_idx]
    y_train = np.asarray([labels[i] for i in split.train_idx], dtype=np.int64)
    test = [messages[i] for i in split.test_idx]
    y_test = np.asarray([labels[i] for i in split.test_idx], dtype=np.int64)

    assembler = FeatureAssembler()
    leakage = audit_leakage(
        messages,
        labels,
        split,
        features=assembler.transform(messages),
        feature_names=assembler.names,
    )

    if args.model:
        detector, _ = load_detector(args.model, settings=settings)
        print(f"loaded model {detector.model_version}")
    else:
        try:
            detector, _ = load_detector(settings=settings)
            print(f"loaded current model {detector.model_version}")
        except FileNotFoundError:
            print("no saved model; training one for this evaluation")
            detector = PhishGuardDetector(settings=settings)
            detector.fit(train, y_train)

    print(f"corpus: {provenance}")
    print(f"running evaluation (defence ablation: {'on' if args.defense_ablation else 'off'})...")
    report = run_evaluation(
        detector,
        train_messages=train,
        y_train=y_train,
        test_messages=test,
        y_test=y_test,
        leakage=leakage,
        settings=settings,
        attack_budget=args.budget,
        max_attacked=args.max_attacked,
        run_modality_ablation=not args.no_modality_ablation,
        run_defense_ablation=args.defense_ablation,
        seed_runs=args.seed_runs,
        output_dir=settings.reports_path,
        split_notes={"strategy": split.strategy, **split.notes, "corpus": provenance},
    )

    acceptance = evaluate_gates(report, settings=settings)
    print(acceptance.render())
    print(f"\nwritten: {settings.reports_path / 'evaluation.json'}")
    print(f"         {settings.reports_path / 'evaluation.md'}")
    print(f"evaluation took {report['evaluation_seconds']}s")

    if args.save_model and detector.is_trained:
        record = save_detector(
            detector,
            settings=settings,
            metrics=report["clean"],
            provenance={"corpus": provenance, "split_strategy": split.strategy},
        )
        print(f"saved model {record.version}")
    if getattr(args, "mlflow", False):
        from phishguard.tracking import evaluation_metrics

        reports = settings.reports_path
        _log_to_mlflow(
            run_name=f"evaluate {detector.model_version}",
            params={
                "kind": "evaluate",
                "model_version": detector.model_version,
                "corpus": provenance,
                "budget": args.budget,
                "max_attacked": args.max_attacked,
                "seed_runs": args.seed_runs,
                "test_version": report["dataset"].get("test_version", {}).get("version", ""),
            },
            metrics=evaluation_metrics(report),
            artifacts=[
                reports / "evaluation.json",
                reports / "evaluation.md",
                reports / "model_card.md",
                reports / "figures",
            ],
            settings=settings,
        )
    return 0 if acceptance.passed or args.no_gate else 1


def cmd_fetch_public(args: argparse.Namespace) -> int:
    """Download public corpora after their terms are acknowledged."""
    from phishguard.data.fetch import SOURCES, TermsNotAccepted, fetch

    if args.list or not args.names:
        print("Public corpora this command can download (see docs/11-real-data.md):\n")
        for src in SOURCES.values():
            print(f"  {src.name:26s} {src.label:5s} {src.period:10s} {src.url}")
        print("\nExample (the closest-in-time pairing the free corpora allow):")
        print("  phishguard fetch-public nazario-2005 spamassassin-easy-ham --accept-terms")
        return 0
    data_dir = Path(args.data_dir)
    try:
        records = fetch(list(args.names), data_dir, accept_terms=args.accept_terms)
    except TermsNotAccepted as exc:
        print("Read these terms first. Nothing has been downloaded.\n")
        print(str(exc))
        print("\nIf you accept them, run the same command again with --accept-terms.")
        return 2
    except KeyError as exc:
        print(str(exc).strip("'\""), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - network errors are reported, not raised
        print(f"download failed: {exc}", file=sys.stderr)
        return 1
    for r in records:
        print(f"  {r['name']}: {r['bytes'] / 2**20:.1f} MB, sha256 {r['sha256'][:16]}...")
    spec = ",".join(r["data_source_spec"] for r in records)
    print(f"\nprovenance: {data_dir / 'PROVENANCE.json'}")
    print("\nNext - audit it before training on it:")
    print(f'  phishguard data --verify --data-source "{spec}"')
    return 0


def cmd_loadtest(args: argparse.Namespace) -> int:
    """Throughput, latency percentiles, errors and memory under concurrent load."""
    from phishguard.eval.loadtest import (
        render_markdown,
        run_http,
        run_in_process,
        run_multiprocess,
        write,
    )

    settings = get_settings()
    settings.ensure_dirs()
    messages, labels, provenance = _load_corpus(args)
    split = _split(args, messages, labels)
    sample = [messages[i] for i in split.test_idx][: max(50, args.sample)]
    levels = tuple(int(x) for x in args.concurrency.split(",") if x.strip())
    if args.processes:
        counts = tuple(int(x) for x in args.processes.split(",") if x.strip())
        print(
            f"load test: multi-process, {counts} server processes | corpus {provenance} "
            f"| {len(sample)} distinct messages | {args.requests} requests per process"
        )
        result = run_multiprocess(
            sample,
            artifacts_dir=settings.artifacts_dir.resolve(),
            model_version=args.model,
            processes=counts,
            requests_per_process=args.requests,
            explain=not args.no_explain,
            budget_ms=settings.gate_p95_latency_ms,
        )
    elif args.url:
        key = args.api_key or os.environ.get("PG_LOADTEST_KEY", "")
        if not key:
            print("--url needs an analyst key: --api-key or PG_LOADTEST_KEY", file=sys.stderr)
            return 2
        print(f"load test: {args.url} | {len(sample)} distinct messages | levels {levels}")
        result = run_http(
            args.url,
            key,
            sample,
            concurrency=levels,
            requests_per_level=args.requests,
            budget_ms=settings.gate_p95_latency_ms,
        )
    else:
        from phishguard.models.registry import load_detector

        detector, _ = load_detector(args.model, settings=settings)
        print(
            f"load test: in-process, model {detector.model_version} | corpus {provenance} "
            f"| {len(sample)} distinct messages | levels {levels}"
        )
        result = run_in_process(
            detector,
            sample,
            settings=settings,
            concurrency=levels,
            requests_per_level=args.requests,
            explain=not args.no_explain,
            budget_ms=settings.gate_p95_latency_ms,
        )
    print()
    print(render_markdown(result))
    print(f"written: {write(result, settings.reports_path)}")
    return 0 if result["summary"]["total_errors"] == 0 else 1


def cmd_hard(args: argparse.Namespace) -> int:
    """Run PG-HARD, the curated hard-case benchmark."""
    import json

    from phishguard.eval.hard_eval import render_hard_markdown, run_hard_evaluation
    from phishguard.models.registry import load_detector

    settings = get_settings()
    settings.ensure_dirs()
    detector, _ = load_detector(args.model, settings=settings)
    messages, labels, provenance = _load_corpus(args)
    split = _split(args, messages, labels)
    train = [messages[i] for i in split.train_idx]
    y_train = np.asarray([labels[i] for i in split.train_idx], dtype=np.int64)
    test = [messages[i] for i in split.test_idx]
    y_test = np.asarray([labels[i] for i in split.test_idx], dtype=np.int64)

    print(f"model {detector.model_version} | reference corpus {provenance}")
    report = run_hard_evaluation(
        detector,
        train_messages=train,
        y_train=y_train,
        ref_messages=test,
        y_ref=y_test,
        variants_per_case=args.variants,
    )

    md = render_hard_markdown(report)
    print()
    print(md)

    out_json = settings.reports_path / "pg-hard.json"
    out_md = settings.reports_path / "pg-hard.md"
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text(md, encoding="utf-8")
    print(f"\nwritten: {out_json}")
    print(f"         {out_md}")

    pg = report["systems"]["phishguard"]
    failed = len(report["failing_cases"])
    if args.gate and failed:
        print(f"\nFAIL: {failed} case(s) outside their tolerated bands")
        return 1
    if args.gate and pg["silent_delivery_rate"] > args.max_silent:
        print(
            f"\nFAIL: silent delivery {pg['silent_delivery_rate']:.1%} "
            f"exceeds {args.max_silent:.1%}"
        )
        return 1
    return 0


def cmd_figures(args: argparse.Namespace) -> int:
    """Draw the report figures from the evaluation JSON."""
    from phishguard.reporting.figures import FiguresUnavailable, render_all, write_captions

    settings = get_settings()
    report = Path(args.report) if args.report else settings.reports_path / "evaluation.json"
    if not report.exists():
        print(f"no evaluation report at {report}")
        print("  run:  phishguard evaluate   (it writes that file), then run this again")
        return 2
    out = Path(args.out) if args.out else settings.reports_path / "figures"
    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    try:
        written = render_all(report, out, formats=formats)
    except FiguresUnavailable as exc:
        print(exc)
        return 2
    import json

    captions = write_captions(json.loads(report.read_text(encoding="utf-8")), out, written)
    for name, files in written.items():
        if name == "_skipped":
            print(f"  skipped (no data in this report): {', '.join(files)}")
            continue
        print(f"  {name:32s} {', '.join(Path(f).name for f in files)}")
    print(f"\nwritten to {out}")
    print(f"captions:  {captions}")
    return 0


def cmd_cost(args: argparse.Namespace) -> int:
    """Recommend an operating point from this organisation's own costs."""
    import json

    from phishguard.data.hardcases import build_hard_benchmark
    from phishguard.eval.cost import CostAssumptions, render_cost_markdown, run_cost_analysis
    from phishguard.models.baseline import TfidfBaseline
    from phishguard.models.registry import load_detector

    settings = get_settings()
    settings.ensure_dirs()
    detector, _ = load_detector(args.model, settings=settings)
    messages, labels, provenance = _load_corpus(args)
    split = _split(args, messages, labels)
    train = [messages[i] for i in split.train_idx]
    y_train = np.asarray([labels[i] for i in split.train_idx], dtype=np.int64)
    test = [messages[i] for i in split.test_idx]
    y_test = np.asarray([labels[i] for i in split.test_idx], dtype=np.int64)
    hard, y_hard, _ = build_hard_benchmark(variants_per_case=8)

    a = CostAssumptions(
        miss_cost=args.miss_cost,
        false_block_cost=args.false_block_cost,
        analyst_miss_rate=args.analyst_miss_rate,
        phish_prevalence=args.prevalence,
        hard_phish_share=args.hard_share,
        hard_ham_share=args.hard_share,
    )
    targets = None
    if args.attack:
        att, att_y, _ = build_hard_benchmark(variants_per_case=4)
        targets = [m for m, lab in zip(att, att_y, strict=False) if lab == 1]
    print(f"model {detector.model_version} | reference corpus {provenance}")
    print(
        "pricing every policy on the grid"
        + (" and attacking the candidates..." if targets else "...")
    )
    result = run_cost_analysis(
        detector=detector,
        ordinary_messages=test,
        ordinary_labels=y_test,
        hard_messages=hard,
        hard_labels=y_hard,
        text_baseline=TfidfBaseline().fit(train, y_train),
        assumptions=a,
        attack_targets=targets,
    )
    md = render_cost_markdown(result)
    out_json = settings.reports_path / "cost.json"
    out_md = settings.reports_path / "cost.md"
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    out_md.write_text(md, encoding="utf-8")

    best = result["optimum"]
    ab = "off" if best["abstain"] is None else f"{best['abstain']:.2f} ({best['abstain_mode']})"
    print()
    print("  For these costs the cheapest policy is:")
    print(
        f"      review >= {best['review']:.2f}   block >= {best['block']:.2f}   abstain at spread >= {ab}"
    )
    print(
        f"      expected cost {best['per_1000']:.1f} per 1,000 messages, "
        f"{best['reviews_per_1000']:.0f} sent to a human"
    )
    dep = result["deployed"]
    print(
        f"  The deployed policy costs {dep['per_1000']:.1f} per 1,000 "
        f"(regret {result['deployed_regret_per_1000']:.1f})."
    )
    if result.get("under_attack"):
        ua = result["under_attack"]
        print("\n  Under the adaptive attack (hard phishing delivered, worst budget):")
        for name in ("deployed", "minimax_regret", "cost_optimal"):
            if name in ua:
                print(f"      {name:15s} {ua[name]['worst_silent_delivery_rate']:.1%}")
    print("\n  To adopt a policy, set PG_REVIEW_THRESHOLD, PG_BLOCK_THRESHOLD,")
    print("  PG_ABSTAIN_DISAGREEMENT and PG_ABSTAIN_MODE, then retrain with")
    print("  PG_TUNE_THRESHOLDS=false so the values are used as given.")
    print(f"\nwritten: {out_json}\n         {out_md}")
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    """Is recent traffic still what the model was built for?"""
    import json

    from phishguard.models.registry import load_detector
    from phishguard.monitoring.drift import drift_report, live_from_audit_rows, simulate_drift
    from phishguard.service.store import DecisionStore

    settings = get_settings()
    detector, _ = load_detector(args.model, settings=settings)
    if getattr(detector, "drift_reference", None) is None:
        print("This model has no drift reference - it was trained before drift monitoring")
        print("existed. Retrain it (phishguard train --save) to capture one.")
        return 2

    if args.simulate:
        sim = simulate_drift(detector, weeks=args.weeks, shift_week=args.shift_week)
        th = sim.get("thresholds", {})
        print(sim["description"])
        print(
            f"alarm thresholds: moderate >= {th.get('moderate', 0):.3f}, "
            f"significant >= {th.get('significant', 0):.3f}  ({th.get('source', '')})\n"
        )
        for w in sim["weeks"]:
            print(
                f"  week {w['week']:2d}  {'shifted' if w['shifted'] else 'stable ':7s}  "
                f"PSI {w['worst_psi']:.3f}  {w['status']:11s}  {w['worst_quantity']}"
            )
        if sim.get("hint"):
            print(f"\nnote: {sim['hint']}")
        return 0

    store = DecisionStore(settings.db_path)
    try:
        rows = store.monitoring_rows(window_hours=args.window_hours)
    finally:
        store.close()
    report = drift_report(
        detector.drift_reference,
        live_from_audit_rows(rows, detector.member_names),
        bands=[r["band"] for r in rows],
    )
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0
    if not report.get("available"):
        print(f"drift: not available - {report.get('reason')}")
        return 0
    th = report["thresholds"]
    print(
        f"drift over the last {args.window_hours}h: {report['status'].upper()} "
        f"({report['n_live']} decisions vs {report['n_reference']} reference messages)"
    )
    print(f"thresholds: moderate >= {th['moderate']:.3f}, significant >= {th['significant']:.3f}\n")
    if report.get("hint"):
        print(f"note: {report['hint']}\n")
    for q in report["quantities"]:
        print(
            f"  {q['quantity']:32s} PSI {q['psi']:.3f}  KS p={q['ks_p_value']:.2g}  {q['severity']}"
        )
    print(f"\n{report['advice']}")
    return 1 if report["status"] == "significant" else 0


def cmd_attack(args: argparse.Namespace) -> int:
    from phishguard.adversarial.attacker import RawScoreSurface, single_transform_sweep
    from phishguard.adversarial.report import robustness_report
    from phishguard.eval.metrics import score_summary
    from phishguard.models.registry import load_detector

    settings = get_settings()
    detector, _ = load_detector(args.model, settings=settings)
    messages, labels, provenance = _load_corpus(args)
    split = _split(args, messages, labels)
    test = [messages[i] for i in split.test_idx]
    y_test = np.asarray([labels[i] for i in split.test_idx], dtype=np.int64)

    clean = score_summary(y_test, detector.predict_proba(test))
    print(f"model {detector.model_version} | corpus {provenance}")
    print(f"clean macro F1 {clean['macro_f1']:.4f}\n")

    report = robustness_report(
        RawScoreSurface(detector),
        test,
        y_test,
        clean_summary=clean,
        budget=args.budget,
        max_attacked=args.max_attacked,
        defenses_active=detector.defenses.active_ids,
        per_family=True,
        seed=settings.attack_seed,
    )
    print(f"attacked {report['attacked_messages']} phishing messages, budget {report['budget']}")
    print(f"  attack success rate  {report['attack_success_rate']:.4f}")
    print(
        f"  macro F1 drop        {report['macro_f1_drop']:.4f} "
        f"({report['clean_macro_f1']:.4f} -> {report['adversarial_macro_f1']:.4f})"
    )
    print(f"  recall drop          {report['recall_drop']:.4f}\n")
    print("per-family attack success:")
    for row in report.get("residual_risk_register", []):
        print(
            f"  {row['family_id']:9s} ASR={row['measured_attack_success_rate']:.4f} "
            f"likelihood={row['likelihood']:<9s} residual={row['residual_risk']}"
        )

    if args.sweep:
        phish = [m for m, y in zip(test, y_test, strict=True) if y == 1][: args.max_attacked]
        print("\nsingle-transform effectiveness:")
        for row in single_transform_sweep(RawScoreSurface(detector), phish)[:12]:
            print(
                f"  {row['transform_id']:9s} {row['family']:9s} "
                f"drop={row['mean_score_drop']:+.5f} "
                f"evasion={row['evasion_rate']:.4f}  {row['name']}"
            )

    out = settings.reports_path / "robustness.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\nwritten: {out}")
    return 0


def _live_service(model: str | None) -> Any:
    """The same ScanService the API runs, on the same audit database.

    A message imported from the command line lands in the same review queue
    the console shows, because both talk to one SQLite file in WAL mode.
    """
    from phishguard.models.registry import load_detector
    from phishguard.service.scanning import ScanService
    from phishguard.service.store import DecisionStore

    settings = get_settings()
    settings.ensure_dirs()
    detector, _ = load_detector(model, settings=settings)
    return ScanService(detector, DecisionStore(settings.db_path), settings), settings


def cmd_import(args: argparse.Namespace) -> int:
    """Import .eml files or an .mbox into the review queue."""
    from phishguard.service.ingest import ingest_messages, parse_mail_bytes
    from phishguard.service.security import Principal

    path = Path(args.input)
    if not path.exists():
        print(f"not found: {path}")
        return 2
    mail_suffixes = {".eml", ".mbox", ".txt", ""}
    files = (
        sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in mail_suffixes)
        if path.is_dir()
        else [path]
    )
    if not files:
        print(f"no .eml or .mbox files under {path}")
        return 2
    service, _ = _live_service(args.model)
    principal = Principal(key_id="key_cli_import", role="analyst")
    totals = {"received": 0, "allow": 0, "review": 0, "block": 0, "failed": 0}
    for file in files:
        try:
            messages = parse_mail_bytes(file.read_bytes(), filename=file.name)
        except ValueError as exc:
            print(f"  skipped {file.name}: {exc}")
            continue
        summary = ingest_messages(
            service, messages, source=f"import:{file.name}", principal=principal
        )
        for k in totals:
            totals[k] += getattr(summary, k)
        for r in summary.results:
            print(f"  {r['band']:6s} {r['score']:.2f}  {r['subject'][:60]}")
    print(
        f"\n{totals['received']} message(s): ALLOW {totals['allow']}  "
        f"REVIEW {totals['review']}  BLOCK {totals['block']}"
        + (f"  failed {totals['failed']}" if totals["failed"] else "")
    )
    print("REVIEW messages are now in the console's Review queue tab.")
    return 0


def cmd_inbox(args: argparse.Namespace) -> int:
    """Watch an IMAP mailbox and score new mail as it arrives."""
    import getpass

    from phishguard.service.ingest import ImapConfig, ImapWatcher

    password = os.environ.get("PG_IMAP_PASSWORD") or getpass.getpass(
        f"IMAP password for {args.user} (for Gmail, an app password): "
    )
    service, settings = _live_service(args.model)
    state = settings.artifacts_dir / "imap-state.json"
    watcher = ImapWatcher(
        ImapConfig(
            host=args.host,
            user=args.user,
            password=password,
            folder=args.folder,
            port=args.port,
            mark_seen=args.mark_seen,
            state_path=None if args.no_state else state,
        ),
        service,
    )
    print(
        f"watching {args.folder} on {args.host} as {args.user} every {args.interval}s "
        "(read-only; Ctrl+C to stop)"
    )
    try:
        watcher.run(interval=args.interval, once=args.once)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    """Score a whole mailbox and produce an analyst work queue.

    This is what a gateway deployment actually does at rollout: point the
    system at an existing mail store, and hand an analyst the list in the
    order it should be worked. The output is deliberately a CSV rather than a
    dashboard, because the first thing a security team does with a triage list
    is sort it in a spreadsheet.
    """
    import csv
    import time

    from phishguard.data.loaders import load_any
    from phishguard.models.registry import load_detector

    settings = get_settings()
    settings.ensure_dirs()
    detector, _ = load_detector(args.model, settings=settings)

    # Real triage has no labels -- that is the point of running it. The loaders
    # require one for single-class formats only so that a labelled corpus can
    # be scored; here an unlabelled run passes a placeholder and simply does
    # not report accuracy.
    scoring = args.label is not None
    load_label = 1 if args.label == "phish" else 0
    try:
        messages, labels = load_any(args.input, label=load_label)
    except ValueError as exc:
        print(f"could not read {args.input}: {exc}")
        return 2
    if not messages:
        print(f"no messages found in {args.input}")
        return 2

    if args.limit and len(messages) > args.limit:
        messages, labels = messages[: args.limit], labels[: args.limit]

    print(f"model {detector.model_version} | {len(messages)} messages from {args.input}")
    started = time.perf_counter()

    rows: list[dict[str, Any]] = []
    # Vectorised scoring for the whole mailbox; evidence only for the messages
    # that land in the work queue (REVIEW or BLOCK), which are the only ones an
    # analyst will open. Scores and bands are identical to one-at-a-time.
    verdicts: list[Any] = []
    chunk = 500
    for start in range(0, len(messages), chunk):
        verdicts.extend(detector.assess_batch(messages[start : start + chunk], explain="queue"))
        if args.progress:
            print(f"  {min(start + chunk, len(messages))}/{len(messages)}")
    for i, (msg, verdict) in enumerate(zip(messages, verdicts, strict=True)):
        top = next(
            (e for e in verdict.evidence if e.get("direction") == "phishing"),
            verdict.evidence[0] if verdict.evidence else {},
        )
        rows.append(
            {
                "index": i,
                "score": round(verdict.score, 4),
                "band": verdict.band,
                "abstained": int(verdict.abstained),
                "disagreement": verdict.signals.get("member_disagreement", 0.0),
                "subject": msg.subject[:120],
                "sender": msg.sender[:120],
                "sender_domain": msg.sender_domain,
                "top_reason": str(top.get("title", ""))[:120],
                "known_label": labels[i] if scoring else "",
            }
        )

    elapsed = time.perf_counter() - started

    # Work queue order: most alarming first, but REVIEW above ALLOW regardless
    # of score, because an abstention is a request for attention.
    rank = {"BLOCK": 0, "REVIEW": 1, "ALLOW": 2}
    rows.sort(key=lambda r: (rank[r["band"]], -r["score"]))

    out = Path(args.out) if args.out else settings.reports_path / "triage.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    counts = {b: sum(1 for r in rows if r["band"] == b) for b in ("BLOCK", "REVIEW", "ALLOW")}
    n = len(rows)
    print()
    print(f"  BLOCK   {counts['BLOCK']:6d}  ({counts['BLOCK'] / n:.1%})")
    print(f"  REVIEW  {counts['REVIEW']:6d}  ({counts['REVIEW'] / n:.1%})  <- the work queue")
    print(f"  ALLOW   {counts['ALLOW']:6d}  ({counts['ALLOW'] / n:.1%})")
    print(f"\n  {n / max(elapsed, 1e-9):.0f} messages/second, {elapsed:.1f}s total")

    # A mail file carries headers and text but not the gateway's view of the
    # sender relationship, so the behavioural family is mostly blind here. The
    # REVIEW queue will be larger than it would be in a live deployment, and
    # an operator who does not know that will read it as a false-alarm problem.
    blind = sum(1 for m in messages if not m.behavioral.available)
    if blind > n * 0.5:
        print(
            f"\n  note: {blind}/{n} messages arrived without behavioural context, "
            "so the\n        system is running on email and URL evidence only. "
            "Expect a larger\n        REVIEW queue than a live gateway would "
            "produce - it is abstaining,\n        not misfiring."
        )
    print(f"\nwritten: {out}")

    if any(r["known_label"] != "" for r in rows):
        from phishguard.eval.metrics import score_summary

        y = np.asarray([r["known_label"] for r in rows], dtype=np.int64)
        scores = np.asarray([r["score"] for r in rows], dtype=np.float64)
        summary = score_summary(y, scores, threshold=detector.block_threshold)
        print(
            f"\nlabels were supplied, so: macro F1 {summary['macro_f1']:.4f}, "
            f"FPR {summary['false_positive_rate']:.4f}, "
            f"recall {summary['recall_phish']:.4f}"
        )
    return 0


def cmd_feedback(args: argparse.Namespace) -> int:
    """Analyst-versus-model agreement, from the audit trail."""
    import json

    from phishguard.service.store import DecisionStore

    settings = get_settings()
    store = DecisionStore(settings.db_path)
    try:
        report = store.feedback_report(window_days=args.days)
    finally:
        store.close()

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"analyst feedback, last {report['window_days']} days")
    print(f"  submissions        {report['n_feedback']}")
    if not report["n_feedback"]:
        print(
            "\n  none yet - use the console's 'Analyst decision' buttons, or POST /api/v1/feedback"
        )
        return 0
    print(
        f"  disagreements      {report['disagreements']} ({report.get('disagreement_rate', 0):.1%})"
    )
    print(f"    reported as wrongly blocked   {report['false_block_reports']}")
    print(f"    reported as missed phishing   {report['missed_phish_reports']}")
    if report["domains_most_reported"]:
        print("\n  most-reported sender domains:")
        for row in report["domains_most_reported"]:
            print(f"    {row['reports']:4d}  {row['domain']}")
    print(f"\n{report['note']}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from phishguard.models.registry import load_detector
    from phishguard.service.contracts import ScanRequest

    detector, _ = load_detector(args.model, settings=get_settings())
    raw = (
        json.loads(Path(args.file).read_text(encoding="utf-8"))
        if args.file
        else json.loads(sys.stdin.read())
    )
    request = ScanRequest.model_validate(raw)
    verdict = detector.assess(request.to_message(), explain=not args.no_explain)
    print(json.dumps(verdict.as_dict(), indent=2))
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    from phishguard.models.registry import current_version, list_models, promote, prune

    settings = get_settings()
    if args.promote:
        promote(args.promote, settings=settings)
        print(f"promoted {args.promote}")
        return 0
    if args.prune is not None:
        removed = prune(args.prune, settings=settings)
        print(f"removed {len(removed)} version(s): {', '.join(removed) or '-'}")
        return 0

    active = current_version(settings=settings)
    records = list_models(settings=settings)
    if not records:
        print(f"no models under {settings.models_path}")
        return 0
    for r in records:
        marker = "*" if r.version == active else " "
        metrics = r.metrics
        f1 = metrics.get("macro_f1", "-")
        prov = (
            r.manifest.get("provenance") or r.manifest.get("training", {}).get("provenance") or {}
        )
        data = (prov.get("train_version") or {}).get("version", "-")
        print(
            f"{marker} {r.version}  {r.created_at}  macro_f1={f1}  data={data}  "
            f"members={','.join(r.manifest.get('members', []))}"
        )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check the environment and, optionally, run the pipeline end to end."""
    from phishguard.doctor import run_checks, self_test

    report = run_checks(verbose=args.verbose)
    if args.json:
        payload: dict[str, Any] = {"environment": report.as_dict()}
    else:
        print(report.render())

    ok = report.ok
    if args.self_test:
        if not args.json:
            print("\nRunning a full pipeline self-test on a small corpus...")
        result = self_test()
        if args.json:
            payload["self_test"] = result.as_dict()
        else:
            print(result.render().replace("environment check", "pipeline self-test"))
        ok = ok and result.ok

    if args.json:
        print(json.dumps(payload, indent=2))
    return 0 if ok else 1


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:  # pragma: no cover
        print("uvicorn is required to serve: pip install 'uvicorn[standard]'", file=sys.stderr)
        return 1
    settings = get_settings()
    workers = args.workers or settings.api_workers
    # Serving scores one message per request, so OpenMP's parallel loops have
    # nothing to share out, and with several worker processes their spinning
    # threads compete for the same cores (docs/07 section 7.14). One OpenMP
    # thread per process is the standard setting for CPU inference servers.
    # Set before any worker starts, so every process inherits it; training runs
    # in a separate command and keeps its parallelism.
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    if args.reload and workers > 1:
        print("--reload runs a single process; ignoring --workers", file=sys.stderr)
        workers = 1
    uvicorn.run(
        "phishguard.service.app:app",
        host=args.host or settings.api_host,
        port=args.port or settings.api_port,
        reload=args.reload,
        workers=workers,
        log_config=None,
    )
    return 0


def cmd_card(args: argparse.Namespace) -> int:
    """Regenerate the model card from the registry and the latest evaluation."""
    from phishguard.models.registry import load_detector
    from phishguard.service.modelcard import render_model_card

    settings = get_settings()
    detector, manifest = load_detector(args.model, settings=settings)
    evaluation: dict[str, Any] = {}
    path = settings.reports_path / "evaluation.json"
    if path.exists():
        evaluation = json.loads(path.read_text(encoding="utf-8"))
    card = render_model_card(detector, manifest, evaluation)
    out = Path(args.out) if args.out else settings.reports_path / "model_card.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(card, encoding="utf-8")
    print(f"written: {out}")
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Adversarially Robust Phishing Defense using Email, URL and "
        "Behavioral Features",
    )
    parser.add_argument("--version", action="version", version=f"phishguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_data_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--n", type=int, default=12000, help="synthetic corpus size")
        p.add_argument("--seed", type=int, default=20260907)
        p.add_argument("--phish-ratio", type=float, default=0.42)
        p.add_argument(
            "--data-source",
            default="synthetic",
            help="'synthetic', comma-separated corpus paths "
            "(e.g. data/nazario.mbox#phish,data/enron#ham), or both "
            "('synthetic,data/phish.mbox#phish,data/ham#ham' mixes them)",
        )
        p.add_argument(
            "--limit", type=int, default=None, help="read at most N messages from each real corpus"
        )
        p.add_argument(
            "--spam-as",
            choices=["skip", "phish", "ham"],
            default="skip",
            help="what a 'spam' label means in a real corpus (default: skip it; "
            "spam is not phishing)",
        )
        p.add_argument("--split", choices=["grouped", "temporal"], default="grouped")
        p.add_argument("--test-size", type=float, default=0.25)
        p.add_argument("--split-seed", type=int, default=11)

    p_data = sub.add_parser("data", help="build the corpus and audit it")
    add_data_args(p_data)
    p_data.add_argument("--show-kinds", action="store_true")
    p_data.add_argument(
        "--verify",
        action="store_true",
        help="audit a real corpus (label conventions, duplicates, era and "
        "source confounds) before training on it",
    )
    p_data.set_defaults(func=cmd_data)

    p_train = sub.add_parser("train", help="train a detector")
    add_data_args(p_train)
    p_train.add_argument("--save", action="store_true", help="register the model")
    p_train.add_argument("--members", default="", help="comma-separated member names")
    p_train.add_argument(
        "--no-adv-train", action="store_true", help="disable adversarial augmentation (D-ADVTRAIN)"
    )
    p_train.add_argument("--with-transformer", action="store_true")
    p_train.add_argument("--allow-leakage", action="store_true")
    p_train.add_argument(
        "--mlflow",
        action="store_true",
        help='also log the run to MLflow (pip install -e ".[tracking]")',
    )
    p_train.set_defaults(func=cmd_train)

    p_eval = sub.add_parser("evaluate", help="produce the evaluation dossier")
    add_data_args(p_eval)
    p_eval.add_argument("--model", default=None, help="model version (default: current)")
    p_eval.add_argument("--budget", type=int, default=10, help="attacker query budget")
    p_eval.add_argument("--max-attacked", type=int, default=200)
    p_eval.add_argument(
        "--defense-ablation",
        action="store_true",
        help="retrain one arm per defensive control (slow)",
    )
    p_eval.add_argument("--no-modality-ablation", action="store_true")
    p_eval.add_argument(
        "--mlflow",
        action="store_true",
        help='also log the run to MLflow (pip install -e ".[tracking]")',
    )
    p_eval.add_argument(
        "--seed-runs",
        type=int,
        default=2,
        help="extra training seeds for the seed-sensitivity table (0 to skip)",
    )
    p_eval.add_argument("--save-model", action="store_true")
    p_eval.add_argument(
        "--no-gate", action="store_true", help="always exit 0, even when a gate fails"
    )
    p_eval.set_defaults(func=cmd_evaluate)

    p_hard = sub.add_parser(
        "hard",
        help="run PG-HARD, the curated hard-case benchmark",
        description=(
            "Score the deployed system and both baselines on 24 hand-designed "
            "cases that each invert a named detection cue. Aggregate accuracy "
            "on the ordinary corpus is dominated by easy mail; this is the "
            "number that is not."
        ),
    )
    add_data_args(p_hard)
    p_hard.add_argument("--model", default=None, help="model version (default: current)")
    p_hard.add_argument(
        "--variants", type=int, default=8, help="deterministic variants per case (default: 8)"
    )
    p_hard.add_argument(
        "--gate",
        action="store_true",
        help="exit non-zero if any case falls outside its tolerated bands",
    )
    p_hard.add_argument(
        "--max-silent",
        type=float,
        default=0.0,
        help="with --gate, the highest tolerated silent-delivery rate",
    )
    p_hard.set_defaults(func=cmd_hard)

    p_fetch = sub.add_parser(
        "fetch-public",
        help="download public phishing / legitimate-mail corpora",
        description=(
            "Download named public corpora into the data folder after you have read "
            "and accepted their terms. Records source, size and SHA-256 in "
            "data/PROVENANCE.json. Nothing is downloaded without --accept-terms."
        ),
    )
    p_fetch.add_argument("names", nargs="*", help="corpus names (see --list)")
    p_fetch.add_argument("--list", action="store_true", help="list the corpora and exit")
    p_fetch.add_argument(
        "--accept-terms",
        action="store_true",
        help="confirm you have read and accept each corpus's terms",
    )
    p_fetch.add_argument("--data-dir", default="data", help="where to put them (git-ignored)")
    p_fetch.set_defaults(func=cmd_fetch_public)
    p_load = sub.add_parser(
        "loadtest",
        help="throughput, latency and memory under concurrent load",
        description=(
            "Drive the full decision path at increasing concurrency and report "
            "throughput, p50/p95/p99 latency, errors and peak memory. In-process by "
            "default; --url measures a running service over HTTP."
        ),
    )
    add_data_args(p_load)
    p_load.add_argument("--model", default=None)
    p_load.add_argument(
        "--concurrency",
        default="1,2,4,8",
        help="comma-separated concurrency levels (default 1,2,4,8)",
    )
    p_load.add_argument("--requests", type=int, default=200, help="requests per level")
    p_load.add_argument(
        "--sample", type=int, default=300, help="distinct messages to cycle through"
    )
    p_load.add_argument("--no-explain", action="store_true", help="scores and bands only")
    p_load.add_argument("--url", default="", help="measure a running service instead")
    p_load.add_argument(
        "--processes",
        default="",
        help="measure throughput with N server processes, e.g. 1,2 "
        "(what 'serve --workers N' would give)",
    )
    p_load.add_argument("--api-key", default="", help="analyst key for --url (or PG_LOADTEST_KEY)")
    p_load.set_defaults(func=cmd_loadtest)
    p_fig = sub.add_parser("figures", help="draw the report figures from the evaluation")
    p_fig.add_argument(
        "--report", default=None, help="evaluation JSON (default: artifacts/reports)"
    )
    p_fig.add_argument(
        "--out", default=None, help="output directory (default: artifacts/reports/figures)"
    )
    p_fig.add_argument("--format", default="png,svg", help="comma-separated: png, svg, pdf")
    p_fig.set_defaults(func=cmd_figures)

    p_cost = sub.add_parser(
        "cost",
        help="recommend thresholds from your organisation's own costs",
        description=(
            "Price every policy on the grid under your costs (in units of one analyst "
            "review), and report the cheapest. With --attack, also measure how the "
            "candidate policies hold up against the adaptive attacker."
        ),
    )
    add_data_args(p_cost)
    p_cost.add_argument("--model", default=None)
    p_cost.add_argument(
        "--miss-cost",
        type=float,
        default=200.0,
        help="cost of one phish delivered with no warning, in analyst reviews",
    )
    p_cost.add_argument(
        "--false-block-cost",
        type=float,
        default=10.0,
        help="cost of quarantining one legitimate message, in analyst reviews",
    )
    p_cost.add_argument(
        "--analyst-miss-rate",
        type=float,
        default=0.05,
        help="share of reviewed phishing an analyst lets through",
    )
    p_cost.add_argument(
        "--prevalence", type=float, default=0.02, help="share of inbound mail that is phishing"
    )
    p_cost.add_argument(
        "--hard-share",
        type=float,
        default=0.10,
        help="share of traffic (both classes) that behaves like PG-HARD",
    )
    p_cost.add_argument(
        "--attack", action="store_true", help="also attack the candidate policies (a few minutes)"
    )
    p_cost.set_defaults(func=cmd_cost)

    p_drift = sub.add_parser(
        "drift", help="check recent traffic for drift against the model's reference"
    )
    p_drift.add_argument("--model", default=None)
    p_drift.add_argument("--window-hours", type=int, default=24)
    p_drift.add_argument("--json", action="store_true")
    p_drift.add_argument(
        "--simulate",
        action="store_true",
        help="demonstrate on simulated weeks with an injected shift",
    )
    p_drift.add_argument("--weeks", type=int, default=10)
    p_drift.add_argument("--shift-week", type=int, default=6)
    p_drift.set_defaults(func=cmd_drift)

    p_attack = sub.add_parser("attack", help="run the adversarial suite")
    add_data_args(p_attack)
    p_attack.add_argument("--model", default=None)
    p_attack.add_argument("--budget", type=int, default=10)
    p_attack.add_argument("--max-attacked", type=int, default=150)
    p_attack.add_argument(
        "--sweep", action="store_true", help="also measure each transform in isolation"
    )
    p_attack.set_defaults(func=cmd_attack)

    p_triage = sub.add_parser(
        "triage",
        help="score a whole mailbox and write an analyst work queue",
        description=(
            "Point the detector at an existing mail store (.mbox, a directory "
            "of .eml files, or a CSV) and write a CSV work queue ordered the "
            "way an analyst should work it."
        ),
    )
    p_triage.add_argument(
        "--input", required=True, help="path to an .mbox, a directory of .eml files, or a .csv"
    )
    p_triage.add_argument(
        "--label",
        choices=["phish", "ham"],
        default=None,
        help="known label for a single-class corpus; enables scoring",
    )
    p_triage.add_argument(
        "--out", default=None, help="output CSV (default: artifacts/reports/triage.csv)"
    )
    p_triage.add_argument("--model", default=None)
    p_triage.add_argument("--limit", type=int, default=0, help="stop after N messages")
    p_triage.add_argument("--progress", action="store_true")
    p_triage.set_defaults(func=cmd_triage)

    p_import = sub.add_parser(
        "import",
        help="import .eml files or an .mbox into the review queue",
        description=(
            "Score real mail from files. Every message is audited and REVIEW "
            "verdicts open cases, exactly as if the mail gateway had sent them."
        ),
    )
    p_import.add_argument("input", help="an .eml, an .mbox, or a folder of them")
    p_import.add_argument("--model", default=None)
    p_import.set_defaults(func=cmd_import)

    p_inbox = sub.add_parser(
        "inbox",
        help="watch an IMAP mailbox (e.g. Gmail) and score new mail",
        description=(
            "Polls a mailbox over IMAP, read-only, and scores every new message. "
            "The password is read from PG_IMAP_PASSWORD or asked for; use an app "
            "password, never your main one."
        ),
    )
    p_inbox.add_argument("--host", default="imap.gmail.com")
    p_inbox.add_argument("--port", type=int, default=993)
    p_inbox.add_argument("--user", required=True, help="the mailbox address")
    p_inbox.add_argument("--folder", default="INBOX")
    p_inbox.add_argument("--interval", type=float, default=60.0, help="seconds between polls")
    p_inbox.add_argument("--once", action="store_true", help="poll once and exit")
    p_inbox.add_argument(
        "--mark-seen", action="store_true", help="mark scored messages as read (default: no)"
    )
    p_inbox.add_argument("--no-state", action="store_true", help="do not remember the last UID")
    p_inbox.add_argument("--model", default=None)
    p_inbox.set_defaults(func=cmd_inbox)

    p_feedback = sub.add_parser(
        "feedback",
        help="analyst-versus-model agreement from the audit trail",
    )
    p_feedback.add_argument("--days", type=int, default=30)
    p_feedback.add_argument("--json", action="store_true")
    p_feedback.set_defaults(func=cmd_feedback)

    p_scan = sub.add_parser("scan", help="score one message from JSON")
    p_scan.add_argument("--file", default=None, help="JSON file (default: stdin)")
    p_scan.add_argument("--model", default=None)
    p_scan.add_argument("--no-explain", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_models = sub.add_parser("models", help="inspect the model registry")
    p_models.add_argument("--promote", default=None, metavar="VERSION")
    p_models.add_argument("--prune", type=int, default=None, metavar="KEEP")
    p_models.set_defaults(func=cmd_models)

    p_card = sub.add_parser("card", help="regenerate the model card")
    p_card.add_argument("--model", default=None)
    p_card.add_argument("--out", default=None)
    p_card.set_defaults(func=cmd_card)

    p_doctor = sub.add_parser("doctor", help="check that this machine can run PhishGuard")
    p_doctor.add_argument(
        "--self-test", action="store_true", help="also train and attack a small model end to end"
    )
    p_doctor.add_argument("--verbose", action="store_true", help="also report optional packages")
    p_doctor.add_argument("--json", action="store_true", help="machine-readable output")
    p_doctor.set_defaults(func=cmd_doctor)

    p_serve = sub.add_parser("serve", help="run the API")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.add_argument(
        "--workers",
        type=int,
        default=None,
        help="server processes (default: PG_API_WORKERS or 1); "
        "throughput scales with processes, not threads",
    )
    p_serve.set_defaults(func=cmd_serve)
    return parser


#: Failure -> (what happened, what to do). The point is that a user who hits
#: one of these gets an instruction, not a stack trace they have to interpret.
_GUIDANCE: tuple[tuple[type[BaseException], str, str], ...] = (
    (
        MemoryError,
        "Ran out of memory.",
        "Training peaks at roughly 400 MB for --n 12000. Try a smaller corpus "
        "('--n 4000'), close other applications, or raise the container's memory "
        "limit. Run 'phishguard doctor' to see what this machine has available.",
    ),
    (
        PermissionError,
        "A file or directory could not be written.",
        "Point the artifacts directory somewhere writable: "
        "PG_ARTIFACTS_DIR=~/phishguard-data. 'phishguard doctor' checks this.",
    ),
    (
        FileNotFoundError,
        "Something expected on disk was missing.",
        "If this mentions a model, run 'phishguard train --save' first. "
        "If it mentions a corpus file, check the --data-source path. "
        "If it mentions a directory, PG_ARTIFACTS_DIR points somewhere that does "
        "not exist - 'phishguard doctor' checks it.",
    ),
    (
        OSError,
        "The operating system refused a file operation.",
        "The most common cause is a full disk ('No space left on device') or a "
        "path that cannot be created. 'phishguard doctor' reports free space and "
        "whether the artifacts directory is writable.",
    ),
    (
        ImportError,
        "A required package is missing or the wrong version.",
        "Reinstall the project: pip install -e '.[dev]'. "
        "Run 'phishguard doctor' for a per-package report.",
    ),
    (
        ValueError,
        "An input was not usable.",
        "The message above says which. Check the argument or corpus format.",
    ),
)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BaseException as exc:  # noqa: BLE001 - deliberate: diagnose, then re-raise
        for kind, headline, fix in _GUIDANCE:
            if isinstance(exc, kind):
                print(f"\nerror: {headline}", file=sys.stderr)
                print(f"  {exc}", file=sys.stderr)
                print(f"\n  {fix}\n", file=sys.stderr)
                if os.environ.get("PG_TRACEBACK"):
                    raise
                return 1
        # Anything unanticipated keeps its traceback: silently swallowing an
        # unknown failure would be worse than showing it.
        print(
            "\nerror: an unexpected failure occurred. The traceback follows.\n"
            "  If this is reproducible, 'phishguard doctor --self-test' will show "
            "whether the environment is at fault.\n",
            file=sys.stderr,
        )
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
