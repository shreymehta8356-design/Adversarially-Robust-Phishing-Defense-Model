"""Command-line interface.

Every result in the report is reproducible from one of these commands, which is
what the "runs from documented setup instructions on a clean machine"
acceptance gate requires.

::

    phishguard data      --n 12000                  build and inspect the corpus
    phishguard train     --n 12000 --save           train and register a model
    phishguard evaluate  --defense-ablation         produce the evaluation dossier
    phishguard attack    --budget 12                run the adversarial suite alone
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
        for spec in args.data_source.split(","):
            spec = spec.strip()
            if not spec:
                continue
            m, y = load_any(spec)
            messages.extend(m)
            labels.extend(y)
        if not messages:
            raise SystemExit(f"no messages loaded from {args.data_source!r}")
        return messages, labels, args.data_source

    from phishguard.data.synthetic import generate_corpus

    messages, labels = generate_corpus(
        args.n, seed=args.seed, phish_ratio=args.phish_ratio
    )
    return messages, labels, f"synthetic(n={args.n}, seed={args.seed})"


def _split(args: argparse.Namespace, messages: list[Any], labels: list[int]):
    from phishguard.data.splits import grouped_split, temporal_split

    if args.split == "temporal":
        return temporal_split(messages, labels, test_size=args.test_size)
    return grouped_split(
        messages, labels, test_size=args.test_size, seed=args.split_seed
    )


# --------------------------------------------------------------------------
def cmd_data(args: argparse.Namespace) -> int:
    from collections import Counter

    from phishguard.data.splits import audit_leakage
    from phishguard.features import FeatureAssembler

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
    report = audit_leakage(
        messages, labels, split, features=X, feature_names=assembler.names
    )
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
        messages, labels, split,
        features=assembler.transform(messages), feature_names=assembler.names,
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
    if args.with_transformer:
        from phishguard.models.members import TransformerMember

        if not TransformerMember.available():
            print(
                "transformer extra not installed; continuing without it "
                "(pip install '.[transformer]')",
                file=sys.stderr,
            )
        else:
            detector.member_names = (*detector.member_names, "transformer")
            detector.members["transformer"] = TransformerMember(
                model_name=settings.transformer_name,
                epochs=settings.transformer_epochs,
                max_len=settings.transformer_max_len,
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
    print(f"\nheld-out: macro F1 {summary['macro_f1']:.4f}  "
          f"PR-AUC {summary['pr_auc']:.4f}  FPR {summary['false_positive_rate']:.4f}")

    if args.save:
        record = save_detector(
            detector, settings=settings, metrics=summary,
            provenance={
                "corpus": provenance,
                "split_strategy": split.strategy,
                "split_notes": split.notes,
                "leakage_passed": leakage.passed,
                "n_train": len(train),
                "n_test": len(test),
            },
        )
        print(f"\nsaved model {record.version} -> {record.path}")
        print(f"  (now the current model for the API)")
    return 0


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
        messages, labels, split,
        features=assembler.transform(messages), feature_names=assembler.names,
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
    print("running evaluation "
          f"(defence ablation: {'on' if args.defense_ablation else 'off'})...")
    report = run_evaluation(
        detector,
        train_messages=train, y_train=y_train,
        test_messages=test, y_test=y_test,
        leakage=leakage, settings=settings,
        attack_budget=args.budget,
        max_attacked=args.max_attacked,
        run_modality_ablation=not args.no_modality_ablation,
        run_defense_ablation=args.defense_ablation,
        output_dir=settings.reports_path,
        split_notes={"strategy": split.strategy, **split.notes,
                     "corpus": provenance},
    )

    acceptance = evaluate_gates(report, settings=settings)
    print(acceptance.render())
    print(f"\nwritten: {settings.reports_path / 'evaluation.json'}")
    print(f"         {settings.reports_path / 'evaluation.md'}")
    print(f"evaluation took {report['evaluation_seconds']}s")

    if args.save_model and detector.is_trained:
        record = save_detector(
            detector, settings=settings, metrics=report["clean"],
            provenance={"corpus": provenance, "split_strategy": split.strategy},
        )
        print(f"saved model {record.version}")
    return 0 if acceptance.passed or args.no_gate else 1


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
        RawScoreSurface(detector), test, y_test, clean_summary=clean,
        budget=args.budget, max_attacked=args.max_attacked,
        defenses_active=detector.defenses.active_ids, per_family=True,
        seed=settings.attack_seed,
    )
    print(f"attacked {report['attacked_messages']} phishing messages, "
          f"budget {report['budget']}")
    print(f"  attack success rate  {report['attack_success_rate']:.4f}")
    print(f"  macro F1 drop        {report['macro_f1_drop']:.4f} "
          f"({report['clean_macro_f1']:.4f} -> {report['adversarial_macro_f1']:.4f})")
    print(f"  recall drop          {report['recall_drop']:.4f}\n")
    print("per-family attack success:")
    for row in report.get("residual_risk_register", []):
        print(f"  {row['family_id']:9s} ASR={row['measured_attack_success_rate']:.4f} "
              f"likelihood={row['likelihood']:<9s} residual={row['residual_risk']}")

    if args.sweep:
        phish = [m for m, y in zip(test, y_test, strict=True) if y == 1][: args.max_attacked]
        print("\nsingle-transform effectiveness:")
        for row in single_transform_sweep(RawScoreSurface(detector), phish)[:12]:
            print(f"  {row['transform_id']:9s} {row['family']:9s} "
                  f"drop={row['mean_score_drop']:+.5f} "
                  f"evasion={row['evasion_rate']:.4f}  {row['name']}")

    out = settings.reports_path / "robustness.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\nwritten: {out}")
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
        print(f"{marker} {r.version}  {r.created_at}  macro_f1={f1}  "
              f"members={','.join(r.manifest.get('members', []))}")
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
        print("uvicorn is required to serve: pip install 'uvicorn[standard]'",
              file=sys.stderr)
        return 1
    settings = get_settings()
    uvicorn.run(
        "phishguard.service.app:app",
        host=args.host or settings.api_host,
        port=args.port or settings.api_port,
        reload=args.reload,
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
        p.add_argument("--data-source", default="synthetic",
                       help="'synthetic' or comma-separated corpus paths "
                            "(e.g. data/nazario.mbox#phish,data/enron#ham)")
        p.add_argument("--split", choices=["grouped", "temporal"], default="grouped")
        p.add_argument("--test-size", type=float, default=0.25)
        p.add_argument("--split-seed", type=int, default=11)

    p_data = sub.add_parser("data", help="build the corpus and audit it")
    add_data_args(p_data)
    p_data.add_argument("--show-kinds", action="store_true")
    p_data.set_defaults(func=cmd_data)

    p_train = sub.add_parser("train", help="train a detector")
    add_data_args(p_train)
    p_train.add_argument("--save", action="store_true", help="register the model")
    p_train.add_argument("--members", default="", help="comma-separated member names")
    p_train.add_argument("--no-adv-train", action="store_true",
                         help="disable adversarial augmentation (D-ADVTRAIN)")
    p_train.add_argument("--with-transformer", action="store_true")
    p_train.add_argument("--allow-leakage", action="store_true")
    p_train.set_defaults(func=cmd_train)

    p_eval = sub.add_parser("evaluate", help="produce the evaluation dossier")
    add_data_args(p_eval)
    p_eval.add_argument("--model", default=None, help="model version (default: current)")
    p_eval.add_argument("--budget", type=int, default=10, help="attacker query budget")
    p_eval.add_argument("--max-attacked", type=int, default=200)
    p_eval.add_argument("--defense-ablation", action="store_true",
                        help="retrain one arm per defensive control (slow)")
    p_eval.add_argument("--no-modality-ablation", action="store_true")
    p_eval.add_argument("--save-model", action="store_true")
    p_eval.add_argument("--no-gate", action="store_true",
                        help="always exit 0, even when a gate fails")
    p_eval.set_defaults(func=cmd_evaluate)

    p_attack = sub.add_parser("attack", help="run the adversarial suite")
    add_data_args(p_attack)
    p_attack.add_argument("--model", default=None)
    p_attack.add_argument("--budget", type=int, default=12)
    p_attack.add_argument("--max-attacked", type=int, default=150)
    p_attack.add_argument("--sweep", action="store_true",
                          help="also measure each transform in isolation")
    p_attack.set_defaults(func=cmd_attack)

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

    p_doctor = sub.add_parser(
        "doctor", help="check that this machine can run PhishGuard")
    p_doctor.add_argument("--self-test", action="store_true",
                          help="also train and attack a small model end to end")
    p_doctor.add_argument("--verbose", action="store_true",
                          help="also report optional packages")
    p_doctor.add_argument("--json", action="store_true", help="machine-readable output")
    p_doctor.set_defaults(func=cmd_doctor)

    p_serve = sub.add_parser("serve", help="run the API")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--reload", action="store_true")
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
        "The most common cause is a full disk (\'No space left on device\') or a "
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
