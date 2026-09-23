#!/usr/bin/env python3
"""Create the issue board for a new PhishGuard repository from docs/backlog.csv.

Run it once, from inside a clone of your GitHub repository, after installing
the GitHub CLI and signing in (``gh auth login``)::

    python scripts/bootstrap_github.py --dry-run    # print what would be created
    python scripts/bootstrap_github.py              # create it

It creates the labels, the six milestones, and one issue per backlog item, with
the acceptance criteria and the evidence in the body. Items already delivered
are closed with a comment naming where the evidence is; planned items stay
open. It is safe to run again: labels are updated in place, and an issue whose
title already exists is skipped.

It does not invent history. Every issue it creates is timestamped with the day
it was run, which is the honest record: from that day on, link your real
commits and pull requests to these issues ("Closes #12") so the board and the
history tell the same story.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKLOG = ROOT / "docs" / "backlog.csv"

LABELS: dict[str, tuple[str, str]] = {
    "type: story": ("1f6feb", "New behaviour, written as a user story"),
    "type: bug": ("d73a4a", "Does not do what the documentation says"),
    "type: experiment": ("8250df", "A measurement that informs a decision"),
    "type: dependencies": ("0366d6", "Dependency updates"),
    "moscow: must": ("b60205", "Must have"),
    "moscow: should": ("d93f0b", "Should have"),
    "moscow: could": ("fbca04", "Could have"),
    "moscow: will not": ("cfd3d7", "Will not have in this release"),
    "area: data": ("0e8a16", "Corpora, splits, hard cases (AI data engineer)"),
    "area: model": ("5319e7", "Features, models, defences, attacks, evaluation (model engineer)"),
    "area: systems": ("1d76db", "Service, security, deployment, CI (systems engineer)"),
    "status: backlog": ("ededed", "Not started"),
    "status: triage": ("ededed", "Needs a decision"),
    "status: planned": ("c5def5", "Scheduled for a later milestone"),
    "status: designed": ("c5def5", "Designed for; not enabled by default"),
    "status: delivered": ("0e8a16", "Done, with evidence in the repository"),
    "status: not planned": ("cfd3d7", "Deliberately not built; the issue records why"),
}

MILESTONES: dict[str, str] = {
    "M1 Discovery and design": "Problem brief, personas, threat model, architecture, ADRs",
    "M2 Core detector": "Features, splits, members, fusion, calibration, explanations",
    "M3 Adversarial and defences": "Attack taxonomy, transforms, attacker, defensive controls",
    "M4 Service and operations": "API, console, review queue, tracing, monitoring, deployment",
    "M5 Evaluation and release": "Dossier, gates, ablations, benchmarks, load test, release",
    "M6 Pilot readiness": "What a supervised pilot on real mail needs next",
}

TYPE_LABEL = {"story": "type: story", "bug": "type: bug", "experiment": "type: experiment"}


def gh(*args: str, dry_run: bool, capture: bool = False) -> str:
    cmd = ["gh", *args]
    if dry_run:
        print("  would run:", " ".join(_quote(a) for a in cmd))
        return ""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603 - fixed program
    if result.returncode != 0 and not capture:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {result.stderr.strip()}")
    return result.stdout if result.returncode == 0 else ""


def _quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def body_for(row: dict[str, str]) -> str:
    lines = [
        f"**Backlog item {row['id']}** — {row['type']}, for {row['persona']}.",
        "",
        "### Acceptance criteria",
        "",
        *[f"- [ ] {c.strip()}" for c in row["acceptance_criteria"].split(";") if c.strip()],
        "",
        f"**Priority:** {row['moscow']} have · **Estimate:** {row['points']} points "
        "(1 point ≈ 2 hours)",
    ]
    if row["evidence"]:
        lines += ["", "### Evidence", "", row["evidence"]]
    lines += ["", "_Created from `docs/backlog.csv` by `scripts/bootstrap_github.py`._"]
    return "\n".join(lines)


def existing_titles(dry_run: bool) -> set[str]:
    if dry_run:
        return set()
    out = gh(
        "issue",
        "list",
        "--state",
        "all",
        "--limit",
        "500",
        "--json",
        "title",
        dry_run=False,
        capture=True,
    )
    return {item["title"] for item in json.loads(out or "[]")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="print the gh commands only")
    args = parser.parse_args()

    if not args.dry_run and shutil.which("gh") is None:
        print(
            "The GitHub CLI is not installed: https://cli.github.com, then 'gh auth login'.",
            file=sys.stderr,
        )
        return 2
    rows = list(csv.DictReader(BACKLOG.open(encoding="utf-8")))

    print(f"labels ({len(LABELS)})")
    for name, (color, description) in LABELS.items():
        gh(
            "label",
            "create",
            name,
            "--color",
            color,
            "--description",
            description,
            "--force",
            dry_run=args.dry_run,
        )

    print(f"milestones ({len(MILESTONES)})")
    for title, description in MILESTONES.items():
        # 422 means it already exists; that is fine on a second run.
        gh(
            "api",
            "repos/{owner}/{repo}/milestones",
            "-f",
            f"title={title}",
            "-f",
            f"description={description}",
            dry_run=args.dry_run,
            capture=True,
        )

    have = existing_titles(args.dry_run)
    print(f"issues ({len(rows)})")
    created = skipped = 0
    for row in rows:
        title = f"{row['id']}: {row['title']}"
        if title in have:
            skipped += 1
            continue
        labels = [
            TYPE_LABEL.get(row["type"], "type: story"),
            f"moscow: {row['moscow'].lower()}",
            f"area: {row['area']}",
            f"status: {row['status']}",
        ]
        label_args = [a for label in labels for a in ("--label", label)]
        url = gh(
            "issue",
            "create",
            "--title",
            title,
            "--body",
            body_for(row),
            "--milestone",
            row["milestone"],
            *label_args,
            dry_run=args.dry_run,
        ).strip()
        created += 1
        if row["status"] in {"delivered", "not planned"}:
            reason = "completed" if row["status"] == "delivered" else "not planned"
            note = (
                f"Delivered — evidence: {row['evidence']}"
                if row["status"] == "delivered"
                else f"Deliberately not built — see {row['evidence']}"
            )
            gh(
                "issue",
                "close",
                url or title,
                "--reason",
                reason,
                "--comment",
                note,
                dry_run=args.dry_run,
            )
    print(f"done: {created} issues created, {skipped} already existed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
