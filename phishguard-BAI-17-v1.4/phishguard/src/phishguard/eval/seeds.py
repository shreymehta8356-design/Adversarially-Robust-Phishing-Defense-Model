"""How much of a headline result is the training seed?

A trained detector is one draw from a distribution: the random seed decides
which campaigns land in the fitting, stacking and calibration pools, which
messages are adversarially augmented, and where the members' optimisers stop.
On an easy test set that variation is invisible. On PG-HARD, where a handful
of records decide the headline, it is not: retraining the same configuration
on the same data with a different seed moved the number of hard phishing
records delivered with no warning between 0 and 6 of 96 in development.

This module retrains the evaluated configuration with further seeds and
reports the spread, so the dossier states a range and names the cases
responsible instead of quoting one lucky (or unlucky) draw.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np


def _outcomes(
    label: str,
    detector: Any,
    test_messages: list[Any],
    y_test: np.ndarray,
    hard: list[Any],
    hard_y: np.ndarray,
    hard_meta: list[dict[str, Any]],
) -> dict[str, Any]:
    bands = np.asarray([d.band for d in detector._decisions(test_messages)])
    hb = np.asarray([d.band for d in detector._decisions(hard)])
    phish, ham = y_test == 1, y_test == 0
    hp, hh = hard_y == 1, hard_y == 0
    silent = np.flatnonzero(hp & (hb == "ALLOW"))
    false_block = np.flatnonzero(hh & (hb == "BLOCK"))
    return {
        "run": label,
        "model_version": getattr(detector, "model_version", ""),
        "thresholds": {
            "review": float(detector.review_threshold),
            "block": float(detector.block_threshold),
        },
        "ordinary": {
            "phish_delivered_unwarned_rate": round(float(np.mean(bands[phish] == "ALLOW")), 5),
            "ham_blocked_rate": round(float(np.mean(bands[ham] == "BLOCK")), 5),
            "ham_to_review_rate": round(float(np.mean(bands[ham] == "REVIEW")), 5),
            "review_load_rate": round(float(np.mean(bands == "REVIEW")), 5),
        },
        "pg_hard": {
            "silent_delivery": int(silent.size),
            "false_block": int(false_block.size),
            "n_phish": int(hp.sum()),
            "n_ham": int(hh.sum()),
            "review_load_rate": round(float(np.mean(hb == "REVIEW")), 4),
            "silent_delivery_cases": dict(Counter(hard_meta[i]["case_id"] for i in silent)),
            "false_block_cases": dict(Counter(hard_meta[i]["case_id"] for i in false_block)),
        },
    }


def seed_sensitivity(
    detector: Any,
    *,
    train_messages: list[Any],
    y_train: np.ndarray,
    test_messages: list[Any],
    y_test: np.ndarray,
    seeds: tuple[int, ...] = (101, 202),
    hard_variants: int = 8,
) -> dict[str, Any]:
    """Outcomes of the evaluated model and of retrains with other seeds."""
    from phishguard.data.hardcases import build_hard_benchmark
    from phishguard.models.detector import PhishGuardDetector

    y_test = np.asarray(y_test).astype(int)
    hard, hard_y, hard_meta = build_hard_benchmark(variants_per_case=hard_variants)
    hard_y = np.asarray(hard_y).astype(int)
    runs = [_outcomes("evaluated model", detector, test_messages, y_test, hard, hard_y, hard_meta)]
    for seed in seeds:
        retrained = PhishGuardDetector(
            settings=detector.settings,
            defenses=detector.defenses,
            member_names=detector.member_names,
        )
        retrained.fit(train_messages, y_train, seed=seed)
        runs.append(
            _outcomes(
                f"retrained, seed {seed}", retrained, test_messages, y_test, hard, hard_y, hard_meta
            )
        )

    def spread(get) -> dict[str, float]:
        vals = [float(get(r)) for r in runs]
        return {"min": min(vals), "max": max(vals), "mean": round(float(np.mean(vals)), 5)}

    cases_silent: Counter[str] = Counter()
    cases_block: Counter[str] = Counter()
    for r in runs:
        cases_silent.update({k: 1 for k in r["pg_hard"]["silent_delivery_cases"]})
        cases_block.update({k: 1 for k in r["pg_hard"]["false_block_cases"]})
    return {
        "runs": runs,
        "n_runs": len(runs),
        "summary": {
            "pg_hard_silent_delivery": spread(lambda r: r["pg_hard"]["silent_delivery"]),
            "pg_hard_false_block": spread(lambda r: r["pg_hard"]["false_block"]),
            "pg_hard_review_load_rate": spread(lambda r: r["pg_hard"]["review_load_rate"]),
            "ordinary_phish_delivered_unwarned_rate": spread(
                lambda r: r["ordinary"]["phish_delivered_unwarned_rate"]
            ),
            "ordinary_review_load_rate": spread(lambda r: r["ordinary"]["review_load_rate"]),
            # In how many runs each case produced at least one wrong decision.
            "silent_delivery_cases": dict(cases_silent),
            "false_block_cases": dict(cases_block),
        },
        "note": (
            "Same data, same configuration, different training seed. The seed decides "
            "which campaigns fall in each training pool, which messages are "
            "adversarially augmented, and where the members' optimisers stop."
        ),
    }


def render_seed_markdown(s: dict[str, Any]) -> str:
    """The dossier table."""
    if not s or not s.get("runs"):
        return ""
    lines = [
        "#### Seed sensitivity\n",
        f"{s['note']} {s['n_runs']} runs:\n",
        "| Run | PG-HARD phish delivered unwarned | PG-HARD legitimate blocked | "
        "PG-HARD review load | Ordinary phish unwarned | Ordinary review load |",
        "|---|---|---|---|---|---|",
    ]
    for r in s["runs"]:
        h, o = r["pg_hard"], r["ordinary"]
        sd = ", ".join(f"{k} ×{v}" for k, v in h["silent_delivery_cases"].items())
        fb = ", ".join(f"{k} ×{v}" for k, v in h["false_block_cases"].items())
        lines.append(
            f"| {r['run']} | {h['silent_delivery']} / {h['n_phish']}"
            + (f" ({sd})" if sd else "")
            + f" | {h['false_block']} / {h['n_ham']}"
            + (f" ({fb})" if fb else "")
            + f" | {h['review_load_rate']:.1%} | {o['phish_delivered_unwarned_rate']:.2%} | "
            f"{o['review_load_rate']:.1%} |"
        )
    sm = s["summary"]
    sd, fb = sm["pg_hard_silent_delivery"], sm["pg_hard_false_block"]
    lines.append("")
    lines.append(
        f"Across the {s['n_runs']} runs, {sd['min']:.0f}–{sd['max']:.0f} hard phishing records "
        f"were delivered with no warning and {fb['min']:.0f}–{fb['max']:.0f} hard legitimate "
        "records were blocked. "
        + (
            "Every silent delivery came from "
            + ", ".join(
                f"{k} (in {v} of {s['n_runs']} runs)"
                for k, v in sm["silent_delivery_cases"].items()
            )
            + ". "
            if sm["silent_delivery_cases"]
            else ""
        )
        + (
            "Every false block came from "
            + ", ".join(
                f"{k} (in {v} of {s['n_runs']} runs)" for k, v in sm["false_block_cases"].items()
            )
            + ". "
            if sm["false_block_cases"]
            else ""
        )
        + "Quote the range, not the evaluated model's single value.\n"
    )
    return "\n".join(lines)
