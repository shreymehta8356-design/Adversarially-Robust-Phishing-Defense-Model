"""Publication figures for the written report, drawn from the evaluation JSON.

Every figure is regenerated from ``artifacts/reports/evaluation.json`` alone --
no trained model, corpus or GPU is needed on the machine that draws them -- so
the figures in the report can never drift from the numbers in the dossier.

Design system
-------------
One set of rules for every figure, so the report reads as one piece of work:

* **Colour by job, validated, never eyeballed.** Series identity uses the first
  three slots of the reference categorical palette (blue, orange, aqua), which
  pass every colour-vision-deficiency gate pairwise. Outcomes use a *diverging*
  scale -- correct automatic decision / sent to a human / wrong -- because the
  three outcomes are ordered and the middle one is genuinely neutral. Status
  colours are not reused as series, and series colours never carry text.
* **Emphasis over rainbow.** Where one system is the subject and the rest are
  context, the subject is the accent hue and the rest are a recessive grey.
* **Thin marks, quiet chrome.** Bars at most ~24 px thick with rounded data
  ends and square baselines, 2 px lines, markers with a surface ring, solid
  hairline gridlines, no dual axes, no dashed grids.
* **Label selectively.** A legend whenever two or more series share a plot;
  direct labels only where a value is the point and the text fits its mark.

Axes are chosen for the data, not by default: the ROC figure uses a
logarithmic false-positive axis because every usable operating point of a mail
filter sits below 1% FPR, which a linear axis compresses into a few pixels.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------
SURFACE = "#ffffff"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"

SERIES_PG = "#2a78d6"  # slot 1 - PhishGuard, wherever it appears as a series
SERIES_TEXT = "#eb6834"  # slot 2 - the text-only filter
SERIES_RULES = "#1baf7a"  # slot 3 - the rule checklist
DEEMPH = "#b5b3ab"  # context in emphasis charts

# Diverging outcome scale: two poles that read as opposite, neutral midpoint.
OUT_CORRECT = "#1c5cab"  # a darker blue step than the PhishGuard series
OUT_HUMAN = "#c9c7bf"  # neutral: no automatic decision was made
OUT_WRONG = "#d03b3b"

FONT_STACK = ["Carlito", "Calibri", "Liberation Sans", "DejaVu Sans", "sans-serif"]

WIDTH_IN = 6.5  # full text width of an A4 page with 2.5 cm margins
DPI = 220


class FiguresUnavailable(RuntimeError):
    """matplotlib is not installed; the message says how to add it."""


def _most_moved(members: list[dict[str, Any]]) -> str:
    return str(max(members, key=lambda r: r["mean_drop"])["member"])


def _least_moved(members: list[dict[str, Any]]) -> str:
    return str(min(members, key=lambda r: r["mean_drop"])["member"])


def _plt():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise FiguresUnavailable(
            "Figures need matplotlib, which is not part of the core install.\n"
            '  Add it with:  pip install -e ".[report]"   (or: pip install matplotlib)'
        ) from exc
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": FONT_STACK,
            "font.size": 9,
            "axes.titlesize": 10.5,
            "axes.titleweight": "bold",
            "axes.titlelocation": "left",
            "axes.titlepad": 10,
            "axes.labelsize": 9,
            "axes.labelcolor": INK2,
            "axes.edgecolor": AXIS,
            "axes.linewidth": 0.8,
            "axes.facecolor": SURFACE,
            "figure.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "xtick.color": MUTED,
            "ytick.color": MUTED,
            "xtick.labelcolor": INK2,
            "ytick.labelcolor": INK2,
            "xtick.labelsize": 8.5,
            "ytick.labelsize": 8.5,
            "legend.fontsize": 8.5,
            "legend.frameon": False,
            "svg.fonttype": "none",
        }
    )
    return plt


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _quiet(ax, *, grid: str = "x") -> None:
    """Recessive chrome: no top/right spines, solid hairline grid behind data."""
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(AXIS)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(length=0, pad=4)
    if grid:
        ax.grid(axis=grid, color=GRID, linewidth=0.8, linestyle="-")
    ax.set_axisbelow(True)


def _pct(v: float, digits: int = 0) -> str:
    return f"{v * 100:.{digits}f}%"


def _data_per_inch(ax) -> tuple[float, float]:
    """Data units per inch along x and y, after limits are final."""
    fig = ax.figure
    bbox = ax.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
    x0, x1 = ax.get_xlim()
    y0, y1 = ax.get_ylim()
    return abs(x1 - x0) / bbox.width, abs(y1 - y0) / bbox.height


def _rounded_hbar(
    ax,
    y: float,
    left: float,
    width: float,
    height: float,
    color: str,
    *,
    round_right: bool = True,
    radius_in: float = 0.035,
    zorder: float = 3,
) -> None:
    """Horizontal bar: rounded data end, square baseline.

    Drawn as a rounded box plus a square patch over the baseline half, with
    the corner radius converted from inches so it stays circular regardless of
    the axis aspect ratio.
    """
    from matplotlib.patches import FancyBboxPatch, Rectangle

    if width <= 0:
        return
    dx, dy = _data_per_inch(ax)
    rx = min(radius_in * dx, width / 2)
    aspect = (radius_in * dy) / max(rx, 1e-12)
    ax.add_patch(
        FancyBboxPatch(
            (left, y - height / 2),
            width,
            height,
            boxstyle=f"round,pad=0,rounding_size={rx}",
            mutation_aspect=aspect,
            linewidth=0,
            facecolor=color,
            zorder=zorder,
        )
    )
    # Square off the side that is not a data end.
    if round_right:
        ax.add_patch(
            Rectangle(
                (left, y - height / 2),
                min(width, max(width - rx, 0) + 1e-9),
                height,
                linewidth=0,
                facecolor=color,
                zorder=zorder,
            )
        )
    else:
        ax.add_patch(
            Rectangle(
                (left + min(rx, width), y - height / 2),
                max(width - rx, 0),
                height,
                linewidth=0,
                facecolor=color,
                zorder=zorder,
            )
        )


def _text_fits(ax, text: str, span_data: float, fontsize: float) -> bool:
    """Would ``text`` fit inside a horizontal span with comfortable padding?"""
    fig = ax.figure
    renderer = fig.canvas.get_renderer()
    t = ax.text(0, 0, text, fontsize=fontsize)
    w_px = t.get_window_extent(renderer=renderer).width
    t.remove()
    dx, _ = _data_per_inch(ax)
    w_data = (w_px / fig.dpi) * dx
    pad = 0.08 * dx  # 0.08 in each side
    return w_data + 2 * pad <= span_data


def _ink_on(fill: str) -> str:
    """White or ink, by the fill's luminance, so in-fill text always clears."""
    fill = fill.lstrip("#")
    r, g, b = (int(fill[i : i + 2], 16) / 255 for i in (0, 2, 4))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    lum = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    return "#ffffff" if lum < 0.35 else INK


def _save(fig, out_dir: Path, name: str, formats: tuple[str, ...]) -> list[Path]:
    written = []
    for fmt in formats:
        path = out_dir / f"{name}.{fmt}"
        fig.savefig(path, dpi=DPI, bbox_inches="tight", pad_inches=0.12)
        written.append(path)
    import matplotlib.pyplot as plt

    plt.close(fig)
    return written


SYSTEM_ORDER = ("phishguard", "B1_tfidf_logreg", "B0_rule_checklist")
SYSTEM_SHORT = {
    "phishguard": "PhishGuard",
    "B1_tfidf_logreg": "Text-only filter",
    "B0_rule_checklist": "Rule checklist",
}


# --------------------------------------------------------------------------
# Figure 1 - PG-HARD outcomes, the headline
# --------------------------------------------------------------------------
def fig_pg_hard_outcomes(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    hard = report.get("pg_hard") or {}
    per_case = hard.get("per_case") or []
    systems = hard.get("systems") or {}
    if not per_case or "phishguard" not in systems:
        return None

    # PhishGuard's per-label outcome mix comes from its per-case bands; the
    # baselines only report aggregate counts, so derive theirs from the two
    # failure rates and the review load, split by label.
    def mix_from_cases(label: int) -> tuple[float, float, float]:
        rows = [r for r in per_case if r["label"] == label]
        total = sum(r["n"] for r in rows)
        correct_band = "BLOCK" if label == 1 else "ALLOW"
        wrong_band = "ALLOW" if label == 1 else "BLOCK"
        c = sum(r["bands"][correct_band] for r in rows)
        h = sum(r["bands"]["REVIEW"] for r in rows)
        w = sum(r["bands"][wrong_band] for r in rows)
        return c / total, h / total, w / total

    n_hp = sum(r["n"] for r in per_case if r["label"] == 1)
    n_hn = sum(r["n"] for r in per_case if r["label"] == 0)

    def mix_from_summary(s: dict[str, Any], label: int) -> tuple[float, float, float] | None:
        """Exact per-label outcome mix from the stored band counts."""
        by = (s.get("bands_by_label") or {}).get("phishing" if label == 1 else "legitimate")
        if not by:
            return None  # an older report: refuse to estimate rather than guess
        total = max(sum(by.values()), 1)
        correct = by["BLOCK" if label == 1 else "ALLOW"] / total
        wrong = by["ALLOW" if label == 1 else "BLOCK"] / total
        return correct, by["REVIEW"] / total, wrong

    mixes: dict[str, dict[int, tuple[float, float, float]]] = {}
    for key in SYSTEM_ORDER:
        if key not in systems:
            continue
        if key == "phishguard":
            mixes[key] = {0: mix_from_cases(0), 1: mix_from_cases(1)}
        else:
            m0, m1 = mix_from_summary(systems[key], 0), mix_from_summary(systems[key], 1)
            if m0 is None or m1 is None:
                continue
            mixes[key] = {0: m0, 1: m1}

    plt = _plt()
    fig, axes = plt.subplots(1, 2, figsize=(WIDTH_IN, 2.55), sharey=True)
    fig.subplots_adjust(wspace=0.08, top=0.72, bottom=0.2)
    keys = [k for k in SYSTEM_ORDER if k in mixes]
    ys = list(range(len(keys)))[::-1]
    panels = (
        (
            0,
            f"Legitimate mail — {n_hn // 8 if n_hn % 8 == 0 else n_hn} hard cases",
            "blocked (false block)",
        ),
        (
            1,
            f"Phishing — {n_hp // 8 if n_hp % 8 == 0 else n_hp} hard cases",
            "delivered, no warning",
        ),
    )
    for ax, (label, title, _wrong_name) in zip(axes, panels, strict=False):
        ax.set_xlim(0, 1)
        ax.set_ylim(-0.6, len(keys) - 0.4)
        _quiet(ax, grid="")
        ax.spines["left"].set_visible(False)
        ax.spines["bottom"].set_visible(False)
        ax.set_xticks([])
        ax.set_title(title, fontsize=9.5, color=INK, pad=6)
        gap = 0.004
        for y, key in zip(ys, keys, strict=False):
            c, h, w = mixes[key][label]
            segs = [(c, OUT_CORRECT), (h, OUT_HUMAN), (w, OUT_WRONG)]
            left = 0.0
            last_nonzero = (
                max(i for i, (v, _) in enumerate(segs) if v > 0)
                if any(v > 0 for v, _ in segs)
                else -1
            )
            for i, (v, col) in enumerate(segs):
                if v <= 0:
                    continue
                width = max(v - (gap if i < last_nonzero else 0), 0)
                _rounded_hbar(
                    ax, y, left, width, 0.5, col, round_right=(i == last_nonzero), radius_in=0.03
                )
                txt = _pct(v)
                if _text_fits(ax, txt, width, 8.5):
                    ax.text(
                        left + width / 2,
                        y,
                        txt,
                        ha="center",
                        va="center",
                        fontsize=8.5,
                        color=_ink_on(col),
                        zorder=5,
                    )
                left += v
        ax.set_yticks(ys)
        ax.set_yticklabels([SYSTEM_SHORT[k] for k in keys], fontsize=9, color=INK)

    # The title claims only what this report's numbers support.
    def wrong(key: str) -> int:
        sy = systems.get(key) or {}
        return int(sy.get("silent_delivery", 0)) + int(sy.get("false_block", 0))

    pg_wrong = wrong("phishguard")
    others = [wrong(k) for k in systems if k != "phishguard"]
    if pg_wrong == 0:
        title = "On hard cases, PhishGuard escalates instead of guessing — and makes no wrong calls"
    elif others and pg_wrong < min(others):
        title = "On hard cases, PhishGuard escalates instead of guessing — and makes the fewest wrong calls"
    else:
        title = "On hard cases, PhishGuard escalates instead of guessing"
    fig.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold", color=INK, y=0.99)
    fig.text(
        0.01,
        0.875,
        f"PG-HARD: {hard.get('n_records', '?')} records, each built to defeat a named "
        "detection cue. All systems tuned to the same false-alarm budget first.",
        fontsize=8.5,
        color=INK2,
        ha="left",
    )
    from matplotlib.patches import Patch

    handles = [
        Patch(facecolor=OUT_CORRECT, label="Correct automatic decision"),
        Patch(facecolor=OUT_HUMAN, label="Sent to a human"),
        Patch(facecolor=OUT_WRONG, label="Wrong (false block · silent delivery)"),
    ]
    fig.legend(
        handles=handles,
        loc="lower left",
        ncol=3,
        bbox_to_anchor=(0.005, -0.02),
        handlelength=1.1,
        handleheight=0.9,
        columnspacing=1.6,
    )
    return _save(fig, out_dir, "fig01_pg_hard_outcomes", formats)


# --------------------------------------------------------------------------
# Figure 2 - Robustness versus attacker query budget
# --------------------------------------------------------------------------
def fig_attack_budget(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    adaptive = (report.get("pg_hard") or {}).get("adaptive_robustness")
    if not adaptive:
        return None
    curves = adaptive["curves"]
    plt = _plt()
    fig, (ax, ax2) = plt.subplots(
        1, 2, figsize=(WIDTH_IN, 2.8), gridspec_kw={"width_ratios": [1.25, 1]}
    )
    fig.subplots_adjust(wspace=0.38, top=0.74, bottom=0.2)

    # ---- left: silent delivery vs budget
    _quiet(ax, grid="y")
    ax.set_ylim(-0.03, 1.0)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax.set_xlabel("Attacker query budget")
    ax.set_title("Phishing delivered with no warning", fontsize=9.5, color=INK, pad=6)

    budgets = [r["budget"] for r in curves["adaptive"]["rows"]]
    xs = list(range(len(budgets)))
    ax.set_xticks(xs)
    ax.set_xticklabels([str(b) for b in budgets])
    ax.set_xlim(-0.25, len(budgets) - 0.6)

    naive = [r["silent_delivery_rate"] for r in curves["naive"]["rows"]]
    adapt = [r["silent_delivery_rate"] for r in curves["adaptive"]["rows"]]
    series = []
    if "text_only" in curves:
        series.append(
            (
                "Text-only filter",
                [r["silent_delivery_rate"] for r in curves["text_only"]["rows"]],
                SERIES_TEXT,
            )
        )
    same = all(abs(a - b) < 1e-9 for a, b in zip(naive, adapt, strict=False))
    if same:
        series.append(("PhishGuard (both attackers)", adapt, SERIES_PG))
    else:
        series.append(("PhishGuard (adaptive)", adapt, SERIES_PG))
        series.append(("PhishGuard (naive)", naive, DEEMPH))
    for name, vals, col in series:
        ax.plot(
            xs,
            vals,
            color=col,
            linewidth=2,
            solid_capstyle="round",
            solid_joinstyle="round",
            zorder=3,
            label=name,
        )
        ax.scatter(xs, vals, s=34, color=col, edgecolors=SURFACE, linewidths=2, zorder=4)
    # End labels, pushed apart vertically so close values never overprint.
    ends = sorted(((vals[-1], _pct(vals[-1])) for _, vals, _ in series), key=lambda t: t[0])
    gap = 0.075  # data units on a 0-1 axis: about one label height here
    placed: list[float] = []
    for v, _ in ends:
        placed.append(max(v, placed[-1] + gap) if placed else v)
    for (v, text), y in zip(ends, placed, strict=False):
        ax.annotate(
            text,
            (xs[-1], v),
            xytext=(xs[-1] + 0.12, y),
            textcoords="data",
            va="center",
            fontsize=8.5,
            color=INK,
            fontweight="bold",
        )
    ax.legend(loc="upper left", bbox_to_anchor=(0, 1.02), handlelength=1.4)

    # ---- right: what the attack does to PhishGuard's decisions
    rows = curves["adaptive"]["rows"]
    _quiet(ax2, grid="")
    ax2.set_ylim(0, 1)
    ax2.set_xlim(-0.6, len(rows) - 0.4)
    ax2.spines["left"].set_visible(False)
    ax2.set_yticks([])
    ax2.set_xticks(range(len(rows)))
    ax2.set_xticklabels([str(r["budget"]) for r in rows])
    ax2.set_xlabel("Attacker query budget")
    ax2.set_title("What PhishGuard did with them", fontsize=9.5, color=INK, pad=6)
    from matplotlib.patches import Rectangle

    for i, r in enumerate(rows):
        n = max(r["n"], 1)
        b = r["bands"]
        segs = [
            (b.get("BLOCK", 0) / n, OUT_CORRECT, "blocked"),
            (b.get("REVIEW", 0) / n, OUT_HUMAN, "to a human"),
            (b.get("ALLOW", 0) / n, OUT_WRONG, "delivered"),
        ]
        bottom = 0.0
        for v, col, _ in segs:
            if v <= 0:
                continue
            h = max(v - 0.006, 0)
            ax2.add_patch(
                Rectangle((i - 0.22, bottom), 0.44, h, facecolor=col, linewidth=0, zorder=3)
            )
            if v >= 0.12:
                ax2.text(
                    i,
                    bottom + h / 2,
                    _pct(v),
                    ha="center",
                    va="center",
                    fontsize=8,
                    color=_ink_on(col),
                    zorder=4,
                )
            bottom += v
    from matplotlib.patches import Patch

    ax2.legend(
        handles=[
            Patch(facecolor=OUT_CORRECT, label="Auto-blocked"),
            Patch(facecolor=OUT_HUMAN, label="Sent to a human"),
            Patch(facecolor=OUT_WRONG, label="Delivered"),
        ],
        loc="upper left",
        bbox_to_anchor=(0, -0.2),
        ncol=3,
        handlelength=1.0,
        columnspacing=1.0,
    )

    tx_last = (
        curves["text_only"]["rows"][-1]["silent_delivery_rate"] if "text_only" in curves else None
    )
    pg_last = max(adapt[-1], naive[-1])
    if pg_last == 0 and tx_last is not None and tx_last >= 0.25:
        title = "Under attack, the text-only filter collapses; PhishGuard concedes certainty, not safety"
    elif tx_last is not None and pg_last < tx_last:
        title = "Under attack, PhishGuard delivers far less hard phishing unwarned than the text-only filter"
    else:
        title = "Hard phishing delivered unwarned as the attacker's query budget grows"
    fig.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold", color=INK, y=0.99)
    fig.text(
        0.01,
        0.875,
        f"{adaptive['targets']} hard phishing records. Graded by the deployed decision "
        "(calibrated score, then abstention), whatever the attacker optimised.",
        fontsize=8.5,
        color=INK2,
        ha="left",
    )
    return _save(fig, out_dir, "fig02_attack_budget", formats)


# --------------------------------------------------------------------------
# Figure 3 - Which readers the strongest attack could move
# --------------------------------------------------------------------------
def fig_member_movement(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    mm = ((report.get("pg_hard") or {}).get("adaptive_robustness") or {}).get("member_movement")
    if not mm:
        return None
    rows = sorted(mm["members"], key=lambda r: r["mean_drop"])
    plt = _plt()
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 2.4))
    fig.subplots_adjust(top=0.7, bottom=0.2, left=0.16)
    _quiet(ax, grid="x")
    ax.set_xlim(0, 1)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1])
    ax.set_xlabel("Mean member score on the attacked hard phishing (1 = certain it is phishing)")
    ys = list(range(len(rows)))
    for y, r in zip(ys, rows, strict=False):
        a, b = r["mean_before"], r["mean_after"]
        ax.plot([b, a], [y, y], color="#9ec5f4", linewidth=2, solid_capstyle="round", zorder=2)
        ax.scatter([a], [y], s=46, color="#9ec5f4", edgecolors=SURFACE, linewidths=2, zorder=3)
        ax.scatter([b], [y], s=46, color="#1c5cab", edgecolors=SURFACE, linewidths=2, zorder=4)
        # Label to the right of the pair, clear of both markers.
        drop = r["mean_drop"]
        ax.text(
            max(a, b) + 0.025,
            y,
            f"−{drop:.2f}" if drop >= 0 else f"+{-drop:.2f}",
            ha="left",
            va="center",
            fontsize=8.5,
            color=INK2,
        )
    ax.set_yticks(ys)
    ax.set_yticklabels(
        [r["member"] for r in rows], fontsize=8.5, color=INK, family="DejaVu Sans Mono"
    )
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.scatter([], [], s=46, color="#9ec5f4", label="Before the attack")
    ax.scatter([], [], s=46, color="#1c5cab", label=f"After {mm['budget']} queries")
    ax.legend(loc="lower right", ncol=2, bbox_to_anchor=(1.0, 1.0))
    drops = {r["member"]: r["mean_drop"] for r in rows}
    structural = [drops[k] for k in ("rules", "engineered") if k in drops]
    textual = [drops[k] for k in ("charngram", "wordtfidf") if k in drops]
    if structural and textual and min(structural) > max(textual) + 0.10 and max(textual) < 0.10:
        title = "The attack can quieten the structural readers, but not the text readers"
    else:
        title = "How far the strongest attack moved each ensemble member"
    fig.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold", color=INK, y=0.99)
    fig.text(
        0.01,
        0.875,
        "Adaptive attacker on the hard phishing records. Only one reader has to keep "
        "objecting for the message to be escalated.",
        fontsize=8.5,
        color=INK2,
        ha="left",
    )
    return _save(fig, out_dir, "fig03_member_movement", formats)


# --------------------------------------------------------------------------
# Figure 4 - Per attack family
# --------------------------------------------------------------------------
def fig_attack_families(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    pf = ((report.get("pg_hard") or {}).get("adaptive_robustness") or {}).get("per_family")
    if not pf or not pf.get("rows"):
        return None
    rows = sorted(pf["rows"], key=lambda r: r.get("text_only_silent_delivery_rate") or 0.0)
    tx_vals = [r.get("text_only_silent_delivery_rate") or 0.0 for r in rows]
    pg_vals = [r["phishguard_silent_delivery_rate"] for r in rows]
    peak = max(tx_vals + pg_vals + [0.05])
    # Axis sized to the data: bars still start at zero, so nothing is
    # exaggerated, but a 23% maximum is no longer squeezed into a 100% axis.
    top = min(1.0, (int(peak * 100 / 10) + 1) * 0.10)
    plt = _plt()
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 3.6))
    fig.subplots_adjust(top=0.8, bottom=0.13, left=0.43, right=0.95)
    _quiet(ax, grid="x")
    ax.set_xlim(0, top)
    ticks = [t / 100 for t in range(0, int(top * 100) + 1, 10 if top > 0.3 else 5)]
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{int(t * 100)}%" for t in ticks])
    ax.set_xlabel(
        f"Hard phishing delivered with no warning (budget {pf['budget']}, one family at a time)"
    )
    ax.set_ylim(-0.6, len(rows) - 0.4)
    # Paired bars per family, each labelled; a zero is drawn as a dot at the
    # baseline so "nothing got through" is visible rather than blank.
    for y, (tx, pg) in enumerate(zip(tx_vals, pg_vals, strict=False)):
        for v, off, col in ((tx, 0.17, SERIES_TEXT), (pg, -0.17, SERIES_PG)):
            if v > 0:
                _rounded_hbar(ax, y + off, 0, v, 0.3, col, radius_in=0.022)
            else:
                ax.scatter(
                    [0],
                    [y + off],
                    s=26,
                    color=col,
                    edgecolors=SURFACE,
                    linewidths=1.5,
                    zorder=6,
                    clip_on=False,
                )
            ax.text(v + top * 0.012, y + off, _pct(v), va="center", fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{r['family_id']}  {r['family']}" for r in rows], fontsize=8.5, color=INK)
    from matplotlib.patches import Patch

    ax.legend(
        handles=[
            Patch(facecolor=SERIES_TEXT, label="Text-only filter"),
            Patch(facecolor=SERIES_PG, label="PhishGuard"),
        ],
        loc="lower right",
        bbox_to_anchor=(1.0, 1.0),
        ncol=2,
    )
    all_zero = all(v == 0 for v in pg_vals)
    title = (
        "No single attack family gets hard phishing past PhishGuard"
        if all_zero
        else "Hard phishing delivered unwarned, one attack family at a time"
    )
    fig.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold", color=INK, y=0.99)
    n_t = ((report.get("pg_hard") or {}).get("adaptive_robustness") or {}).get("targets")
    fig.text(
        0.01,
        0.905,
        (f"{n_t} hard phishing records. " if n_t else "")
        + "The attacker may use one family of transforms at a time; a dot marks 0%.",
        fontsize=8.5,
        color=INK2,
        ha="left",
    )
    return _save(fig, out_dir, "fig04_attack_families", formats)


# --------------------------------------------------------------------------
# Figure 5 - ROC on a log false-positive axis
# --------------------------------------------------------------------------
def fig_roc(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    curves = report.get("curves") or {}
    if "phishguard" not in curves:
        return None
    plt = _plt()
    fig, ax = plt.subplots(figsize=(WIDTH_IN * 0.62, 3.0))
    fig.subplots_adjust(top=0.88)
    _quiet(ax, grid="both")
    ax.set_xscale("log")
    floor = curves["phishguard"]["roc"].get("fpr_floor", 1e-4)
    ax.set_xlim(floor, 1)
    ax.set_ylim(0.5, 1.005)
    ax.set_xlabel("False-positive rate (log scale)")
    ax.set_ylabel("Phishing caught (true-positive rate)")
    ax.set_yticks([0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    ax.set_yticklabels(["50%", "60%", "70%", "80%", "90%", "100%"])
    ax.set_xticks([1e-4, 1e-3, 1e-2, 1e-1, 1])
    ax.set_xticklabels(["0.01%", "0.1%", "1%", "10%", "100%"])
    plotted = [
        ("phishguard", "PhishGuard", SERIES_PG),
        ("B1_tfidf_logreg", "Text-only filter", SERIES_TEXT),
        ("B0_rule_checklist", "Rule checklist", SERIES_RULES),
    ]
    for key, name, col in plotted:
        c = curves.get(key)
        if not c or not c["roc"]["fpr"]:
            continue
        fpr = [max(f, floor) for f in c["roc"]["fpr"]]
        auc = (report.get("baselines", {}).get(key, {}) or {}).get("roc_auc")
        if key == "phishguard":
            auc = report.get("clean", {}).get("roc_auc")
        label = f"{name}  (AUC {auc:.4f})" if auc else name
        ax.step(
            fpr,
            c["roc"]["tpr"],
            where="post",
            color=col,
            linewidth=2,
            label=label,
            zorder=4 if key == "phishguard" else 3,
        )
    op = report.get("clean", {})
    if op:
        ox, oy = max(op.get("false_positive_rate", 0.0), floor), op.get("recall_phish", 0.0)
        ax.scatter([ox], [oy], s=46, color=SERIES_PG, edgecolors=SURFACE, linewidths=2, zorder=6)
        # Labelled below the curves with a leader, so the text never sits on
        # a line; the point is the 0.5 cut-off the clean metrics use.
        ax.annotate(
            "0.5 cut-off",
            (ox, oy),
            xytext=(ox * 2.2, oy - 0.085),
            textcoords="data",
            ha="left",
            va="center",
            fontsize=8,
            color=INK2,
            arrowprops={
                "arrowstyle": "-",
                "color": INK2,
                "linewidth": 0.7,
                "shrinkA": 0,
                "shrinkB": 4,
            },
        )
    ax.legend(loc="lower right")
    fig.suptitle(
        "Detection at the false-alarm rates a mail gateway can afford",
        x=0.01,
        ha="left",
        fontsize=10.5,
        fontweight="bold",
        color=INK,
        y=0.99,
    )
    return _save(fig, out_dir, "fig05_roc_log_fpr", formats)


# --------------------------------------------------------------------------
# Figure 6 - Calibration
# --------------------------------------------------------------------------
def fig_reliability(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    cal = report.get("calibration") or {}
    bins = [b for b in cal.get("reliability", []) if b.get("count")]
    if not bins:
        return None
    plt = _plt()
    fig, (ax, axh) = plt.subplots(
        2, 1, figsize=(WIDTH_IN * 0.55, 3.6), sharex=True, gridspec_kw={"height_ratios": [3, 1.1]}
    )
    fig.subplots_adjust(hspace=0.12, top=0.84)
    _quiet(ax, grid="both")
    ax.plot([0, 1], [0, 1], color=AXIS, linewidth=1, zorder=1)
    ax.text(0.56, 0.47, "perfect calibration", fontsize=8, color=MUTED, rotation=0)
    # A bin holding one or two messages has an observed rate of exactly 0 or 1
    # by construction. Joining those points draws a dramatic curve out of no
    # data at all, so sparse bins are shown hollow and never connected.
    MIN_N = 10
    solid = [b for b in bins if b["count"] >= MIN_N]
    sparse = [b for b in bins if b["count"] < MIN_N]
    xs = [b["mean_predicted"] for b in solid]
    ys = [b["observed_frequency"] for b in solid]
    # Two populated bins define a straight line that lies on the diagonal by
    # construction and reads as the reference itself; only a genuine curve
    # (three or more populated bins) is joined up.
    if len(solid) >= 3:
        ax.plot(xs, ys, color=SERIES_PG, linewidth=2, zorder=3)
    ax.scatter(
        xs,
        ys,
        s=40,
        color=SERIES_PG,
        edgecolors=SURFACE,
        linewidths=2,
        zorder=4,
        label=f"bins with n ≥ {MIN_N}",
    )
    if sparse:
        ax.scatter(
            [b["mean_predicted"] for b in sparse],
            [b["observed_frequency"] for b in sparse],
            s=34,
            facecolors=SURFACE,
            edgecolors=SERIES_PG,
            linewidths=1.6,
            zorder=4,
            label=f"{sum(b['count'] for b in sparse)} message(s) in sparse bins",
        )
    # Lower right is the one region a reliability curve above the diagonal
    # never enters.
    ax.legend(loc="lower right", fontsize=8, handletextpad=0.4)
    for b in solid:
        yv = b["observed_frequency"]
        off = (6, -14) if yv > 0.9 else ((5, 3) if yv < 0.1 else (7, -12))
        ax.annotate(
            f"n={b['count']:,}",
            (b["mean_predicted"], yv),
            xytext=off,
            textcoords="offset points",
            fontsize=8,
            color=INK2,
            va="bottom" if yv < 0.1 else "baseline",
        )
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.03, 1.05)
    ax.set_ylabel("Observed phishing rate")
    ax.set_yticks([0, 0.5, 1])
    hist = (report.get("score_histograms") or {}).get("calibrated")
    _quiet(axh, grid="y")
    if hist:
        edges = hist["edges"]
        w = edges[1] - edges[0]
        centres = [e + w / 2 for e in edges[:-1]]
        # One series: the point of this panel is *where* the mass sits (at
        # exactly 0 and 1), not the class split, and a class colour here
        # would collide with the series colours used in the other figures.
        total = [a + b for a, b in zip(hist["legitimate"], hist["phishing"], strict=False)]
        axh.bar(centres, total, width=w * 0.9, color=DEEMPH, zorder=3)
        axh.set_yscale("log")
        axh.set_ylabel("Messages (log)")
    axh.set_xlabel("Predicted probability of phishing")
    fig.suptitle(
        f"Calibration: ECE {cal.get('ece', 0):.4f}",
        x=0.02,
        ha="left",
        fontsize=10.5,
        fontweight="bold",
        color=INK,
        y=0.99,
    )
    note = "Hollow markers: bins too sparse to estimate a rate."
    if hist:
        tot = [a + b for a, b in zip(hist["legitimate"], hist["phishing"], strict=False)]
        extreme = (tot[0] + tot[-1]) / max(sum(tot), 1)
        if extreme >= 0.8:
            note = (
                f"{extreme:.0%} of messages score within {hist['edges'][1]:.3f} of 0 or 1, "
                "which is why ECE is near zero."
            )
    fig.text(0.02, 0.9, note, fontsize=8, color=INK2)
    return _save(fig, out_dir, "fig06_calibration", formats)


# --------------------------------------------------------------------------
# Figure 7 - Modality ablation
# --------------------------------------------------------------------------
def fig_modality(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    rows = report.get("modality_ablation") or []
    if not rows:
        return None
    p = float(report.get("dataset", {}).get("test_phish_rate", 0.5))

    def errors_per_1000(r: dict[str, Any]) -> float:
        return 1000 * ((1 - r["recall_phish"]) * p + r["false_positive_rate"] * (1 - p))

    rows = sorted(rows, key=errors_per_1000, reverse=True)
    vals = [errors_per_1000(r) for r in rows]
    plt = _plt()
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 2.8))
    fig.subplots_adjust(top=0.8, left=0.26)
    _quiet(ax, grid="x")
    top = max(vals) * 1.18
    ax.set_xlim(0, top)
    ax.set_ylim(-0.6, len(rows) - 0.4)
    for y, (r, v) in enumerate(zip(rows, vals, strict=False)):
        full = len(r["families"]) == 3
        _rounded_hbar(ax, y, 0, v, 0.56, SERIES_PG if full else DEEMPH, radius_in=0.03)
        ax.text(
            v + top * 0.012,
            y,
            f"{v:.1f}",
            va="center",
            fontsize=8.5,
            color=INK if full else INK2,
            fontweight="bold" if full else "normal",
        )
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r["label"] for r in rows], fontsize=9, color=INK)
    ax.set_xlabel("Errors per 1,000 messages (missed phishing + false alarms) — lower is better")
    singles = [v for r, v in zip(rows, vals, strict=False) if len(r["families"]) == 1]
    fulls = [v for r, v in zip(rows, vals, strict=False) if len(r["families"]) == 3]
    multi = [v for r, v in zip(rows, vals, strict=False) if len(r["families"]) > 1]
    if fulls and fulls[0] <= min(vals) and singles and min(singles) > max(multi):
        title = "No single feature family is enough; all three together make the fewest errors"
    elif fulls and fulls[0] <= min(vals):
        title = "All three feature families together make the fewest errors"
    else:
        title = "Errors by feature-family combination"
    fig.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold", color=INK, y=0.99)
    fig.text(
        0.01,
        0.875,
        "Engineered member alone, trained on each combination of the three families.",
        fontsize=8.5,
        color=INK2,
        ha="left",
    )
    return _save(fig, out_dir, "fig07_modality_ablation", formats)


# --------------------------------------------------------------------------
# Figure 8 - The operating point: cost frontier and robustness
# --------------------------------------------------------------------------
def fig_cost(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    """Benign-traffic cost against leakage under attack, one row per candidate.

    An earlier version drew a two-axis workload/safety frontier. It was
    misleading: the frontier's low-review, low-miss points buy that position
    with false blocks, which the two axes do not show, so every candidate
    appeared strictly dominated. Total expected cost is the honest single axis
    for the benign side, and pairing it row-for-row with the attack result
    shows the trade in one glance.
    """
    c = report.get("cost") or {}
    ua = c.get("under_attack") or {}
    if not c.get("deployed") or not ua:
        return None
    order = [
        ("deployed", "Deployed default", c["deployed"]),
        ("minimax_regret", "Minimax-regret", None),
        ("cost_optimal", "Cost-optimal", c.get("optimum")),
    ]
    pts = c.get("candidate_points") or {}
    rows = []
    for key, name, pol in order:
        if key not in ua:
            continue
        if key == "minimax_regret":
            # The minimax policy's cost at the *stated* assumptions is not stored
            # directly; it is recovered from the candidate costs below.
            pol = None
        rows.append((key, name, pol))

    # Benign cost for each candidate at the stated assumptions.
    def benign_cost(key: str) -> float | None:
        if key == "deployed":
            return c["deployed"]["per_1000"]
        if key == "cost_optimal":
            return c["optimum"]["per_1000"]
        return (c.get("candidate_costs") or {}).get(key)

    plt = _plt()
    fig, (ax, ax2) = plt.subplots(
        1, 2, figsize=(WIDTH_IN, 2.5), sharey=True, gridspec_kw={"width_ratios": [1.2, 1]}
    )
    fig.subplots_adjust(wspace=0.18, top=0.68, bottom=0.22, left=0.25)
    ys = list(range(len(rows)))[::-1]
    costs = [benign_cost(k) for k, _, _ in rows]
    leaks = [ua[k]["worst_silent_delivery_rate"] for k, _, _ in rows]

    _quiet(ax, grid="x")
    top_c = max([v for v in costs if v is not None] + [1.0]) * 1.16
    ax.set_xlim(0, top_c)
    ax.set_ylim(-0.6, len(rows) - 0.4)
    for y, (key, _, _), v in zip(ys, rows, costs, strict=False):
        if v is None:
            continue
        col = SERIES_PG if key == "deployed" else DEEMPH
        _rounded_hbar(ax, y, 0, v, 0.5, col, radius_in=0.03)
        ax.text(
            v + top_c * 0.015,
            y,
            f"{v:.0f}",
            va="center",
            fontsize=8.5,
            color=INK if key == "deployed" else INK2,
            fontweight="bold" if key == "deployed" else "normal",
        )
    ax.set_yticks(ys)
    labels = []
    for key, name, _ in rows:
        reviews = (pts.get(key) or {}).get("reviews_per_1000")
        labels.append(name if reviews is None else f"{name}\n{reviews:.0f} per 1,000 to a human")
    ax.set_yticklabels(labels, fontsize=8.5, color=INK, linespacing=1.3)
    ax.set_xlabel("Benign cost per 1,000 messages")
    known = [(k, v) for (k, _, _), v in zip(rows, costs, strict=False) if v is not None]
    dep_cost = dict(known).get("deployed")
    costs_most = dep_cost is not None and dep_cost >= max(v for _, v in known)
    ax.set_title(
        "On benign traffic, the default costs most"
        if costs_most
        else "Expected cost on benign traffic",
        fontsize=9.5,
        color=INK,
        pad=6,
    )

    _quiet(ax2, grid="x")
    top_l = max(0.1, (int(max(leaks) * 10) + 1) / 10)
    ax2.set_xlim(0, top_l)
    for y, (key, _, _), v in zip(ys, rows, leaks, strict=False):
        col = SERIES_PG if key == "deployed" else DEEMPH
        if v > 0:
            _rounded_hbar(ax2, y, 0, v, 0.5, col, radius_in=0.03)
        else:
            ax2.scatter(
                [0], [y], s=34, color=col, edgecolors=SURFACE, linewidths=2, zorder=6, clip_on=False
            )
        atk = ua.get(key) or {}
        label = _pct(v) + (
            f" · {atk['worst_silent_delivered']} of {atk['n_targets']}"
            if atk.get("n_targets")
            else ""
        )
        ax2.text(
            v + top_l * 0.03,
            y,
            label,
            va="center",
            fontsize=8.5,
            color=INK if key == "deployed" else INK2,
            fontweight="bold" if key == "deployed" else "normal",
        )
    ticks = [0, top_l / 2, top_l]
    ax2.set_xticks(ticks)
    ax2.set_xticklabels([_pct(t) for t in ticks])
    ax2.set_xlabel("Hard phish delivered under attack")
    dep_leak = dict(zip([k for k, _, _ in rows], leaks, strict=False)).get("deployed")
    only_default = dep_leak is not None and all(
        (v > dep_leak) for (k, _, _), v in zip(rows, leaks, strict=False) if k != "deployed"
    )
    ax2.set_title(
        "Under attack, only the default holds"
        if only_default
        else "Hard phishing delivered under attack",
        fontsize=9.5,
        color=INK,
        pad=6,
    )
    ax2.tick_params(axis="y", length=0)

    fig.suptitle(
        "The default buys adversarial robustness with analyst time — and says so"
        if (costs_most and only_default)
        else "The operating point: benign cost against leakage under attack",
        x=0.01,
        ha="left",
        fontsize=11,
        fontweight="bold",
        color=INK,
        y=0.99,
    )
    a = c.get("assumptions", {})
    fig.text(
        0.01,
        0.855,
        f"Illustrative costs, in analyst reviews: missed phish {a.get('miss_cost', 0):.0f}, "
        f"false block {a.get('false_block_cost', 0):.0f}. {a.get('phish_prevalence', 0):.0%} "
        f"phishing, {a.get('hard_phish_share', 0):.0%} hard traffic.",
        fontsize=8.5,
        color=INK2,
        ha="left",
    )
    return _save(fig, out_dir, "fig08_operating_point", formats)


# --------------------------------------------------------------------------
# Figure 9 - Drift monitoring
# --------------------------------------------------------------------------
def fig_drift(report: dict[str, Any], out_dir: Path, formats) -> list[Path] | None:
    d = report.get("drift") or {}
    weeks = d.get("weeks") or []
    th = d.get("thresholds") or {}
    if not weeks or "significant" not in th:
        return None
    plt = _plt()
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 3.0))
    fig.subplots_adjust(top=0.71, bottom=0.16, right=0.78)
    _quiet(ax, grid="y")
    xs = [w["week"] for w in weeks]
    ys = [w["worst_psi"] for w in weeks]
    top = max(ys + [th["significant"]]) * 1.2
    ax.set_ylim(0, top)
    ax.set_xlim(min(xs) - 0.5, max(xs) + 0.5)
    # Calibrated bands as quiet background regions. Each band is labelled at
    # its own vertical centre in the right margin -- labelling the two lines
    # instead collides whenever the calibrated thresholds sit close together.
    mod, sig = th["moderate"], th["significant"]
    ax.axhspan(sig, top, color="#fbe3e3", zorder=0, linewidth=0)
    ax.axhspan(mod, sig, color="#f4f1e8", zorder=0, linewidth=0)
    for yv in (sig, mod):
        ax.axhline(yv, color=AXIS, linewidth=0.8, zorder=1)
    labels = [
        ((sig + top) / 2, f"significant ≥ {sig:.2f}\ninvestigate, retrain"),
        ((mod + sig) / 2, f"moderate ≥ {mod:.2f} · watch"),
        (mod / 2, "stable"),
    ]
    # Keep the three labels at least ~one line apart (axis fraction), pushing
    # upwards from the bottom so the order is always preserved.
    min_gap = 0.11 * top
    placed: list[float] = []
    for yv, _ in sorted(labels):
        yv = max(yv, placed[-1] + min_gap) if placed else yv
        placed.append(yv)
    for (_, text), yv in zip(sorted(labels), placed, strict=False):
        ax.text(
            max(xs) + 0.6,
            min(yv, top * 0.97),
            text,
            va="center",
            fontsize=8,
            color=INK2,
            clip_on=False,
            linespacing=1.15,
        )
    shift = d.get("shift_week")
    if shift:
        ax.axvline(shift - 0.5, color=INK2, linewidth=1, zorder=1)
        ax.text(shift - 0.4, top * 0.93, "shift begins", fontsize=8, color=INK2, va="top")
    ax.plot(xs, ys, color=SERIES_PG, linewidth=2, zorder=3, solid_capstyle="round")
    colors = [
        OUT_WRONG
        if w["status"] == "significant"
        else ("#c98500" if w["status"] == "moderate" else SERIES_PG)
        for w in weeks
    ]
    ax.scatter(xs, ys, s=40, c=colors, edgecolors=SURFACE, linewidths=2, zorder=4)
    ax.set_xticks(xs)
    ax.set_xlabel("Week")
    ax.set_ylabel("Worst PSI across monitored quantities")
    # The title states what this run shows, so it can never overclaim: the
    # moderate level is a 95th-percentile watch line, and a stable week may
    # legitimately reach it (about one in twenty, by construction).
    pre = [w for w in weeks if not w.get("shifted")]
    post = [w for w in weeks if w.get("shifted")]
    pre_sig = sum(w["status"] == "significant" for w in pre)
    post_sig = sum(w["status"] == "significant" for w in post)
    pre_any = sum(w["status"] != "stable" for w in pre)
    post_any = sum(w["status"] != "stable" for w in post)
    if pre and post and pre_any == 0 and post_any == len(post):
        title = "The drift monitor stays quiet on every stable week and flags every shifted one"
    elif pre and post and pre_sig == 0 and post_sig == len(post):
        title = "No stable week raises the drift alarm; every shifted week does"
    else:
        title = (
            f"Drift flagged on {pre_any} of {len(pre)} stable weeks and "
            f"{post_any} of {len(post)} shifted weeks"
        )
    fig.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold", color=INK, y=0.99)
    fig.text(
        0.01,
        0.905,
        f"{d.get('per_week', '?')} messages a week at 2% phishing; from week {shift}, a quarter "
        "of traffic is mail the model was not trained on. Bands are calibrated on stable,\n"
        "campaign-structured weeks: 'moderate' is their 95th percentile, so about one stable "
        "week in twenty is expected to reach it.",
        fontsize=8.5,
        color=INK2,
        ha="left",
        va="top",
        linespacing=1.3,
    )
    return _save(fig, out_dir, "fig09_drift", formats)


# --------------------------------------------------------------------------
# Optional figures contributed by other modules (cost model, drift)
# --------------------------------------------------------------------------
EXTRA_FIGURES: list[Callable[[dict[str, Any], Path, tuple[str, ...]], list[Path] | None]] = []

FIGURES: list[tuple[str, Callable[..., list[Path] | None]]] = [
    ("PG-HARD outcomes", fig_pg_hard_outcomes),
    ("Robustness vs query budget", fig_attack_budget),
    ("Which readers the attack moved", fig_member_movement),
    ("Per attack family", fig_attack_families),
    ("ROC on log-FPR axis", fig_roc),
    ("Calibration", fig_reliability),
    ("Modality ablation", fig_modality),
    ("Operating point and cost", fig_cost),
    ("Drift monitoring", fig_drift),
]


def render_all(
    report_path: Path,
    out_dir: Path,
    *,
    formats: tuple[str, ...] = ("png", "svg"),
) -> dict[str, list[str]]:
    """Draw every figure the report has data for. Returns name -> files."""
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, list[str]] = {}
    skipped: list[str] = []
    for name, fn in FIGURES + [(f.__name__, f) for f in EXTRA_FIGURES]:
        paths = fn(report, out_dir, formats)
        if paths:
            written[name] = [str(p) for p in paths]
        else:
            skipped.append(name)
    if skipped:
        written["_skipped"] = skipped
    return written


# --------------------------------------------------------------------------
# Captions - generated from the same report, so they cannot drift either
# --------------------------------------------------------------------------
def captions(report: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(file stem, short title, caption)`` for every figure with data."""
    out: list[tuple[str, str, str]] = []
    hard = report.get("pg_hard") or {}
    sysd = hard.get("systems") or {}
    om = hard.get("ordinary_mail") or {}
    if sysd.get("phishguard"):
        pg, tx, rl = (
            sysd["phishguard"],
            sysd.get("B1_tfidf_logreg", {}),
            sysd.get("B0_rule_checklist", {}),
        )
        pg_wrong = int(pg.get("silent_delivery", 0)) + int(pg.get("false_block", 0))
        wrong_cases = sorted(
            {
                r["case_id"]
                for r in hard.get("per_case", [])
                if r["bands"].get("ALLOW" if r["label"] == 1 else "BLOCK", 0) > 0
            }
        )
        verdict = (
            "PhishGuard makes no wrong automatic decision"
            if pg_wrong == 0
            else f"PhishGuard makes {pg_wrong} wrong automatic decision{'s' if pg_wrong != 1 else ''}"
            + (
                f", all in case{'s' if len(wrong_cases) > 1 else ''} {_and_join(wrong_cases)}"
                if wrong_cases
                else ""
            )
        )
        seeds = (report.get("seed_sensitivity") or {}).get("summary") or {}
        seed_note = ""
        if seeds:
            sd, fb = seeds["pg_hard_silent_delivery"], seeds["pg_hard_false_block"]
            n_runs = (report.get("seed_sensitivity") or {}).get("n_runs", 0)
            seed_note = (
                f" Retrained with {n_runs - 1} further seed{'s' if n_runs != 2 else ''}, "
                f"PhishGuard delivered {sd['min']:.0f}–{sd['max']:.0f} hard phishing records "
                f"unwarned and blocked {fb['min']:.0f}–{fb['max']:.0f} hard legitimate ones, "
                "so the figure shows one draw from that range."
            )
        out.append(
            (
                "fig01_pg_hard_outcomes",
                "Outcomes on the PG-HARD benchmark",
                f"Outcomes on PG-HARD, {hard.get('n_records')} records built from "
                f"{hard.get('description', {}).get('n_cases', 24)} hand-designed cases that each defeat a "
                "named detection cue. All three systems were first tuned to the same false-alarm "
                f"budget on ordinary mail. {verdict} "
                f"(silent delivery {pg['silent_delivery_rate']:.1%}, false block "
                f"{pg['false_block_rate']:.1%}); the text-only filter blocks "
                f"{tx.get('false_block_rate', 0):.0%} of the hard legitimate mail and the rule "
                f"checklist delivers {rl.get('silent_delivery_rate', 0):.0%} of the hard phishing "
                "unwarned. PhishGuard's result is bought with escalation: it sends "
                f"{pg['review_load_rate']:.0%} of these hard records, and "
                f"{om.get('review_load_rate', 0):.1%} of ordinary mail, to a human." + seed_note,
            )
        )
    adaptive = hard.get("adaptive_robustness") or {}
    if adaptive:
        c = adaptive["curves"]
        tx_rows = c.get("text_only", {}).get("rows", [])
        pg_rows = c["adaptive"]["rows"]
        b_hi = pg_rows[-1]["budget"]
        out.append(
            (
                "fig02_attack_budget",
                "Robustness against query budget",
                f"Left: share of {adaptive['targets']} hard phishing records delivered with no warning "
                "after a budgeted black-box attack, at increasing query budgets. The text-only filter "
                + (
                    f"rises from {tx_rows[0]['silent_delivery_rate']:.0%} to "
                    f"{tx_rows[-1]['silent_delivery_rate']:.0%} at {b_hi} queries; "
                    if tx_rows
                    else ""
                )
                + _pg_attack_sentence(c)
                + " Right: the attack is not without effect - the share PhishGuard auto-blocks "
                f"falls from {pg_rows[0]['auto_blocked_rate']:.0%} to {pg_rows[-1]['auto_blocked_rate']:.0%} "
                f"as the attacker spends queries, and at {b_hi} queries "
                f"{pg_rows[-1]['bands'].get('REVIEW', 0) / max(pg_rows[-1]['n'], 1):.0%} are escalated to "
                "review. Every attacker is graded by the deployed decision, not by the score it optimised.",
            )
        )
        mm = adaptive.get("member_movement")
        if mm:
            out.append(
                (
                    "fig03_member_movement",
                    "Which ensemble members the attack could move",
                    f"Mean score of each ensemble member on the hard phishing records before and after "
                    f"the strongest adaptive attack ({mm['budget']} queries): "
                    + "; ".join(
                        f"{r['member']} {r['mean_before']:.2f} to {r['mean_after']:.2f}"
                        for r in sorted(mm["members"], key=lambda r: -r["mean_drop"])
                    )
                    + ". "
                    + (
                        f"The attack moves {_most_moved(mm['members'])} "
                        f"most and {_least_moved(mm['members'])} least. "
                        if len(mm["members"]) > 1
                        else ""
                    )
                    + "Because escalation needs only one reader to keep objecting, the members' "
                    "weaknesses matter only where they line up, which is the mechanism behind Figure 2.",
                )
            )
        pf = adaptive.get("per_family")
        if pf:
            worst = max(pf["rows"], key=lambda r: r.get("text_only_silent_delivery_rate") or 0)
            out.append(
                (
                    "fig04_attack_families",
                    "Robustness by attack family",
                    f"Hard phishing delivered with no warning when the attacker is restricted to one "
                    f"attack family at a time (budget {pf['budget']}). The text-only filter is most "
                    f"exposed to {worst['family_id']} ({worst['family'].lower()}, "
                    f"{worst.get('text_only_silent_delivery_rate', 0):.0%}); "
                    + (
                        "no family achieves a silent delivery against PhishGuard."
                        if all(r["phishguard_silent_delivery_rate"] == 0 for r in pf["rows"])
                        else "against PhishGuard the worst family is "
                        + (
                            lambda w: (
                                f"{w['family_id']} ({w['phishguard_silent_delivery_rate']:.0%})."
                            )
                        )(max(pf["rows"], key=lambda r: r["phishguard_silent_delivery_rate"]))
                    ),
                )
            )
    if report.get("curves", {}).get("phishguard"):
        clean = report.get("clean", {})
        out.append(
            (
                "fig05_roc_log_fpr",
                "ROC curve on a logarithmic false-positive axis",
                "Receiver operating characteristic on the ordinary held-out test set, with the "
                "false-positive rate on a logarithmic axis so that the low-FPR region a mail gateway "
                "actually operates in is visible. The marker is the 0.5 cut-off used for the clean "
                f"metrics (FPR {clean.get('false_positive_rate', 0):.2%}, recall "
                f"{clean.get('recall_phish', 0):.2%}); the deployed policy has two thresholds and an "
                "abstention band rather than one cut-off. " + _roc_sentence(report),
            )
        )
    cal = report.get("calibration") or {}
    if cal.get("reliability"):
        out.append(
            (
                "fig06_calibration",
                "Calibration",
                f"Reliability of the calibrated score (isotonic; ECE {cal.get('ece', 0):.4f}, "
                f"uncalibrated {cal.get('ece_uncalibrated', 0):.4f}). "
                + _saturation_sentence(report)
                + "Hollow markers are bins holding fewer than ten messages, which carry no reliable "
                "estimate.",
            )
        )
    if report.get("modality_ablation"):
        out.append(
            (
                "fig07_modality_ablation",
                "Feature-family ablation",
                "Errors per 1,000 messages (missed phishing plus false alarms) for the engineered "
                "member trained on each combination of the three feature families. "
                + _modality_sentence(report),
            )
        )
    c = report.get("cost") or {}
    if c.get("deployed") and c.get("under_attack"):
        a = c.get("assumptions", {})
        ua = c.get("under_attack") or {}
        pts = c.get("candidate_points") or {}
        costs = {
            "deployed": (c.get("deployed") or {}).get("per_1000"),
            "cost_optimal": (c.get("optimum") or {}).get("per_1000"),
            **{k: v for k, v in (c.get("candidate_costs") or {}).items()},
        }
        names = {
            "deployed": "the deployed default",
            "minimax_regret": "the minimax-regret policy",
            "cost_optimal": "the cost-optimal policy",
        }
        present = [k for k in ("deployed", "minimax_regret", "cost_optimal") if k in ua]
        text = (
            "Left: expected cost of handling benign traffic, per 1,000 messages, at "
            f"{a.get('phish_prevalence', 0):.0%} phishing prevalence with "
            f"{a.get('hard_phish_share', 0):.0%} hard traffic and illustrative costs in analyst "
            f"reviews (missed phish {a.get('miss_cost', 0):.0f}, false block "
            f"{a.get('false_block_cost', 0):.0f}), for "
            + _and_join(
                f"{names[k]} ({costs[k]:.0f}"
                + (
                    f"; {pts[k]['reviews_per_1000']:.0f} per 1,000 to a human"
                    if (pts.get(k) or {}).get("reviews_per_1000") is not None
                    else ""
                )
                + ")"
                for k in present
                if costs.get(k) is not None
            )
            + ". Right: the share of hard phishing each policy delivers with no warning under "
            "the adaptive attack: "
            + _and_join(
                f"{names[k]} {ua[k]['worst_silent_delivery_rate']:.0%}"
                + (
                    f" ({ua[k]['worst_silent_delivered']} of {ua[k]['n_targets']})"
                    if ua[k].get("n_targets")
                    else ""
                )
                for k in present
            )
            + ". "
        )
        dep_leak = ua.get("deployed", {}).get("worst_silent_delivery_rate")
        cheaper_leak = [ua[k]["worst_silent_delivery_rate"] for k in present if k != "deployed"]
        if dep_leak is not None and cheaper_leak and dep_leak < min(cheaper_leak):
            text += (
                "The cost model prices ordinary mail, but an attacker adapts to the deployed "
                "policy; that is why the more conservative default is kept and its "
                "benign-traffic price is reported."
            )
        out.append(("fig08_operating_point", "Operating point: cost and robustness", text))
    d = report.get("drift") or {}
    if d.get("weeks"):
        th = d.get("thresholds") or {}
        pre = [w for w in d["weeks"] if not w["shifted"]]
        post = [w for w in d["weeks"] if w["shifted"]]
        out.append(
            (
                "fig09_drift",
                "Drift monitoring",
                f"Worst population stability index (PSI) across the monitored quantities for "
                f"{len(d['weeks'])} simulated weeks of {d.get('per_week')} messages. From week "
                f"{d.get('shift_week')} a quarter of traffic is mail unlike the training data. "
                f"{sum(w['status'] != 'stable' for w in pre)} of {len(pre)} stable weeks and "
                f"{sum(w['status'] != 'stable' for w in post)} of {len(post)} shifted weeks are flagged "
                f"(moderate or significant); {sum(w['status'] == 'significant' for w in post)} of the "
                f"shifted weeks reach the significant level"
                + (
                    f", and {sum(w['status'] == 'moderate' for w in pre)} stable week(s) reach the "
                    "moderate watch level, which is expected at about one week in twenty"
                    if any(w["status"] == "moderate" for w in pre)
                    else ""
                )
                + ". The thresholds "
                f"(moderate {th.get('moderate', 0):.2f}, significant {th.get('significant', 0):.2f}) "
                "are the 95th and 99th percentiles of the worst-quantity PSI of stable, "
                "campaign-structured windows, not the textbook 0.10 and 0.25, which assume "
                "independent samples and would fire on most stable weeks of campaign-structured mail.",
            )
        )
    return out


def _pg_attack_sentence(curves: dict[str, Any]) -> str:
    """PhishGuard's attacked result, stated as it is -- never 'stays at 0%' unless it does."""
    naive = [r["silent_delivery_rate"] for r in curves.get("naive", {}).get("rows", [])]
    rows = curves.get("adaptive", {}).get("rows", [])
    adapt = [r["silent_delivery_rate"] for r in rows]
    if not adapt:
        return ""
    peak = max(adapt)
    at = rows[adapt.index(peak)]
    n = at.get("n")
    peak_txt = f"{peak:.0%}" + (f" ({round(peak * n)} of {n})" if n else "")
    if peak == 0 and (not naive or max(naive) == 0):
        return (
            "PhishGuard stays at 0% against both a score-minimising attacker and an adaptive "
            "attacker that targets the abstention control."
        )
    naive_txt = (
        f"PhishGuard delivers {max(naive):.0%} against a score-minimising attacker; "
        if naive
        else ""
    )
    return (
        naive_txt + "an adaptive attacker that targets the abstention control reaches "
        f"{peak_txt} at {at['budget']} queries and {adapt[-1]:.0%} at {rows[-1]['budget']}."
    )


def _and_join(items) -> str:
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _roc_sentence(report: dict[str, Any]) -> str:
    aucs = {
        "PhishGuard": (report.get("clean") or {}).get("roc_auc"),
        "the text-only filter": (report.get("baselines", {}).get("B1_tfidf_logreg") or {}).get(
            "roc_auc"
        ),
        "the rule checklist": (report.get("baselines", {}).get("B0_rule_checklist") or {}).get(
            "roc_auc"
        ),
    }
    known = {k: v for k, v in aucs.items() if v is not None}
    if not known:
        return ""
    text = "ROC AUC: " + _and_join(f"{k} {v:.4f}" for k, v in known.items()) + ". "
    if all(v >= 0.95 for v in known.values()):
        text += "On ordinary mail every system ranks well; the separation that matters is in Figures 1 and 2."
    else:
        text += (
            "Ranking on ordinary mail already separates the systems, and Figures 1 and 2 show "
            "the gap widening on hard and attacked mail."
        )
    return text


def _saturation_sentence(report: dict[str, Any]) -> str:
    """Whether the calibrated score is saturated at 0 and 1, from the stored histogram."""
    h = (report.get("score_histograms") or {}).get("calibrated") or {}
    edges = h.get("edges") or []
    if len(edges) < 3:
        return ""
    counts = [a + b for a, b in zip(h.get("legitimate", []), h.get("phishing", []), strict=False)]
    total = sum(counts) or 1
    extreme = (counts[0] + counts[-1]) / total
    lo, hi = edges[1], 1 - edges[1]
    if extreme >= 0.8:
        return (
            f"{extreme:.0%} of test messages score below {lo:.3f} or above {hi:.3f}, as the "
            "histogram shows, so the low ECE reflects strong separation on this corpus rather "
            "than a hard calibration problem solved. "
        )
    return (
        f"{extreme:.0%} of test messages score below {lo:.3f} or above {hi:.3f}; the rest "
        "spread across the range, where calibration is actually tested. "
    )


def _modality_sentence(report: dict[str, Any]) -> str:
    """What the ablation shows, computed rather than asserted."""
    rows = report.get("modality_ablation") or []
    p = float(report.get("dataset", {}).get("test_phish_rate", 0.5))
    err = {
        r["label"]: 1000 * ((1 - r["recall_phish"]) * p + r["false_positive_rate"] * (1 - p))
        for r in rows
    }
    fams = {r["label"]: len(r["families"]) for r in rows}
    if not err:
        return ""
    best = min(err, key=err.get)
    full = next((k for k, n in fams.items() if n == 3), None)
    singles = {k: v for k, v in err.items() if fams[k] == 1}
    pairs = {k: v for k, v in err.items() if fams[k] == 2}
    parts = []
    if singles and pairs:
        worst_single = max(singles, key=singles.get)
        ratio = singles[worst_single] / max(min(pairs.values()), 1e-9)
        parts.append(
            f"The weakest single family ({worst_single}) makes {singles[worst_single]:.1f} "
            f"errors per 1,000, {ratio:.1f} times the best pair"
        )
    if full is not None:
        if best == full:
            margin = min((v for k, v in err.items() if k != full), default=err[full]) - err[full]
            parts.append(
                f"all three together make the fewest ({err[full]:.1f}), "
                f"{margin:.1f} fewer than the next best"
            )
        else:
            parts.append(
                f"all three together make {err[full]:.1f}, not the fewest: "
                f"{best} makes {err[best]:.1f}"
            )
    return ("; ".join(parts) + ".") if parts else ""


def write_captions(report: dict[str, Any], out_dir: Path, written: dict[str, list[str]]) -> Path:
    present = {Path(p).stem for files in written.values() if isinstance(files, list) for p in files}
    lines = [
        "# Figures for the report",
        "",
        "Generated by `phishguard figures` from `artifacts/reports/evaluation.json`. "
        "Every number below is read from that file, so re-running the evaluation and "
        "this command keeps figures and captions in step.",
        "",
        "Insert the `.png` files into Word (they are 220 dpi at 6.5 in wide); use the "
        "`.svg` files for LaTeX or anywhere that scales.",
        "",
    ]
    n = 0
    for stem, title, text in captions(report):
        if stem not in present:
            continue
        n += 1
        lines += [
            f"## Figure {n} — {title}",
            "",
            f"File: `{stem}.png`",
            "",
            f"**Figure {n}.** {text}",
            "",
        ]
    path = out_dir / "CAPTIONS.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
