"""Error analysis and subgroup slicing.

An aggregate macro F1 hides exactly the failures that matter. This module
answers three questions the brief demands and an examiner will ask:

1. **Where does it fail?** Per-lure-type and per-difficulty slices, so that
   "0.99 overall" is decomposed into the cases that are easy and the cases that
   are not.
2. **How does it fail?** Errors are bucketed into named categories with the
   evidence that produced them, rather than listed as anonymous row indices.
3. **Does it fail unevenly?** Subgroup metrics across message properties the
   system did not train on directly - message length, presence of links,
   whether behavioral context was available - which is where a model that has
   learned a shortcut shows itself.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np

from phishguard.eval.metrics import prf
from phishguard.schemas import EmailMessage


def slice_metrics(
    messages: list[EmailMessage],
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    threshold: float = 0.5,
    min_size: int = 8,
) -> dict[str, list[dict[str, Any]]]:
    """Metrics broken out by several message properties."""
    y_true = np.asarray(y_true).astype(int)
    pred = (np.asarray(scores) >= threshold).astype(int)

    def _bucket(name: str, keys: list[str]) -> list[dict[str, Any]]:
        groups: dict[str, list[int]] = defaultdict(list)
        for i, k in enumerate(keys):
            groups[k].append(i)
        rows: list[dict[str, Any]] = []
        for key, idx in groups.items():
            if len(idx) < min_size:
                continue
            sel = np.asarray(idx)
            stats = prf(y_true[sel], pred[sel])
            rows.append(
                {
                    "slice": name,
                    "value": key,
                    "n": len(idx),
                    "positive_rate": round(float(y_true[sel].mean()), 4),
                    "accuracy": stats["accuracy"],
                    "macro_f1": stats["macro_f1"],
                    "recall_phish": stats["recall_phish"],
                    "false_positive_rate": stats["false_positive_rate"],
                    "errors": int(stats["fp"] + stats["fn"]),
                }
            )
        rows.sort(key=lambda r: (r["macro_f1"], -r["n"]))
        return rows

    lure = [m.source.split(":", 1)[-1] or "unknown" for m in messages]
    has_links = [
        "with links" if ("http" in m.body.lower() or "http" in m.html_body.lower()) else "no links"
        for m in messages
    ]
    context = [
        "behavioural context" if m.behavioral.available else "no behavioural context"
        for m in messages
    ]
    length = []
    for m in messages:
        n = len(m.body)
        length.append(
            "short (<250)" if n < 250 else ("medium (250-800)" if n < 800 else "long (800+)")
        )
    html = ["html part" if m.html_body.strip() else "text only" for m in messages]
    attach = ["with attachment" if m.attachments else "no attachment" for m in messages]
    auth = [
        "auth all pass"
        if (m.auth.spf, m.auth.dkim, m.auth.dmarc) == ("pass", "pass", "pass")
        else "auth imperfect"
        for m in messages
    ]

    return {
        "lure_type": _bucket("lure_type", lure),
        "links": _bucket("links", has_links),
        "behavioural_context": _bucket("behavioural_context", context),
        "body_length": _bucket("body_length", length),
        "html": _bucket("html", html),
        "attachments": _bucket("attachments", attach),
        "authentication": _bucket("authentication", auth),
    }


#: Named failure modes. Order matters: the first matching rule wins, so the
#: more specific diagnoses come first.
def classify_error(
    message: EmailMessage, y_true: int, score: float, *, threshold: float = 0.5
) -> str:
    """Give a failure a name an engineer can act on."""
    from phishguard.features.urls import extract_links

    links = extract_links(message.body, message.html_body)
    kind = message.source.split(":", 1)[-1]
    predicted_phish = score >= threshold

    if y_true == 1 and not predicted_phish:
        if kind == "clone":
            return "missed: cloned legitimate template, signal is header/URL only"
        if kind in {"bec_ceo", "vendor_swap"}:
            return "missed: business email compromise, no link and no lexical tells"
        if kind == "thread_hijack":
            return "missed: thread hijack inside an existing conversation"
        if not links:
            return "missed: no link to analyse, text-only lure"
        if message.behavioral.prior_messages_from_sender > 5:
            return "missed: sender has correspondence history"
        if (message.auth.spf, message.auth.dkim, message.auth.dmarc) == ("pass", "pass", "pass"):
            return "missed: fully authenticated attacker-owned domain"
        return "missed: other"

    if y_true == 0 and predicted_phish:
        if kind == "suspicious_ham":
            return "false alarm: legitimate marketing with phishing-shaped surface"
        if kind.startswith("real_"):
            return "false alarm: genuine transactional mail using security vocabulary"
        if any("bit.ly" in h or "tinyurl" in h for h, _ in links):
            return "false alarm: legitimate use of a link shortener"
        if message.behavioral.sender_first_seen:
            return "false alarm: unknown but legitimate sender"
        if message.behavioral.domain_age_days < 90:
            return "false alarm: young but legitimate domain"
        return "false alarm: other"
    return "correct"


def error_report(
    messages: list[EmailMessage],
    y_true: np.ndarray,
    scores: np.ndarray,
    *,
    threshold: float = 0.5,
    max_examples: int = 12,
) -> dict[str, Any]:
    """Categorised errors plus the worst individual cases."""
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=np.float64)
    pred = (scores >= threshold).astype(int)
    wrong = np.flatnonzero(pred != y_true)

    categories: dict[str, int] = defaultdict(int)
    examples: list[dict[str, Any]] = []
    for i in wrong:
        cat = classify_error(
            messages[int(i)], int(y_true[i]), float(scores[i]), threshold=threshold
        )
        categories[cat] += 1
        examples.append(
            {
                "index": int(i),
                "category": cat,
                "true_label": int(y_true[i]),
                "score": round(float(scores[i]), 5),
                # Confidence in the wrong direction: how badly it was wrong.
                "severity": round(abs(float(scores[i]) - threshold), 5),
                "lure_type": messages[int(i)].source.split(":", 1)[-1],
                "subject": messages[int(i)].subject[:120],
                "sender_domain": messages[int(i)].sender_domain,
            }
        )
    examples.sort(key=lambda e: -e["severity"])

    return {
        "n_errors": int(wrong.size),
        "error_rate": round(float(wrong.size / max(y_true.size, 1)), 5),
        "categories": [
            {"category": k, "count": v}
            for k, v in sorted(categories.items(), key=lambda kv: -kv[1])
        ],
        "worst_examples": examples[:max_examples],
    }


def confidence_profile(
    y_true: np.ndarray, scores: np.ndarray, *, n_bins: int = 10
) -> list[dict[str, Any]]:
    """Accuracy as a function of confidence.

    A well-behaved model is most accurate where it is most confident. A flat or
    inverted profile means the score cannot be used for triage, whatever the
    aggregate metrics say.
    """
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=np.float64)
    confidence = np.abs(scores - 0.5) * 2.0
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(confidence, edges[1:-1]), 0, n_bins - 1)
    pred = (scores >= 0.5).astype(int)
    rows: list[dict[str, Any]] = []
    for b in range(n_bins):
        mask = idx == b
        n = int(mask.sum())
        rows.append(
            {
                "confidence_lower": round(float(edges[b]), 3),
                "confidence_upper": round(float(edges[b + 1]), 3),
                "count": n,
                "accuracy": round(float((pred[mask] == y_true[mask]).mean()), 5) if n else 0.0,
            }
        )
    return rows
