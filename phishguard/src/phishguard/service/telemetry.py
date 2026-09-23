"""Structured logging and Prometheus metrics, with no extra dependencies.

Two deliberate choices.

**Structured JSON logs.** Every log line is one JSON object carrying a
``request_id``, so a decision can be traced end to end. No message content and
no mailbox address is ever logged: senders are pseudonymised with a salted
digest before they reach a log line, which is what makes "personal data must
not be committed" enforceable rather than aspirational.

**A small metrics registry rather than ``prometheus_client``.** The exposition
format is a few lines of text, the four metric types this service needs are
straightforward, and owning the ~120 lines removes a dependency from the
container. It implements counters, gauges and histograms with the standard
``_bucket``/``_sum``/``_count`` layout, so Prometheus and Grafana consume it
unchanged.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from typing import Any, Iterable

# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------
_LABEL_ESCAPES = str.maketrans({"\\": "\\\\", '"': '\\"', "\n": "\\n"})


def _fmt_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(
        f'{k}="{str(v).translate(_LABEL_ESCAPES)}"' for k, v in sorted(labels.items())
    )
    return "{" + inner + "}"


class _Metric:
    def __init__(self, name: str, help_text: str, mtype: str) -> None:
        self.name = name
        self.help = help_text
        self.type = mtype
        self._lock = threading.Lock()

    def _header(self) -> list[str]:
        return [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.type}"]


class Counter(_Metric):
    """Monotonically increasing count."""

    def __init__(self, name: str, help_text: str, labelnames: tuple[str, ...] = ()) -> None:
        super().__init__(name, help_text, "counter")
        self.labelnames = labelnames
        self._values: dict[tuple[str, ...], float] = {}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = tuple(str(labels.get(n, "")) for n in self.labelnames)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def render(self) -> list[str]:
        lines = self._header()
        with self._lock:
            items = list(self._values.items())
        if not items:
            lines.append(f"{self.name}{_fmt_labels({})} 0")
        for key, value in items:
            labels = dict(zip(self.labelnames, key, strict=True))
            lines.append(f"{self.name}{_fmt_labels(labels)} {value:g}")
        return lines


class Gauge(_Metric):
    """A value that can go up and down."""

    def __init__(self, name: str, help_text: str, labelnames: tuple[str, ...] = ()) -> None:
        super().__init__(name, help_text, "gauge")
        self.labelnames = labelnames
        self._values: dict[tuple[str, ...], float] = {}

    def set(self, value: float, **labels: str) -> None:
        key = tuple(str(labels.get(n, "")) for n in self.labelnames)
        with self._lock:
            self._values[key] = float(value)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = tuple(str(labels.get(n, "")) for n in self.labelnames)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def render(self) -> list[str]:
        lines = self._header()
        with self._lock:
            items = list(self._values.items())
        for key, value in items:
            labels = dict(zip(self.labelnames, key, strict=True))
            lines.append(f"{self.name}{_fmt_labels(labels)} {value:g}")
        return lines


class Histogram(_Metric):
    """Cumulative histogram in the Prometheus exposition layout."""

    DEFAULT_BUCKETS = (1, 2.5, 5, 10, 25, 50, 100, 150, 250, 500, 1000, 2500)

    def __init__(
        self,
        name: str,
        help_text: str,
        buckets: Iterable[float] = DEFAULT_BUCKETS,
        labelnames: tuple[str, ...] = (),
    ) -> None:
        super().__init__(name, help_text, "histogram")
        self.labelnames = labelnames
        self.buckets = tuple(sorted(float(b) for b in buckets))
        self._counts: dict[tuple[str, ...], list[int]] = {}
        self._sum: dict[tuple[str, ...], float] = {}
        self._total: dict[tuple[str, ...], int] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = tuple(str(labels.get(n, "")) for n in self.labelnames)
        with self._lock:
            counts = self._counts.setdefault(key, [0] * len(self.buckets))
            for i, edge in enumerate(self.buckets):
                if value <= edge:
                    counts[i] += 1
            self._sum[key] = self._sum.get(key, 0.0) + float(value)
            self._total[key] = self._total.get(key, 0) + 1

    def render(self) -> list[str]:
        lines = self._header()
        with self._lock:
            keys = list(self._counts.keys())
            snapshot = {
                k: (list(self._counts[k]), self._sum.get(k, 0.0), self._total.get(k, 0))
                for k in keys
            }
        for key, (counts, total_sum, total_count) in snapshot.items():
            labels = dict(zip(self.labelnames, key, strict=True))
            for edge, count in zip(self.buckets, counts, strict=True):
                lines.append(
                    f"{self.name}_bucket{_fmt_labels({**labels, 'le': f'{edge:g}'})} {count}"
                )
            lines.append(
                f"{self.name}_bucket{_fmt_labels({**labels, 'le': '+Inf'})} {total_count}"
            )
            lines.append(f"{self.name}_sum{_fmt_labels(labels)} {total_sum:g}")
            lines.append(f"{self.name}_count{_fmt_labels(labels)} {total_count}")
        return lines


class Registry:
    """Holds the service's metrics and renders the exposition text."""

    def __init__(self) -> None:
        self._metrics: list[_Metric] = []

    def register(self, metric: _Metric) -> Any:
        self._metrics.append(metric)
        return metric

    def render(self) -> str:
        chunks: list[str] = []
        for metric in self._metrics:
            chunks.extend(metric.render())  # type: ignore[attr-defined]
        return "\n".join(chunks) + "\n"


REGISTRY = Registry()

# --- service metrics ------------------------------------------------------
REQUESTS = REGISTRY.register(
    Counter("phishguard_requests_total", "HTTP requests handled",
            ("endpoint", "method", "status"))
)
REQUEST_LATENCY = REGISTRY.register(
    Histogram("phishguard_request_duration_ms", "End-to-end request latency (ms)",
              labelnames=("endpoint",))
)
SCANS = REGISTRY.register(
    Counter("phishguard_scans_total", "Messages assessed", ("band",))
)
SCAN_LATENCY = REGISTRY.register(
    Histogram("phishguard_scan_duration_ms", "Model assessment latency (ms)")
)
SCORE_HISTOGRAM = REGISTRY.register(
    Histogram(
        "phishguard_score", "Distribution of assessed phishing probability",
        buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 1.0),
    )
)
FEEDBACK = REGISTRY.register(
    Counter("phishguard_feedback_total", "Analyst feedback recorded", ("label",))
)
AUTH_FAILURES = REGISTRY.register(
    Counter("phishguard_auth_failures_total", "Rejected requests", ("reason",))
)
RATE_LIMITED = REGISTRY.register(
    Counter("phishguard_rate_limited_total", "Requests rejected by the rate limiter")
)
MODEL_INFO = REGISTRY.register(
    Gauge("phishguard_model_info", "1 for the loaded model version",
          ("model_version", "calibration"))
)
BEHAVIORAL_CONTEXT = REGISTRY.register(
    Counter("phishguard_behavioral_context_total",
            "Whether callers supplied behavioural context", ("available",))
)
ADVERSARIAL_PROBES = REGISTRY.register(
    Counter("phishguard_adversarial_probes_total", "Adversarial probes run", ("evaded",))
)
UPTIME = REGISTRY.register(
    Gauge("phishguard_uptime_seconds", "Seconds since the service started")
)

_STARTED_AT = time.time()


def render_metrics() -> str:
    UPTIME.set(time.time() - _STARTED_AT)
    return REGISTRY.render()


def uptime_seconds() -> float:
    return time.time() - _STARTED_AT


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
_REDACT_KEYS = {
    "body", "html_body", "subject", "sender", "reply_to", "to", "return_path",
    "password", "api_key", "authorization", "x-api-key", "token", "secret",
}


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with reserved fields promoted to the top level."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in getattr(record, "extra_fields", {}).items():
            if key.lower() in _REDACT_KEYS:
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = (
            f"{time.strftime('%H:%M:%S', time.gmtime(record.created))} "
            f"{record.levelname:<7} {record.name}: {record.getMessage()}"
        )
        extra = getattr(record, "extra_fields", {})
        if extra:
            base += "  " + " ".join(
                f"{k}={v}" for k, v in extra.items() if k.lower() not in _REDACT_KEYS
            )
        return base


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Install the root handler. Safe to call more than once."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # uvicorn's own access log would duplicate ours, in a different format.
    logging.getLogger("uvicorn.access").disabled = True


def log_event(
    logger: logging.Logger, level: int, message: str, /, **fields: Any
) -> None:
    """Log with structured fields, dropping anything that could carry content."""
    safe = {k: v for k, v in fields.items() if k.lower() not in _REDACT_KEYS}
    logger.log(level, message, extra={"extra_fields": safe})
