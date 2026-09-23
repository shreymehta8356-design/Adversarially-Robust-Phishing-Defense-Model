"""Request tracing: where did the time go, and which log lines belong together.

Logs say *what* happened and metrics say *how often*; a trace says *where the
time went inside one request*, stage by stage. That is the third leg of the
operational evidence the brief asks for, and it answers the question an
operator actually has when latency moves: which member got slower.

Deliberately small and dependency-free, like the metrics registry:

* **W3C Trace Context.** An incoming ``traceparent`` header is continued, so
  PhishGuard's spans join a mail gateway's own trace; otherwise a new trace is
  started. The response carries ``traceparent`` back, and the trace id is
  written to the audit record, the log line and the scan response, so one id
  finds a decision in all three.
* **Spans by stage.** Each ensemble member, the fusion and calibration step,
  evidence generation, the audit write and the queue update are spans.
  Evidence generation re-scores perturbed copies of the message; the member
  calls it makes are *counted into* the explanation span rather than recorded
  one by one, so a trace stays readable.
* **Three sinks.** A ``Server-Timing`` response header (browser developer tools
  draw it as a waterfall), a per-stage Prometheus histogram, and a small
  in-memory ring of recent traces behind an admin endpoint. An OpenTelemetry
  collector can be fed from the structured ``trace`` log line without adding
  a dependency to the container.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_TOKEN = re.compile(r"[^A-Za-z0-9_.-]")


@dataclass(slots=True)
class Span:
    name: str
    span_id: str
    parent_id: str | None
    start_ms: float
    duration_ms: float = 0.0
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Trace:
    trace_id: str
    root_span_id: str
    parent_span_id: str | None
    name: str
    started: float
    started_wall: float
    spans: list[Span] = field(default_factory=list)
    duration_ms: float = 0.0

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.started) * 1000.0


_CURRENT: ContextVar[Trace | None] = ContextVar("pg_trace", default=None)
_PARENT: ContextVar[str | None] = ContextVar("pg_span_parent", default=None)
_RECORD: ContextVar[bool] = ContextVar("pg_span_record", default=True)

#: The most recent finished traces, newest last. Bounded; never holds content.
RECENT: deque[dict[str, Any]] = deque(maxlen=50)
_RECENT_LOCK = threading.Lock()


def _span_id() -> str:
    return secrets.token_hex(8)


def parse_traceparent(header: str | None) -> tuple[str, str] | None:
    """``(trace_id, parent_span_id)`` from a valid W3C header, else ``None``."""
    if not header:
        return None
    m = _TRACEPARENT.match(header.strip().lower())
    if not m or m.group(1) == "0" * 32 or m.group(2) == "0" * 16:
        return None
    return m.group(1), m.group(2)


def current() -> Trace | None:
    return _CURRENT.get()


def current_trace_id() -> str:
    t = _CURRENT.get()
    return t.trace_id if t else ""


@contextmanager
def trace(name: str, *, traceparent: str | None = None) -> Iterator[Trace]:
    """Run the block inside a trace, continuing ``traceparent`` if valid.

    If a trace is already active this nests as a span instead, so library
    code can open a trace unconditionally and still compose.
    """
    active = _CURRENT.get()
    if active is not None:
        with span(name):
            yield active
        return
    incoming = parse_traceparent(traceparent)
    t = Trace(
        trace_id=incoming[0] if incoming else secrets.token_hex(16),
        root_span_id=_span_id(),
        parent_span_id=incoming[1] if incoming else None,
        name=name,
        started=time.perf_counter(),
        started_wall=time.time(),
    )
    token_t = _CURRENT.set(t)
    token_p = _PARENT.set(t.root_span_id)
    try:
        yield t
    finally:
        t.duration_ms = t.elapsed_ms()
        _PARENT.reset(token_p)
        _CURRENT.reset(token_t)
        _finish(t)


@contextmanager
def span(name: str, *, record_children: bool = True, **attrs: Any) -> Iterator[Span | None]:
    """Time one stage of the current trace. A no-op outside a trace."""
    t = _CURRENT.get()
    if t is None or not _RECORD.get():
        yield None
        return
    s = Span(
        name=name, span_id=_span_id(), parent_id=_PARENT.get(), start_ms=t.elapsed_ms(), attrs=attrs
    )
    token_p = _PARENT.set(s.span_id)
    token_r = _RECORD.set(record_children)
    try:
        yield s
    finally:
        s.duration_ms = t.elapsed_ms() - s.start_ms
        _RECORD.reset(token_r)
        _PARENT.reset(token_p)
        t.spans.append(s)


def stage_timings(t: Trace | None = None) -> dict[str, float]:
    """Total milliseconds per span name (a member called twice is summed)."""
    t = t or _CURRENT.get()
    if t is None:
        return {}
    out: dict[str, float] = {}
    for s in t.spans:
        out[s.name] = out.get(s.name, 0.0) + s.duration_ms
    return {k: round(v, 3) for k, v in out.items()}


def traceparent_header(t: Trace) -> str:
    return f"00-{t.trace_id}-{t.root_span_id}-01"


def server_timing_header(t: Trace, *, limit: int = 16) -> str:
    """``Server-Timing`` value: one entry per stage plus the total."""
    parts = [
        f"{_TOKEN.sub('_', name)};dur={ms:.2f}"
        for name, ms in list(stage_timings(t).items())[:limit]
    ]
    parts.append(f"total;dur={t.duration_ms or t.elapsed_ms():.2f}")
    return ", ".join(parts)


def summary(t: Trace) -> dict[str, Any]:
    return {
        "trace_id": t.trace_id,
        "name": t.name,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t.started_wall)),
        "duration_ms": round(t.duration_ms, 3),
        "parent_span_id": t.parent_span_id,
        "spans": [
            {
                "name": s.name,
                "span_id": s.span_id,
                "parent_id": s.parent_id,
                "start_ms": round(s.start_ms, 3),
                "duration_ms": round(s.duration_ms, 3),
                **({"attrs": s.attrs} if s.attrs else {}),
            }
            for s in sorted(t.spans, key=lambda s: s.start_ms)
        ],
    }


def recent(limit: int = 20) -> list[dict[str, Any]]:
    with _RECENT_LOCK:
        items = list(RECENT)[-limit:]
    return list(reversed(items))


def _finish(t: Trace) -> None:
    # Imported lazily: telemetry imports nothing from here, so there is no cycle.
    from phishguard.service import telemetry

    for name, ms in stage_timings(t).items():
        telemetry.STAGE_LATENCY.observe(ms, stage=name)
    if t.spans:
        with _RECENT_LOCK:
            RECENT.append(summary(t))
