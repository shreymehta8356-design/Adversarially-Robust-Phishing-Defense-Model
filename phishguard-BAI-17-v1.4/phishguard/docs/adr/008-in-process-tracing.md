# ADR-008: In-process request tracing with W3C Trace Context, no collector required

- **Status**: Accepted
- **Date**: 2026-09-22
- **Deciders**: Capstone team (BAI-17)

## Context

The acceptance gates ask for operational evidence: logs, metrics, **traces**
and model monitoring. Logs and metrics already existed. What was missing was
the answer to "where did the time go in *this* slow request?" — the question
the p95 latency gate (G7) eventually forces someone to ask.

The mail gateway assesses inline. If assessment slows down, mail queues. The
pipeline has distinct stages — canonicalisation and features, four members,
fusion and calibration, explanation, the audit write, opening a review case —
and a latency histogram over the whole request cannot say which one regressed.

Two constraints shape the choice. The system must run on a clean laptop and in
an air-gapped container with no extra services (docs/01 §1.8, Portability).
And the trace must be joinable with the caller's: the gateway, not PhishGuard,
is where an incident investigation starts.

## Decision

Tracing is implemented in-process in `service/tracing.py`:

- The **W3C Trace Context** `traceparent` header is honoured if the caller sends
  one and started if not; the trace id is returned in `traceparent`, recorded on
  the audit row and written to the log line.
- Spans are recorded with `contextvars` around each pipeline stage (`assess`,
  `member.*`, `fusion`, `explain`, `audit.write`, `queue.open`). They cost
  microseconds and record timings only — never content.
- Stage timings are returned in the standard `Server-Timing` header and as
  `stage_ms` in the scan response, exported as the
  `phishguard_stage_duration_ms` histogram, and the last 50 traces are
  available to administrators at `GET /api/v1/traces/recent`.

## Alternatives considered

### OpenTelemetry SDK with an OTLP exporter and a collector (Jaeger, Tempo)

The industry standard, and the right answer in a platform that already runs a
collector. Rejected as the default because it adds at least one service to the
deployment and several dependencies to the install, and a trace nobody can
view without a collector does not help the person running `python start.py` on
a laptop. Because the wire format is the same W3C header, adopting the SDK later
is an exporter behind the existing span API, not a redesign.

### Metrics only: one histogram per stage

Cheaper still, and it answers "which stage is slow on average". Rejected on its
own because averages hide the request an operator is actually looking at; the
per-request view (headers, response field, recent traces) is what connects a
slow audit record or a gateway complaint to its cause. The histogram is kept
alongside it.

### Profiling in production

A sampling profiler gives more detail than spans. Rejected for the serving
path: it is an operational tool to reach for after a trace has located the
stage, not a signal to leave running.

## Consequences

The traces paid for themselves before release. The load test showed scoring in
a server worker thread taking about three times as long as on the main thread;
the stage timings put the entire difference in the two stages that use OpenMP.
Limiting OpenMP to one thread per serving thread (`runtime.py`) took
single-worker p50 from 36.6 ms to 11.7 ms and throughput from 27 to 84 messages
a second on a 2-core machine (docs/07 §7.14). Without per-stage timings that
would have looked like "the model is slow".

## When to revisit

When PhishGuard is deployed next to an existing OpenTelemetry collector, add
the OTLP exporter and keep the in-process ring buffer for air-gapped installs.
