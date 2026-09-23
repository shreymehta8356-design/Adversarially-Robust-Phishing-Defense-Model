"""Load and resource measurement: how the service behaves when it is busy.

Single-message latency says how fast one request is on an idle machine. A mail
gateway is never idle: messages arrive in bursts, several at once. This module
drives the real request path -- validation, assessment, evidence, the audit
write and the review queue -- at increasing concurrency and records, for each
level, throughput, the latency distribution, errors and the process's peak
memory. It answers two questions the single-message number cannot:

* **Where does it saturate?** Throughput stops rising when every worker is
  busy; beyond that point, extra concurrency only lengthens the queue and the
  p95 climbs. The level at which p95 crosses the latency budget is the
  headroom figure a deployment is sized from.
* **Does it fail under load, or only slow down?** Errors are counted
  separately from latency. A service that starts returning 500s at eight
  concurrent requests has a different problem from one that queues them.

Two modes. **In-process** calls ``ScanService`` directly from a thread pool --
the whole decision path without an HTTP server, reproducible anywhere. **HTTP**
sends the same requests to a running service with the standard library alone,
which adds the web framework, JSON and the network to the measurement.

Scoring is CPU-bound Python and NumPy, so in-process throughput is bounded by
the interpreter lock and the core count; the results say so rather than
presenting thread count as if it were parallelism.

A third mode, **multi-process**, answers the capacity-planning question that
follows: does adding server processes (``phishguard serve --workers N``) add
throughput? Each process loads the model from the registry, all of them share
one audit database (SQLite in WAL mode, as a multi-worker deployment would),
and they start together on a signal, so the measurement is of processes
competing for the same cores and the same database, not of start-up time.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

#: Seconds a worker process may take to load the model before the run is abandoned.
_READY_TIMEOUT_S = 300.0


def peak_rss_mb() -> float | None:
    """Peak resident memory of this process, where the platform can say."""
    try:
        import resource  # POSIX: the kernel's own high-water mark

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports kilobytes, macOS bytes.
        return round(peak / (2**20 if sys.platform == "darwin" else 2**10), 1)
    except Exception:  # noqa: BLE001, S110 - not available on Windows
        pass
    try:
        import psutil  # optional; on Windows it exposes the peak working set

        info = psutil.Process().memory_info()
        return round(getattr(info, "peak_wset", info.rss) / 2**20, 1)
    except Exception:  # noqa: BLE001 - optional dependency
        return None


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return ordered[int(k)]


def _level(call, payloads: list[Any], concurrency: int, n_requests: int) -> dict[str, Any]:
    """Run ``n_requests`` calls with ``concurrency`` workers."""
    latencies: list[float] = []
    errors: dict[str, int] = {}
    lock = threading.Lock()

    def one(i: int) -> None:
        payload = payloads[i % len(payloads)]
        t0 = time.perf_counter()
        try:
            call(payload)
        except Exception as exc:  # noqa: BLE001 - counted, not raised
            with lock:
                key = type(exc).__name__
                errors[key] = errors.get(key, 0) + 1
            return
        elapsed = (time.perf_counter() - t0) * 1000.0
        with lock:
            latencies.append(elapsed)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(one, range(n_requests)))
    wall = time.perf_counter() - started
    return {
        "concurrency": concurrency,
        "requests": n_requests,
        "succeeded": len(latencies),
        "errors": sum(errors.values()),
        "error_kinds": errors,
        "seconds": round(wall, 3),
        "throughput_per_s": round(len(latencies) / wall, 1) if wall else 0.0,
        "mean_ms": round(statistics.fmean(latencies), 2) if latencies else 0.0,
        "p50_ms": round(_percentile(latencies, 0.50), 2),
        "p95_ms": round(_percentile(latencies, 0.95), 2),
        "p99_ms": round(_percentile(latencies, 0.99), 2),
        "max_ms": round(max(latencies), 2) if latencies else 0.0,
    }


def _summarise(levels: list[dict[str, Any]], budget_ms: float) -> dict[str, Any]:
    best = max(levels, key=lambda r: r["throughput_per_s"]) if levels else None
    within = [r for r in levels if r["p95_ms"] <= budget_ms and r["errors"] == 0]
    return {
        "peak_throughput_per_s": best["throughput_per_s"] if best else 0.0,
        "peak_throughput_concurrency": best["concurrency"] if best else 0,
        "max_concurrency_within_budget": max((r["concurrency"] for r in within), default=0),
        "total_errors": sum(r["errors"] for r in levels),
        "latency_budget_ms": budget_ms,
    }


def run_in_process(
    detector: Any,
    messages: list[Any],
    *,
    settings: Any | None = None,
    concurrency: tuple[int, ...] = (1, 2, 4, 8),
    requests_per_level: int = 200,
    explain: bool = True,
    budget_ms: float = 150.0,
) -> dict[str, Any]:
    """Drive ``ScanService.scan`` -- the whole decision path -- from a thread pool."""
    from phishguard.service.contracts import ScanRequest
    from phishguard.service.scanning import ScanService
    from phishguard.service.security import Principal
    from phishguard.service.store import DecisionStore

    settings = settings or detector.settings
    # A throwaway audit store: the writes are part of what is being measured,
    # but they must not land in the real audit trail.
    store = DecisionStore(Path(tempfile.mkdtemp(prefix="pg-load-")) / "audit.db")
    service = ScanService(detector, store, settings)
    principal = Principal(key_id="key_loadtest", role="analyst")
    payloads = [ScanRequest.from_message(m, client_reference="loadtest") for m in messages]

    def call(req: Any) -> None:
        service.scan(req, principal=principal, explain=explain)

    # Warm the caches once, outside the measurement -- in a pool thread, like
    # every measured call, so the main thread's native thread pools are left
    # exactly as training expects them.
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(call, payloads[0]).result()
    levels = [_level(call, payloads, c, requests_per_level) for c in concurrency]
    store.close()
    return {
        "mode": "in-process",
        "explain": explain,
        "cpu_count": os.cpu_count(),
        "peak_rss_mb": peak_rss_mb(),
        "levels": levels,
        "summary": _summarise(levels, budget_ms),
        "note": (
            "ScanService called directly from a thread pool: the full decision path "
            "including the audit write and the review queue, without the web framework. "
            "Scoring is CPU-bound, so one process serves requests one at a time in order of "
            "arrival (PG_SCORING_CONCURRENCY=1): extra concurrency lengthens the wait, not "
            "the work. More throughput comes from more processes "
            "('phishguard serve --workers N'), up to the number of cores."
        ),
    }


def _process_worker(
    artifacts_dir: str,
    model_version: str | None,
    db_path: str,
    bodies: list[str],
    n_requests: int,
    explain: bool,
    ready: Any,
    start: Any,
    results: Any,
) -> None:  # pragma: no cover - child process
    """One server-like process: load the model, wait for the start signal, then
    handle ``n_requests`` messages one at a time, as a single worker would."""
    try:
        from phishguard.config import Settings
        from phishguard.models.registry import load_detector
        from phishguard.runtime import limit_native_threads_for_serving
        from phishguard.service.contracts import ScanRequest
        from phishguard.service.scanning import ScanService
        from phishguard.service.security import Principal
        from phishguard.service.store import DecisionStore

        settings = Settings(artifacts_dir=Path(artifacts_dir))
        detector, _ = load_detector(model_version, settings=settings)
        service = ScanService(detector, DecisionStore(Path(db_path)), settings)
        principal = Principal(key_id="key_loadtest", role="analyst")
        payloads = [ScanRequest.model_validate_json(b) for b in bodies]
        # Requests run on a pool thread, as they do in the API server (which
        # runs synchronous endpoints in a thread pool). That matters: the
        # serving-thread OpenMP limit applies to pool threads only, and without
        # it two processes on two cores oversubscribe the CPU with spinning
        # OpenMP threads -- p95 went from 18 ms to 6.9 s when this was wrong.
        pool = ThreadPoolExecutor(max_workers=1)

        def scan(req: Any) -> None:
            limit_native_threads_for_serving()
            service.scan(req, principal=principal, explain=explain)

        pool.submit(scan, payloads[0]).result()  # warm caches, set the limit
        ready.put(("ready", os.getpid()))
    except Exception as exc:  # noqa: BLE001 - reported to the parent, not raised
        ready.put(("error", f"{type(exc).__name__}: {exc}"))
        return
    start.wait()
    latencies: list[float] = []
    errors: dict[str, int] = {}
    for i in range(n_requests):
        t0 = time.perf_counter()
        try:
            pool.submit(scan, payloads[i % len(payloads)]).result()
        except Exception as exc:  # noqa: BLE001 - counted, not raised
            errors[type(exc).__name__] = errors.get(type(exc).__name__, 0) + 1
            continue
        latencies.append((time.perf_counter() - t0) * 1000.0)
    pool.shutdown()
    results.put({"latencies": latencies, "errors": errors, "finished": time.time()})


def run_multiprocess(
    messages: list[Any],
    *,
    artifacts_dir: Path,
    model_version: str | None = None,
    processes: tuple[int, ...] = (1, 2),
    requests_per_process: int = 150,
    explain: bool = True,
    budget_ms: float = 150.0,
) -> dict[str, Any]:
    """Throughput with 1, 2, ... server processes sharing one audit database.

    Each level starts fresh processes (spawned, as on Windows), waits until every
    one has loaded the model and warmed up, then releases them together. The
    wall clock runs from that signal until the last process finishes.
    """
    import multiprocessing as mp

    from phishguard.service.contracts import ScanRequest

    ctx = mp.get_context("spawn")
    bodies = [
        ScanRequest.from_message(m, client_reference="loadtest").model_dump_json() for m in messages
    ]
    levels: list[dict[str, Any]] = []
    for n_proc in processes:
        db_path = Path(tempfile.mkdtemp(prefix="pg-load-mp-")) / "audit.db"
        ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
        workers = [
            ctx.Process(
                target=_process_worker,
                daemon=True,
                args=(
                    str(artifacts_dir),
                    model_version,
                    str(db_path),
                    bodies,
                    requests_per_process,
                    explain,
                    ready,
                    start,
                    results,
                ),
            )
            for _ in range(n_proc)
        ]
        for w in workers:
            w.start()
        try:
            for _ in workers:
                status, detail = ready.get(timeout=_READY_TIMEOUT_S)
                if status != "ready":
                    raise RuntimeError(f"a load-test worker failed to start: {detail}")
            started = time.time()
            start.set()
            outcomes = [
                results.get(timeout=_READY_TIMEOUT_S + 60 * requests_per_process) for _ in workers
            ]
        finally:
            for w in workers:
                w.join(timeout=30)
                if w.is_alive():
                    w.terminate()
        wall = max(o["finished"] for o in outcomes) - started
        latencies = [x for o in outcomes for x in o["latencies"]]
        errors: dict[str, int] = {}
        for o in outcomes:
            for k, v in o["errors"].items():
                errors[k] = errors.get(k, 0) + v
        levels.append(
            {
                "processes": n_proc,
                "concurrency": n_proc,
                "requests": n_proc * requests_per_process,
                "succeeded": len(latencies),
                "errors": sum(errors.values()),
                "error_kinds": errors,
                "seconds": round(wall, 3),
                "throughput_per_s": round(len(latencies) / wall, 1) if wall > 0 else 0.0,
                "mean_ms": round(statistics.fmean(latencies), 2) if latencies else 0.0,
                "p50_ms": round(_percentile(latencies, 0.50), 2),
                "p95_ms": round(_percentile(latencies, 0.95), 2),
                "p99_ms": round(_percentile(latencies, 0.99), 2),
                "max_ms": round(max(latencies), 2) if latencies else 0.0,
            }
        )
    base = levels[0]["throughput_per_s"] if levels and levels[0]["throughput_per_s"] else None
    for lv in levels:
        lv["speedup"] = round(lv["throughput_per_s"] / base, 2) if base else None
    return {
        "mode": "multi-process",
        "explain": explain,
        "cpu_count": os.cpu_count(),
        "levels": levels,
        "summary": _summarise(levels, budget_ms),
        "note": (
            "Each process is one server worker handling one request at a time, all sharing "
            "one SQLite audit database in WAL mode. Speed-up is throughput relative to one "
            "process; it is bounded by the number of CPU cores."
        ),
    }


def run_http(
    url: str,
    api_key: str,
    messages: list[Any],
    *,
    concurrency: tuple[int, ...] = (1, 2, 4, 8),
    requests_per_level: int = 200,
    budget_ms: float = 150.0,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Send the same requests to a running service over HTTP (standard library only)."""
    from phishguard.service.contracts import ScanRequest

    endpoint = url.rstrip("/") + "/api/v1/scan"
    if not endpoint.startswith(("http://", "https://")):
        raise ValueError("the URL must start with http:// or https://")
    bodies = [
        ScanRequest.from_message(m, client_reference="loadtest").model_dump_json().encode()
        for m in messages
    ]

    def call(body: bytes) -> None:
        req = urllib.request.Request(  # noqa: S310 - scheme checked above
            endpoint,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code}") from exc

    call(bodies[0])
    levels = [_level(call, bodies, c, requests_per_level) for c in concurrency]
    return {
        "mode": "http",
        "url": endpoint,
        "cpu_count": os.cpu_count(),
        "levels": levels,
        "summary": _summarise(levels, budget_ms),
        "note": (
            "Measured end to end through the web framework and the network. The "
            "service's own memory is not visible from here; read it from the "
            "container or process monitor."
        ),
    }


def render_markdown(result: dict[str, Any]) -> str:
    s = result["summary"]
    lines = [
        f"Mode: **{result['mode']}**"
        + (
            f", explanations {'on' if result.get('explain') else 'off'}"
            if "explain" in result
            else ""
        )
        + f"; {result.get('cpu_count')} CPU cores"
        + (f"; peak memory {result['peak_rss_mb']} MB" if result.get("peak_rss_mb") else "")
        + ".\n",
    ]
    if result["mode"] == "multi-process":
        lines += [
            "| Server processes | Throughput / s | Speed-up | p50 ms | p95 ms | p99 ms | Errors |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in result["levels"]:
            lines.append(
                f"| {r['processes']} | {r['throughput_per_s']:.1f} | {r.get('speedup') or 0:.2f}x | "
                f"{r['p50_ms']:.1f} | {r['p95_ms']:.1f} | {r['p99_ms']:.1f} | {r['errors']} |"
            )
    else:
        lines += [
            "| Concurrent requests | Throughput / s | p50 ms | p95 ms | p99 ms | Errors |",
            "|---|---|---|---|---|---|",
        ]
        for r in result["levels"]:
            lines.append(
                f"| {r['concurrency']} | {r['throughput_per_s']:.1f} | {r['p50_ms']:.1f} | "
                f"{r['p95_ms']:.1f} | {r['p99_ms']:.1f} | {r['errors']} |"
            )
    lines.append("")
    unit = "server process" if result["mode"] == "multi-process" else "concurrent request"

    def reqs(n: int) -> str:
        return f"{n} {unit}{'' if n == 1 else 'es' if unit.endswith('ss') else 's'}"

    lines.append(
        f"Peak throughput **{s['peak_throughput_per_s']:.1f} messages/s** at "
        f"{reqs(s['peak_throughput_concurrency'])}; p95 stays within the "
        f"{s['latency_budget_ms']:.0f} ms budget up to **{reqs(s['max_concurrency_within_budget'])}**; "
        f"{s['total_errors']} errors across all levels. {result['note']}\n"
    )
    return "\n".join(lines)


def write(result: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = "loadtest-processes.json" if result.get("mode") == "multi-process" else "loadtest.json"
    path = out_dir / name
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path
