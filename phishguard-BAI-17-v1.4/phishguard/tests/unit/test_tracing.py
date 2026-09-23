"""Request tracing: W3C trace context, per-stage spans, and one id everywhere."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from phishguard.service import tracing


def test_a_valid_traceparent_is_continued_and_invalid_ones_are_ignored():
    tid, pid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
    assert tracing.parse_traceparent(f"00-{tid}-{pid}-01") == (tid, pid)
    for bad in (
        None,
        "",
        "garbage",
        f"01-{tid}-{pid}-01",
        f"00-{tid[:-1]}-{pid}-01",
        f"00-{'0' * 32}-{pid}-01",
        f"00-{tid}-{'0' * 16}-01",
    ):
        assert tracing.parse_traceparent(bad) is None
    with tracing.trace("req", traceparent=f"00-{tid}-{pid}-01") as t:
        assert t.trace_id == tid and t.parent_span_id == pid
    assert re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01", tracing.traceparent_header(t))


def test_spans_nest_sum_by_name_and_collapse_inside_explanations():
    with tracing.trace("req") as t:
        with tracing.span("member.a"):
            pass
        with tracing.span("member.a"):
            pass
        with tracing.span("explain", record_children=False):
            with tracing.span("member.b"):  # counted into explain, not listed
                pass
        with tracing.span("outer") as outer:
            with tracing.span("inner") as inner:
                pass
    names = [s.name for s in t.spans]
    assert names.count("member.a") == 2 and "member.b" not in names
    assert inner.parent_id == outer.span_id and outer.parent_id == t.root_span_id
    timings = tracing.stage_timings(t)
    assert set(timings) == {"member.a", "explain", "outer", "inner"}
    header = tracing.server_timing_header(t)
    assert header.endswith(re.search(r"total;dur=[0-9.]+$", header).group(0))
    assert all(
        re.fullmatch(r"[A-Za-z0-9_.-]+;dur=[0-9.]+", part.strip()) for part in header.split(",")
    )


def test_a_nested_trace_joins_the_outer_one():
    with tracing.trace("http") as outer:
        with tracing.trace("scan") as inner:
            assert inner is outer
    assert [s.name for s in outer.spans] == ["scan"]


def test_spans_outside_a_trace_are_free_no_ops():
    with tracing.span("nothing") as s:
        assert s is None
    assert tracing.current_trace_id() == ""


def test_one_trace_id_on_the_response_the_audit_record_and_the_stage_timings():
    from phishguard.service.scanning import ScanService
    from phishguard.service.store import DecisionStore
    from tests.helpers import scan_request, trained_detector

    detector, settings = trained_detector()
    store = DecisionStore(Path(tempfile.mkdtemp(prefix="pg-trace-")) / "audit.db")
    service = ScanService(detector, store, settings)
    response = service.scan(scan_request())
    assert re.fullmatch(r"[0-9a-f]{32}", response.trace_id)
    assert store.get_decision(response.decision_id)["trace_id"] == response.trace_id
    stages = response.stage_ms
    for name in detector.member_names:
        assert f"member.{name}" in stages
    assert {"assess", "fusion", "explain", "audit.write"} <= set(stages)
    assert all(v >= 0 for v in stages.values())


def test_recent_traces_are_bounded_and_carry_no_message_content():
    from phishguard.service.scanning import ScanService
    from phishguard.service.store import DecisionStore
    from tests.helpers import scan_request, trained_detector

    detector, settings = trained_detector()
    service = ScanService(
        detector, DecisionStore(Path(tempfile.mkdtemp(prefix="pg-trace-")) / "audit.db"), settings
    )
    secret_subject = "Quarterly bonus letter for R. Kapoor"
    for _ in range(3):
        service.scan(scan_request(subject=secret_subject))
    assert len(tracing.RECENT) <= tracing.RECENT.maxlen
    dumped = json.dumps(tracing.recent(5))
    assert secret_subject not in dumped and "Kapoor" not in dumped


def test_stage_latency_is_exported_as_a_prometheus_histogram():
    from phishguard.service import telemetry

    with tracing.trace("req"):
        with tracing.span("fusion"):
            pass
    lines = telemetry.render_metrics().splitlines()
    assert any(
        line.startswith("phishguard_stage_duration_ms_bucket{") and 'stage="fusion"' in line
        for line in lines
    )
    assert any(
        line.startswith("phishguard_stage_duration_ms_count{") and 'stage="fusion"' in line
        for line in lines
    )


def test_serving_threads_limit_openmp_and_the_main_thread_is_left_alone():
    """Load testing found worker-thread inference ~3x slower from idle OpenMP
    teams; serving threads are limited to one OpenMP thread, training is not."""
    import threading

    from phishguard import runtime

    assert runtime.limit_native_threads_for_serving() is False  # main thread
    result: dict[str, object] = {}

    def worker() -> None:
        result["limited"] = runtime.limit_native_threads_for_serving()
        result["again"] = runtime.limit_native_threads_for_serving()  # idempotent
        try:
            from threadpoolctl import threadpool_info

            result["openmp"] = [
                i["num_threads"] for i in threadpool_info() if i.get("user_api") == "openmp"
            ]
        except ImportError:
            result["openmp"] = []

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert result["limited"] == result["again"]
    if result["limited"]:
        assert all(n == 1 for n in result["openmp"])
