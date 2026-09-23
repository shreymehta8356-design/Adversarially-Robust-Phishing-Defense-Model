"""Load testing: the harness measures what it claims and counts failures honestly."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from phishguard.eval import loadtest


def test_in_process_load_test_reports_every_level_without_errors():
    from tests.helpers import corpus, trained_detector

    detector, settings = trained_detector()
    messages, _ = corpus()
    result = loadtest.run_in_process(
        detector, list(messages[:30]), settings=settings, concurrency=(1, 2), requests_per_level=12
    )
    assert result["mode"] == "in-process"
    assert [lvl["concurrency"] for lvl in result["levels"]] == [1, 2]
    for lvl in result["levels"]:
        assert lvl["requests"] == 12 and lvl["succeeded"] == 12 and lvl["errors"] == 0
        assert 0 < lvl["p50_ms"] <= lvl["p95_ms"] <= lvl["p99_ms"] <= lvl["max_ms"]
        assert lvl["throughput_per_s"] > 0
    assert result["summary"]["total_errors"] == 0
    assert "messages/s" in loadtest.render_markdown(result)


class _Handler(BaseHTTPRequestHandler):
    """Accepts every third request with 500, the rest with 200."""

    counter = 0
    lock = threading.Lock()

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        with _Handler.lock:
            _Handler.counter += 1
            fail = _Handler.counter % 3 == 0
        assert self.path == "/api/v1/scan" and self.headers["X-API-Key"] == "k"
        self.send_response(500 if fail else 200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):  # silence the test output
        pass


def test_http_load_test_counts_server_errors_instead_of_hiding_them():
    from tests.helpers import corpus

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        messages, _ = corpus()
        url = f"http://127.0.0.1:{server.server_address[1]}"
        result = loadtest.run_http(
            url, "k", list(messages[:5]), concurrency=(2,), requests_per_level=9
        )
    finally:
        server.shutdown()
    level = result["levels"][0]
    assert level["succeeded"] + level["errors"] == 9
    assert level["errors"] >= 2 and level["error_kinds"].get("RuntimeError") == level["errors"]
    assert result["summary"]["max_concurrency_within_budget"] == 0  # errors disqualify a level


def test_only_http_urls_are_accepted():
    try:
        loadtest.run_http("file:///etc/passwd", "k", [])
    except ValueError:
        pass
    else:
        raise AssertionError("a non-HTTP URL was accepted")


def test_multi_process_load_test_starts_real_workers_that_share_one_audit_store():
    """Each level spawns processes that load the model from the registry, as
    ``serve --workers N`` would, and every request is accounted for."""
    from phishguard.models.registry import save_detector
    from tests.helpers import corpus, trained_detector

    detector, settings = trained_detector()
    record = save_detector(detector, settings=settings, make_current=False)
    messages, _ = corpus()
    result = loadtest.run_multiprocess(
        list(messages[:6]),
        artifacts_dir=settings.artifacts_dir,
        model_version=record.version,
        processes=(1, 2),
        requests_per_process=4,
    )
    assert result["mode"] == "multi-process"
    assert [lvl["processes"] for lvl in result["levels"]] == [1, 2]
    for lvl in result["levels"]:
        assert lvl["requests"] == lvl["succeeded"] == 4 * lvl["processes"]
        assert lvl["errors"] == 0 and lvl["throughput_per_s"] > 0
    assert result["levels"][0]["speedup"] == 1.0
    assert "Server processes" in loadtest.render_markdown(result)


def test_scoring_slots_are_first_come_first_served():
    """Waiters are served in arrival order; an unfair semaphore let the
    releasing thread win again and pushed p99 past two seconds under load."""
    import time

    from phishguard.service.scanning import FairSlots

    slots = FairSlots(1)
    slots.acquire()
    order: list[int] = []
    threads = []
    for i in range(5):
        t = threading.Thread(target=lambda i=i: (slots.acquire(), order.append(i), slots.release()))
        t.start()
        threads.append(t)
        while slots.waiting < i + 1:  # make arrival order deterministic
            time.sleep(0.001)
    slots.release()
    for t in threads:
        t.join(timeout=5)
    assert order == [0, 1, 2, 3, 4]
    slots.acquire()  # the last release returned the slot to the pool
    slots.release()


def test_one_scoring_slot_serialises_scoring_without_losing_requests():
    import tempfile
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path

    from phishguard.service.scanning import ScanService
    from phishguard.service.store import DecisionStore
    from tests.helpers import scan_request, trained_detector

    detector, settings = trained_detector()
    service = ScanService(
        detector, DecisionStore(Path(tempfile.mkdtemp(prefix="pg-slots-")) / "audit.db"), settings
    )
    active, peak, lock = [0], [0], threading.Lock()
    original = detector.assess

    def counting_assess(*args, **kwargs):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            return original(*args, **kwargs)
        finally:
            with lock:
                active[0] -= 1

    detector.assess = counting_assess
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: service.scan(scan_request()), range(8)))
    finally:
        del detector.assess  # restore the class method on the shared detector
    assert len({r.decision_id for r in responses}) == 8
    assert peak[0] == 1
    assert all("wait.scoring" in r.stage_ms for r in responses)
