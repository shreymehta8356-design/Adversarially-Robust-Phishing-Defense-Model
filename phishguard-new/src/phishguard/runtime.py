"""Native thread-pool hygiene for the serving path.

Found by the load test (``phishguard loadtest``) and explained by the request
traces: scoring one message inside a worker thread -- which is where the API
runs every request -- took about three times as long as the same call on the
main thread, and the whole difference sat in the members that call into
OpenMP (the gradient-boosted engineered member, and evidence generation that
re-scores it).

The cause is the OpenMP runtime, not the model. A single-message prediction
has one row, so OpenMP's parallel loop has nothing to share out, but each
worker thread still gets its own team of OpenMP threads, and on a small
machine those teams busy-wait for work and compete for the same cores as the
Python code between calls. Measured on a 2-core container, one worker thread:
p50 36.6 ms before, 11.7 ms after limiting OpenMP to one thread per serving
thread; throughput 27 to 84 messages a second.

The limit is applied once per serving *worker* thread, only on the serving
path. The main thread -- where training and batch evaluation run -- is never
limited, so fits keep their parallelism and stay bit-for-bit reproducible.
"""

from __future__ import annotations

import threading
from typing import Any

_LOCAL = threading.local()
_LOCK = threading.Lock()
_CONTROLLER: Any = None


def limit_native_threads_for_serving() -> bool:
    """Limit OpenMP to one thread in the calling thread. Idempotent and cheap.

    Returns ``True`` if a limit is in force for this thread. Never raises: if
    ``threadpoolctl`` (a scikit-learn dependency) is unavailable, serving still
    works, only slower in worker threads.
    """
    if getattr(_LOCAL, "limited", None) is not None:
        return bool(_LOCAL.limited)
    if threading.current_thread() is threading.main_thread():
        # The main thread trains and runs batch jobs, which do use OpenMP's
        # parallel loops; under a web server it never runs a request at all.
        _LOCAL.limited = False
        return False
    global _CONTROLLER
    try:
        with _LOCK:
            if _CONTROLLER is None:
                from threadpoolctl import ThreadpoolController

                _CONTROLLER = ThreadpoolController()
        _CONTROLLER.limit(limits=1, user_api="openmp")
        _LOCAL.limited = True
    except Exception:  # noqa: BLE001 - optional optimisation, never a failure
        _LOCAL.limited = False
    return bool(_LOCAL.limited)
