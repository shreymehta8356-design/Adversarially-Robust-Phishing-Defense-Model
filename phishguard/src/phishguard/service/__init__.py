"""HTTP service layer.

The decision logic lives in :mod:`phishguard.service.scanning` and is free of
any web framework, so it can be tested without an HTTP server. FastAPI in
:mod:`phishguard.service.app` is a thin adapter over it.

Importing ``app`` is deferred: the training and evaluation paths should not
require the web dependencies to be installed.
"""

from phishguard.service.contracts import ScanRequest, ScanResponse
from phishguard.service.scanning import ScanService
from phishguard.service.store import DecisionStore, get_store

__all__ = ["DecisionStore", "ScanRequest", "ScanResponse", "ScanService", "get_store"]
