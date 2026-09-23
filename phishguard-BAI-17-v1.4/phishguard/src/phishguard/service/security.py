"""Authentication, authorisation and rate limiting.

Framework-independent on purpose: everything here is plain Python that can be
unit-tested without spinning up an HTTP server, and the FastAPI layer is a thin
adapter over it. Aligned with the OWASP API Security Top 10 items that apply to
a single-purpose scoring service:

* **API1 Broken object-level authorisation** - decisions are addressed by an
  unguessable id and every read is scoped to the caller's role.
* **API2 Broken authentication** - keys are compared in constant time against
  stored digests, never against plaintext, and never logged.
* **API4 Unrestricted resource consumption** - a token-bucket limiter per key,
  a hard body-size cap, and bounded batch sizes.
* **API5 Broken function-level authorisation** - the adversarial probe and the
  audit trail require the ``admin`` role; scanning requires ``analyst``; an
  email user's ``reporter`` key can submit reports and read its own, and is
  never shown a score, so it cannot be used as a scoring oracle.
* **API8 Security misconfiguration** - the service refuses to start in
  production without explicit keys, rather than falling back to a default.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Literal

Role = Literal["reporter", "analyst", "admin"]

#: Role hierarchy: each role can do everything the roles below it can.
#: ``reporter`` - an email user: report a suspicious message, read own reports.
#: ``analyst``  - score mail, work the review queue, record feedback.
#: ``admin``    - the audit trail, the adversarial probe, high-risk releases.
_ROLE_RANK: dict[str, int] = {"reporter": 1, "analyst": 2, "admin": 3}


class AuthError(Exception):
    """Raised when a request cannot be authenticated or is not permitted."""

    def __init__(self, message: str, *, status: int = 401, reason: str = "unauthenticated"):
        super().__init__(message)
        self.status = status
        self.reason = reason


class RateLimitError(Exception):
    def __init__(self, retry_after: float) -> None:
        super().__init__("rate limit exceeded")
        self.retry_after = retry_after


def hash_key(api_key: str) -> str:
    """SHA-256 digest of a key. Only digests are held in memory."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class Principal:
    """The authenticated caller."""

    key_id: str
    role: Role

    def can(self, required: Role) -> bool:
        return _ROLE_RANK.get(self.role, 0) >= _ROLE_RANK.get(required, 99)


class ApiKeyAuthenticator:
    """Constant-time API-key authentication over stored digests."""

    def __init__(self, keys: dict[str, str]) -> None:
        """``keys`` maps plaintext key -> role; only digests are retained."""
        self._digests: dict[str, tuple[str, str]] = {}
        for raw, role in keys.items():
            if role not in _ROLE_RANK:
                continue
            digest = hash_key(raw)
            # A short, non-reversible identifier so logs can distinguish callers
            # without ever holding the key itself.
            key_id = f"key_{digest[:8]}"
            self._digests[digest] = (key_id, role)

    @property
    def configured(self) -> bool:
        return bool(self._digests)

    def authenticate(self, presented: str | None) -> Principal:
        if not presented:
            raise AuthError("missing API key", status=401, reason="missing_key")
        candidate = hash_key(presented.strip())
        # Compare against every digest in constant time so that neither the
        # number of keys nor an early match is observable through timing.
        matched: tuple[str, str] | None = None
        for digest, value in self._digests.items():
            if hmac.compare_digest(candidate, digest):
                matched = value
        if matched is None:
            raise AuthError("invalid API key", status=401, reason="invalid_key")
        return Principal(key_id=matched[0], role=matched[1])  # type: ignore[arg-type]

    def require(self, presented: str | None, role: Role) -> Principal:
        principal = self.authenticate(presented)
        if not principal.can(role):
            raise AuthError(
                f"role '{principal.role}' is not permitted to perform this action "
                f"(requires '{role}')",
                status=403,
                reason="forbidden",
            )
        return principal


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    """Per-caller token bucket.

    Chosen over a fixed window because a mail gateway's traffic is bursty:
    a fixed window either rejects a legitimate burst or permits double the
    intended rate across a window boundary. The bucket allows a burst up to its
    capacity and then enforces the steady rate.
    """

    def __init__(self, rate_per_minute: int, burst: int | None = None) -> None:
        self.rate_per_second = max(rate_per_minute, 1) / 60.0
        self.capacity = float(burst if burst is not None else max(rate_per_minute, 1))
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str, *, cost: float = 1.0, now: float | None = None) -> None:
        """Consume ``cost`` tokens or raise :class:`RateLimitError`."""
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = bucket
            elapsed = max(now - bucket.updated, 0.0)
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate_per_second)
            bucket.updated = now
            if bucket.tokens < cost:
                deficit = cost - bucket.tokens
                raise RateLimitError(retry_after=round(deficit / self.rate_per_second, 3))
            bucket.tokens -= cost

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


@dataclass(slots=True)
class SecurityConfig:
    """Everything the request path needs to make a security decision."""

    authenticator: ApiKeyAuthenticator
    limiter: TokenBucketLimiter
    max_body_bytes: int = 1_000_000
    max_upload_bytes: int = 50_000_000
    using_development_keys: bool = False
    warnings: list[str] = field(default_factory=list)


def build_security(settings) -> SecurityConfig:  # noqa: ANN001 - avoids a circular import
    """Assemble the security configuration, refusing unsafe production setups."""
    keys = settings.resolved_api_keys()
    warnings: list[str] = []
    using_dev = False

    if not keys:
        if settings.environment == "prod":
            raise RuntimeError(
                "PG_API_KEYS must be set in production. Provide comma-separated "
                "'role:key' pairs, e.g. PG_API_KEYS='analyst:<key>,admin:<key>'."
            )
        raise RuntimeError("no API keys configured and no development fallback available")

    if not settings.api_keys.strip():
        using_dev = True
        warnings.append(
            "Using built-in development API keys. Set PG_API_KEYS before exposing "
            "this service to anything but localhost."
        )

    return SecurityConfig(
        authenticator=ApiKeyAuthenticator(keys),
        limiter=TokenBucketLimiter(settings.rate_limit_per_minute),
        max_body_bytes=settings.max_body_bytes,
        max_upload_bytes=getattr(settings, "max_upload_bytes", 50_000_000),
        using_development_keys=using_dev,
        warnings=warnings,
    )


def new_request_id() -> str:
    """Unguessable correlation id, also used as the audit-trail key."""
    return f"req_{secrets.token_hex(10)}"


def new_decision_id() -> str:
    return f"dec_{secrets.token_hex(12)}"


def new_feedback_id() -> str:
    return f"fb_{secrets.token_hex(10)}"


def new_case_id() -> str:
    return f"case_{secrets.token_hex(8)}"


def generate_api_key(role: Role = "analyst") -> str:
    """Generate a key for an operator to install. Never stored by this module."""
    return f"pg_{role[:2]}_{secrets.token_urlsafe(32)}"
