"""Shared test builders.

Plain module-level helpers rather than pytest fixtures, so that the same test
files run under ``pytest`` and under the dependency-free collector in
``scripts/run_tests.py``. Expensive objects (a trained detector, a corpus) are
built once and cached.
"""

from __future__ import annotations

import functools
import tempfile
from pathlib import Path
from typing import Any

import numpy as np

from phishguard.config import Settings
from phishguard.schemas import (
    Attachment,
    AuthResults,
    BehavioralContext,
    EmailMessage,
)

#: Small enough to keep the suite fast, large enough for the models to fit.
TRAIN_N = 1400


def make_settings(**overrides: Any) -> Settings:
    tmp = Path(tempfile.mkdtemp(prefix="phishguard-test-"))
    defaults: dict[str, Any] = {
        "environment": "test",
        "artifacts_dir": tmp,
        "log_format": "text",
        "adv_train_multiplier": 1,
    }
    defaults.update(overrides)
    settings = Settings(**defaults)
    settings.ensure_dirs()
    return settings


def phishing_message(**overrides: Any) -> EmailMessage:
    base: dict[str, Any] = {
        "subject": "URGENT: Your account will be suspended",
        "body": (
            "Dear Customer,\n\nWe detected unauthorized access on your account. "
            "You must verify your identity immediately or your account will be "
            "permanently closed.\n\n"
            "Verify now: http://paypa1-secure-verify.tk/account/login?id=8fj2kd\n\n"
            "PayPal Security Team"
        ),
        "html_body": (
            '<html><body><a href="http://paypa1-secure-verify.tk/account/login">'
            "https://www.paypal.com/signin</a>"
            '<form><input type="password" name="pass"></form></body></html>'
        ),
        "sender": "PayPal Support <security@paypa1-secure-verify.tk>",
        "reply_to": "recovery@mail.ru",
        "to": ["victim@corp.example"],
        "auth": AuthResults(spf="fail", dkim="none", dmarc="fail"),
        "attachments": [Attachment("invoice.pdf.exe", "application/octet-stream", 24000)],
        "behavioral": BehavioralContext(
            available=True,
            sender_first_seen=True,
            hour_local=3,
            domain_age_days=4,
            burst_count_1h=180,
            display_name_alias_count=6,
        ),
        "source": "test:phish",
        "group_key": "test-phish-1",
    }
    base.update(overrides)
    return EmailMessage(**base)


def ham_message(**overrides: Any) -> EmailMessage:
    base: dict[str, Any] = {
        "subject": "Weekly status - Warehouse",
        "body": (
            "Status for this week:\n\n"
            "Done: supplier list verified, staging backfill completed.\n"
            "In progress: reconciliation report.\n"
            "Blocked: waiting on the partner API key.\n\n"
            "Thanks,\nPriya Sharma"
        ),
        "sender": "Priya Sharma <priya.sharma@northgate-industries.example>",
        "to": ["team@northgate-industries.example"],
        "auth": AuthResults(spf="pass", dkim="pass", dmarc="pass"),
        "behavioral": BehavioralContext(
            available=True,
            sender_first_seen=False,
            prior_messages_from_sender=84,
            prior_replies_to_sender=30,
            hour_local=10,
            domain_age_days=3200,
            burst_count_1h=2,
            display_name_alias_count=1,
            external_sender=False,
        ),
        "source": "test:ham",
        "group_key": "test-ham-1",
    }
    base.update(overrides)
    return EmailMessage(**base)


@functools.lru_cache(maxsize=4)
def corpus(n: int = TRAIN_N, seed: int = 7):
    from phishguard.data.synthetic import generate_corpus

    messages, labels = generate_corpus(n, seed=seed)
    return messages, labels


@functools.lru_cache(maxsize=2)
def split_corpus(n: int = TRAIN_N, seed: int = 7):
    from phishguard.data.splits import grouped_split

    messages, labels = corpus(n, seed)
    split = grouped_split(messages, labels, test_size=0.25, seed=3)
    train = [messages[i] for i in split.train_idx]
    y_train = np.asarray([labels[i] for i in split.train_idx], dtype=np.int64)
    test = [messages[i] for i in split.test_idx]
    y_test = np.asarray([labels[i] for i in split.test_idx], dtype=np.int64)
    return train, y_train, test, y_test, split


@functools.lru_cache(maxsize=1)
def trained_detector():
    """A detector trained once and reused across the suite."""
    from phishguard.models.detector import PhishGuardDetector

    train, y_train, _, _, _ = split_corpus()
    settings = make_settings()
    detector = PhishGuardDetector(settings=settings)
    detector.fit(train, y_train)
    return detector, settings


@functools.lru_cache(maxsize=1)
def scan_service():
    """A ScanService backed by a temporary audit store."""
    from phishguard.service.scanning import ScanService
    from phishguard.service.store import DecisionStore

    detector, settings = trained_detector()
    store = DecisionStore(Path(tempfile.mkdtemp(prefix="pg-store-")) / "audit.db")
    return ScanService(detector, store, settings), store, settings


def scan_request(**overrides: Any):
    from phishguard.service.contracts import ScanRequest

    base: dict[str, Any] = {
        "subject": "URGENT: verify your account",
        "body": (
            "Dear Customer, confirm your password at "
            "http://secure-verify-9f2.tk/account/login or your account will be closed."
        ),
        "sender": "Support <no-reply@secure-verify-9f2.tk>",
        "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
    }
    base.update(overrides)
    return ScanRequest(**base)
