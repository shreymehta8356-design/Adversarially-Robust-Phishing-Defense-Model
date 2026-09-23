"""Internal domain types.

These are plain dataclasses, deliberately free of any web-framework or
validation dependency, because they are used inside tight feature-extraction
and adversarial-search loops. The HTTP boundary types live in
``phishguard.service.contracts`` and convert into these.

The domain model is the contract between the three feature families:
an :class:`EmailMessage` carries everything the email and URL extractors need,
and an optional :class:`BehavioralContext` carries the deployment-time signals
that only a mail gateway can know. Behavioral context is *optional by design*:
the system degrades to email+URL only, and records that it did so.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

# --------------------------------------------------------------------------
# Verdict vocabulary
# --------------------------------------------------------------------------
BAND_ALLOW = "ALLOW"
BAND_REVIEW = "REVIEW"
BAND_BLOCK = "BLOCK"
BANDS = (BAND_ALLOW, BAND_REVIEW, BAND_BLOCK)

LABEL_HAM = 0
LABEL_PHISH = 1

_ADDR_RE = re.compile(r"<\s*([^<>@\s]+@[^<>@\s]+)\s*>|([^<>@\s]+@[^<>@\s]+)")


def parse_address(raw: str) -> tuple[str, str]:
    """Split ``"Acme Support <no-reply@acme.example>"`` into display + address.

    Returns ``(display_name, email_address)``; either may be empty. Parsing is
    intentionally permissive because phishing headers are frequently malformed
    and a hard parse failure would be a denial-of-service vector.
    """
    if not raw:
        return "", ""
    raw = raw.strip()
    m = _ADDR_RE.search(raw)
    if not m:
        return raw.strip('"< >'), ""
    addr = (m.group(1) or m.group(2) or "").strip().lower()
    display = raw[: m.start()].strip().strip('"').strip("'").strip()
    if not display and "<" not in raw:
        display = ""
    return display, addr


def address_domain(addr: str) -> str:
    """Domain part of an email address, lowercased; empty when absent."""
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].strip().lower().strip(".")


def pseudonymize(value: str, salt: str) -> str:
    """Stable, non-reversible identifier for audit logs.

    Personal data must not be committed or logged in the clear (privacy
    requirement + the portfolio's acceptance gate). We keep a salted digest so
    that an analyst can still correlate repeat senders without the log holding
    a real mailbox address.
    """
    if not value:
        return ""
    digest = hashlib.sha256(f"{salt}|{value.lower()}".encode()).hexdigest()
    return f"px_{digest[:20]}"


@dataclass(slots=True)
class Attachment:
    """Attachment metadata. Content is never parsed or stored."""

    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0

    @property
    def extension(self) -> str:
        name = self.filename.strip().lower()
        return name.rsplit(".", 1)[-1] if "." in name else ""


@dataclass(slots=True)
class BehavioralContext:
    """Deployment-time relationship and interaction signals.

    Every field has a neutral default so that a caller with no mail-gateway
    history still gets a valid object. ``available`` records whether the caller
    actually supplied context, which the feature layer exposes as a first-class
    feature -- the model is told when it is flying blind rather than being
    silently fed zeros.
    """

    available: bool = False
    #: True the first time this sender address writes to this recipient.
    sender_first_seen: bool = True
    prior_messages_from_sender: int = 0
    prior_replies_to_sender: int = 0
    #: 0 for a new thread, >0 for a reply chain.
    thread_depth: int = 0
    #: Local hour of receipt, 0-23.
    hour_local: int = 12
    is_weekend: bool = False
    recipient_count: int = 1
    bcc_count: int = 0
    #: Sender is outside the organisation's own domains.
    external_sender: bool = True
    #: How many times users previously reported this sender domain.
    domain_report_count: int = 0
    #: Historic click-through rate on links from this domain, 0..1.
    domain_click_rate: float = 0.0
    #: Messages seen from this domain in the last hour (campaign burstiness).
    burst_count_1h: int = 1
    #: Distinct addresses that have used this display name (impersonation).
    display_name_alias_count: int = 1
    #: Organisational tenure of the sender domain in days (0 = unknown/new).
    domain_age_days: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "sender_first_seen": self.sender_first_seen,
            "prior_messages_from_sender": self.prior_messages_from_sender,
            "prior_replies_to_sender": self.prior_replies_to_sender,
            "thread_depth": self.thread_depth,
            "hour_local": self.hour_local,
            "is_weekend": self.is_weekend,
            "recipient_count": self.recipient_count,
            "bcc_count": self.bcc_count,
            "external_sender": self.external_sender,
            "domain_report_count": self.domain_report_count,
            "domain_click_rate": self.domain_click_rate,
            "burst_count_1h": self.burst_count_1h,
            "display_name_alias_count": self.display_name_alias_count,
            "domain_age_days": self.domain_age_days,
        }


@dataclass(slots=True)
class AuthResults:
    """SMTP authentication verdicts as reported by the receiving gateway."""

    spf: str = "none"  # pass | fail | softfail | neutral | none
    dkim: str = "none"  # pass | fail | none
    dmarc: str = "none"  # pass | fail | none

    def as_dict(self) -> dict[str, str]:
        return {"spf": self.spf, "dkim": self.dkim, "dmarc": self.dmarc}


@dataclass(slots=True)
class EmailMessage:
    """A single message under assessment."""

    subject: str = ""
    body: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)
    behavioral: BehavioralContext = field(default_factory=BehavioralContext)
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    received_hops: int = 2
    #: Free-form provenance tag: which corpus / generator produced this record.
    source: str = ""
    #: Campaign or thread grouping key. Used to build leakage-safe splits.
    group_key: str = ""

    # ------------------------------------------------------------- derived
    @property
    def sender_display(self) -> str:
        return parse_address(self.sender)[0]

    @property
    def sender_address(self) -> str:
        return parse_address(self.sender)[1]

    @property
    def sender_domain(self) -> str:
        return address_domain(self.sender_address)

    @property
    def reply_to_address(self) -> str:
        return parse_address(self.reply_to)[1]

    @property
    def return_path_address(self) -> str:
        return parse_address(self.return_path)[1]

    @property
    def text(self) -> str:
        """Subject + body, the single string the text models consume."""
        return f"{self.subject}\n{self.body}".strip()

    def with_text(self, subject: str | None = None, body: str | None = None) -> EmailMessage:
        """Return a copy with replaced text. Used by adversarial transforms."""
        return replace(
            self,
            subject=self.subject if subject is None else subject,
            body=self.body if body is None else body,
        )

    def copy(self, **changes: Any) -> EmailMessage:
        return replace(self, **changes)

    def fingerprint(self) -> str:
        """Content hash used for near-duplicate and leakage checks."""
        payload = f"{self.subject}\x00{self.body}\x00{self.sender_address}"
        return hashlib.sha1(payload.encode("utf-8", "ignore")).hexdigest()  # noqa: S324

    def redacted(self, salt: str) -> dict[str, Any]:
        """Privacy-preserving projection safe to write to the audit log.

        The subject digest is **salted**, like the sender identifier. An earlier
        revision hashed it with bare SHA-256, which is not a redaction: subject
        lines come from a small, highly predictable space ("Invoice 4417 is
        ready", "Reset your password"), so an unsalted digest is recoverable by
        dictionary attack against a stolen database. Salting removes that, and
        the digest still supports its only purpose, which is grouping identical
        subjects within one deployment.
        """
        return {
            "subject_hash": hashlib.sha256(
                f"{salt}|subject|{self.subject}".encode("utf-8", "ignore")
            ).hexdigest()[:16],
            "sender_px": pseudonymize(self.sender_address, salt),
            "sender_domain": self.sender_domain,
            "recipient_count": len(self.to) or self.behavioral.recipient_count,
            "body_length": len(self.body),
            "attachment_count": len(self.attachments),
            "received_at": self.received_at.isoformat(),
            "source": self.source,
        }


@dataclass(slots=True)
class Verdict:
    """The system's decision about one message."""

    score: float
    band: str
    label: int
    model_version: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    signals: dict[str, float] = field(default_factory=dict)
    member_scores: dict[str, float] = field(default_factory=dict)
    defenses_applied: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    behavioral_available: bool = False
    abstained: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": round(float(self.score), 6),
            "band": self.band,
            "label": int(self.label),
            "model_version": self.model_version,
            "evidence": self.evidence,
            "signals": {k: round(float(v), 6) for k, v in self.signals.items()},
            "member_scores": {k: round(float(v), 6) for k, v in self.member_scores.items()},
            "defenses_applied": self.defenses_applied,
            "latency_ms": round(float(self.latency_ms), 3),
            "behavioral_available": self.behavioral_available,
            "abstained": self.abstained,
        }
