"""HTTP data contracts.

These pydantic models are the API's published interface: they are what OpenAPI
documents, what input validation enforces, and what the analyst console and any
mail-gateway integration code against. They convert to and from the internal
dataclasses in :mod:`phishguard.schemas`, which keeps framework types out of
the feature-extraction hot path.

Validation here is a security control, not a convenience. Bounds on body size,
recipient counts, attachment counts and URL length are the first line of
defence against resource-exhaustion through the scan endpoint, which is
reachable by anything that can reach the mail gateway.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from phishguard.schemas import (
    Attachment,
    AuthResults,
    BehavioralContext,
    EmailMessage,
)

MAX_SUBJECT = 2_000
MAX_BODY = 200_000
MAX_HTML = 400_000
MAX_RECIPIENTS = 200
MAX_ATTACHMENTS = 50

AuthVerdict = Literal["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]


class AttachmentIn(BaseModel):
    """Attachment *metadata*. Content is never accepted, sent or stored."""

    model_config = ConfigDict(extra="forbid")

    filename: Annotated[str, Field(max_length=512)] = ""
    content_type: Annotated[str, Field(max_length=255)] = ""
    size_bytes: Annotated[int, Field(ge=0, le=10_000_000_000)] = 0

    def to_domain(self) -> Attachment:
        return Attachment(
            filename=self.filename,
            content_type=self.content_type,
            size_bytes=self.size_bytes,
        )


class AuthResultsIn(BaseModel):
    """SMTP authentication verdicts as reported by the receiving gateway."""

    model_config = ConfigDict(extra="forbid")

    spf: AuthVerdict = "none"
    dkim: AuthVerdict = "none"
    dmarc: AuthVerdict = "none"

    def to_domain(self) -> AuthResults:
        return AuthResults(spf=self.spf, dkim=self.dkim, dmarc=self.dmarc)


class BehavioralContextIn(BaseModel):
    """Optional sender-relationship context from the mail gateway.

    Omit the whole object when unavailable. The system does not invent it: the
    verdict records ``behavioral_available: false`` and the evidence list says
    so explicitly, so a downstream consumer knows the assessment ran on
    email and URL evidence only.
    """

    model_config = ConfigDict(extra="forbid")

    sender_first_seen: bool = True
    prior_messages_from_sender: Annotated[int, Field(ge=0, le=1_000_000)] = 0
    prior_replies_to_sender: Annotated[int, Field(ge=0, le=1_000_000)] = 0
    thread_depth: Annotated[int, Field(ge=0, le=1_000)] = 0
    hour_local: Annotated[int, Field(ge=0, le=23)] = 12
    is_weekend: bool = False
    recipient_count: Annotated[int, Field(ge=0, le=100_000)] = 1
    bcc_count: Annotated[int, Field(ge=0, le=100_000)] = 0
    external_sender: bool = True
    domain_report_count: Annotated[int, Field(ge=0, le=1_000_000)] = 0
    domain_click_rate: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    burst_count_1h: Annotated[int, Field(ge=0, le=1_000_000)] = 1
    display_name_alias_count: Annotated[int, Field(ge=0, le=100_000)] = 1
    domain_age_days: Annotated[int, Field(ge=0, le=100_000)] = 0

    def to_domain(self) -> BehavioralContext:
        return BehavioralContext(
            available=True,
            sender_first_seen=self.sender_first_seen,
            prior_messages_from_sender=self.prior_messages_from_sender,
            prior_replies_to_sender=self.prior_replies_to_sender,
            thread_depth=self.thread_depth,
            hour_local=self.hour_local,
            is_weekend=self.is_weekend,
            recipient_count=self.recipient_count,
            bcc_count=self.bcc_count,
            external_sender=self.external_sender,
            domain_report_count=self.domain_report_count,
            domain_click_rate=self.domain_click_rate,
            burst_count_1h=self.burst_count_1h,
            display_name_alias_count=self.display_name_alias_count,
            domain_age_days=self.domain_age_days,
        )


class ScanRequest(BaseModel):
    """One message submitted for assessment."""

    model_config = ConfigDict(extra="forbid")

    subject: Annotated[str, Field(max_length=MAX_SUBJECT)] = ""
    body: Annotated[str, Field(max_length=MAX_BODY)] = ""
    html_body: Annotated[str, Field(max_length=MAX_HTML)] = ""
    sender: Annotated[str, Field(max_length=512)] = ""
    reply_to: Annotated[str, Field(max_length=512)] = ""
    return_path: Annotated[str, Field(max_length=512)] = ""
    to: Annotated[list[str], Field(max_length=MAX_RECIPIENTS)] = Field(default_factory=list)
    attachments: Annotated[list[AttachmentIn], Field(max_length=MAX_ATTACHMENTS)] = Field(
        default_factory=list
    )
    auth: AuthResultsIn = Field(default_factory=AuthResultsIn)
    behavioral: BehavioralContextIn | None = None
    received_at: datetime | None = None
    received_hops: Annotated[int, Field(ge=0, le=100)] = 2
    #: Free-form caller reference echoed back on the verdict, for correlation.
    client_reference: Annotated[str, Field(max_length=128)] = ""

    @field_validator("to")
    @classmethod
    def _trim_recipients(cls, v: list[str]) -> list[str]:
        return [addr.strip()[:320] for addr in v if addr and addr.strip()]

    @classmethod
    def from_message(cls, m: EmailMessage, *, client_reference: str = "") -> ScanRequest:
        """The request a gateway would send for a domain message.

        Used by the load test and the tests to drive the real request path.
        Values are clipped to the contract's bounds, so a synthetic message
        can never fail validation that a real caller would pass.
        """
        beh = None
        if m.behavioral.available:
            fields = {}
            for name, info in BehavioralContextIn.model_fields.items():
                value = getattr(m.behavioral, name, info.default)
                for meta in info.metadata:
                    if getattr(meta, "le", None) is not None:
                        value = min(value, meta.le)
                    if getattr(meta, "ge", None) is not None:
                        value = max(value, meta.ge)
                fields[name] = value
            beh = BehavioralContextIn(**fields)
        return cls(
            subject=m.subject[:MAX_SUBJECT],
            body=m.body[:MAX_BODY],
            html_body=m.html_body[:MAX_HTML],
            sender=m.sender[:512],
            reply_to=m.reply_to[:512],
            return_path=m.return_path[:512],
            to=list(m.to)[:MAX_RECIPIENTS],
            attachments=[
                AttachmentIn(
                    filename=a.filename[:512],
                    content_type=a.content_type[:255],
                    size_bytes=int(a.size_bytes),
                )
                for a in m.attachments[:MAX_ATTACHMENTS]
            ],
            auth=AuthResultsIn(spf=m.auth.spf, dkim=m.auth.dkim, dmarc=m.auth.dmarc),
            behavioral=beh,
            received_at=m.received_at,
            received_hops=min(int(m.received_hops), 100),
            client_reference=client_reference,
        )

    def to_message(self) -> EmailMessage:
        return EmailMessage(
            subject=self.subject,
            body=self.body,
            html_body=self.html_body,
            sender=self.sender,
            reply_to=self.reply_to,
            return_path=self.return_path,
            to=list(self.to),
            attachments=[a.to_domain() for a in self.attachments],
            auth=self.auth.to_domain(),
            behavioral=(self.behavioral.to_domain() if self.behavioral else BehavioralContext()),
            received_at=self.received_at or datetime.now(timezone.utc),
            received_hops=self.received_hops,
            source="api",
        )


class UrlScanRequest(BaseModel):
    """Standalone URL assessment, for click-time protection integrations."""

    model_config = ConfigDict(extra="forbid")

    url: Annotated[str, Field(min_length=1, max_length=4_096)]
    client_reference: Annotated[str, Field(max_length=128)] = ""


class BatchScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: Annotated[list[ScanRequest], Field(min_length=1, max_length=100)]
    explain: bool = False


class EvidenceItem(BaseModel):
    kind: str
    id: str
    title: str
    detail: str = ""
    direction: str = "neutral"
    weight: float = 0.0


class ScanResponse(BaseModel):
    """The verdict returned to the caller."""

    request_id: str
    decision_id: str
    score: float
    band: Literal["ALLOW", "REVIEW", "BLOCK"]
    label: int
    model_version: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    signals: dict[str, float] = Field(default_factory=dict)
    member_scores: dict[str, float] = Field(default_factory=dict)
    defenses_applied: list[str] = Field(default_factory=list)
    behavioral_available: bool = False
    abstained: bool = False
    latency_ms: float = 0.0
    client_reference: str = ""
    #: W3C trace id: the same id is on the audit record and the log line.
    trace_id: str = ""
    #: Milliseconds per pipeline stage for this request (members, fusion,
    #: explanation, audit write) - where the time went.
    stage_ms: dict[str, float] = Field(default_factory=dict)


class UrlScanResponse(BaseModel):
    request_id: str
    url: str
    canonical_url: str
    registered_domain: str
    risk_score: float
    band: Literal["ALLOW", "REVIEW", "BLOCK"]
    signals: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    client_reference: str = ""


class BatchScanResponse(BaseModel):
    request_id: str
    results: list[ScanResponse]
    total_latency_ms: float


class IngestResult(BaseModel):
    index: int
    subject: str
    sender: str
    band: Literal["ALLOW", "REVIEW", "BLOCK"]
    score: float
    decision_id: str
    top_reason: str = ""


class IngestResponse(BaseModel):
    """What happened to an uploaded ``.eml`` or ``.mbox``."""

    request_id: str
    source: str
    received: int
    allow: int
    review: int
    block: int
    failed: int
    seconds: float
    results: list[IngestResult]


class FeedbackRequest(BaseModel):
    """An analyst's correction on a decision.

    Feedback is recorded and surfaced for review. It is deliberately *not* used
    to retrain automatically: an endpoint that lets a caller move the decision
    boundary is a poisoning vector, so retraining stays a reviewed, manual act.
    """

    model_config = ConfigDict(extra="forbid")

    decision_id: Annotated[str, Field(min_length=1, max_length=64)]
    analyst_label: Literal["phishing", "legitimate", "unsure"]
    rationale: Annotated[str, Field(max_length=2_000)] = ""
    action_taken: Annotated[str, Field(max_length=64)] = ""


class FeedbackResponse(BaseModel):
    feedback_id: str
    decision_id: str
    recorded_at: str
    note: str


class DecisionRecord(BaseModel):
    """One row of the audit trail. Contains no message content."""

    decision_id: str
    request_id: str
    created_at: str
    score: float
    band: str
    label: int
    model_version: str
    subject_hash: str
    sender_px: str
    sender_domain: str
    recipient_count: int
    body_length: int
    attachment_count: int
    behavioral_available: bool
    latency_ms: float
    top_evidence: list[str] = Field(default_factory=list)
    feedback_label: str | None = None


class DecisionPage(BaseModel):
    items: list[DecisionRecord]
    total: int
    limit: int
    offset: int


class AdversarialProbeRequest(BaseModel):
    """Run the attack suite against one message. Admin only.

    Exposed because a security team needs to answer "would this get through if
    the attacker tried harder?" for a specific message they are holding, and
    because it is how the residual-risk claims stay honest after deployment.
    """

    model_config = ConfigDict(extra="forbid")

    message: ScanRequest
    budget: Annotated[int, Field(ge=1, le=40)] = 10
    families: list[str] | None = None


class AdversarialProbeResponse(BaseModel):
    request_id: str
    original_score: float
    final_score: float
    evaded: bool
    queries: int
    steps: list[str]
    families_used: list[str]
    trajectory: list[float]
    interpretation: str


class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool
    model_version: str | None = None
    uptime_seconds: float = 0.0


class ModelInfoResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    model_version: str
    trained_at: str
    members: list[str]
    feature_families: list[str]
    defenses: dict[str, bool]
    active_defense_ids: list[str]
    thresholds: dict[str, float]
    #: Where the thresholds came from: tuned to a false-alarm budget, or
    #: configured, and why.
    threshold_source: str = ""
    calibration_method: str
    attack_taxonomy: list[dict[str, Any]]
    defense_catalogue: list[dict[str, Any]]
    training: dict[str, Any] | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""
    request_id: str = ""


# --------------------------------------------------------------------------
# Review queue and user reports
# --------------------------------------------------------------------------
ReportCategory = Literal[
    "suspicious_link", "unexpected_attachment", "impersonation", "payment_request", "other"
]


class ReportRequest(BaseModel):
    """An email user reporting a message they think is phishing.

    The ``reporter`` role may submit and read its own reports and nothing
    else. It is never shown a score: a reporting endpoint that returned the
    model's verdict would be a free scoring oracle for anyone with a reporter
    key.
    """

    model_config = ConfigDict(extra="forbid")

    message: ScanRequest
    category: ReportCategory = "other"
    note: Annotated[str, Field(max_length=500)] = ""
    #: An opaque identifier for the person reporting (for example a mail
    #: client's user id). Stored only as a salted digest.
    reporter_ref: Annotated[str, Field(max_length=128)] = ""


class ReportReceipt(BaseModel):
    case_id: str
    received_at: str
    status: str
    message: str


class ReportSummary(BaseModel):
    case_id: str
    received_at: str
    category: str
    state: str
    status: str


class ReportList(BaseModel):
    reports: list[ReportSummary]
    total: int


class CaseEvent(BaseModel):
    at: str
    actor: str
    actor_role: str
    action: str
    from_state: str | None = None
    to_state: str | None = None
    note: str = ""


class CaseSummary(BaseModel):
    """One case in the review queue. Contains no message content."""

    model_config = ConfigDict(protected_namespaces=())

    case_id: str
    decision_id: str
    created_at: str
    state: str
    origin: str
    priority: int
    sla_due_at: str
    overdue: bool
    age_seconds: float
    assignee: str | None = None
    resolution: str | None = None
    score: float
    band: str
    sender_domain: str = ""
    top_evidence: list[str] = Field(default_factory=list)
    report_category: str = ""
    model_version: str = ""
    trace_id: str = ""


class CaseDetail(CaseSummary):
    member_scores: dict[str, float] = Field(default_factory=dict)
    events: list[CaseEvent] = Field(default_factory=list)
    #: What *this* caller may do next, so a client can show only valid buttons.
    #: ``resolve:released`` is listed separately because a high-risk release
    #: needs an administrator even when resolving does not.
    allowed_actions: list[str] = Field(default_factory=list)


class CasePage(BaseModel):
    cases: list[CaseSummary]
    total: int
    limit: int
    offset: int


class CaseActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["claim", "unclaim", "escalate", "resolve", "reopen", "comment"]
    resolution: Literal["confirmed_phishing", "released"] | None = None
    note: Annotated[str, Field(max_length=1_000)] = ""


class WhoAmI(BaseModel):
    key_id: str
    role: str
