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
            behavioral=(
                self.behavioral.to_domain() if self.behavioral else BehavioralContext()
            ),
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
    calibration_method: str
    attack_taxonomy: list[dict[str, Any]]
    defense_catalogue: list[dict[str, Any]]
    training: dict[str, Any] | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""
    request_id: str = ""
