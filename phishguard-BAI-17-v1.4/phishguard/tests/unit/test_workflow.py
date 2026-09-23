"""The review queue: every transition, every permission, every audit event.

The state machine is where a REVIEW band becomes a human decision, so the
tests pin the rules an attacker or a careless analyst would most like to break:
releasing a held phish, resolving someone else's case, deciding a case nobody
claimed, or reading the model's score through the reporting endpoint.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from phishguard.service import workflow
from phishguard.service.workflow import InvalidTransition, NotPermitted, decide

ANALYST_A = ("key_aaaa", "analyst")
ANALYST_B = ("key_bbbb", "analyst")
ADMIN = ("key_admn", "admin")
REPORTER = ("key_rprt", "reporter")


def _raises(exc_type, **kwargs) -> str:
    try:
        decide(**kwargs)
    except exc_type as exc:
        return str(exc)
    raise AssertionError(f"expected {exc_type.__name__}")


# ------------------------------------------------------------ state machine
def test_the_happy_path_claim_then_resolve():
    t = decide(
        action="claim", state="open", actor=ANALYST_A[0], actor_role="analyst", assignee=None
    )
    assert (t.from_state, t.to_state, t.assignee) == ("open", "in_review", ANALYST_A[0])
    t = decide(
        action="resolve",
        state="in_review",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=ANALYST_A[0],
        resolution="confirmed_phishing",
    )
    assert (t.to_state, t.resolution) == ("resolved", "confirmed_phishing")


def test_a_case_must_be_claimed_before_it_is_resolved():
    msg = _raises(
        InvalidTransition,
        action="resolve",
        state="open",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=None,
        resolution="confirmed_phishing",
    )
    assert "claimed" in msg


def test_an_analyst_cannot_work_a_case_another_analyst_owns():
    """Object-level authorisation: owning a case is a permission."""
    for action, extra in (
        ("resolve", {"resolution": "confirmed_phishing"}),
        ("unclaim", {}),
        ("escalate", {"note": "needs IR"}),
    ):
        _raises(
            NotPermitted,
            action=action,
            state="in_review",
            actor=ANALYST_B[0],
            actor_role="analyst",
            assignee=ANALYST_A[0],
            **extra,
        )
    # ...but an administrator can.
    t = decide(
        action="resolve",
        state="in_review",
        actor=ADMIN[0],
        actor_role="admin",
        assignee=ANALYST_A[0],
        resolution="confirmed_phishing",
    )
    assert t.to_state == "resolved"


def test_releasing_a_message_the_model_would_block_needs_an_administrator():
    msg = _raises(
        NotPermitted,
        action="resolve",
        state="in_review",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=ANALYST_A[0],
        resolution="released",
        note="looks fine to me",
        score=0.93,
        block_threshold=0.8,
    )
    assert "administrator" in msg
    t = decide(
        action="resolve",
        state="in_review",
        actor=ADMIN[0],
        actor_role="admin",
        assignee=ANALYST_A[0],
        resolution="released",
        note="verified with sender",
        score=0.93,
        block_threshold=0.8,
    )
    assert t.resolution == "released"
    # Below the block threshold an analyst may release, but must say why.
    _raises(
        InvalidTransition,
        action="resolve",
        state="in_review",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=ANALYST_A[0],
        resolution="released",
        note="",
        score=0.5,
    )
    decide(
        action="resolve",
        state="in_review",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=ANALYST_A[0],
        resolution="released",
        note="known supplier",
        score=0.5,
    )


def test_escalated_cases_are_decided_by_an_administrator():
    t = decide(
        action="escalate",
        state="in_review",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=ANALYST_A[0],
        note="payment already made",
    )
    assert t.to_state == "escalated"
    _raises(
        NotPermitted,
        action="resolve",
        state="escalated",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=ANALYST_A[0],
        resolution="confirmed_phishing",
    )
    decide(
        action="resolve",
        state="escalated",
        actor=ADMIN[0],
        actor_role="admin",
        assignee=ANALYST_A[0],
        resolution="confirmed_phishing",
    )


def test_only_an_administrator_reopens_and_must_say_why():
    _raises(
        NotPermitted,
        action="reopen",
        state="resolved",
        actor=ANALYST_A[0],
        actor_role="analyst",
        assignee=ANALYST_A[0],
        note="new evidence",
    )
    _raises(
        InvalidTransition,
        action="reopen",
        state="resolved",
        actor=ADMIN[0],
        actor_role="admin",
        assignee=None,
        note="",
    )
    t = decide(
        action="reopen",
        state="resolved",
        actor=ADMIN[0],
        actor_role="admin",
        assignee=ANALYST_A[0],
        note="second report of the same campaign",
    )
    assert (t.to_state, t.assignee) == ("open", None)


def test_reporters_never_work_the_queue():
    _raises(
        NotPermitted,
        action="claim",
        state="open",
        actor=REPORTER[0],
        actor_role="reporter",
        assignee=None,
    )


def test_every_action_state_pair_is_either_allowed_or_refused_explicitly():
    """No combination falls through silently."""
    for state in workflow.CASE_STATES:
        for action in workflow.ACTIONS:
            try:
                t = decide(
                    action=action,
                    state=state,
                    actor=ADMIN[0],
                    actor_role="admin",
                    assignee=ADMIN[0],
                    resolution="confirmed_phishing",
                    note="n",
                )
            except workflow.WorkflowError as exc:
                assert exc.status in (403, 409)
            else:
                assert t.to_state in workflow.CASE_STATES


def test_priorities_follow_how_urgent_the_case_is():
    assert workflow.priority_for("user_report", "ALLOW") == 1
    assert workflow.priority_for("model_review", "REVIEW") == 2
    assert workflow.priority_for("user_report", "REVIEW") == 2
    assert workflow.priority_for("user_report", "BLOCK") == 3
    assert workflow.sla_due(1000.0, 1) == 1000.0 + 3600


def test_reporter_status_never_mentions_a_score():
    for state in workflow.CASE_STATES:
        for resolution in (None, *workflow.RESOLUTIONS):
            text = workflow.reporter_status(state, resolution).lower()
            assert "score" not in text and "%" not in text and "0." not in text


# --------------------------------------------------------- through the service
def _service():
    from phishguard.service.scanning import ScanService
    from phishguard.service.store import DecisionStore
    from tests.helpers import trained_detector

    detector, settings = trained_detector()
    store = DecisionStore(Path(tempfile.mkdtemp(prefix="pg-queue-")) / "audit.db")
    return ScanService(detector, store, settings), store, detector


def _principal(pair):
    from phishguard.service.security import Principal

    return Principal(key_id=pair[0], role=pair[1])


def _held_message(service):
    """Find a message the model routes to REVIEW (it opens a case by itself)."""
    from phishguard.service.contracts import ScanRequest
    from tests.helpers import corpus

    messages, _ = corpus()
    for m in messages[:600]:
        req = ScanRequest(
            subject=m.subject,
            body=m.body,
            sender=m.sender,
            to=list(m.to),
            auth={"spf": m.auth.spf, "dkim": m.auth.dkim, "dmarc": m.auth.dmarc},
        )
        r = service.scan(req, principal=_principal(ANALYST_A))
        if r.band == "REVIEW":
            return r
    raise AssertionError("no REVIEW message in the first 600 of the corpus")


def test_a_review_decision_opens_a_p2_case_and_resolution_records_feedback():
    service, store, _ = _service()
    r = _held_message(service)
    page = service.list_cases(state="active")
    case = next(c for c in page.cases if c.decision_id == r.decision_id)
    assert (case.state, case.origin, case.priority) == ("open", "model_review", 2)
    assert not case.overdue

    a = _principal(ANALYST_A)
    from phishguard.service.contracts import CaseActionRequest

    detail = service.act_on_case(case.case_id, CaseActionRequest(action="claim"), principal=a)
    assert detail.state == "in_review" and detail.assignee == a.key_id
    assert "resolve:confirmed_phishing" in detail.allowed_actions
    detail = service.act_on_case(
        case.case_id,
        CaseActionRequest(
            action="resolve", resolution="confirmed_phishing", note="credential lure"
        ),
        principal=a,
    )
    assert (detail.state, detail.resolution) == ("resolved", "confirmed_phishing")
    assert [e.action for e in detail.events] == ["opened", "claim", "resolve"]
    assert [(e.from_state, e.to_state) for e in detail.events][1:] == [
        ("open", "in_review"),
        ("in_review", "resolved"),
    ]
    # The resolution is analyst feedback, recorded once.
    record = store.get_decision(r.decision_id)
    assert record["feedback_label"] == "phishing"
    stats = service.queue_stats()
    assert stats["by_state"]["resolved"] >= 1 and stats["resolutions"]["confirmed_phishing"] >= 1


def test_a_second_analyst_cannot_steal_a_claimed_case():
    from phishguard.service.contracts import CaseActionRequest

    service, _, _ = _service()
    r = _held_message(service)
    case = next(c for c in service.list_cases().cases if c.decision_id == r.decision_id)
    service.act_on_case(
        case.case_id, CaseActionRequest(action="claim"), principal=_principal(ANALYST_A)
    )
    try:
        service.act_on_case(
            case.case_id, CaseActionRequest(action="claim"), principal=_principal(ANALYST_B)
        )
    except workflow.InvalidTransition:
        pass
    else:
        raise AssertionError("a claimed case was claimed twice")


def test_the_store_refuses_a_stale_transition():
    """Two analysts validating against the same state: only one update wins."""
    service, store, _ = _service()
    r = _held_message(service)
    case_id = next(c.case_id for c in service.list_cases().cases if c.decision_id == r.decision_id)
    kwargs = dict(
        case_id=case_id,
        expected_state="open",
        to_state="in_review",
        resolution=None,
        action="claim",
        actor_role="analyst",
    )
    assert store.apply_transition(assignee=ANALYST_A[0], actor=ANALYST_A[0], **kwargs)
    assert not store.apply_transition(assignee=ANALYST_B[0], actor=ANALYST_B[0], **kwargs)


def test_a_user_report_is_queued_without_revealing_the_score():
    from phishguard.service.contracts import ReportRequest, ScanRequest
    from tests.helpers import ham_message

    service, _, _ = _service()
    ham = ham_message()
    reporter = _principal(REPORTER)
    receipt = service.report(
        ReportRequest(
            message=ScanRequest(subject=ham.subject, body=ham.body, sender=ham.sender),
            category="impersonation",
            note="unexpected tone",
            reporter_ref="user-42@corp.example",
        ),
        principal=reporter,
    )
    dumped = receipt.model_dump()
    assert set(dumped) == {"case_id", "received_at", "status", "message"}
    assert "score" not in receipt.message.lower()

    case = service.get_case(receipt.case_id)
    assert case.origin == "user_report" and case.report_category == "impersonation"
    assert case.priority in (1, 2, 3)
    mine = service.my_reports(principal=reporter, reporter_ref="user-42@corp.example")
    assert [r.case_id for r in mine.reports] == [receipt.case_id]
    # Another reporter identity sees nothing of it.
    other = service.my_reports(principal=reporter, reporter_ref="someone-else@corp.example")
    assert other.reports == []
    # The reporter identity is stored only as a digest.
    import sqlite3

    raw = (
        sqlite3.connect(service.store.path)
        .execute("SELECT reporter_px FROM cases WHERE case_id = ?", (receipt.case_id,))
        .fetchone()[0]
    )
    assert raw and "user-42" not in raw


def test_a_reported_message_the_model_allowed_jumps_the_queue():
    from phishguard.service.contracts import ReportRequest, ScanRequest
    from tests.helpers import ham_message

    service, _, _ = _service()
    ham = ham_message()
    receipt = service.report(
        ReportRequest(
            message=ScanRequest(
                subject=ham.subject,
                body=ham.body,
                sender=ham.sender,
                auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            )
        ),
        principal=_principal(REPORTER),
    )
    case = service.get_case(receipt.case_id)
    if case.band == "ALLOW":
        assert case.priority == 1
        assert service.list_cases().cases[0].case_id == receipt.case_id


def test_an_old_store_is_upgraded_in_place():
    import sqlite3

    from phishguard.service.store import SCHEMA_VERSION, DecisionStore

    path = Path(tempfile.mkdtemp(prefix="pg-old-db-")) / "audit.db"
    conn = sqlite3.connect(path)
    # The version-1 decisions table, exactly as the first release created it.
    conn.executescript(
        "CREATE TABLE schema_version (version INTEGER NOT NULL);"
        "INSERT INTO schema_version VALUES (1);"
        "CREATE TABLE decisions (decision_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL, created_ts REAL NOT NULL, score REAL NOT NULL, "
        "band TEXT NOT NULL, label INTEGER NOT NULL, model_version TEXT NOT NULL, "
        "subject_hash TEXT NOT NULL DEFAULT '', sender_px TEXT NOT NULL DEFAULT '', "
        "sender_domain TEXT NOT NULL DEFAULT '', recipient_count INTEGER NOT NULL DEFAULT 0, "
        "body_length INTEGER NOT NULL DEFAULT 0, attachment_count INTEGER NOT NULL DEFAULT 0, "
        "behavioral_available INTEGER NOT NULL DEFAULT 0, latency_ms REAL NOT NULL DEFAULT 0, "
        "member_scores TEXT NOT NULL DEFAULT '{}', top_evidence TEXT NOT NULL DEFAULT '[]', "
        "key_id TEXT NOT NULL DEFAULT '', client_reference TEXT NOT NULL DEFAULT '');"
        "INSERT INTO decisions (decision_id, request_id, created_at, created_ts, score, band, "
        "label, model_version) VALUES ('dec_old', 'req_old', '2026-01-01', 1.0, 0.5, "
        "'REVIEW', 1, 'pg-old');"
    )
    conn.commit()
    conn.close()
    store = DecisionStore(path)
    assert store.schema_version() == SCHEMA_VERSION
    columns = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(decisions)")}
    assert "trace_id" in columns
    assert store.list_cases()[1] == 0
    assert store.get_decision("dec_old")["band"] == "REVIEW"  # old rows survive
