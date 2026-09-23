"""The review queue: cases, their states, and who may move them.

A REVIEW band is a promise that a person will look at the message. Without an
explicit lifecycle that promise is unenforceable: nobody can say which held
messages are waiting, who is looking at one, how long it has waited, or who
decided to release it. This module is that lifecycle, as a small state machine
with no storage and no HTTP, so every rule in it is unit-testable.

States
------
``open``        waiting for an analyst
``in_review``   claimed by one analyst, who now owns it
``escalated``   handed to an administrator (incident response)
``resolved``    decided: ``confirmed_phishing`` or ``released``

Transitions
-----------
===========  ======================  ============  =========================
action       from                    to            who
===========  ======================  ============  =========================
claim        open                    in_review     analyst
unclaim      in_review               open          the assignee, or admin
escalate     in_review               escalated     the assignee, or admin
resolve      in_review               resolved      the assignee, or admin
resolve      escalated               resolved      admin
reopen       resolved                open          admin
comment      any                     (unchanged)   analyst
===========  ======================  ============  =========================

Three rules carry most of the security weight:

* **Object-level authorisation** (OWASP API1). Owning a case is a permission.
  An analyst cannot resolve, release or escalate a case another analyst has
  claimed; only its assignee or an administrator can.
* **High-risk release needs an administrator.** Releasing a message the model
  scored at or above the block threshold delivers something the model was
  confident is phishing. That is the one action in the queue an attacker would
  most like an analyst to take, so it requires the ``admin`` role.
* **Every transition is an audit event**, with the actor, the role, the states
  on either side and the reason. Resolving a case also records analyst feedback,
  so queue outcomes feed the disagreement metrics without a second step.

Priority and service levels
---------------------------
=====  ==========================================================  ========
P1     A user reported a message the model *allowed*: possibly a     1 hour
       phish sitting in inboxes now
P2     A message held for review (by the model, or reported while    4 hours
       held): a recipient is waiting
P3     A user reported a message the model already blocked           24 hours
=====  ==========================================================  ========
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

CaseState = Literal["open", "in_review", "escalated", "resolved"]
CaseAction = Literal["claim", "unclaim", "escalate", "resolve", "reopen", "comment"]
Resolution = Literal["confirmed_phishing", "released"]
Origin = Literal["model_review", "user_report"]

CASE_STATES: tuple[str, ...] = ("open", "in_review", "escalated", "resolved")
ACTIVE_STATES: tuple[str, ...] = ("open", "in_review", "escalated")
ACTIONS: tuple[str, ...] = ("claim", "unclaim", "escalate", "resolve", "reopen", "comment")
RESOLUTIONS: tuple[str, ...] = ("confirmed_phishing", "released")

#: Service level per priority, in seconds.
SLA_SECONDS: dict[int, int] = {1: 3600, 2: 4 * 3600, 3: 24 * 3600}

#: The analyst label a resolution implies, recorded as feedback.
RESOLUTION_LABEL: dict[str, str] = {
    "confirmed_phishing": "phishing",
    "released": "legitimate",
}

_ROLE_RANK = {"reporter": 1, "analyst": 2, "admin": 3}


class WorkflowError(Exception):
    """Base class; carries an HTTP-like status for the API layer."""

    status = 400


class InvalidTransition(WorkflowError):
    """The action is not allowed from the case's current state."""

    status = 409


class NotPermitted(WorkflowError):
    """The caller's role or ownership does not allow this action."""

    status = 403


@dataclass(frozen=True, slots=True)
class Transition:
    """The outcome of a permitted action."""

    action: str
    from_state: str
    to_state: str
    assignee: str | None
    resolution: str | None


def priority_for(origin: str, band: str) -> int:
    """Queue priority from how the case arose and what the model decided."""
    if origin == "user_report" and band == "ALLOW":
        return 1  # the model delivered it: possibly a phish in inboxes now
    if band == "REVIEW":
        return 2  # held for a decision: a recipient is waiting
    return 3  # a report on mail the model already blocked


def sla_due(created_ts: float, priority: int) -> float:
    return created_ts + SLA_SECONDS.get(priority, SLA_SECONDS[3])


def _at_least(role: str, required: str) -> bool:
    return _ROLE_RANK.get(role, 0) >= _ROLE_RANK[required]


def decide(
    *,
    action: str,
    state: str,
    actor: str,
    actor_role: str,
    assignee: str | None,
    resolution: str | None = None,
    note: str = "",
    score: float = 0.0,
    block_threshold: float = 0.8,
) -> Transition:
    """Validate one action against the state machine and return its outcome.

    Raises :class:`InvalidTransition` for an action the state does not allow
    and :class:`NotPermitted` for a caller who may not take it. Never mutates
    anything: the caller persists the returned transition.
    """
    if action not in ACTIONS:
        raise InvalidTransition(f"unknown action {action!r}")
    if state not in CASE_STATES:
        raise InvalidTransition(f"case is in an unknown state {state!r}")
    if not _at_least(actor_role, "analyst"):
        raise NotPermitted("only analysts and administrators work the review queue")
    is_admin = _at_least(actor_role, "admin")
    owns = assignee is not None and assignee == actor

    if action == "comment":
        if not note.strip():
            raise InvalidTransition("a comment needs a note")
        return Transition(action, state, state, assignee, None)

    if action == "claim":
        if state != "open":
            raise InvalidTransition(f"only an open case can be claimed (this one is {state})")
        return Transition(action, state, "in_review", actor, None)

    if action == "unclaim":
        if state != "in_review":
            raise InvalidTransition(f"only a case in review can be released (this one is {state})")
        if not (owns or is_admin):
            raise NotPermitted(
                "only the analyst who claimed this case, or an admin, can release it"
            )
        return Transition(action, state, "open", None, None)

    if action == "escalate":
        if state != "in_review":
            raise InvalidTransition(f"only a case in review can be escalated (this one is {state})")
        if not (owns or is_admin):
            raise NotPermitted(
                "only the analyst who claimed this case, or an admin, can escalate it"
            )
        if not note.strip():
            raise InvalidTransition("say why the case is being escalated")
        return Transition(action, state, "escalated", assignee, None)

    if action == "resolve":
        if resolution not in RESOLUTIONS:
            raise InvalidTransition(f"resolution must be one of {', '.join(RESOLUTIONS)}")
        if state == "escalated":
            if not is_admin:
                raise NotPermitted("an escalated case is resolved by an administrator")
        elif state == "in_review":
            if not (owns or is_admin):
                raise NotPermitted(
                    "only the analyst who claimed this case, or an admin, can resolve it"
                )
        else:
            raise InvalidTransition(
                f"a case must be claimed before it is resolved (this one is {state})"
            )
        if resolution == "released":
            if not note.strip():
                raise InvalidTransition("releasing a held message needs a reason")
            if score >= block_threshold and not is_admin:
                raise NotPermitted(
                    f"the model scored this message {score:.2f}, at or above the block "
                    f"threshold ({block_threshold:.2f}); releasing it needs an administrator"
                )
        return Transition(action, state, "resolved", assignee or actor, resolution)

    # action == "reopen"
    if state != "resolved":
        raise InvalidTransition(f"only a resolved case can be reopened (this one is {state})")
    if not is_admin:
        raise NotPermitted("reopening a decided case needs an administrator")
    if not note.strip():
        raise InvalidTransition("say why the case is being reopened")
    return Transition(action, state, "open", None, None)


#: What a reporter is told about their report. Deliberately free of scores:
#: a reporting endpoint that returned the model's verdict would be a scoring
#: oracle for anyone holding a reporter key.
REPORTER_MESSAGES: dict[str, str] = {
    "open": "Received. The security team will review it.",
    "in_review": "An analyst is reviewing it now.",
    "escalated": "It has been passed to the incident-response team.",
    "confirmed_phishing": "Confirmed as phishing and removed. Thank you - reporting it helped.",
    "released": "Reviewed and found to be safe. It has been delivered normally.",
}


def reporter_status(state: str, resolution: str | None) -> str:
    if state == "resolved" and resolution:
        return REPORTER_MESSAGES.get(resolution, "Reviewed.")
    return REPORTER_MESSAGES.get(state, "Received.")
