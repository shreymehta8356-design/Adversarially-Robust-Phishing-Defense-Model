# ADR-007: Model the review queue as an explicit state machine with object-level authorisation

- **Status**: Accepted
- **Date**: 2026-09-22
- **Deciders**: Capstone team (BAI-17)

## Context

ADR-006 created a REVIEW band: messages the model is unsure about are held for
a person instead of being auto-decided. That band is only a control if someone
actually looks at the message. Before this decision, "the analyst queue" was a
filter over the decision history. It could not answer four questions an
operator asks every shift:

1. Which held messages are still waiting, and for how long?
2. Who is looking at this one right now?
3. Who released that message, when, and why?
4. What happened to the message an employee reported last Tuesday?

It also left the most sensitive action in the system — releasing a held message
to its recipient — open to any analyst key, with no owner and no reason
recorded. Releasing a message the model was confident about is exactly what a
social engineer phoning the SOC wants an analyst to do.

The portfolio asks for an operational workflow with "realistic state
transitions and role-based user journeys", and the stakeholder analysis
(docs/01 §1.2) makes the reporting journey — an employee flags a message and
learns the outcome — part of the problem, not an extra.

## Decision

Every REVIEW decision and every user report becomes a **case** with one of four
states — `open`, `in_review`, `escalated`, `resolved` — a priority, a service
level and, once claimed, an owner. Transitions are defined in one pure module,
`service/workflow.py`, with no storage and no HTTP, so every rule is a unit
test. The store applies a transition only if the case is still in the state the
decision was made against (compare-and-set), so concurrent or stale actions are
refused rather than lost.

Three rules carry the security weight:

- **Object-level authorisation** (OWASP API1:2023). Only the analyst who
  claimed a case, or an administrator, may release, resolve or escalate it.
- **High-risk release needs an administrator.** Releasing a message scored at
  or above the block threshold requires the `admin` role and a written reason.
- **Every transition is an audit event** with actor, role, both states and the
  note; resolving also records analyst feedback, which feeds the disagreement
  metric and never retrains anything automatically (`OOS-3`).

A third API role, `reporter`, may submit a report and read its own reports.
It is told what happened in plain words and is never shown a score or band,
because a reporting endpoint that returned the verdict would be a free scoring
oracle.

Priorities encode urgency, not score: P1 (1 hour) for a report on mail the model
allowed — possibly a phish in inboxes now; P2 (4 hours) for a held message; P3
(24 hours) for a report on mail already blocked.

## Alternatives considered

### Keep the queue as a view over decisions, add an "assignee" column

The smallest change: no new tables, no state machine. Rejected because the
rules that matter are about *transitions* — who may move a case from where to
where — and a column cannot express them. Without explicit states, "released"
and "never looked at" are indistinguishable in the data, which is precisely the
distinction an auditor needs.

### Use an external ticketing system (Jira, ServiceNow, TheHive)

Real SOCs do this, and it brings SLAs, dashboards and on-call integration for
free. Rejected for the MVP because it adds a service the deployment guide would
have to install, and because the authorisation rule that matters most — a
high-risk release needs an administrator — depends on the model's score, which
the ticketing system does not know. The case API is deliberately shaped so that
a connector can mirror cases into a ticketing system later without moving the
rules out of PhishGuard.

### A general workflow engine

A BPMN engine or a state-machine library would make the lifecycle configurable.
Rejected: seven transitions do not justify a dependency, and a configurable
lifecycle is a lifecycle an administrator can misconfigure into allowing an
unowned release. The table of transitions fits on one screen and is tested
exhaustively (`test_every_action_state_pair_is_either_allowed_or_refused_explicitly`).

## Consequences

- A held message now has an owner, an age and a deadline; overdue cases are a
  Prometheus gauge with an alert rule, so "nobody is reading the queue" is
  detectable rather than discovered after an incident.
- Queue outcomes become labelled data (analyst feedback) as a side effect of
  doing the job, without opening a poisoning path.
- The API surface grows by six endpoints and one role, each covered by tests.
- The database gains two tables and a schema version; older databases are
  migrated in place on start-up.

## When to revisit

If the organisation adopts a case-management platform, mirror cases into it and
keep the authorisation rules here. If more than one team works the queue,
add queue ownership by team before adding anything else.
