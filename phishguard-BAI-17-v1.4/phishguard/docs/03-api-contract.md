# 3. API and data contracts

The published interface. Generated from the same pydantic models the service
validates against, so this document cannot drift from the implementation: run
`make openapi` for the machine-readable version.

---

## 3.1 Conventions

**Base URL** `http://localhost:8000` (compose default)
**Content type** `application/json` on every endpoint except `/metrics`
**Authentication** `X-API-Key: <key>` header on every `/api/v1/*` endpoint

**Roles**

| Role | Who | May call |
|---|---|---|
| `reporter` | Any email user, through the report page or a mail-client add-in | `/reports`, `/reports/mine`, `/whoami` |
| `analyst` | SOC analysts, and the mail gateway's service key | everything a reporter may, plus `/scan`, `/scan/batch`, `/scan/url`, `/ingest`, `/feedback`, `/compare`, `/cases*`, `/model`, `/stats`, `/drift`, `/benchmark` |
| `admin` | Security engineers and the incident-response lead | everything an analyst may, plus `/decisions*`, `/adversarial/probe`, `/traces/recent`, releasing high-risk cases, resolving escalated cases and reopening resolved ones |

Roles are hierarchical: `admin` ⊃ `analyst` ⊃ `reporter`. The audit trail and
the adversarial probe are admin-gated for different reasons: the trail is an
oversight surface, and the probe is a genuine offensive capability — it tells
the caller which edits lower the score, which is exactly what a defender needs
and exactly what an attacker would want. The reporter role is the narrowest on
purpose: it can report and read its own reports, and it is never shown a score
(misuse case M9).

**Correlation and tracing.** Every response carries:

| Header | Meaning |
|---|---|
| `X-Request-ID` | Send your own to have it echoed; otherwise one is generated. In the logs and on the audit record |
| `traceparent` | [W3C Trace Context](https://www.w3.org/TR/trace-context-1/). Send one and PhishGuard joins your trace; otherwise it starts one. The trace id is on the audit record and in the response body as `trace_id` |
| `Server-Timing` | Per-stage durations in milliseconds, readable in any browser's developer tools |
| `X-Response-Time-ms` | End-to-end time inside the service |

**Errors.** Uniform shape:

```json
{ "error": "...", "detail": "...", "request_id": "req_a1b2c3d4e5f6a7b8c9d0" }
```

| Status | Meaning |
|---|---|
| `400` / `422` | Malformed body, or a field outside its declared bounds |
| `401` | Missing or invalid API key |
| `403` | Authenticated, but the role is insufficient — or, on a case, this caller may not take this action (someone else owns it; a high-risk release needs an admin) |
| `404` | No such decision or case |
| `409` | The case's current state does not allow the action — including a claim another analyst won first |
| `413` | Body exceeds `PG_MAX_BODY_BYTES` |
| `429` | Rate limit exceeded; `Retry-After` header is set |
| `503` | No model loaded — see `/readyz` for the reason |

## 3.2 Operational endpoints

### `GET /healthz` — liveness

Never touches the model, so it stays useful when the model is the thing that
is broken.

```json
{
  "status": "ok",
  "version": "1.3.0",
  "model_loaded": true,
  "model_version": "pg-0e0dffa24f",
  "uptime_seconds": 1284.3
}
```

### `GET /readyz` — readiness

`200` when a model is loaded; `503` with the reason when not. This is the
distinction an orchestrator needs: a service that is alive but cannot serve
should stop receiving traffic without being restarted.

```json
{ "status": "not ready", "reason": "no model found under /data/models",
  "hint": "run 'phishguard train --save'" }
```

### `GET /metrics` — Prometheus exposition

`text/plain; version=0.0.4`. See [§3.7](#37-metrics).

## 3.3 `POST /api/v1/scan`

Assess one message. Requires `analyst`.

### Request

| Field | Type | Default | Bound | Notes |
|---|---|---|---|---|
| `subject` | string | `""` | ≤ 2 000 | |
| `body` | string | `""` | ≤ 200 000 | Plain-text part |
| `html_body` | string | `""` | ≤ 400 000 | HTML part; link-text/href mismatch is scored from it |
| `sender` | string | `""` | ≤ 512 | `Display Name <addr@domain>` or a bare address |
| `reply_to` | string | `""` | ≤ 512 | |
| `return_path` | string | `""` | ≤ 512 | Envelope sender |
| `to` | string[] | `[]` | ≤ 200 items | |
| `attachments` | object[] | `[]` | ≤ 50 items | **Metadata only** — content is never accepted |
| `auth` | object | all `none` | | `spf`, `dkim`, `dmarc` ∈ `pass \| fail \| softfail \| neutral \| none \| temperror \| permerror` |
| `behavioral` | object \| null | `null` | | Omit when unavailable; see below |
| `received_at` | datetime | now | | ISO-8601 |
| `received_hops` | int | `2` | 0–100 | `Received:` header count |
| `client_reference` | string | `""` | ≤ 128 | Echoed back for correlation |

Unknown fields are **rejected**, not ignored: a typo in an integration should
fail loudly at the boundary rather than silently disable a signal.

**`attachments[]`** — `filename` (≤ 512), `content_type` (≤ 255),
`size_bytes` (0 – 10¹⁰).

**`behavioral`** — omit the whole object when the gateway has no sender history.
The system does not invent it: the response sets `behavioral_available: false`
and the evidence list says so explicitly.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sender_first_seen` | bool | `true` | First message from this sender to this recipient |
| `prior_messages_from_sender` | int | `0` | |
| `prior_replies_to_sender` | int | `0` | Two-way history is much stronger evidence than one-way |
| `thread_depth` | int | `0` | 0 for a new thread |
| `hour_local` | int | `12` | 0–23, recipient's local time |
| `is_weekend` | bool | `false` | |
| `recipient_count` | int | `1` | |
| `bcc_count` | int | `0` | |
| `external_sender` | bool | `true` | |
| `domain_report_count` | int | `0` | Prior user reports against this domain |
| `domain_click_rate` | float | `0.0` | 0–1, historic click-through on links from this domain |
| `burst_count_1h` | int | `1` | Messages from this domain in the last hour |
| `display_name_alias_count` | int | `1` | Distinct addresses that have used this display name |
| `domain_age_days` | int | `0` | 0 = unknown or newly registered |

### Example

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-analyst-key-change-me' \
  -d '{
    "subject": "URGENT: Your Microsoft 365 account will be suspended",
    "body": "Dear Customer,\n\nVerify your identity within 24 hours:\nhttp://microsoft-verify-9f2x.tk/account/login\n\nMicrosoft Security Team",
    "sender": "Microsoft 365 Security <security@microsoft-verify-9f2x.tk>",
    "reply_to": "recovery.team@mail.ru",
    "to": ["victim@corp.example"],
    "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
    "behavioral": {
      "sender_first_seen": true, "prior_messages_from_sender": 0,
      "hour_local": 3, "domain_age_days": 4, "burst_count_1h": 220,
      "display_name_alias_count": 6
    }
  }'
```

### Response

```json
{
  "request_id": "req_9f2a...",
  "decision_id": "dec_4573d288ad70...",
  "score": 0.99,
  "band": "BLOCK",
  "label": 1,
  "model_version": "pg-0e0dffa24f",
  "evidence": [
    {
      "kind": "context", "id": "destination",
      "title": "Primary link resolves to microsoft-verify-9f2x.tk",
      "detail": "http://microsoft-verify-9f2x.tk/account/login",
      "direction": "neutral", "weight": 0.0
    },
    {
      "kind": "rule", "id": "R09",
      "title": "A link impersonates a brand it does not belong to",
      "detail": "link_any_brand_impersonation = 1",
      "direction": "phishing", "weight": 0.9
    },
    {
      "kind": "feature", "id": "beh_young_domain",
      "title": "Sending domain was registered recently",
      "detail": "score would change by -0.043 if this were normal",
      "direction": "phishing", "weight": 0.043
    }
  ],
  "signals": {
    "raw_fusion": 0.998, "trust_deficit": 1.0,
    "review_threshold": 0.4, "block_threshold": 0.8
  },
  "member_scores": {
    "rules": 1.0, "engineered": 1.0, "charngram": 0.968, "wordtfidf": 0.964
  },
  "defenses_applied": ["D-NORM", "D-URL", "D-ADVTRAIN", "D-ENSEMBLE",
                       "D-ABSTAIN", "D-VELOCITY"],
  "behavioral_available": true,
  "abstained": false,
  "latency_ms": 27.1,
  "client_reference": "",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "stage_ms": {
    "member.rules": 1.01, "member.engineered": 2.65, "member.charngram": 0.95,
    "member.wordtfidf": 0.53, "fusion": 0.19, "explain": 4.23,
    "assess": 9.73, "audit.write": 0.23
  }
}
```

With the headers (a caller that sent its own `traceparent` keeps its trace id):

```http
HTTP/1.1 200 OK
X-Request-ID: req_9f2a...
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-802015535f26fb66-01
Server-Timing: member.rules;dur=1.01, member.engineered;dur=2.65, member.charngram;dur=0.95, member.wordtfidf;dur=0.53, fusion;dur=0.19, explain;dur=4.23, assess;dur=9.73, audit.write;dur=0.23, total;dur=10.11
X-Response-Time-ms: 10.62
```

`stage_ms` is where a slow request spent its time. `explain` is usually the
largest stage, because counterfactual evidence re-scores the engineered member
with each candidate feature set to its normal value. The single-message
endpoint always explains, because an analyst reads its output; the batch
endpoint does not unless the request sets `"explain": true`, which is why batch
throughput is materially higher.

**Evidence items.** `kind` ∈ `rule | feature | member | token | defense |
context`. `direction` ∈ `phishing | legitimate | neutral` — mitigating evidence
is included, because a reviewer needs both sides. `weight` orders the list;
`context` items carry weight 0 and are pinned so that caveats are never
truncated away.

**Bands.** `ALLOW` deliver · `REVIEW` queue for an analyst · `BLOCK` quarantine.
`abstained` is `true` exactly when `band == "REVIEW"`.

## 3.4 Other scanning endpoints

### `POST /api/v1/scan/batch`

`{"messages": [<ScanRequest>, ...], "explain": false}` — 1 to 100 messages.
Each is audited individually. Returns `{request_id, results[], total_latency_ms}`.

### `POST /api/v1/scan/url`

`{"url": "...", "client_reference": ""}` — for click-time protection.

Deliberately **rule-based, not model-based**, and the response says so: the
trained model expects a message, and inventing a synthetic one around a bare
URL would produce a confident number with nothing behind it. A transparent
weighted score over the URL family is the honest answer to "here is a URL and
nothing else".

```json
{
  "url": "http://paypa1-secure.tk/account/login",
  "canonical_url": "http://paypa1-secure.tk/account/login",
  "registered_domain": "paypa1-secure.tk",
  "risk_score": 0.68, "band": "REVIEW",
  "reasons": [
    "Impersonates a brand it does not belong to",
    "Top-level domain has a high abuse rate",
    "Path contains 2 credential-page keywords"
  ]
}
```

### `POST /api/v1/ingest`

Import real mail: one saved message (`.eml`) or a whole mailbox (`.mbox`),
sent as the **raw request body** rather than as JSON — `Content-Type:
message/rfc822` or `application/mbox`, with the file name in `X-Filename`.
No multipart parser is involved, and the body limit for this one endpoint is
`PG_MAX_UPLOAD_BYTES` (default 50 MB) instead of the usual 1 MB.

```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "X-API-Key: $KEY" -H "Content-Type: message/rfc822" -H "X-Filename: saved.eml" \
  --data-binary @saved.eml
```

Every message goes through the same path as `/scan`: it is audited, and a
REVIEW verdict opens a case. Messages arrive without behavioural context, and
each verdict says so.

```json
{
  "request_id": "req_...", "source": "upload:saved.eml",
  "received": 2, "allow": 1, "review": 0, "block": 1, "failed": 0, "seconds": 0.21,
  "results": [
    {"index": 0, "subject": "Your account has been limited", "sender": "PayPal <service@paypa1-secure-login.com>",
     "band": "BLOCK", "score": 1.0, "decision_id": "dec_...",
     "top_reason": "A link impersonates a brand it does not belong to"}
  ]
}
```

`422` when the body is not a readable message (no `From` or `Subject` header,
or an empty mbox). The `phishguard import` and `phishguard inbox` commands use
the same code path from the command line and an IMAP mailbox respectively.

## 3.5 Oversight endpoints

### `POST /api/v1/feedback`

```json
{ "decision_id": "dec_...", "analyst_label": "phishing|legitimate|unsure",
  "rationale": "", "action_taken": "" }
```

`404` if the decision is unknown. The response repeats the important part:

> Recorded for review. Feedback is never used to retrain automatically: an
> endpoint that could move the decision boundary would be a poisoning vector,
> so retraining stays a reviewed action.

### `GET /api/v1/decisions` — admin

Query: `limit` (1–500, default 50), `offset`, `band`, `sender_domain`,
`min_score`.

Every row is content-free by construction:

```json
{
  "items": [{
    "decision_id": "dec_...", "created_at": "2026-09-07T20:31:44.812+00:00",
    "score": 0.99, "band": "BLOCK", "model_version": "pg-0e0dffa24f",
    "subject_hash": "0e7edf49a983a030",
    "sender_px": "px_c65347ea907cc63c5a3a",
    "sender_domain": "microsoft-verify-9f2x.tk",
    "recipient_count": 1, "body_length": 214, "attachment_count": 0,
    "behavioral_available": true, "latency_ms": 27.1,
    "top_evidence": ["A link impersonates a brand it does not belong to"],
    "feedback_label": "phishing"
  }],
  "total": 1, "limit": 50, "offset": 0
}
```

`subject_hash` is a truncated SHA-256 of the subject; `sender_px` is a salted,
non-reversible sender identifier that still supports correlating repeat senders.

### `GET /api/v1/decisions/{decision_id}` — admin

One record, or `404`.

## 3.6 Model and monitoring

### `GET /api/v1/model`

Model card data: version, members, feature families, active defences,
thresholds, calibration method, the full **attack taxonomy** and the
**defence catalogue**, plus the metrics recorded at training time.

### `GET /api/v1/stats`

Query: `window_hours` (1–720, default 24).

```json
{
  "decisions": 1428, "mean_score": 0.41, "mean_latency_ms": 11.2,
  "bands": {"ALLOW": 812, "REVIEW": 44, "BLOCK": 572},
  "top_sender_domains": [{"domain": "...", "count": 61, "mean_score": 0.93}],
  "feedback": {"phishing": 18, "legitimate": 3},
  "analyst_disagreements": 3,
  "score_distribution": [{"lower": 0.0, "upper": 0.1, "count": 690}]
}
```

`analyst_disagreements` counts decisions where an analyst's label contradicted
the band. It is the most useful drift signal the service can produce from its
own data, and it is what the retraining trigger in the model card refers to.

### `GET /api/v1/drift`

Query: `window_hours` (1–2160, default 24). Compares the decisions in the
window with the legitimate-mail reference the model captured at training,
using only the audit trail's content-free columns.

```json
{
  "available": true, "n_reference": 1550, "n_live": 400, "window_hours": 168,
  "status": "significant",
  "worst": {"quantity": "member:charngram", "psi": 0.535, "severity": "significant",
            "ks_statistic": 0.21, "ks_p_value": 1.2e-9,
            "reference_mean": 0.050, "live_mean": 0.228},
  "quantities": [ "... one row per monitored quantity, largest shift first ..." ],
  "thresholds": {"moderate": 0.3614, "significant": 0.4995, "null_median": 0.1695,
                 "source": "calibrated: 95th/99th percentile of the worst-quantity PSI of 400 stable windows of 400 messages made of whole, held-out campaigns"},
  "textbook_thresholds": {"moderate": 0.1, "significant": 0.25},
  "live_band_shares": {"ALLOW": 0.688, "REVIEW": 0.233, "BLOCK": 0.08},
  "advice": "Investigate the source of the shift, check analyst disagreement (`phishguard feedback`), and plan a retrain on recent data."
}
```

With fewer than 30 decisions in the window, or a model saved before
monitoring existed, the response is `{"available": false, "reason": "..."}`
rather than a verdict. `status` is `stable`, `moderate` (above the 95th
percentile of stable windows — watch) or `significant` (above the 99th —
act); §9.12 says what to do about each.

### `POST /api/v1/compare`

Same body as `/scan`. Scores the message with the full system and with a
text-only filter (TF-IDF + logistic regression) trained on the same corpus,
and returns both side by side: `{"phishguard": {...}, "text_only": {...}}`,
each with a score, a band and — for PhishGuard — the member scores and
evidence. It explains rather than decides, so it is **not** written to the
audit trail.

### `GET /api/v1/benchmark`

The most recent PG-HARD run written by `phishguard hard` (or
`phishguard evaluate`): per-system silent-delivery and false-block rates, and
the case-by-case table. `{"available": false, ...}` until one has been run.

### `POST /api/v1/adversarial/probe` — admin

```json
{ "message": <ScanRequest>, "budget": 12, "families": ["A-URL", "A-UNI"] }
```

Runs the budgeted attack suite against this one message and reports how far an
attacker could move it:

```json
{
  "original_score": 0.998, "final_score": 0.971, "evaded": false,
  "queries": 12, "steps": ["A-UNI-01", "A-URL-03"],
  "families_used": ["A-UNI", "A-URL"],
  "trajectory": [0.998, 0.982, 0.971],
  "interpretation": "Held, but the score fell 0.027 under attack (A-UNI-01, A-URL-03). The margin is thinner than the clean score suggests."
}
```

## 3.7 Metrics

| Metric | Type | Labels |
|---|---|---|
| `phishguard_requests_total` | counter | `endpoint`, `method`, `status` |
| `phishguard_request_duration_ms` | histogram | `endpoint` |
| `phishguard_scans_total` | counter | `band` |
| `phishguard_scan_duration_ms` | histogram | |
| `phishguard_score` | histogram | |
| `phishguard_feedback_total` | counter | `label` |
| `phishguard_auth_failures_total` | counter | `reason` |
| `phishguard_rate_limited_total` | counter | |
| `phishguard_behavioral_context_total` | counter | `available` |
| `phishguard_adversarial_probes_total` | counter | `evaded` |
| `phishguard_model_info` | gauge | `model_version`, `calibration` |
| `phishguard_uptime_seconds` | gauge | |
| `phishguard_stage_duration_ms` | histogram | `stage` — from request traces |
| `phishguard_cases_opened_total` | counter | `origin`, `priority` |
| `phishguard_case_actions_total` | counter | `action` |
| `phishguard_case_resolution_seconds` | histogram | |
| `phishguard_queue_depth` | gauge | `state` |
| `phishguard_queue_overdue` | gauge | |

## 3.8 The internal contract

Distinct from the HTTP contract and just as load-bearing: the **feature
contract** is the fixed, ordered list of 265 feature names, serialised into the
model manifest at save time and verified at load time.

```python
assembler.verify(manifest["training"]["feature_contract"])
# RuntimeError: feature contract mismatch between saved model and runtime:
#   1 missing, 0 unexpected (first missing: ['url_brand_squat'], ...)
```

Drift between training-time and serving-time features is the single most common
cause of a model that scores well offline and fails in production, and it fails
*silently* — the vector still has the right shape and the numbers still look
plausible. Making it a hard error at load time is the cheapest possible
insurance.

## 3.9 Reporting a suspicious message (email users)

### `POST /api/v1/reports` — reporter

An employee reports a message they think is phishing. It is assessed with the
same pipeline, audited, and **always** queued for an analyst. The receipt
carries a case id and a plain-language status — **never a score or band**,
because a reporting endpoint that returned the verdict would be a free scoring
oracle for anyone with a reporter key (misuse case M9).

```json
{
  "message": { "subject": "Action required: confirm your payroll details",
               "body": "Hello, Payroll is moving to a new portal ...",
               "sender": "HR Services <hr@payroll-hr-portal.co>" },
  "category": "payment_request",
  "note": "Asked me to change bank details",
  "reporter_ref": "u-10482"
}
```

| Field | Type | Notes |
|---|---|---|
| `message` | object | Same shape and bounds as `POST /scan` |
| `category` | enum | `suspicious_link`, `unexpected_attachment`, `impersonation`, `payment_request`, `other` |
| `note` | string ≤ 500 | Shown to the analyst on the case timeline |
| `reporter_ref` | string ≤ 128 | Optional opaque id (a mail client's user id). Stored only as a salted digest, so a shared reporter key can still show each person their own reports |

```json
{
  "case_id": "case_b264894f6e9aa6b8",
  "received_at": "2026-09-22T07:19:10.000+00:00",
  "status": "open",
  "message": "Received. The security team will review it."
}
```

The case's priority is set from what the model had decided: **P1** (1 hour) if
it had *allowed* the message — possibly a phish in inboxes now — **P2** (4 hours)
if it was held for review, **P3** (24 hours) if it was already blocked.

### `GET /api/v1/reports/mine` — reporter

The caller's own reports and what became of them. Query: `reporter_ref`
(optional), `limit` ≤ 200.

```json
{
  "reports": [
    { "case_id": "case_b264894f6e9aa6b8", "received_at": "2026-09-22T07:19:10.000+00:00",
      "category": "payment_request", "state": "resolved",
      "status": "Confirmed as phishing and removed. Thank you - reporting it helped." }
  ],
  "total": 1
}
```

| Case state | What the reporter is told |
|---|---|
| `open` | Received. The security team will review it. |
| `in_review` | An analyst is reviewing it now. |
| `escalated` | It has been passed to the incident-response team. |
| resolved, `confirmed_phishing` | Confirmed as phishing and removed. Thank you - reporting it helped. |
| resolved, `released` | Reviewed and found to be safe. It has been delivered normally. |

### `GET /api/v1/whoami` — reporter

`{"key_id": "k_r51b0e", "role": "reporter"}` — so a client can show the right
screens. The key id is a digest prefix; the key itself is never returned or
logged.

## 3.10 The review queue

Every REVIEW decision and every user report is a **case**. The lifecycle and
its authorisation rules are in [§2.9](02-architecture.md); this section is the
wire format. Cases contain **no message content** — the analyst sees the
verdict, the member scores, the evidence titles, the sender's domain and the
history, which is enough to decide and not enough to read anyone's mail.

### `GET /api/v1/cases` — analyst

Query: `state` (`active` = open, in review or escalated; `all`; or one state),
`priority` (1–3), `limit` ≤ 500, `offset`. Ordered by priority, then age.

```json
{
  "cases": [
    {
      "case_id": "case_b264894f6e9aa6b8",
      "decision_id": "dec_aa59891ee580407dfaad5baf",
      "created_at": "2026-09-22T07:19:10.000+00:00",
      "state": "open", "origin": "user_report", "priority": 3,
      "sla_due_at": "2026-09-23T07:19:10+00:00", "overdue": false, "age_seconds": 0.0,
      "assignee": null, "resolution": null,
      "score": 1.0, "band": "BLOCK", "sender_domain": "payroll-hr-portal.co",
      "top_evidence": ["Primary link resolves to payroll-hr-portal.co",
                       "No sender history was supplied with this message",
                       "Body asks for credentials", "Body applies deadline pressure"],
      "report_category": "payment_request",
      "model_version": "pg-0e0dffa24f",
      "trace_id": "7e7ebc8888eb98043416803add5fe4ed"
    }
  ],
  "total": 1, "limit": 50, "offset": 0
}
```

### `GET /api/v1/cases/{case_id}` — analyst

The summary above plus `member_scores`, the full `events` timeline and
`allowed_actions` — the actions **this caller** may take next, so a client shows
only the buttons that will work:

```json
{
  "state": "in_review", "assignee": "k_3f9a1c",
  "events": [
    { "at": "2026-09-22T07:19:10.000+00:00", "actor": "k_r51b0e", "actor_role": "reporter",
      "action": "opened", "from_state": null, "to_state": "open",
      "note": "Asked me to change bank details" },
    { "at": "2026-09-22T07:19:10.001+00:00", "actor": "k_3f9a1c", "actor_role": "analyst",
      "action": "claim", "from_state": "open", "to_state": "in_review", "note": "" }
  ],
  "allowed_actions": ["unclaim", "escalate", "resolve:confirmed_phishing", "comment"]
}
```

`resolve:released` is missing from that list because the model scored this
message at or above the block threshold: an analyst may confirm it, but
releasing it needs an administrator (misuse case M10).

### `POST /api/v1/cases/{case_id}/actions` — analyst

```json
{ "action": "resolve", "resolution": "confirmed_phishing",
  "note": "Look-alike payroll domain; confirmed with HR" }
```

| `action` | From state | Who | Needs |
|---|---|---|---|
| `claim` | `open` | any analyst | — |
| `unclaim` | `in_review` | the assignee, or an admin | — |
| `escalate` | `in_review` | the assignee, or an admin | `note` |
| `resolve` | `in_review` | the assignee, or an admin | `resolution`; `note` if `released` |
| `resolve` | `escalated` | admin | `resolution`; `note` if `released` |
| `reopen` | `resolved` | admin | `note` |
| `comment` | any | any analyst | `note` |

Releasing a message scored at or above the block threshold additionally needs
the admin role. The response is the updated case detail. Errors:

| Status | Example `detail` |
|---|---|
| `409` | `only an open case can be claimed (this one is in_review)` — another analyst claimed it first |
| `403` | `only the analyst who claimed this case, or an admin, can resolve it` |
| `403` | `the model scored this message 1.00, at or above the block threshold (0.80); releasing it needs an administrator` |
| `404` | `case not found` |

Resolving a case also records analyst feedback against the decision
(`confirmed_phishing` → `phishing`, `released` → `legitimate`), which feeds the
disagreement metric. Nothing is retrained automatically (`OOS-3`).

### `GET /api/v1/cases/stats` — analyst

Queue health over the last 30 days:

```json
{
  "by_state": { "open": 0, "in_review": 0, "escalated": 0, "resolved": 1 },
  "active_by_priority": { "P1": 0, "P2": 0, "P3": 0 },
  "overdue": 0,
  "resolved_in_window": 1,
  "resolutions": { "confirmed_phishing": 1, "released": 0 },
  "median_seconds_to_claim": 0.0,
  "median_seconds_to_resolve": 0.0,
  "resolved_within_sla": 1.0,
  "user_reports_resolved": 1,
  "user_report_precision": 1.0,
  "service_levels": { "P1": "1 h", "P2": "4 h", "P3": "24 h" }
}
```

## 3.11 Traces

### `GET /api/v1/traces/recent` — admin

The most recent request traces (at most 50 are kept in memory), newest first.
Timings and span names only — never content. Query: `limit` ≤ 50.

```json
{
  "traces": [
    {
      "trace_id": "7e7ebc8888eb98043416803add5fe4ed",
      "name": "scan", "started_at": "2026-09-22T07:19:09Z", "duration_ms": 10.108,
      "spans": [
        { "name": "assess", "start_ms": 0.007, "duration_ms": 9.731 },
        { "name": "member.rules", "start_ms": 0.023, "duration_ms": 1.011 },
        { "name": "member.engineered", "start_ms": 1.047, "duration_ms": 2.645 },
        { "name": "member.charngram", "start_ms": 3.716, "duration_ms": 0.951 },
        { "name": "member.wordtfidf", "start_ms": 4.679, "duration_ms": 0.528 },
        { "name": "fusion", "start_ms": 5.23, "duration_ms": 0.185 },
        { "name": "explain", "start_ms": 5.477, "duration_ms": 4.233 },
        { "name": "audit.write", "start_ms": 9.792, "duration_ms": 0.229 }
      ]
    }
  ]
}
```

Span and parent ids are included in the real response and omitted here for
brevity. The same timings are exported as the `phishguard_stage_duration_ms`
histogram, so the question "which stage got slower this week" is a Grafana
panel, not a log search.

---

**Next:** [§4 Threat model →](04-threat-model.md)
