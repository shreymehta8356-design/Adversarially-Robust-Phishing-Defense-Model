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

| Role | May call |
|---|---|
| `analyst` | `/scan`, `/scan/batch`, `/scan/url`, `/feedback`, `/model`, `/stats` |
| `admin` | everything an analyst may, plus `/decisions*` and `/adversarial/probe` |

`admin` inherits `analyst`. The audit trail and the adversarial probe are
admin-gated for different reasons: the trail is an oversight surface, and the
probe is a genuine offensive capability — it tells the caller which edits lower
the score, which is exactly what a defender needs and exactly what an attacker
would want.

**Correlation.** Every response carries `X-Request-ID`. Send your own to have it
echoed; otherwise one is generated. It appears in the structured logs and in
the audit record.

**Errors.** Uniform shape:

```json
{ "error": "...", "detail": "...", "request_id": "req_a1b2c3d4e5f6a7b8c9d0" }
```

| Status | Meaning |
|---|---|
| `400` / `422` | Malformed body, or a field outside its declared bounds |
| `401` | Missing or invalid API key |
| `403` | Authenticated, but the role is insufficient |
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
  "version": "1.0.0",
  "model_loaded": true,
  "model_version": "pg-0bcb098e45",
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
  "model_version": "pg-0bcb098e45",
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
  "client_reference": ""
}
```

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
    "score": 0.99, "band": "BLOCK", "model_version": "pg-0bcb098e45",
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

---

**Next:** [§4 Threat model →](04-threat-model.md)
