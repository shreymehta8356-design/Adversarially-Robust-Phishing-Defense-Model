# 9. Administrator and user guide

Two audiences, two halves.

**Part I** is for the security analyst who uses the console to assess messages
and triage a queue. It assumes no knowledge of the model and none is needed.

**Part II** is for whoever runs the service: keys, thresholds, the model
registry, monitoring, the audit trail and what to do when something goes wrong.
It assumes [§8](08-deployment-guide.md) has already been followed and a system
is running.

Neither half requires the other. An analyst never needs Part II; an
administrator should read Part I anyway, because most support questions are
about what a verdict means.

---

# Part I — Analyst guide

## 9.1 Getting into the console

| What | Value |
|---|---|
| URL | `http://localhost:8000` (or wherever the service is deployed) |
| Credential | an **analyst** API key, from your administrator |
| Browser | anything current; the console is plain HTML with no build step |

Paste the key into the field at the top right and press **Connect** (or Enter).
The dot beside it turns green and a toast names the loaded model version.

If the dot stays red, hover it — the tooltip carries the reason:

| Message | Meaning |
|---|---|
| `401 — …` | The key is wrong, or has been rotated. Ask your administrator. |
| `403 — …` | The key is valid but lacks the role for that action. The adversarial probe and decision history need an **admin** key. |
| `no model loaded` | The service is up but has no model. An administrator's problem: §9.11. |
| `Cannot reach the API` | The service is not running, or the URL is wrong. |
| `429 — rate limit exceeded` | You have exceeded 120 requests a minute. Wait; the response says how long. |

The key is held in the browser's `sessionStorage`, so it survives a page
refresh and is discarded when the tab closes. It is never written to disk and
never appears in a URL. Treat it as a password: it authorises scanning, and on
an admin key it authorises the adversarial probe, which is an offensive
capability.

## 9.2 The four tabs

| Tab | What it is for | Role |
|---|---|---|
| **Assess a message** | Score a single message and read the evidence behind the verdict. The main working surface. | analyst |
| **Decision history** | The audit trail: every decision this service has made, filterable by band and sender domain. | admin |
| **Adversarial probe** | Attack the message currently in the form and see whether the verdict survives. | admin |
| **Model & monitoring** | Which model is loaded, live operational counters, the score distribution, and the attack taxonomy. | analyst |

Tabs load their data when you open them, so a stale panel is fixed by
switching away and back.

## 9.3 Assessing a message

### The form

| Field | Notes |
|---|---|
| **From** | Full header form, `Name <user@example.com>`. The display name matters as much as the address — brand-name-versus-domain mismatch is one of the strongest single signals. |
| **Reply-To** | Optional. A Reply-To on a different domain from the From address is a classic BEC pattern. |
| **SPF / DKIM / DMARC** | `pass`, `fail`, `softfail` or `none`. Take these from the received headers; `none` means the check was not performed, which is different from `fail`. |
| **Subject** | As received, including any `Re:` or `Fwd:` prefix — thread-hijack detection uses them. |
| **Body (plain text)** | Include URLs as they appear. Do not tidy the text: obfuscation, odd spacing and mixed scripts are signal, and cleaning them up destroys evidence. |
| **HTML part** | Optional, under the collapsible heading. Worth pasting whenever you have it: link-text-versus-href mismatch is only visible here, and it is invisible to any model reading body text alone. |

Keyboard shortcut: **Ctrl+Enter** (or Cmd+Enter) assesses from anywhere in the
form.

### Behavioural context, and when to leave it off

The **Behavioural context** panel supplies what the message itself cannot say:
what this sender's relationship with the recipient looks like.

| Field | What it means | Where you get it |
|---|---|---|
| Prior messages from sender | How many messages this recipient has had from this sender before | Mail archive / gateway |
| Sender domain age (days) | How long the sending domain has existed | WHOIS or the gateway's reputation data |
| Messages from domain, last hour | Campaign burst size | Gateway telemetry |
| Hour received (local) | Recipient's local time, 0–23 | The message's timestamp |
| Recipients | How many addresses were on the message | Headers |
| Addresses using this display name | How many distinct addresses have used this display name | Gateway telemetry |

**Leave the panel switched off when you do not have real values.** This is the
important instruction in this section. Absence is handled properly: the system
records `behavioral_available = false`, sets the block to neutral defaults, and
adds an evidence item saying "No sender history was supplied with this message
— assessment used email and URL evidence only, which widens the uncertainty on
this verdict." That is an honest verdict on partial information.

Inventing plausible-looking numbers is worse than supplying none, because the
model treats them as observed fact and the evidence list will not warn you. If
you know the sender is new but not the domain age, switch the panel off rather
than guessing.

The cost of running without behavioural context is measured: the modality
ablation in [§7.5](07-evaluation-dossier.md) puts an email + URL model at
0.99897 macro F1 against 0.99793 for all three families on clean data — a
negligible clean-accuracy difference — but the robustness comparison in §7.4 is
where the family earns its place. Verdicts without behavioural context are
weaker against a determined attacker, not against ordinary mail.

### The worked examples

The **Load an example…** dropdown fills the whole form, including behavioural
context. Six cases, chosen to demonstrate different things:

| Example | What it demonstrates |
|---|---|
| **Credential phishing (obvious)** | The straightforward case. Brand impersonation, failed authentication, young domain, burst sending, a password form in the HTML. Every member agrees; the score is near 1.0. |
| **Cloned brand template (hard)** | A genuine brand password-reset email, word for word, from a domain the brand does not own. The text carries no signal at all — the text members score it low and the verdict comes from the header, the URL and the behavioural block. This is the single best demonstration of why the system reads three families. |
| **Business email compromise (no link)** | No URL, no attachment, no obvious lexical tell. A payment-redirection request in plain prose. Shows what the system does when there is nothing to extract. |
| **Legitimate internal mail** | The control case. Should be ALLOW with mitigating evidence visible. |
| **Legitimate password reset (hard negative)** | The same vocabulary as the clone, the opposite verdict. Load it immediately after the clone: the pair shows why a keyword filter cannot do this job. |
| **Obfuscated with homoglyphs** | Cyrillic lookalikes, zero-width characters, spaced-out words, leetspeak. Shows canonicalisation folding the text back and, more interestingly, the obfuscation effort itself appearing as evidence. |

Loading an example overwrites the form. Assess it, then change one thing — drop
the Reply-To, set DMARC to `pass`, raise prior messages from 0 to 80 — and
reassess. Watching which single edit moves the score is the fastest way to
develop a feel for what the system weighs.

## 9.4 Reading a verdict

### The score and the band

The gauge shows the calibrated probability that the message is phishing, as a
percentage. It is calibrated, which means a score of 0.80 is intended to mean
roughly an 80% chance — not merely "higher is worse".

The pill beneath it is the operational decision:

| Band | Score | What happens to the message | What you do |
|---|---|---|---|
| **ALLOW** | below 0.40 | Delivered to the recipient | Nothing. It is not in your queue. |
| **REVIEW** | 0.40 to below 0.80 | Held for a human decision | **This is your queue.** See the checklist in §9.7. |
| **BLOCK** | 0.80 and above | Quarantined automatically | Nothing, unless a user disputes it — then §9.15. |

The thresholds are policy, not model behaviour, and an administrator can change
them (§9.9). The band shown is always the one the running configuration
produces.

Below the pill: the model version, assessment latency, whether behavioural
context was supplied, the decision ID, and which defences were applied. Quote
the **decision ID** in any ticket — it is what links your report to the audit
record.

### The member scores

Four bars, one per detection view:

| Member | Reads |
|---|---|
| `rules` | A 37-rule analyst checklist, the transparent baseline |
| `engineered` | All 265 numeric features across the three families |
| `charngram` | Character 3–5-grams of the text |
| `wordtfidf` | Word 1–2-grams of the text |

**Agreement and disagreement both carry information.** All four high is an
unambiguous phish; all four low is unambiguously ordinary mail.

The case worth stopping on is **split members**: the `engineered` member high
and the two text members low. That means the text reads as legitimate while the
structural evidence — sender domain, URL shape, behavioural context — says
otherwise. That is the signature of a **cloned template**: real copy lifted from
a real brand, sent from somewhere it should not be. It is also, precisely, what
a text-only filter misses.

The reverse — text members high, `engineered` low — usually means aggressive
marketing language from a legitimate sender. Check the sending domain before
concluding anything.

The system flags large spreads itself. When the members disagree by more than
0.25 the evidence list gains an item titled **"Detection views disagree —
possible evasion attempt"**, with the two most influential member scores in its
detail line. When they agree it says so, neutrally.

### The evidence list

Every item is a sentence, not a feature name. Each has a kind, a direction and
a weight.

| Kind | What it is |
|---|---|
| `rule` | A checklist rule that fired, with the specific value that triggered it |
| `feature` | A numeric signal that contributed materially, phrased in plain English |
| `token` | A word or character sequence the text members weighted heavily |
| `member` | The agreement/disagreement item described above |
| `context` | Facts about the assessment itself — most importantly, missing behavioural context |
| `defense` | A canonicalisation or guard that acted on the message |

**Direction** is colour-coded and is the part analysts most often overlook:

- **Toward phishing** — the signal raised the score.
- **Toward legitimate** — the signal *lowered* it. Mitigating evidence is shown
  deliberately, because a reviewer who only ever sees the case for the
  prosecution cannot make a judgement. When a message scores 0.62 and half the
  list is mitigating, that 0.62 means something different from a 0.62 where
  everything points one way.
- **Neutral** — context, not argument.

**Weight** is a comparable magnitude used for ordering. Treat it as a ranking
device: the third item genuinely mattered more than the eighth. Do not read it
as a probability or a percentage contribution.

If nothing stood out, the list says so explicitly rather than showing an empty
box. A high score with no individual standout means the verdict came from the
accumulation of many weak signals, which is itself worth noting in a report.

## 9.5 Recording feedback

Three buttons under every verdict: **Confirm phishing**, **Mark legitimate**,
**Unsure**.

Press one whenever you have reached a conclusion, especially when you disagree
with the verdict. Use **Unsure** honestly — a recorded "I could not tell" is
more useful than a coerced binary, and it is the input that identifies messages
worth a second analyst.

### What happens to it

Feedback is written to the audit trail against the decision ID, with your key
identifier and a timestamp. It then does exactly two things:

1. It appears in the decision history, so a reviewer can see where analysts and
   the model diverged.
2. It feeds the **analyst-disagreement counter** on the Model & monitoring tab
   — the count of feedback that contradicts the band, i.e. analysts marking
   ALLOW decisions as phishing or BLOCK decisions as legitimate. That counter is
   the primary drift signal this system produces from its own operation (§9.11).

**It never retrains the model automatically.** This is a deliberate design
decision, not a missing feature. An endpoint that accepted labels and folded
them straight into the model would be a poisoning vector: anyone who could
reach it with a valid key could teach the system that a particular pattern is
benign, and the attack would leave no trace in any metric until it had already
worked. It is recorded as out-of-scope threat `OOS-3` in the threat model for
exactly that reason.

So retraining is a deliberate, reviewed, human action (§9.11). Your feedback
is evidence for that decision, not a trigger of it. The toast that appears when
you submit says the same thing in one line.

## 9.6 The adversarial probe

*Requires an admin key.*

The probe takes whatever is currently in the assessment form, runs the attack
suite against it under a query budget, and reports whether the verdict held.
It answers a question a single score cannot: **is this verdict robust, or is it
sitting on a knife edge?**

Set a budget (12 is the default and matches the figure used throughout
[§7](07-evaluation-dossier.md)) and press **Run probe**.

### Reading the result

| Tile | Meaning |
|---|---|
| **Original score** | The message as you entered it |
| **After attack** | The lowest score the attacker reached |
| **Queries used** | How much of the budget was spent |
| **Outcome** | `held` or `EVADED` |

The **trajectory** is a bar per query, showing the score as the attacker
worked. A flat trajectory means no transform found purchase. A staircase means
the attacker was making steady progress and would likely have continued with a
larger budget — which is worth knowing even when the outcome is `held`.

Beneath it, the transforms that were applied, and one of three interpretations:

**"EVADED after N queries using …"** — a determined attacker could get a message
like this past the detector. This is a finding, not a curiosity. Capture the
message, route senders matching the pattern to review, and tell your
administrator: it also fires the `PhishGuardAdversarialProbeEvasion` alert
(§9.16).

**"Held, but the score fell 0.NNN under attack … The margin is thinner than the
clean score suggests."** — this is the phrase worth understanding properly. It
appears when the verdict survived but the score moved by more than 0.05. A
message scoring 0.99 that falls to 0.93 under twelve queries is *not* as safe
as a message scoring 0.99 that does not move at all. The first sits on signals
the attacker can erode; the second sits on signals they cannot touch. With a
larger budget, more restarts, or one transform this suite does not contain, the
first message is the one that gets through. Treat it as: this verdict is
correct today and this message pattern is a candidate for the next corpus
refresh.

**"Held. N queries moved the score by 0.NNN; no transform materially reduced
the assessment."** — the verdict rests on evidence this attacker cannot reach.
Typically the behavioural and header evidence is carrying the decision, which
is the design working as intended.

### What it is for, and what it is not for

Use it to sanity-check a verdict before acting on it, to test a new lure pattern
before it arrives at volume, and to demonstrate the system's robustness
honestly — including when the answer is uncomfortable.

It is admin-gated because it is a genuine offensive capability: it tells the
caller which edits reduce the score, which is exactly what a defender needs and
exactly what an attacker would want. Every probe is recorded in the audit trail
with the key that ran it. Do not run it against messages you did not obtain
legitimately, and do not share the transform sequence outside your team.

## 9.7 How to triage a REVIEW-band message

The REVIEW band exists because the alternative — forcing every uncertain
message into a silent decision — pushes the error onto either the recipient or
the sender. Here it lands on you instead. A message reaches you because the
system's confidence fell between 0.40 and 0.80.

Work through this in order. Most messages resolve in the first three steps.

**1. Check the authentication block first.** SPF, DKIM and DMARC are in the
evidence list. Any failure on a message claiming to be from a major brand is
close to decisive — real brands get their authentication right. All three
passing does not clear a message; it just means the next steps matter more.
Note that on the evaluation corpus, the messages where the system errs are the
ones where authentication *passes* ([§7.11](07-evaluation-dossier.md)).

**2. Compare the display name with the sending domain.** Does the claimed
identity own the domain that sent this? A brand name in the display name over a
domain that is not theirs is the single most common phishing structure, and it
is the one your eye can check faster than any model.

**3. Look at the member bars for a split.** `engineered` high with the text
members low means a cloned template: the words are genuine because they were
copied. Do not be reassured by text that reads perfectly — that is the point of
a clone.

**4. Check where the links actually go.** Hover, do not click. If the HTML part
was supplied, the evidence list will already name any link-text-versus-href
mismatch. A link whose visible text is one domain and whose href is another is
sufficient on its own.

**5. Read the mitigating evidence.** Anything pointing toward legitimate?
Established correspondence, a signature block, an unsubscribe link, an aged
domain? A REVIEW verdict with substantial mitigating evidence is a genuinely
ambiguous message; one with none is a phish the model was slightly unsure of.

**6. Check the behavioural context — or note that it was missing.** If the
evidence list says no sender history was supplied, the verdict was made on two
families out of three. That alone can explain a mid-range score, and it means
the answer may be in the mail archive rather than in the message.

**7. Check the sender domain in decision history.** Filter the history tab by
sender domain. Fifty BLOCK decisions from the same domain in the last hour is a
campaign, and this message is part of it.

**8. When it is still ambiguous, run the probe.** "Held but the margin is
thinner than the clean score suggests" tells you the verdict is fragile. That
is a reason to escalate rather than to close.

**9. Decide, record feedback, and quote the decision ID.** Both directions
matter: a confirmed phish and a confirmed false positive are equally valuable
as drift signals, and the second is the one people forget to record.

**When to escalate rather than decide.** A message targeting finance or payroll
with a payment instruction; any message where you would have to contact the
apparent sender to be sure; anything the probe reports as EVADED. These are not
triage failures — they are the cases the band exists to surface.

---

# Part II — Administrator guide

## 9.8 Roles and keys

Two roles. `admin` inherits everything `analyst` can do.

| Role | Endpoints |
|---|---|
| `analyst` | `POST /api/v1/scan`, `/scan/batch`, `/scan/url`, `POST /api/v1/feedback`, `GET /api/v1/model`, `GET /api/v1/stats` |
| `admin` | all of the above, plus `GET /api/v1/decisions`, `GET /api/v1/decisions/{id}`, `POST /api/v1/adversarial/probe` |

`/healthz`, `/readyz` and `/metrics` are unauthenticated by design: a health
check that needs a credential fails for the wrong reasons, and the metrics
endpoint exposes counters, not content.

The split is drawn where it is for two specific reasons. **Decision history is
admin-only** because it is the audit trail, and an audit trail readable by
everyone it audits is not one. **The adversarial probe is admin-only** because
it is an evasion oracle: it reports which edits reduce a score.

### Generating keys

```bash
python3 -c "import secrets; print('analyst:pg_an_' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('admin:pg_ad_'   + secrets.token_urlsafe(32))"
```

Install them as a comma-separated list:

```bash
PG_API_KEYS=analyst:pg_an_...,admin:pg_ad_...
```

The service stores only SHA-256 digests of keys in memory; the plaintext exists
only in your environment configuration. Logs and audit records carry a derived
`key_id`, never the key.

In `PG_ENVIRONMENT=prod` the service **refuses to start** without
`PG_API_KEYS`. In `dev` it falls back to documented development keys and warns
loudly on every startup. Never run `dev` anywhere reachable.

### Rotating them

Rotation is a restart with a new value. There is no key database to migrate.

```bash
# 1. Generate the replacement, and add it alongside the old one:
PG_API_KEYS=analyst:pg_an_OLD,analyst:pg_an_NEW,admin:pg_ad_OLD,admin:pg_ad_NEW
docker compose up -d

# 2. Move every client and every analyst to the new key.
# 3. Remove the old entries and restart again:
PG_API_KEYS=analyst:pg_an_NEW,admin:pg_ad_NEW
docker compose up -d
```

Overlapping the keys avoids an outage on the inline mail path. Rotate on a
schedule, on any staff change, and immediately on the events in §9.16.

Issue **separate keys per client** — one for the mail gateway, one for the
console, one per integration — so that revoking one does not disrupt the rest,
and so the `key_id` in the audit trail identifies who did what. Rate limiting
(`PG_RATE_LIMIT_PER_MINUTE`, default 120) is applied per key, which is another
reason not to share one.

## 9.9 Thresholds

```
score <  PG_REVIEW_THRESHOLD (0.40)   -> ALLOW   deliver
        0.40 <= score < 0.80          -> REVIEW  analyst queue
score >= PG_BLOCK_THRESHOLD  (0.80)   -> BLOCK   quarantine
```

**These are policy decisions, not model decisions.** The model produces a
calibrated probability; the thresholds decide what your organisation does with
each probability. Changing them does not make the model better or worse at
anything, and it requires no retraining — a restart is enough.

| Change | Effect | Cost |
|---|---|---|
| **Raise** the review threshold (0.40 → 0.50) | Fewer messages queued for analysts | More phishing delivered with no human ever seeing it |
| **Lower** the review threshold (0.40 → 0.30) | More phishing caught before delivery | More analyst work, much of it on legitimate mail |
| **Raise** the block threshold (0.80 → 0.90) | Fewer legitimate messages auto-quarantined | More phishing reaching the queue instead of being stopped |
| **Lower** the block threshold (0.80 → 0.70) | More phishing auto-quarantined | More legitimate mail quarantined — the failure that gets filters switched off |

### Choosing them against a false-positive budget

The right way to set thresholds is not to pick a probability that sounds
confident. It is to state a tolerance — "no more than two legitimate messages
blocked per thousand" — and find the threshold that delivers it.

`phishguard evaluate` reports this under `at_operating_point`, which finds the
lowest threshold whose false-positive rate stays within `PG_GATE_MAX_FPR`
(default 0.02).

On the current corpus it derives a threshold of **0.03215**, achieving a
false-positive rate of 0.00213 against a 0.02 budget. That is far below the
deployed block threshold of 0.80, which is the expected shape on a corpus the
model separates this cleanly: almost any cut-off above the noise floor meets the
budget, so the derived figure tells you the *floor*, not the right answer.

**Read it as a floor, not a recommendation.** The deployed 0.40 and 0.80 are
reasoned defaults chosen to leave the REVIEW band enough width to be useful,
not values derived from the dossier. On real traffic, where legitimate mail has
a genuinely spread-out score distribution rather than piling up near zero, the
derived threshold becomes informative and worth following.

So set thresholds from **your own traffic**, not from the dossier:

1. Run for a fortnight with the defaults and let the audit trail fill.
2. Read the score distribution from `GET /api/v1/stats` or the Grafana panel.
3. Find the score below which your analysts have never confirmed a phish —
   that is a candidate review threshold.
4. Find the score above which they have never overturned a block — that is a
   candidate block threshold.
5. Change one at a time, and watch the review rate and the disagreement counter
   for a fortnight before changing the other.

Never set the two thresholds equal. That collapses REVIEW to nothing and
removes the human-oversight control entirely, which is the design decision
recorded in [ADR-006](adr/006-abstention-band.md).

## 9.10 The model registry

Every trained model is kept, with its manifest, feature contract, metrics and
provenance. One is marked current, and that is the one the API serves.

```bash
docker compose run --rm api models                        # list; * marks current
docker compose run --rm api models --promote pg-0bcb098e45  # make one current
docker compose run --rm api models --prune 5              # keep the newest 5
```

Locally, drop the `docker compose run --rm api` prefix and use `phishguard`
directly.

**A version** is a content-addressed identifier — `pg-0bcb098e45` — covering
the trained members, the fusion weights, the calibrator, the exact ordered list
of 265 feature names, the active defence set, and the provenance of the corpus
it was trained on. It appears in every scan response, every audit record, every
log line and the `phishguard_model_info` metric, so any decision can be traced
to the artefact that produced it.

The feature contract is verified on load. A model whose feature layout does not
match the running code refuses to load with `feature contract mismatch` rather
than scoring against misaligned columns — a failure that would otherwise be
silent and would corrupt every subsequent verdict.

Promotion takes effect on the next service restart. Keep at least the current
model and its predecessor, so that a rollback is one command (§9.15).

## 9.11 Retraining

### When

Retrain on a signal, not on a calendar. Three signals, in order of how much
they should worry you:

**1. Analyst-disagreement rate climbing.** Available from
`GET /api/v1/stats` and on the console's Model & monitoring tab. It counts
feedback that contradicts the band — analysts marking ALLOW decisions as
phishing, or BLOCK decisions as legitimate. This is the most useful drift
signal the service produces on its own, because it is a direct measurement of
the model disagreeing with the people who know. A rate that doubles over a
fortnight is worth acting on.

**2. Score distribution shift.** The Grafana panel and
`stats.score_distribution` show the histogram over time. A healthy deployment
has a stable bimodal shape. Mass migrating into the middle means the model is
becoming less certain about traffic it used to be sure of, which usually means
the traffic changed. Note that calibration is measured on the training
distribution ([§7.12](07-evaluation-dossier.md)), so under genuine shift the
probabilities themselves drift, and the thresholds stop meaning what they meant.

**3. Accumulated confirmed misses.** A body of analyst-confirmed phishing that
the system scored as ALLOW is the corpus for the next model. This is the
intended use of the feedback loop: humans decide when the evidence is worth
retraining on, and nothing folds back automatically (`OOS-3`).

Also retrain after any change to feature extraction, and after any evasion the
adversarial probe finds (§9.16).

### How

```bash
docker compose run --rm api train --n 12000 --save
docker compose restart api
```

Training refuses to run if the leakage audit fails, and prints exactly which
check failed. That refusal is a feature: a model trained on leaked data will
report excellent metrics and behave badly, and the audit is the only thing
standing between you and a confidently wrong system. `--allow-leakage` exists
but should be treated as requiring a written reason.

### Verifying before you promote

**Do not restart the API onto a new model until it has passed the gates.**

```bash
docker compose run --rm api evaluate --n 12000 --budget 12 --defense-ablation
```

This writes `artifacts/reports/evaluation.json` and `evaluation.md`, prints the
acceptance-gate table, and **exits non-zero if any blocking gate fails**. Ten
gates; the ones a retrain most often moves:

| Gate | Criterion | Threshold | Reference value |
|---|---|---|---|
| G1 | Clean macro F1 | ≥ 0.90 | 0.99948 |
| G3 | False-positive rate | ≤ 0.02 | 0.00000 |
| G5 | Macro F1 drop under attack | ≤ 0.15 | 0.00051 |
| G6 | Attack success (escapes auto-block) | ≤ 0.35 | 0.06667 |
| G7 | p95 latency | ≤ 150 ms | 44.816 ms |
| G8 | Delta over the rule baseline | ≥ 0.01 | 0.08839 |
| G9 | Robustness advantage over the text-only baseline | ≥ 0 | 0.48333 |
| G10 | No data leakage | must pass | passed |

Compare the new run against the previous `evaluation.json` before promoting.
A model that improves clean macro F1 while G6 worsens is a **regression**, not
an improvement: this project's claim is about robustness, and trading it for
third-decimal-place clean accuracy gives away the thing that distinguishes the
system. Also run the attack suite on its own for the per-family breakdown:

```bash
docker compose run --rm api attack --budget 12 --sweep
```

## 9.12 Monitoring

Grafana at `http://localhost:3000` (`admin`/`admin` on a fresh install — change
it), with the dashboard pre-provisioned. Prometheus scrapes `GET /metrics`.

### Dashboard panels

| Panel | What to look for |
|---|---|
| **Service up** | Should be 1. Anything else is an outage on the inline mail path. |
| **Messages assessed (1h)** | Volume. A sudden drop usually means a gateway integration broke, not that mail stopped. |
| **Assessment p95 (ms)** | Against the 150 ms budget. Reference: 44.8 ms with explanation, 11.5 ms without. |
| **Routed to analysts** | The review rate — your analyst workload in one number. |
| **Model version** | Confirms which artefact is live. Check after every restart. |
| **Decisions by band** | The ALLOW/REVIEW/BLOCK mix over time. Stable shape; sudden changes are the signal. |
| **Assessment latency percentiles** | p50/p95/p99 together. A widening gap means tail latency, which causes queue backlog. |
| **Score distribution over time** | The drift panel. Healthy is bimodal and stable; mass moving to the middle is §9.11's signal 2. |
| **Behavioural context availability** | The share of traffic arriving with sender history. Falling means the gateway integration is degrading. |
| **Analyst feedback** | Volume and split of analyst labels. Zero feedback means nobody is using the queue, which is its own problem. |
| **Rejected requests** | 401/403/429. A baseline of zero; any sustained non-zero is either a misconfigured client or probing. |
| **Adversarial probes** | Probe runs, split by whether they evaded. |

### Alert rules

From `docker/alerts.yml`. Each one was included because it changes what an
operator does; a rule nobody acts on trains people to ignore the ones that
matter.

| Alert | Fires when | Severity | What it means and what to do |
|---|---|---|---|
| **PhishGuardDown** | `up == 0` for 2m | critical | Prometheus cannot scrape the API. **Inbound mail is not being assessed.** Check `docker compose logs api` and `/readyz`. Confirm the gateway's fail-open or fail-closed behaviour is what you intended — this is the moment it matters. |
| **PhishGuardNoModelLoaded** | `phishguard_model_info` absent for 5m | critical | The service is live but has no model, so every scan returns 503. Usually a failed bootstrap or a promoted version that will not load (check for `feature contract mismatch`). Run `phishguard train --save`, or promote a known-good version. |
| **PhishGuardHighLatency** | p95 > 150 ms for 10m | warning | The inline path is over budget and the gateway will start backing up. Check host load and concurrent scan volume. Immediate mitigation: have callers request assessments without explanations, which is roughly 4× faster. |
| **PhishGuardBlockRateCollapsed** | BLOCK share < 1% of traffic for 30m | warning | Almost nothing is being blocked. This is far more likely to be a fault than good news — a wrong model promoted, or callers sending truncated messages. Check the loaded model version and a sample of recent requests. |
| **PhishGuardReviewQueueGrowing** | REVIEW share > 35% for 20m | warning | A third of traffic is going to humans. Either the input distribution shifted or the thresholds need retuning. **Sustained high review volume means analysts stop reading the queue**, which removes the human-oversight control entirely. Treat as urgent even though it is a warning. |
| **PhishGuardBehaviouralContextMissing** | > 50% of traffic without behavioural context for 30m | info | Most callers are supplying no sender history, so the system is running on two families out of three. Check the gateway integration. |
| **PhishGuardAuthFailureSpike** | > 1 rejected request/s for 10m | warning | Sustained authentication failures: a misconfigured client, or credential probing. Identify the source; if it is not a client you recognise, rotate keys (§9.16). |
| **PhishGuardAdversarialProbeEvasion** | any successful probe evasion in 1h | warning | An analyst demonstrated an evasion against the **deployed** model. This is a genuine finding: capture the message, add it to the corpus, and re-run the evaluation before the next release. See §9.16. |

## 9.13 The audit trail

Every assessment writes one record. Read it through `GET /api/v1/decisions`
(admin), filterable by band, sender domain and minimum score, or through the
console's Decision history tab.

### What a record contains

| Field | Notes |
|---|---|
| `decision_id`, `request_id` | Identity and correlation with the logs |
| `created_at` | Timestamp |
| `score`, `band`, `label` | The verdict |
| `model_version` | Which artefact decided |
| `subject_hash` | A **salted digest** of the subject — matches identical subjects, does not reveal them |
| `sender_px` | A **pseudonymised** sender identifier: non-reversible, correlatable across records |
| `sender_domain` | Kept in the clear — it is the investigative pivot |
| `recipient_count`, `body_length`, `attachment_count` | Sizes, not content |
| `behavioral_available` | Whether the verdict had all three families |
| `latency_ms`, `member_scores` | Performance and the four member scores |
| `top_evidence` | Evidence **titles** only |
| `key_id`, `client_reference` | Who asked |

Separate tables hold analyst feedback (label, rationale, action, key) and
adversarial probes (original and final score, whether it evaded, queries,
transforms, key).

### What it deliberately does not contain

**No message content.** No subject line in the clear, no body, no HTML, no
URLs, no attachment names, no recipient addresses, no sender address.

This is data minimisation as an implemented property rather than a policy
statement, and it is enforced by tests. It means the trail holds enough to
investigate an incident — which domain, when, what score, what evidence, which
model, who reviewed it — and not enough to reconstruct anyone's mail. A
compromise of this database does not leak the organisation's email.

The cost is real and worth stating: you cannot re-score a historical decision
from the audit trail, because the message is gone. If you need to keep messages
for that, keep them where messages belong, under the retention and access
controls that apply to mail.

The pseudonymisation salt (`PG_PSEUDONYMIZATION_SALT`) is what makes
`sender_px` correlatable across records. **Set it once per deployment and keep
it.** Changing it does not break the service, but records written before and
after will no longer match each other.

### Retention

`PG_AUDIT_RETENTION_DAYS`, default **90**. Enforced by a sweep at startup and
daily thereafter, which deletes decisions older than the window. Set it to your
organisation's actual policy: too short and you cannot investigate an incident
reported late; too long and you are holding operational data with no purpose.
The sweep logs how many rows it removed.

## 9.14 Backup and restore

Everything durable is in one volume: the model registry and the audit database.

```bash
# Back up
docker run --rm -v phishguard_phishguard-data:/data -v "$PWD":/backup \
  alpine tar czf /backup/phishguard-backup-$(date +%F).tgz -C /data .

# Restore into a fresh volume
docker compose down
docker run --rm -v phishguard_phishguard-data:/data -v "$PWD":/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/phishguard-backup-2026-09-07.tgz -C /data"
docker compose up -d
```

The audit database is SQLite in WAL mode. A `tar` of a live volume can catch a
write in progress; for a guaranteed-consistent copy, stop the API first, or
back up outside peak hours and accept that the last few seconds may be absent.

**What is not in the backup, and must be kept separately:** `PG_API_KEYS` and
`PG_PSEUDONYMIZATION_SALT`. Restoring the volume without the original salt
leaves you with an audit trail whose new rows cannot be correlated with its old
ones. Keep both in whatever secret store your organisation already uses, and
test a restore before you need one — an untested backup is a hypothesis.

## 9.15 Incident playbook

### "A phishing message got through"

**1. Get the decision record.** Ask for the decision ID from the recipient's
reported message, or find it by sender domain and time in
`GET /api/v1/decisions`. Note the score, the band, the model version, and
whether `behavioral_available` was true.

**2. Establish which failure this was.** They need different responses:

| Score | What happened | Response |
|---|---|---|
| Below 0.40 | The model was confidently wrong | Steps 3–6 |
| 0.40–0.80 | The system flagged it; a human cleared it, or nobody looked | A queue or process problem, not a model problem. Check whether the queue is being read (§9.12, review rate) and re-brief on §9.7. |
| No record at all | The gateway never called the API | An integration or availability problem. Check `PhishGuardDown` history for that period. |

**3. Reproduce it.** Assess the message in the console. If the score now differs
from the recorded one, the model changed in between — check `model_version`.

**4. Probe it.** Run the adversarial probe on the message. If it reports an
evasion, you are looking at an attack against the model rather than an ordinary
miss, and §9.16 applies.

**5. Contain, immediately, without waiting for a model change.** Block the
sender domain at the gateway. If the pattern is a campaign, block on the
structural feature the campaign shares. **Lowering the block threshold is
available but is the blunt instrument** — it affects all traffic, and it will
block legitimate mail. If you use it, set a date to revert it.

**6. Fix it properly.** Add the message and its near variants to the corpus.
Retrain (§9.11). Verify the acceptance gates, and specifically verify that the
message now scores where it should. Promote. Record the decision ID and the
model versions before and after in the incident record.

**7. Ask the honest question.** Was this a novel attack family? The robustness
figures in [§7](07-evaluation-dossier.md) are measured against thirty transforms
this project designed, and a genuinely new family is untested by construction.
If this message did not resemble anything in the taxonomy, that is the finding,
and it belongs in the residual-risk register rather than in a retraining ticket.

### "We blocked something legitimate"

Treat this as **more urgent** than a miss, not less. A filter that blocks
legitimate mail loses the confidence of the people it protects, and gets
switched off — after which its recall is zero.

**1. Release the message first.** Do it through the mail platform. The
investigation does not need to block the sender's business.

**2. Get the decision record and read the evidence.** `top_evidence` on the
record names what drove the score. This almost always identifies the cause in
one line — a failed DMARC on a legitimate sender, a marketing domain with a
young registration, a bulk-send burst, a URL shortener in a genuine newsletter.

**3. Check whether it was a one-off or systematic.** Filter decision history by
that sender domain. A single BLOCK among many ALLOWs is a borderline message; a
whole domain blocked is a systematic false positive and needs an allowlist entry
at the gateway today, while you fix the model properly.

**4. Record the analyst feedback.** Mark it legitimate against the decision ID.
This is the input that makes false positives visible in the disagreement
counter — and it is the one people skip, because releasing the message feels
like closing the ticket.

**5. Fix the cause, not the symptom.** Add the message to the corpus as a hard
negative and retrain. **Watch G3 (false-positive rate ≤ 0.02) specifically** on
the verification run.

**6. If false positives are recurring, the thresholds are wrong.** Raising the
block threshold from 0.80 to 0.85 moves borderline messages into REVIEW instead
of quarantine — trading analyst time for delivery reliability. That is often the
right trade, and §9.9 describes how to choose it.

### Rolling back a bad model

```bash
docker compose run --rm api models                          # find the previous version
docker compose run --rm api models --promote pg-PREVIOUS
docker compose restart api
curl -s http://localhost:8000/readyz                        # confirm the version
```

Faster and safer than retraining under pressure. This is why `models --prune`
should always keep several versions.

## 9.16 Security operations

### Key rotation

Rotate on a schedule, on any staff change, and **immediately** on:

- `PhishGuardAuthFailureSpike` from a source you cannot identify.
- A key appearing anywhere it should not — a commit, a ticket, a screenshot, a
  chat message.
- Any suspicion that an admin key has leaked. An admin key grants the
  adversarial probe, which is an evasion oracle: an attacker holding one can
  ask the system which edits reduce a score. Treat this as more serious than an
  analyst key.

Follow the overlapping procedure in §9.8 so the mail path stays up.

### Dependency scanning

```bash
make audit          # pip-audit --strict
```

Runs in CI on every change. The service downloads nothing at runtime, needs no
outbound network, and runs as a non-root user with capabilities dropped — so
the dependency surface is the main remaining supply-chain exposure. Rebuild and
redeploy on any high-severity finding.

### When the adversarial-probe alert fires

`PhishGuardAdversarialProbeEvasion` means someone demonstrated a working
evasion against the model you are currently serving. Not a drill, and not a
model-quality metric — a specific message pattern that gets past a specific
deployed artefact.

**1. Establish who ran it.** The probe record carries the `key_id`. If it was
not one of your analysts, you have a credential incident: rotate every key now
and work out how the key was obtained.

**2. Capture everything.** The probe record holds the original and final
scores, the query count and the exact transform sequence. That sequence is the
attack. Store it with the message.

**3. Assess the exposure.** Which family did the transforms come from? Cross-
reference the residual-risk register in
[§7.4](07-evaluation-dossier.md#74-the-result-that-matters-robustness). A known
family with a known residual risk is expected behaviour at the margin — the
measured escape-block rate is 0.06667, so evasions exist and the register says
so. A transform sequence outside the taxonomy is a different matter: it is an
untested family, which is the limitation §7.12 names explicitly.

**4. Contain.** Route senders matching the pattern to REVIEW at the gateway.
Consider lowering the block threshold temporarily for that sender class only.

**5. Close it properly.** Add the evading message and its variants to the
corpus. Retrain with D-ADVTRAIN enabled (it is on by default and carries the
largest measured share of the robustness: removing it triples attack success
from 0.03333 to 0.10833). Re-run the full evaluation including the defence
ablation, and confirm G5, G6 and G9 all still pass. Promote only then.

**6. Feed it back into the taxonomy.** If the transform sequence was novel, it
belongs in `src/phishguard/adversarial/transforms.py` with a test in
`tests/unit/test_transforms.py`, so the next evaluation measures it. The
robustness numbers are only as good as the suite, and the suite only improves
when findings are written into it.

---

**Next:** [§10 Individual contribution and work log →](10-work-log.md)
