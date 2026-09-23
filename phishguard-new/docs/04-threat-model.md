# 4. Threat model

Who the adversary is, what they can and cannot do, what the system defends
against, what it deliberately does not, and what the measurements actually show.

---

## 4.1 Scope and method

This document covers two threat surfaces that are routinely conflated in
phishing-detection work and are analysed separately here.

The first is **attacks on the model**: an operator rewriting a message so that
the classifier scores it below the block threshold while the lure still works on
the victim. This is adversarial evasion, and it is the project's distinguishing
contribution — most detection work reports clean accuracy and stops, which
measures the wrong thing for a system whose entire input is written by someone
who wants it to fail.

The second is **attacks on the service**: the API, the audit store, the
container, the analyst console. This is ordinary application security, but it is
not optional. A robust model behind an API that leaks the audit trail or can be
queried without a key is not a defensible system.

The method differs by surface because the surfaces differ. STRIDE is used for
the service, where the assets are conventional and the threat categories are
well-established (§4.8). For the model, STRIDE says nothing useful, so a custom
capability-bounded taxonomy is used instead: eight attack families, each defined
by what the attacker must be able to do, each mapped to a named defensive
control, each scored independently (§4.5, §4.7). The capability model in §4.4 is
the load-bearing part — it is what makes the robustness numbers mean something.

## 4.2 Assets

| Asset | Why it matters | Primary threat |
|---|---|---|
| Recipient credentials and funds | The thing the attacker is actually after. A single delivered credential-harvest message can cost an account, and through it a domain | Evasion (all eight families) |
| Decision integrity of the model | If the score can be steered, every downstream control that consumes it inherits the flaw | Evasion; model-artefact tampering |
| Confidentiality of the audit trail | Decision records describe who corresponded with whom. An insider reading them is a privacy breach even though no message body is stored | Information disclosure; insider misuse (M4) |
| Availability on the inline mail path | Assessment is synchronous inside the gateway's per-message budget. If PhishGuard stalls, mail queues, and the operational answer to queued mail is to switch the filter off | Resource exhaustion; hostile input (M2) |
| The analyst's attention | A genuine asset, and the one most easily destroyed. Every false positive and every low-value review item spends it, and an analyst who has stopped reading the queue is equivalent to no queue at all | False-positive pressure; review-band inflation |
| Model artefacts and the registry | Weights are the boundary between the black-box threat model here and the white-box one that is out of scope (`OOS-2`) | Artefact exfiltration |

## 4.3 Trust boundaries

```mermaid
graph TB
    subgraph untrusted["Untrusted — attacker-controlled"]
        ATT["Phishing operator<br/><i>authors the message,<br/>observes the verdict</i>"]
        MSG["Crafted message<br/><i>headers · subject · body · HTML</i>"]
        ATT --> MSG
    end

    subgraph edge["Semi-trusted — organisational mail path"]
        MG["Mail gateway / MTA<br/><i>supplies sender-relationship context</i>"]
    end

    subgraph svc["Trusted — PhishGuard service"]
        API["API surface<br/><i>auth · rate limit · bounded contracts</i>"]
        SCORE["Scoring pipeline<br/><i>offline only — no DNS, no HTTP</i>"]
        API --> SCORE
    end

    subgraph data["Trusted — persistence"]
        DB[("Audit store<br/><i>salted digests, no content</i>")]
    end

    subgraph console["Authenticated operators"]
        AN["Analyst<br/><i>analyst role</i>"]
        AD["Administrator<br/><i>admin role</i>"]
    end

    MSG -->|"SMTP"| MG
    MG -->|"POST /api/v1/scan<br/>X-API-Key"| API
    SCORE -->|"redacted decision record"| DB
    API -->|"score · band · evidence"| MG
    AN -->|"review queue, feedback"| API
    AD -->|"audit trail, adversarial probe"| API
    DB -.->|"admin only"| AD

    classDef bad fill:#fce9e8,stroke:#b3261e,color:#7a1a15,stroke-dasharray:4 3
    classDef mid fill:#fff6e5,stroke:#b8860b,color:#5a3d00
    classDef good fill:#e8f0fb,stroke:#1f5fbf,color:#16202c
    class ATT,MSG bad
    class MG mid
    class API,SCORE,DB,AN,AD good
```

Four boundaries are crossed. Message content crosses from fully attacker-
controlled into the gateway; nothing in it is ever trusted. Sender-relationship
context crosses from the gateway into the API and *is* trusted, which is an
assumption recorded in §4.11. Decision records cross into the store, and only in
redacted form. Operator requests cross into the API and are separated by role.

## 4.4 The adversary (capability model)

The adversary modelled here is **a competent phishing operator with full control
of the message they send and black-box query access to the detector's verdict,
under a query budget**. This is the realistic worst case rather than a
convenient one: commercial phishing kits are routinely tested against public
scanners before a campaign launches, so assuming the attacker can observe a
verdict and iterate is not pessimism, it is current practice.

They **can** rewrite any part of the message they author — subject, body, HTML
part, display name, Reply-To, attachment names. They can choose their own
infrastructure: domain, host, path, redirect chains, shortener wrapping,
punycode registration. They can choose when and how fast to send — time of day,
pacing, recipient count, whether the subject is framed as a reply. They can
observe the detector's score for a candidate message and iterate on it, up to a
query budget.

They **cannot** change the recipient's history with them: prior correspondence
volume and reply ratio are properties of the victim's mailbox, not of the
message. They cannot age their own domain retroactively, or erase user reports
already filed against it. They cannot make the brand's genuine domain send the
mail — taking over `paypal.com` is domain compromise, a different threat with
different controls, excluded as `OOS-1`. And they cannot see model weights or
gradients: this is a black-box, decision-based threat model, not a white-box
one (`OOS-2`).

Getting that boundary right is the whole exercise. Draw it too wide — assume the
attacker can do anything — and every defence fails by construction, so the
robustness number is trivially pessimistic and carries no information. Draw it
too narrow — assume they can only add typos — and the number is trivially
optimistic and carries no information either. The boundary above is chosen so
that each capability corresponds to something a real operator demonstrably does.

The boundaries are enforced mechanically rather than by convention. The
behavioural transforms in `adversarial/transforms.py` mutate only
attacker-controlled fields, so no attack in the suite can rewrite the victim's
correspondence history. And `payload_preserved` rejects any candidate that has
stopped being a working phishing message, on three necessary conditions:
reachability (if the original carried links, at least one must survive and still
resolve to an original destination host, with shortener wrapping accepted
because the victim still lands on the same page), the ask (an actionable request
must remain in the visible text), and non-degeneracy (the message may not
collapse to near-nothing, measured across all channels the victim sees). Without
these checks, an "attack" that empties the body would count as a successful
evasion and the robustness numbers would be meaningless.

## 4.5 Attack taxonomy

Eight families, chosen so that each maps to a distinct defensive control and can
be scored independently in the residual-risk register. The first six are the
original suite; A-TRUST and A-CHANNEL were added in 1.1.0.

| ID | Name | Capability required | Attacker cost | Victim-visible | Countered by |
|---|---|---|---|---|---|
| **A-LEX** | Lexical and semantic perturbation | Free — the attacker authors the text | Low | No — the lure reads normally, often better | D-NORM, D-ADVTRAIN, D-ENSEMBLE, D-ABSTAIN |
| **A-UNI** | Unicode and homoglyph obfuscation | Free — any mail client renders these identically | Low | Barely — rendering is near-identical | D-NORM, D-ADVTRAIN |
| **A-URL** | URL obfuscation and redirection | Cheap — a redirect host or a shortener account | Low to medium | Yes, if the victim inspects the link before clicking | D-URL, D-ADVTRAIN, D-ENSEMBLE |
| **A-STRUCT** | Structural and HTML manipulation | Free — the attacker authors the HTML part | Low | No | D-NORM, D-ENSEMBLE, D-ADVTRAIN |
| **A-HDR** | Header and identity shaping | Cheap for the attacker's own domain; impossible for the brand's real domain, which is `OOS-1` | Medium | No — improves the lure's credibility | D-ENSEMBLE, D-ABSTAIN |
| **A-BEH** | Behavioural and timing mimicry | Send time, pacing and framing only; cannot fabricate correspondence history or domain age | High — low-and-slow sending cuts campaign reach | No | D-VELOCITY, D-ENSEMBLE, D-ABSTAIN |
| **A-TRUST** | Payload relocation onto reputable infrastructure | An account on the hosting platform, surviving only until abuse takedown; the redirector must already exist on the trusted domain | Medium — accounts are cheap, takedowns are fast | No — the visible domain is more credible, not less | D-URL, D-ENSEMBLE, D-ABSTAIN |
| **A-CHANNEL** | Out-of-band payload delivery | A staffed phone line or an image pipeline; converts far fewer victims per message because the victim must act manually | High — callback fraud needs live operators | Yes — the victim must dial or scan, which loses conversions | D-ENSEMBLE, D-ABSTAIN, D-VELOCITY |

Effectiveness below is measured per family over 150 attacked messages each, at
the deployed operating point (block threshold 0.8, review threshold 0.4), under
a query budget of 10, against model `pg-0e0dffa24f`. Attack success means the
score fell below 0.8, so the message is no longer auto-quarantined; silent
delivery means it fell below 0.4 and would reach the inbox with no human
review. At this budget no family, run alone, achieved either: every family's
attack success rate and silent-delivery rate is 0.0, so the subsections below
report how far each family moves the score, and there is no query cost of
evasion to report. A-TRUST (mean score drop 0.00012, largest 0.00515) and
A-CHANNEL (0.00019, largest 0.01097) behave the same way. The adaptive attack
on PG-HARD's hard phishing, at 40 queries, separates the families better:
against PhishGuard, A-HDR and A-BEH each delivered 1 of 48 records unwarned and
the other six none ([§7.4](07-evaluation-dossier.md#74-the-result-that-matters-robustness)).

### A-LEX — Lexical and semantic perturbation

`A-LEX-01` synonym substitution, `A-LEX-02` typo injection, `A-LEX-03` benign
padding, `A-LEX-04` tone softening, `A-LEX-05` deadline removal. Attack success
rate **0.0** (none of 150 escaped the block band), silent delivery **0.0**,
mean score drop **0.00077**, largest single drop **0.03536**.

### A-UNI — Unicode and homoglyph obfuscation

`A-UNI-01` homoglyph substitution, `A-UNI-02` zero-width insertion, `A-UNI-03`
leetspeak, `A-UNI-04` word splitting, `A-UNI-05` combining diacritics. Attack
success rate **0.0**, silent delivery **0.0**, mean score drop **0.00089**,
largest drop **0.04722**. The family the full composed attack reached for most
often (83 of 150 messages), without moving any out of auto-quarantine.

### A-URL — URL obfuscation and redirection

`A-URL-01` shortener wrapping, `A-URL-02` open-redirect chaining, `A-URL-03`
percent-encoding, `A-URL-04` subdomain padding, `A-URL-05` path and query noise,
`A-URL-06` scheme downgrade. Attack success rate **0.0**, silent delivery
**0.0**, mean score drop **0.00185**, largest drop **0.09035** — the largest
movement of any family, still without taking a message below the block
threshold. `A-URL-02` is the transform that, until 1.3.0, silently ran
A-TRUST-02's code (a second function named `t_open_redirect` replaced the
first; found by ruff F811); these figures use the corrected suite.

### A-STRUCT — Structural and HTML manipulation

`A-STR-01` HTML entity encoding, `A-STR-02` invisible span injection, `A-STR-03`
text-as-image, `A-STR-04` markup noise. Attack success rate **0.0**, silent
delivery **0.0**, mean score drop **0.00010**, largest drop **0.00246**.

### A-HDR — Header and identity shaping

`A-HDR-01` drop divergent Reply-To, `A-HDR-02` neutral display name, `A-HDR-03`
authentication alignment, `A-HDR-04` Return-Path alignment, `A-HDR-05`
attachment renaming, `A-HDR-06` hop reduction. Attack success rate **0.0**,
silent delivery **0.0**, mean score drop **0.00006**, largest drop **0.00235** —
the smallest movement of any family on ordinary phishing, although on PG-HARD
at 40 queries it is one of the two families that delivered a hard phishing
record unwarned (1 of 48).

### A-BEH — Behavioural and timing mimicry

`A-BEH-01` business-hours delivery, `A-BEH-02` low-and-slow sending, `A-BEH-03`
thread framing, `A-BEH-04` single sending identity. Attack success rate
**0.0**, silent delivery **0.0**, mean score drop **0.00141**, largest drop
**0.05101**. No longer the lowest measured effect: its mean drop is second only
to A-URL's, and on PG-HARD at 40 queries it delivered 1 of 48 hard phishing
records unwarned and left the fewest still auto-blocked (16.7%). Its real cost
is still the highest in the taxonomy, shared with A-CHANNEL, because the
transforms that move the behavioural block are exactly the ones that shrink the
campaign.

## 4.6 Defensive controls

The Counters column is the attack taxonomy read the other way round: each
family in §4.5 names the controls meant to blunt it (`countered_by`), and
`describe_defenses()` derives this column from those lists, so the two cannot
disagree. It lists what a control is designed against. D-ENSEMBLE and
D-ABSTAIN also act on every message whatever the family, as a backstop.

| ID | What it does | Counters | Cost | Residual gap |
|---|---|---|---|---|
| **D-NORM** | NFKC normalisation, zero-width and bidi stripping, confusable folding, diacritic removal, leetspeak folding, separator rejoining and run collapsing before any text feature is computed; the obfuscation deltas are kept as features so evasion effort is itself evidence | A-LEX, A-UNI, A-STRUCT | ~0.15 ms/message; no measurable clean-accuracy loss | Confusables outside the curated table, and paraphrase attacks that use no obfuscation at all, pass through unchanged |
| **D-URL** | Percent-decoding, punycode decoding, host homoglyph folding and recursive unwrapping of open-redirect and shortener parameters, so the extractor scores the destination the victim actually reaches | A-URL, A-TRUST | ~0.1 ms/URL; strictly offline, no DNS or HTTP | A shortener whose target is not embedded in the query string cannot be resolved offline; the wrapper itself remains a feature |
| **D-ADVTRAIN** | Each phishing training example is augmented with attacked variants from the full transform suite, fitting the boundary on the perturbed manifold rather than only on pristine text | A-LEX, A-UNI, A-URL, A-STRUCT | Training set grows by the augmentation multiplier; inference unchanged | Generalises to unseen transforms only as far as they resemble the training perturbations; a genuinely novel family is out of scope |
| **D-ENSEMBLE** | Calibrated stacker over rule, engineered-feature, character-n-gram and word-n-gram members reading different views, so a perturbation that lowers one member often raises another | A-LEX, A-URL, A-STRUCT, A-HDR, A-BEH, A-TRUST, A-CHANNEL | ~4× single-model inference; still sub-10 ms/message on CPU | Members share the text channel, so a strong semantic paraphrase moves them together; behavioural features are the decorrelating leg |
| **D-ABSTAIN** | Three-way decision — ALLOW below the review threshold, BLOCK above the block threshold, REVIEW in between, queued for an analyst instead of auto-decided | A-LEX, A-HDR, A-BEH, A-TRUST, A-CHANNEL | Analyst time proportional to the review-band width | An attack that pushes a message below the review threshold still evades silently; banding converts some evasions into review load, not zero |
| **D-VELOCITY** | Decision-time escalation raising the score when a sender domain arrives in an unusual burst from an unknown contact, using the behavioural block rather than content; bounded to +0.15 and monotone | A-BEH, A-CHANNEL | One bounded arithmetic adjustment; no extra model call | Low-and-slow, individually targeted spear-phishing produces no burst and is unaffected |

## 4.7 Measured residual risk

Against the full composed attack — every family available to the search, 150
messages, budget 10 — the attack success rate is **0.0** (no message escaped the
block band) and the silent delivery rate is **0.0** (none reached the ALLOW
band). Mean final score **0.99583**; mean score drop **0.0033**, median
**0.00007**, maximum **0.05894**; mean **18.6** queries spent; no message
evaded, so there is no median query cost of evasion. Macro F1 is **0.98805**
clean and **0.99481** under attack, recall **0.97556** and **0.99333**; the
attacked figures are scored on the raw fusion score and the clean ones on the
calibrated score, so the apparent improvement comes from the calibrator, not
the attack, and on one surface the attack changes no decision at a 0.5 cut-off
([§7.4](07-evaluation-dossier.md#74-the-result-that-matters-robustness)). The
reported macro F1 drop is **0.0**. Measured against the calibrated score the
deployed API actually returns, attack success is also **0.0**.

Read the zero for what it is. At a budget of 10 the composed search makes about
one accepted edit per message, drawn in practice from A-UNI, A-LEX and A-URL, so
it bounds a cheap attacker, not a determined one. The deployed policy still
registered the attack: 11 of the 150 attacked messages moved from BLOCK to
REVIEW, none to ALLOW, and the review rate rose from 0.16099 to 0.16667. The
stronger test is the adaptive attack on PG-HARD's 48 hard phishing records,
which targets the abstention control: at 40 and at 120 queries it delivers 3 of
them (6.2%) with no warning, against 29 and 43 for the text-only filter.

The residual-risk register scores every family as **likelihood: very low**, with
residual risk **low** for A-LEX, A-UNI, A-URL and A-STRUCT and **very low** for
A-HDR, A-BEH, A-TRUST and A-CHANNEL. Impact is **high** for A-LEX, A-UNI, A-URL
and A-STRUCT — the victim reaches the landing page with the lure intact — and
**medium** for A-HDR, A-BEH, A-TRUST and A-CHANNEL; A-HDR and A-BEH improve
credibility or timing without themselves delivering the payload. The likelihood
column is derived from each family's measured attack success rate, which is 0.0
for all eight at this budget, so it does not reflect PG-HARD, where A-HDR and
A-BEH each got one hard phishing record through at 40 queries.

### Leave-one-out ablation

| Arm | Clean macro F1 | Clean FPR | Adversarial macro F1 | Attack success | Silent delivery | ASR vs full |
|---|---|---|---|---|---|---|
| All defences | 0.98805 | 0.00096 | 0.99481 | 0.0 | 0.0 | — |
| without D-NORM | 0.98857 | 0.00096 | 0.99533 | 0.0 | 0.0 | 0.0 |
| without D-URL | 0.99118 | 0.00289 | 0.99429 | 0.0 | 0.0 | 0.0 |
| without D-ADVTRAIN | 0.99429 | 0.00385 | 0.99481 | 0.0 | 0.0 | 0.0 |
| without D-ENSEMBLE | 0.97826 | 0.03372 | 0.9689 | **0.1** | **0.1** | **+0.1** |
| without D-ABSTAIN | 0.98805 | 0.00096 | 0.99481 | 0.0 | 0.0 | 0.0 |
| without D-VELOCITY | 0.98805 | 0.00096 | 0.99481 | 0.0 | 0.0 | 0.0 |
| No defences | 0.97358 | 0.03372 | 0.96786 | **0.09167** | **0.06667** | **+0.09167** |

The ablation arms are measured on their own harness — each retrained from
scratch and attacked at the same budget of 10, on the first 120 of the 150
messages — and compared against each other. The "all defences" arm reproduces
the registered model's clean and adversarial macro F1 exactly.

**One control carries the measurable robustness at this budget.** Removing
D-ENSEMBLE — which leaves the single `engineered` member — takes the escape
rate from 0.0 to 0.1 (12 of 120), and every one of those escapes is also a
silent delivery: one message in ten reaching the inbox unreviewed. The same arm
has the worst clean false-positive rate of the single-control arms, 0.03372.
Removing everything gives 0.09167 and 0.06667, no worse than removing the
ensemble alone. Multi-view fusion is doing the measurable work.

On 7 September removing D-ADVTRAIN more than tripled the escape rate; on this
run, at a budget of 10, removing it changes nothing measurable. The ordinary
test set at this budget is not hard enough to separate adversarial training,
canonicalisation and URL unwrapping from the full system: the composed search
makes about one edit per message, and every arm that keeps the ensemble holds
every attacked message above the block threshold. The PG-HARD adaptive attack
is the more discriminating test, but it is run against the deployed model only,
not against each arm.

**Five controls show no measurable effect on this metric, and it would be
dishonest to claim otherwise.** D-NORM, D-URL, D-ADVTRAIN, D-ABSTAIN and
D-VELOCITY all leave the attack success rate at exactly 0.0 with silent
delivery at 0.0. That is the measurement, and the explanation matters more than
the number.

D-ABSTAIN and D-VELOCITY *cannot* register on this metric by construction. Both
operate downstream of the raw score that the ablation attacks: the abstention
band is a threshold policy applied to a score, and the velocity guard is a
bounded adjustment applied to a score. Attacking the raw surface and then asking
whether a downstream banding policy changed it is asking the wrong question of
the wrong number. This is a measurement limitation, not evidence that the
controls are inert. Their value appears in the banded outcome instead, where
under attack the review rate rises from 0.16099 to 0.16667 and phishing messages
routed to an analyst rise from 200 to 211, while phishing delivered outright
stays at 2 and no legitimate mail is blocked in either condition. The band is
absorbing attack pressure as review load rather than as silent delivery, which
is exactly what it exists to do.

D-NORM's null result has a different and less comfortable explanation: its
effect is most likely masked because the ensemble already resists the unicode
family without it. On this run removing D-NORM does not even cost adversarial
macro F1 (0.99533 against 0.99481, a difference of about one message), and on a
corpus where character- and word-n-gram members plus the other controls already
absorb A-UNI at this budget, canonicalisation has little left to contribute. It
would matter considerably more in a text-only deployment with a single model,
which is the configuration most published phishing detectors actually ship.

D-URL and D-ADVTRAIN share a pattern worth stating plainly. Removing either
leaves the escape rate at 0.0 and *raises* clean macro F1 at a 0.5 cut-off (to
0.99118 and 0.99429, against 0.98805), while raising the clean false-positive
rate (to 0.00289 and 0.00385, against 0.00096 — two and three more legitimate
messages flagged). On the binding constraint — false positives — both earn
their place, by a few messages; on the raw attack success rate at this budget
neither shows anything, and a 120-message arm cannot distinguish a one-message
difference from noise in either direction.

## 4.8 STRIDE analysis of the service

| Category | Threat to this system | Control | Where |
|---|---|---|---|
| **Spoofing** | An unauthenticated caller submits scans, or a stolen key is guessed by timing the comparison | API keys compared in constant time (`hmac.compare_digest`) against stored SHA-256 digests, never against plaintext and never logged; the loop runs over every digest so neither an early match nor the number of keys is observable; the service refuses to start in production without `PG_API_KEYS` rather than falling back to a default (M7) | `service/security.py` — `ApiKeyAuthenticator`, `build_security` |
| **Tampering** | Hostile input crafted to corrupt parsing or reach the store; injection through a filter parameter | Every request contract sets `extra="forbid"`, so unknown fields are rejected rather than silently ignored; bounded lengths on subject, body, HTML, sender, Reply-To, Return-Path, recipients and attachments; batches capped at 100; parameterised SQL throughout the store | `service/contracts.py`, `service/store.py`; `tests/security/test_security.py` |
| **Repudiation** | An analyst or administrator denies having made a decision, a correction or a release; an incident cannot be reconstructed | Every request carries an unguessable request ID, echoed as `X-Request-ID`, and a W3C trace id echoed as `traceparent`, both emitted in structured logs; every decision is persisted with its request ID, trace id, the calling `key_id`, timestamp, score, band, model version and top evidence titles; feedback is recorded against the decision ID; every review-queue transition is a `case_events` row with actor, role, the states on either side and the reason | `service/security.py` — `new_request_id`; `service/app.py`; `service/store.py`; `service/telemetry.py` |
| **Information disclosure** | An insider reads colleagues' mail through the audit trail (M4); the scanner is used as an SSRF primitive or as an oracle for victim activity (M5) | No message content is stored — rows hold a salted subject digest, a pseudonymised sender, the domain, sizes, the score and evidence titles, which is enough to investigate and not enough to reconstruct anyone's mail; the salt makes the subject digest non-reversible against a short-subject dictionary; logs never carry content; the audit trail is admin-only; decision IDs come from `secrets`; retention is bounded and swept. The system never resolves a URL or opens an attachment — every URL signal is lexical and strictly offline | `schemas.py` — `pseudonymize`, `redacted`; `service/store.py`; `retention_sweep`; `tests/security/test_security.py` |
| **Denial of service** | A caller floods the inline path, or one crafted message hangs the scanner and backs up the gateway (M2) | Per-key token-bucket limiter, chosen over a fixed window because gateway traffic is bursty and a fixed window either rejects a legitimate burst or permits double the rate across a boundary; hard body-size cap (1 MB default); bounded batch sizes; permissive parsers that do not raise; no unbounded regex backtracking on attacker-controlled input; container memory limit; liveness independent of the model | `service/security.py` — `TokenBucketLimiter`, `SecurityConfig.max_body_bytes`; `docker-compose.yml` |
| **Elevation of privilege** | A reporter reaches scanning; an analyst reaches the audit trail or the adversarial probe, or acts on a case another analyst owns; a container escape from the API process | Three roles with an explicit hierarchy — reporting requires `reporter` and returns no score, scanning and feedback require `analyst`, the audit trail, the traces and the adversarial probe require `admin`; object-level checks on every case action (M11), and high-risk release reserved to `admin` (M10); the probe is admin-gated precisely because it reports which edits reduce a score, which is what a defender needs and equally what an attacker wants; the container runs non-root, with `cap_drop: ALL` and `no-new-privileges:true` | `service/security.py` — `Principal.can`, `require`; `service/app.py` — `require_admin`; `docker/api.Dockerfile`, `docker-compose.yml` |

## 4.9 Explicitly out of scope

These are deliberate exclusions, recorded so the residual-risk register is
honest about what the system does not defend against and so the gap is covered
by something else rather than assumed away.

**OOS-1 — Compromise of a genuine brand or partner domain.** Mail genuinely
originating from the real domain passes every header and reputation check by
construction; there is no content signal that reliably separates it from
legitimate mail from the same domain. This is an authentication and
account-security problem, not a content-classification one, and it is mitigated
elsewhere by MFA on mail accounts, DMARC enforcement and egress monitoring.

**OOS-2 — White-box gradient-based evasion.** This assumes the attacker holds
model weights. If weights leak, the correct response is rotation and retraining,
not a robustness claim — a system that claims robustness to an attacker who can
compute gradients against it is claiming something no deployed detector
delivers. Mitigated by artefact access control and model-registry auditing.

**OOS-3 — Training-data poisoning through the analyst feedback loop.** Feedback
is stored and surfaced for review but is never used to retrain automatically;
retraining is a deliberate, reviewed action. Active learning from the analyst
queue was designed for and then deliberately not built, because it is precisely
this vector. Mitigated by human review of feedback before any retraining run.

**OOS-4 — Malicious payload analysis (attachment detonation, page fetching).**
The system never resolves a URL or opens an attachment. Fetching
attacker-controlled content from the gateway would create an SSRF surface and
leak victim telemetry to the attacker — a fetch is an unambiguous signal that
the message arrived and was inspected. Mitigated by a dedicated sandbox
detonation service downstream.

## 4.10 Abuse cases

The misuse cases enumerated in §1.6 of the problem brief, each against the
control that answers it.

| # | Misuse case | Control |
|---|---|---|
| M1 | Repeated API queries to tune a message until it passes | Per-key token-bucket rate limiting; every probe audited; the adversarial-probe endpoint is admin-only, so the defender holds the capability and an anonymous caller does not |
| M2 | A crafted message designed to crash or hang the scanner | Bounded input and batch sizes, no unbounded regex backtracking, permissive parsers that never raise; `tests/security/` |
| M3 | Model poisoning through the feedback endpoint | Feedback recorded, never used to retrain automatically; `OOS-3` |
| M4 | Insider reads colleagues' mail via the audit trail | No content stored — salted subject digest, pseudonymised sender, domain, sizes, verdict; admin-only access |
| M5 | The scanner used as an SSRF primitive or an activity oracle | No URL is ever resolved and no attachment opened; every URL signal is lexical; `OOS-4` |
| M6 | Decisions used to justify blocking a competitor or an individual | Decisions are content-derived and fully auditable; attribution to a person or organisation is named out of scope in the model card |
| M7 | Deployment with development API keys | The service refuses to start in production without `PG_API_KEYS` and warns loudly when development keys are active |
| M8 | A legitimate organisation penalised for a brand-like domain | Named as a known harm; the REVIEW band (D-ABSTAIN) and the feedback loop are the mitigation; brand lists are confined to one inspectable file |
| M9 | A reporter key used as a free scoring oracle | The report endpoint returns a case id and a plain-language status, never a score or band; the `reporter` role reaches nothing else (`test_reporter_status_never_mentions_a_score`) |
| M10 | An analyst is talked into releasing a message the model was confident about | Releasing a message scored at or above the block threshold needs the `admin` role and a written reason, recorded in the case history (`test_releasing_a_message_the_model_would_block_needs_an_administrator`) |
| M11 | An analyst acts on a case another analyst owns (OWASP API1, broken object-level authorisation) | Only the assignee or an admin may release, resolve or escalate a claimed case; transitions are compare-and-set on the current state, so a stale or concurrent write is refused with 409 (`test_a_second_analyst_cannot_steal_a_claimed_case`, `test_the_store_refuses_a_stale_transition`) |

## 4.11 Assumptions that would invalidate this model

**The corpus is synthetic, so the attack suite's coverage reflects what its
authors thought of.** This is the largest threat to the validity of every number
in §4.7. The transforms were written by the same people who built the defences,
which is a structural conflict: a family nobody imagined is by definition absent
from both the training augmentation and the evaluation. The zero attack success
rates in §4.7 should be read as "these transforms, composed under a budget of
10, did not succeed on ordinary phishing", not as "this system is robust" — and
the adaptive attack on PG-HARD, which got 3 of 48 hard phishing records
through, is the reminder. Coverage also depends on the suite's code being
right: until 1.3.0 a second function named `t_open_redirect` replaced the
first, so A-URL-02 silently ran A-TRUST-02's code and open-redirect chaining was
neither evaluated nor trained against, and only static analysis (ruff F811)
caught it. The comparative results — which controls matter relative to each
other — survive this limitation better than the absolute ones do.

**The query budget of 10 is an assumption about the attacker, not a property of
the system.** An operator willing to spend hundreds of queries against a live
endpoint has a materially better chance than the measurement suggests. At a
budget of 10 the composed search makes about one accepted edit per message and
no ordinary phishing message evaded; on PG-HARD the adaptive attacker got
nothing through at 10 queries and 3 of 48 hard phishing records through at 40
([§7.4](07-evaluation-dossier.md#74-the-result-that-matters-robustness)) — the
budget, not the suite, decided the outcome. Rate limiting and probe auditing
(M1) are what make the budget assumption defensible in deployment, and if those
are removed or misconfigured, the robustness claim degrades with them.

**Behavioural context is assumed trustworthy.** The A-BEH capability boundary
holds only because correspondence history and domain age come from the gateway
rather than from the message. A compromised gateway could forge that context
outright, at which point the decorrelating leg of the ensemble is under attacker
control and the A-BEH results no longer bound anything. The gateway is drawn as
semi-trusted in §4.3 for this reason; nothing in this system detects a lying
gateway.

**The brand and TLD lists are assumed current.** Several features depend on
lists that age continuously as new brands are impersonated and new TLDs are
delegated. They are confined to one reviewable file specifically so that ageing
is visible and correctable, but a stale list quietly degrades A-URL and A-HDR
coverage without any metric moving until the next evaluation run.

**The operating point is assumed to hold.** Every figure in §4.5 and §4.7 is
measured at a block threshold of 0.8 and a review threshold of 0.4. An
administrator who widens the ALLOW band to reduce review load moves silent
delivery directly, and the residual-risk register would need re-running rather
than re-reading.

---

**Next:** [§5 Test strategy →](05-test-strategy.md)
