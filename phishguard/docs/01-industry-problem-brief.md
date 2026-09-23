# 1. Industry problem brief

**BAI-17 — Adversarially Robust Phishing Defense using Email, URL and Behavioral Features**
T.Y. B.Sc. Artificial Intelligence · KES' Shroff College · Semester V

---

## 1.1 The problem, stated precisely

Phishing detectors perform well on a fixed dataset and fail when attackers alter
spelling, domains, or message style.

That sentence is the whole brief, and the important word in it is *fixed*. A
model fitted on last quarter's corpus is being asked to classify messages that
were written **after** it was trained, by someone who can see whether their
message got through. The literature reports macro F1 above 0.98 on public
corpora routinely; operational filters are bypassed daily. Both facts are true,
and the gap between them is the subject of this project.

The gap has a specific shape. A phishing kit is tested against public scanners
before a campaign launches. If the message is caught, the operator edits it and
tries again: a synonym here, a Cyrillic character there, a redirect chain, a
different sending domain. Each edit costs the attacker almost nothing and none
of them changes what the message *does*. A detector that has learned the surface
form of last quarter's phishing has learned exactly the thing the attacker is
free to change.

## 1.2 Stakeholders

| Stakeholder | What they need | What failure costs them |
|---|---|---|
| **Recipient** (any employee) | Not to be asked to be an expert. Clear signal when a message is dangerous. | Credential loss, financial loss, and the blame that follows |
| **Security analyst** (SOC) | Triage that is worth reading: high-signal queue, evidence they can act on, no wall of false alarms | Alert fatigue; the queue stops being read, which removes the last human control |
| **Mail administrator** | An inline filter that does not delay mail and does not quarantine the invoice the finance team is waiting for | A single high-profile false positive gets the filter switched off |
| **CISO / risk owner** | Defensible assurance: what is this thing's actual failure mode, and what covers it | Cannot answer an audit question, or discovers the answer during an incident |
| **Finance / AP team** | Protection specifically against invoice fraud and payment-diversion, which is where the money goes | Direct financial loss, often irrecoverable |
| **Attacker** (adversarial stakeholder) | Cheap, repeatable evasion | — modelled explicitly in [§4 Threat model](04-threat-model.md) |

The adversary is listed as a stakeholder deliberately. A system whose
requirements document does not contain the attacker's goals will be evaluated
only against the cases its authors happened to think of.

## 1.3 Current process and its evidence

The baseline this project must beat is not "nothing". It is the combination of:

1. **Reputation and authentication filtering** at the gateway (SPF/DKIM/DMARC,
   domain blocklists). Effective against bulk campaigns from known-bad
   infrastructure; blind to a first-use domain with correctly published records.
2. **A keyword and rule engine** — the analyst checklist. Implemented in this
   project as baseline **B0** (`src/phishguard/models/baseline.py`, 37 named
   rules) so that the comparison is a measurement, not an assertion.
3. **User reporting** — a "report phishing" button. High precision, arrives
   after delivery, and depends on the recipient noticing.

Measured on this project's held-out test set, B0 reaches **macro F1 0.911 with
a 2.2% false-positive rate**. That is the bar. A 2.2% false-positive rate on
real mail volume is already at the edge of what a business tolerates, which is
why "improve recall" is not by itself a useful goal.

## 1.4 User stories

**Recipient**

- As an employee, I want a dangerous message to be quarantined before I see it,
  so that I am not the last line of defence.
- As an employee, when a message is held, I want to know *why* in one sentence,
  so that I can tell the difference between a mistake and a real threat.

**Analyst**

- As an analyst, I want each queued message to arrive with the evidence that put
  it there, so that I can triage in seconds rather than reconstruct the reasoning.
- As an analyst, I want to record that the model was wrong, so that the error is
  captured — without that correction silently retraining the model behind my back.
- As an analyst, I want to ask "would this get through if the attacker tried
  harder?" for a message I am holding, so that I can judge whether a near-miss
  is a gap.

**Administrator**

- As a mail administrator, I want to tune the block threshold against a
  false-positive budget rather than a probability, because that is the language
  my service-level agreement is written in.
- As a mail administrator, I want assessment to complete inline within the
  gateway's per-message budget, so that mail does not queue.

**Risk owner**

- As a CISO, I want a written statement of what this system does not defend
  against, so that the gap is covered by something else rather than assumed away.
- As a CISO, I want the robustness claim to be a measurement I can re-run, not a
  paragraph in a slide deck.

## 1.5 Misuse and abuse cases

Enumerated because the acceptance gates require it, and because several of them
changed the design.

| # | Misuse case | Design response |
|---|---|---|
| **M1** | Attacker queries the API repeatedly to tune a message until it passes | Rate limiting per key; every probe is audited; the adversarial-probe endpoint is admin-only so the *defender* has the capability and an anonymous caller does not |
| **M2** | Attacker submits a crafted message designed to crash or hang the scanner | Bounded input sizes, bounded batch sizes, no unbounded regex backtracking on attacker-controlled input, permissive parsers that never raise; tested in `tests/security/` |
| **M3** | Attacker poisons the model through the analyst feedback endpoint | Feedback is **recorded, never used to retrain automatically**. Retraining is a reviewed, manual act. Documented as `OOS-3` |
| **M4** | Insider uses the audit trail to read colleagues' mail | The audit trail stores no content: a salted subject digest, a pseudonymised sender, the domain, sizes and the verdict. There is nothing to read |
| **M5** | Attacker uses the scanner as an SSRF primitive or an oracle for victim activity by embedding internal URLs | The system **never resolves a URL or opens an attachment**. Every URL signal is lexical. Tested in `tests/security/test_security.py` |
| **M6** | The system is used to justify blocking mail from a competitor or a specific individual | Decisions are content-derived and auditable; the model card names "attributing an attack to a person or organisation" as out of scope |
| **M7** | An operator deploys with the development API keys | The service refuses to start in production without `PG_API_KEYS`, and logs a loud warning when development keys are in use |
| **M8** | A legitimate organisation is penalised because its domain resembles a brand | Named as a known harm in the model card; the REVIEW band and the feedback loop are the mitigation; the brand lists are inspectable in one file |

## 1.6 Scope

**In scope**

- Inbound organisational email: headers, subject, plain-text body, HTML part,
  attachment *metadata*, and sender-relationship context from the gateway.
- A calibrated probability, a three-way decision, and analyst-readable evidence.
- Robustness against an attacker who rewrites the message they send.

**Explicitly out of scope** (with the reasoning, because an unstated exclusion
is a hidden assumption):

| Exclusion | Why |
|---|---|
| Attachment detonation and page fetching | Fetching attacker-controlled content from the gateway creates an SSRF surface and leaks victim telemetry to the attacker. Belongs in a dedicated sandbox downstream |
| Compromise of a genuine brand or partner domain | Mail genuinely sent from the real domain passes every header and reputation check by construction. This is an authentication problem (`OOS-1`) |
| Outbound mail and data-loss prevention | A different problem with different features |
| Non-email channels (SMS, voice, chat) | The behavioural family assumes a mail gateway |
| Automated remediation | The system detects and explains; quarantine, notification and takedown are downstream |
| White-box gradient attacks | Assumes leaked model weights; the response to that is rotation, not a robustness claim (`OOS-2`) |

## 1.7 Success metrics

Every one of these is checked automatically by `phishguard evaluate`, which
exits non-zero on failure. See [§7 Evaluation](07-evaluation-dossier.md).

| ID | Metric | Threshold | Why this number |
|---|---|---|---|
| G1 | Macro F1 | ≥ 0.90 | Weights both classes equally; a model cannot pass by ignoring one |
| G2 | PR-AUC | ≥ 0.93 | Threshold-free, and honest when the positive class is a minority of live traffic |
| G3 | False-positive rate | ≤ 0.02 | **The binding constraint.** Above this, the business switches the filter off |
| G4 | Expected calibration error | ≤ 0.08 | The thresholds are policy; the probabilities must mean what they say |
| G5 | Macro F1 drop under attack | ≤ 0.15 | The project's distinguishing requirement |
| G6 | Attack success (escapes auto-block) | ≤ 0.35 | Measured at the deployed operating point, not at 0.5 |
| G7 | p95 assessment latency | ≤ 150 ms | The gateway assesses inline; the tail is what causes backlog |
| G8 | Macro F1 advantage over B0 | ≥ 0.01 | The learned system must beat the checklist it replaces |
| G9 | Robustness advantage over B1 | ≥ 0 | The tri-modal design is justified by robustness, not clean accuracy |
| G10 | Leakage audit | must pass | Group overlap or a leaked feature invalidates every other number |

**Non-functional requirements**

| Requirement | Target |
|---|---|
| Availability | Liveness independent of the model; `/readyz` reports *why* it is not ready |
| Reproducibility | A fixed seed reproduces the corpus, the split and the metrics on any machine |
| Privacy | No message content in the database or in logs; audit retention bounded and swept |
| Portability | Clean machine to running system in one command, offline, no downloads |
| Observability | Structured logs, Prometheus metrics, score-distribution drift signal |
| Security | Role-separated API keys, rate limits, bounded inputs, dependency scanning in CI |

## 1.8 Prioritised backlog

Ordered by "what would this project be worthless without".

### Must have — delivered

| # | Item | Where |
|---|---|---|
| B1 | Three independent feature families with clean interfaces | `features/` |
| B2 | Leakage-safe campaign-grouped splitting, with an audit that can fail the build | `data/splits.py` |
| B3 | Calibrated fusion over heterogeneous members | `models/detector.py` |
| B4 | Threat-informed attack taxonomy and a semantic-preserving transform suite | `adversarial/` |
| B5 | Named, individually ablatable defensive controls | `defenses/` |
| B6 | Baseline comparison (manual checklist and conventional text model) | `models/baseline.py` |
| B7 | Evaluation dossier with automated go/no-go gates | `eval/` |
| B8 | Serving API with authentication, audit trail and human oversight | `service/` |
| B9 | Analyst console with evidence and feedback | `ui/` |
| B10 | Containerised deployment, observability, CI | `docker/`, `.github/` |
| B11 | Model card, threat model, residual-risk register | `docs/`, generated |

### Should have — delivered

| # | Item | Where |
|---|---|---|
| B12 | Modality ablation quantifying each family's contribution | `eval/run_eval.py` |
| B13 | Defence ablation quantifying each control's contribution | `eval/run_eval.py` |
| B14 | Per-decision counterfactual explanations | `explain/` |
| B15 | Adversarial probe endpoint for post-deployment assurance | `service/app.py` |
| B16 | Public-corpus loaders with provenance and licensing recorded | `data/loaders.py` |

### Could have — designed for, not enabled by default

| # | Item | Status |
|---|---|---|
| B17 | Transformer member (DistilBERT) | Implemented and guarded behind an extra; off by default because it needs a GPU to be practical and the ablation shows what it would have to beat |
| B18 | Temporal-drift evaluation over a longer horizon | Temporal split implemented; a multi-quarter study needs real longitudinal data |
| B19 | Active learning from the analyst queue | Deliberately not built: it is the poisoning vector in `OOS-3` |

### Will not have

- Attachment detonation, URL fetching, outbound DLP, automated takedown.

## 1.9 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Synthetic corpus flatters the model | **High** | High | Leakage audit; no single feature above ~0.84 AUC; hard-subset metrics reported separately; comparative results emphasised over absolute; limitation stated in the model card and the dossier |
| A novel attack family defeats the defences | Medium | High | Residual-risk register; the REVIEW band converts uncertainty into review rather than silent delivery; the probe endpoint keeps the claim testable after deployment |
| False positives erode trust | Medium | High | FPR is the strictest gate; the operating point is chosen on a false-positive budget; abstention band |
| Brand and TLD lists age | **High** | Medium | Confined to one reviewable file; quarterly review named in the model card's maintenance section |
| Behavioural context unavailable in deployment | Medium | Medium | Graceful degradation with the absence recorded as a feature and surfaced in the evidence; a monitoring alert fires when most traffic lacks it |
| Model or corpus drift after deployment | **High** | Medium | Score-distribution monitoring; analyst-disagreement rate; alerting rules shipped with the stack |

---

**Next:** [§2 Solution design pack →](02-architecture.md)
