# 10. Individual contribution and work log

## 10.1 What this document is for

The portfolio requires each student to **independently evidence at least 100
hours** of work on the capstone. This document is where that evidence is
assembled: what you did, when, for how long, and — the part that carries the
weight — what artefact in this repository resulted from it.

Two things follow from the word *independently*.

**Hours are claimed against artefacts, not against memory.** An entry reading
"worked on the model, 6 hours" evidences nothing. An entry reading "implemented
isotonic calibration with a Platt fallback and the no-op degenerate case;
`src/phishguard/models/calibration.py`; 8 tests in `tests/unit/test_metrics.py`;
commit `a1b2c3d`" is checkable by an examiner in under a minute. Write the
second kind.

**Each student maintains their own log.** On a team of two or three the module
ownership is divided (§10.2) and each person logs only their own work. Shared
activities — design discussions, integration sessions, the demonstration — are
logged by everyone who attended, with the same date and a note of who else was
present, so that the examiner can cross-check the entries against each other.

Fill in §10.4, §10.5 and §10.7, complete the checklist in §10.6, and prepare
§10.8. Sections 10.1 to 10.3 are reference material and need no editing.

## 10.2 Role-to-module map

The portfolio defines three roles. This table maps each to the concrete files in
this repository, so a team of one to three can divide ownership without
ambiguity about who owns what.

**A team of one** owns all three columns and says so in the log — that is the
normal case for this project, and it is why the module map matters more than
the role labels: the evidence is per-module either way.

### AI data engineer

*Annotation strategy, data pipeline, augmentation, evaluation dataset.*

| Module | Path | What it is |
|---|---|---|
| Synthetic corpus generator | `src/phishguard/data/synthetic.py` | More than 40 lure types, campaign structure, difficulty balancing — the annotation strategy, since it assigns the labels |
| Hard-case benchmark | `src/phishguard/data/hardcases.py` | PG-HARD: 24 hand-written cases, each inverting a named detection cue, 8 variants each |
| Splitting and leakage audit | `src/phishguard/data/splits.py` | Campaign-grouped split, MinHash/LSH near-duplicate scrub, the four-check leakage audit |
| Public corpora | `src/phishguard/data/loaders.py`, `verify.py`, `fetch.py` | mbox and maildir loaders, the corpus audit that catches era and label confounds, the fetcher with its provenance record |
| Dataset versions | `src/phishguard/data/fingerprint.py` | Content-addressed fingerprints of every training and test set |
| Brand and reputation tables | `src/phishguard/data/banks.py` | Brand domains, high-abuse TLDs, disposable and free-hosting suffixes |
| Lexicons | `src/phishguard/features/lexicons.py` | The eight social-engineering lexicons |
| Email feature extraction | `src/phishguard/features/email.py` | 125 header, subject, body, HTML and attachment features |
| URL feature extraction | `src/phishguard/features/urls.py` | 107 URL features, public-suffix handling, canonicalisation |
| Behavioural feature extraction | `src/phishguard/features/behavioral.py` | 33 relationship, timing, distribution and campaign-shape features |
| Tests | `test_splits.py`, `test_features.py`, `test_urls.py`, `test_hardcases.py`, `test_real_corpora.py`, `test_fetch.py`, `test_fingerprint.py`, all in `tests/unit/` | 91 tests |
| Documents | `docs/06-data-dictionary.md`, `docs/11-real-data.md`, `docs/adr/002-synthetic-corpus.md` | |

### Model engineer

*Model design and training, optimisation, uncertainty, robustness, ablation studies.*

| Module | Path | What it is |
|---|---|---|
| Detector | `src/phishguard/models/detector.py` | Members → fusion → calibration → banding; the three-pool training procedure |
| Ensemble members | `src/phishguard/models/members.py` | `engineered`, `charngram`, `wordtfidf`, optional transformer |
| Baselines | `src/phishguard/models/baseline.py` | B0 rule checklist (also the `rules` member) and B1 TF-IDF logistic regression |
| Calibration | `src/phishguard/models/calibration.py` | Isotonic with Platt and no-op fallbacks, ECE/MCE, reliability curves |
| Model registry | `src/phishguard/models/registry.py` | Versioning, manifests, feature-contract verification, promote/prune |
| Feature assembler | `src/phishguard/features/assembler.py` | The 265-feature ordered contract and family selection |
| Attack taxonomy and transforms | `src/phishguard/adversarial/taxonomy.py`, `transforms.py` | 8 families, 35 transforms |
| Attackers and reporting | `src/phishguard/adversarial/attacker.py`, `adaptive.py`, `report.py` | Budgeted black-box attacker, the adaptive attacker that targets the abstention band, per-family and residual-risk reporting |
| Defensive controls | `src/phishguard/defenses/controls.py`, `normalize.py` | D-NORM, D-URL, D-ADVTRAIN, D-ENSEMBLE, D-ABSTAIN, D-VELOCITY |
| Explanations | `src/phishguard/explain/attributions.py`, `evidence.py` | Occlusion counterfactuals, analyst evidence cards |
| Evaluation harness | `src/phishguard/eval/run_eval.py`, `metrics.py`, `acceptance.py`, `error_analysis.py`, `hard_eval.py`, `seeds.py` | The dossier, both ablations, PG-HARD grading, seed sensitivity, the ten acceptance gates |
| Cost model | `src/phishguard/eval/cost.py` | The thresholds priced in analyst reviews, under attack and by minimax regret |
| Report figures and tracking | `src/phishguard/reporting/figures.py`, `src/phishguard/tracking.py` | Nine figures with data-driven captions; optional MLflow logging |
| Tests | `test_metrics.py`, `test_transforms.py`, `test_normalize.py`, `test_defenses.py`, `test_cost.py`, `test_tracking.py`, all in `tests/unit/` | 74 tests |
| Documents | `docs/04-threat-model.md`, `docs/07-evaluation-dossier.md`, `docs/adr/001`, `003`, `005`, `006` | |

### Systems engineer

*Edge/cloud integration, interface, safety controls, deployment and testing.*

| Module | Path | What it is |
|---|---|---|
| HTTP API | `src/phishguard/service/app.py` | 23 API endpoints plus the console and report pages; dependency wiring, middleware, security headers |
| Scan orchestration | `src/phishguard/service/scanning.py` | `ScanService` — the framework-free decision path |
| Request/response contracts | `src/phishguard/service/contracts.py` | Pydantic models, validation bounds |
| Security | `src/phishguard/service/security.py` | API-key auth, three roles (analyst, admin, reporter), token-bucket rate limiting |
| Audit store | `src/phishguard/service/store.py` | SQLite/WAL schema, pseudonymisation, retention sweep, the review-queue tables |
| Review queue | `src/phishguard/service/workflow.py` | The case state machine, object-level authorisation, service levels |
| Tracing and telemetry | `src/phishguard/service/tracing.py`, `telemetry.py` | W3C Trace Context and per-stage spans; JSON logging, Prometheus registry |
| Drift monitoring | `src/phishguard/monitoring/drift.py` | Calibrated PSI and KS tests on live traffic |
| Console and report page | `src/phishguard/static/index.html`, `report.html` | Six tabs, zero build step; the page any employee uses to report a message |
| CLI and preflight | `src/phishguard/cli.py`, `doctor.py`; `start.py` at the root | 17 commands; the machine check; the one-command start |
| Load testing | `src/phishguard/eval/loadtest.py` | In-process, multi-process, or against a running service |
| Container and stack | `docker/api.Dockerfile`, `docker/entrypoint.sh`, `docker-compose.yml` | Non-root image, bootstrap training, three-service stack |
| Monitoring | `docker/prometheus.yml`, `docker/alerts.yml`, `docker/grafana/` | 10 alert rules, 18 dashboard panels |
| CI and tooling | `.github/workflows/` (CI, CodeQL, release), `Makefile`, `scripts/run_tests.py` | |
| Tests | `tests/integration/test_service.py`, `tests/security/test_security.py`, and `test_workflow.py`, `test_tracing.py`, `test_loadtest.py`, `test_portability.py`, `test_drift.py` in `tests/unit/` | 116 tests |
| Documents | `docs/02-architecture.md`, `docs/03-api-contract.md`, `docs/08-deployment-guide.md`, `docs/09-admin-user-guide.md`, `docs/adr/004`, `007`, `008` | |

### Shared boundaries to agree explicitly

Three seams cause most ownership disputes. Settle them in writing at the start
and note the decision in your log:

| Seam | Between | Suggested split |
|---|---|---|
| `src/phishguard/features/` | Data and model engineer | Extraction logic (`email.py`, `urls.py`, `behavioral.py`, `lexicons.py`) to the data engineer; the ordered contract (`assembler.py`) to the model engineer, because the registry verifies it |
| `src/phishguard/defenses/` | Model and systems engineer | D-NORM, D-URL and D-ADVTRAIN to the model engineer; D-ABSTAIN and D-VELOCITY are policy applied at request time, so their integration into `ScanService` is the systems engineer's |
| `src/phishguard/eval/` | Model and systems engineer | The metrics and ablations to the model engineer; the acceptance gates as a **CI build-blocking mechanism** to the systems engineer |

## 10.3 Phase definitions

The five mandated phases, and what each means in this project.

| # | Phase | Hours | In this project |
|---|---|---|---|
| 1 | Problem discovery, requirement validation and backlog | 15 | Reading the phishing-defence literature and incident data; deciding that adversarial robustness, not raw accuracy, is the problem; the threat model; acceptance criteria that a build can fail on |
| 2 | Architecture, UI/data design and technical spike | 15 | C4 levels 1–3; the feature schema; the three-pool training design; the first six ADRs; a throwaway spike proving the attack loop is feasible |
| 3 | Owned module implementation and unit testing | 40 | Your columns from §10.2, with tests written alongside rather than afterwards |
| 4 | Integration, security, performance and acceptance testing | 15 | End-to-end path, the 24 security tests, latency against the 150 ms gate and the load test, the ten acceptance gates |
| 5 | Deployment, documentation, demonstration and viva preparation | 15 | Container and compose stack, monitoring, the twelve documents, the demonstration script, §10.8 |

## 10.4 Worked example — the first 20 hours

> ⚠️ **THIS IS AN EXAMPLE. DELETE IT AND REPLACE IT WITH YOUR OWN ENTRIES.**
> It is here to show the expected granularity: one row per session, hours to one
> decimal place, a named artefact for every row, and a commit reference that an
> examiner can open. Entries with no artefact are the ones that get challenged.

| # | Date | Hours | Phase | Activity | Artefact / evidence | Commit |
|---|---|---|---|---|---|---|
| 1 | 2026-07-06 | 2.0 | 1 | Literature review: 11 papers on adversarial evasion of phishing classifiers. Noted that most report accuracy on static corpora and none report attack success against a deployed threshold. | `notes/literature-review.md`, 11 annotated entries | `abc1234` |
| 2 | 2026-07-07 | 1.5 | 1 | Reviewed 4 public corpora (Nazario, Enron, PhishTank, SpamAssassin). Established that none carry behavioural or sender-relationship data — the finding that forced the synthetic-corpus decision. | `notes/corpus-survey.md`; later became `docs/adr/002-synthetic-corpus.md` | `abc1234` |
| 3 | 2026-07-08 | 2.0 | 1 | Problem framing session with supervisor. Agreed the project's claim is comparative robustness, not absolute accuracy — this is what makes the result defensible on a synthetic corpus. | Supervisor meeting note, 2026-07-08; issue #1 "Define the project claim" | `def5678` |
| 4 | 2026-07-09 | 2.5 | 1 | Drafted the threat model: attacker capability, six attack families, four out-of-scope threats with reasons. | `docs/04-threat-model.md` §1–§3 (first draft) | `def5678` |
| 5 | 2026-07-10 | 2.0 | 1 | Wrote the acceptance criteria as ten machine-checkable gates with thresholds and a written rationale each. Rejected two earlier candidates as unmeasurable. | `docs/01-industry-problem-brief.md` §4; issues #2–#11, one per gate | `ghi9012` |
| 6 | 2026-07-13 | 2.0 | 1 | Backlog construction: 34 issues across five milestones, each with an acceptance criterion. Estimated and ordered. | GitHub project board, milestones M1–M5 | — |
| 7 | 2026-07-14 | 1.5 | 1 | Requirement validation with two practising SOC analysts: what a verdict must show for them to act on it. Result: evidence must be sentences, and mitigating evidence must be visible. | `notes/analyst-interviews.md`; issue #12 "Evidence must include mitigating signals" | — |
| 8 | 2026-07-15 | 1.5 | 1 | Reviewed data-protection constraints on holding message content. Concluded the audit trail must hold no content at all. | `notes/data-protection.md`; issue #13 | `jkl3456` |
| 9 | 2026-07-16 | 2.0 | 2 | C4 level 1 and 2. Decided one application container over three services; wrote up the reasoning against the alternative. | `docs/02-architecture.md` §2.1–§2.2 | `mno7890` |
| 10 | 2026-07-17 | 1.0 | 2 | Technical spike: 80-line script attacking a scikit-learn TF-IDF classifier with homoglyph substitution, to check the attack loop was feasible at all before designing around it. Escaped a 0.5 threshold in 4 queries. | `spikes/attack-feasibility.py` (throwaway, kept for evidence); issue #14 | `pqr1234` |
| 11 | 2026-07-20 | 2.0 | 2 | Feature schema: three families, 265 features, fixed order. Wrote the family/block breakdown and the argument for why behavioural absence must be a feature rather than a zero. | `docs/02-architecture.md` §2.6 | `stu5678` |

**Running total: 20.0 hours** (Phase 1: 15.0, Phase 2: 5.0)

Points the example is making, which are easy to miss:

- **Entry 3 has no code artefact and is still evidenced** — a meeting note and a
  linked issue. Design and validation hours are legitimate; they just need a
  different kind of evidence.
- **Entry 10 logs a throwaway spike.** The script was never merged into the
  system and is kept only as evidence. That is exactly what "technical spike"
  means in Phase 2, and deleting it loses the hour.
- **Entries 1 and 2 share a commit**, entries 6 and 7 have none. Not every hour
  produces a commit; every hour produces *something*.
- **The hours are uneven** (1.0 to 2.5). A log where every session is exactly
  2.0 hours reads as reconstructed after the fact, because it is.

## 10.5 Work log — remaining hours

> Replace the example above and continue here. Add rows as needed. Keep the
> running total current so the final figure is not a last-minute reconstruction.

| # | Date | Hours | Phase | Activity | Artefact / evidence | Commit |
|---|---|---|---|---|---|---|
| 12 | | | | | | |
| 13 | | | | | | |
| 14 | | | | | | |
| 15 | | | | | | |
| 16 | | | | | | |
| 17 | | | | | | |
| 18 | | | | | | |
| 19 | | | | | | |
| 20 | | | | | | |
| 21 | | | | | | |
| 22 | | | | | | |
| 23 | | | | | | |
| 24 | | | | | | |
| 25 | | | | | | |
| 26 | | | | | | |
| 27 | | | | | | |
| 28 | | | | | | |
| 29 | | | | | | |
| 30 | | | | | | |
| 31 | | | | | | |
| 32 | | | | | | |
| 33 | | | | | | |
| 34 | | | | | | |
| 35 | | | | | | |
| 36 | | | | | | |
| 37 | | | | | | |
| 38 | | | | | | |
| 39 | | | | | | |
| 40 | | | | | | |
| 41 | | | | | | |
| 42 | | | | | | |
| 43 | | | | | | |
| 44 | | | | | | |
| 45 | | | | | | |
| 46 | | | | | | |
| 47 | | | | | | |
| 48 | | | | | | |
| 49 | | | | | | |
| 50 | | | | | | |

**Running total: ______ hours**

## 10.6 Evidence checklist

An examiner will ask how they can tell this work is yours. Each item below is
something they can verify without taking your word for it. Tick what you have,
and be honest about what you do not — a log with three strong evidence types is
better than one claiming six unconvincingly.

### Independent evidence

- [ ] **Branch history.** Work done on named branches (`feat/url-features`,
      `fix/calibration-fallback`) rather than committed straight to `main`.
      `git log --author="<you>" --oneline` should tell a coherent story that
      matches the dates in §10.5.
- [ ] **Commits authored by you, spread over time.** Commit timestamps that
      match your logged sessions. A repository whose entire history is one
      commit two days before the deadline evidences nothing, regardless of what
      the log says.
- [ ] **Pull requests, with review comments.** On a team: PRs you raised and
      PRs you reviewed. On your own: PRs into `main` with a description
      explaining what changed and why. Review comments are the strongest single
      evidence of understanding, because they show judgement rather than output.
- [ ] **The issue board.** Issues you opened, estimated, moved and closed, each
      with an acceptance criterion. Link issue numbers in log entries.
- [ ] **Test authorship.** Which of the 289 tests you wrote. This is the most
      persuasive evidence available, because a test proves you understood the
      failure it prevents. `tests/unit/test_transforms.py` is a good example to
      be able to speak to: it exists to stop an attack transform being written
      that cheats — for instance by fabricating the victim's correspondence
      history — which would silently invalidate every robustness number.
- [ ] **The evaluation dossier, regenerated by you.** Run
      `phishguard evaluate --n 9000 --budget 10 --max-attacked 150 --defense-ablation`
      yourself, on your own machine, and keep the console output. Being able to
      say how long it took and what G9 came out at on your machine is worth
      more than any table you can quote. (The dossier's run took about 19
      minutes on two cores; G9 was 0.2933.)
- [ ] **A demonstration recording.** Five to ten minutes following the script in
      [§8](08-deployment-guide.md): clean start, obvious phish, hard clone, hard
      negative, adversarial probe, feedback, audit trail. Record it before the
      viva; it is also the best rehearsal available.
- [ ] **Design artefacts predating the code.** Diagrams, ADR drafts, meeting
      notes, the spike script. These evidence Phases 1 and 2, which are 30 of
      the 100 hours and the hardest to evidence retrospectively.
- [ ] **CI history.** Runs of `.github/workflows/ci.yml` on your commits,
      including the failing ones. A history with failures that you then fixed is
      more credible than one that is green throughout.

### On a team of two or three, additionally

- [ ] A written ownership split, agreed at the start, matching §10.2 —
      including the three shared seams.
- [ ] Cross-references: your log names who else was in each shared session, and
      their log says the same thing.
- [ ] At least one PR review from each teammate on your work, and from you on
      theirs.

## 10.7 Hours summary

| Phase | Mandated | Actual | Principal evidence |
|---|---|---|---|
| 1. Problem discovery, requirement validation and backlog | 15 | | |
| 2. Architecture, UI/data design and technical spike | 15 | | |
| 3. Owned module implementation and unit testing | 40 | | |
| 4. Integration, security, performance and acceptance testing | 15 | | |
| 5. Deployment, documentation, demonstration and viva preparation | 15 | | |
| **Total** | **100** | | |

| | |
|---|---|
| **Name** | |
| **Roll number** | |
| **Role(s) held** | AI data engineer / Model engineer / Systems engineer |
| **Modules owned** | |
| **Repository** | |
| **Declaration** | The hours recorded above are my own work and are evidenced by the artefacts named. |
| **Signature / date** | |

If your actual hours diverge from the mandated distribution, **say so and give
the reason** rather than adjusting the numbers to fit. "Phase 3 ran to 46 hours
because the isotonic calibrator needed two rewrites; Phase 5 came in at 9
because the documentation was drafted alongside the modules" is a credible log.
Five numbers that land exactly on 15/15/40/15/15 are not.

## 10.8 Viva preparation

Nineteen questions an examiner is likely to ask about **this** project, with the
honest answer in one line and where the full version lives. The uncomfortable
ones are here deliberately — an examiner who finds a weakness you have not
already named will assume you did not know about it.

The general rule: **never defend a number you cannot criticise.** Every strong
result in this project has a matching limitation, and stating the limitation
before you are asked is what distinguishes understanding from recital.

| # | Question | Honest one-line answer | Where |
|---|---|---|---|
| 1 | Your clean macro F1 is 0.9880. Why should I believe any of it? | You should not believe it as a real-world number — the corpus is synthetic and the model can learn the generator, so it is an upper bound; what transfers is the comparative results, because they are measured under identical conditions. | [§7.12](07-evaluation-dossier.md) |
| 2 | Then what *is* your result? | On PG-HARD — 24 cases that each defeat a named cue — PhishGuard delivers 0 of 96 hard phishing records unwarned and wrongly blocks 8 of 96 legitimate ones (all one case), where the text-only filter also misses none but blocks 49; against an attacker who knows about abstention and spends 120 queries, 3 of 48 get through PhishGuard and 43 of 48 through the text-only filter. | §7.0, §7.4 |
| 3 | Five of your six defences show no effect in the ablation. Defend keeping them. | D-ABSTAIN and D-VELOCITY act after the raw score the ablation attacks, so they cannot register there by construction — D-ABSTAIN's effect is plain in the banded view (all 11 messages the attack moves out of BLOCK stop in REVIEW) and on PG-HARD (44 of 48 attacked records end in REVIEW); the other three are nulls of a weak test, because at a 10-query budget nothing moves in any arm that keeps the ensemble, so the test cannot say which control stopped it. | §7.6 |
| 4 | Why measure attack success at 0.80 rather than 0.5? | Because the deployed policy has no 0.5 boundary in it: dragging a message from 0.99 to 0.79 takes it out of auto-quarantine, which is a real gain for the attacker that a 0.5-anchored metric scores as total failure. | §7.4 |
| 5 | Does the behavioural family earn its place? | Not on clean accuracy, where it is worth one or two messages either way (all three families 0.9865, email + URL 0.9845) and the ordering has already flipped once; it earns it because it is the only family the attacker cannot rewrite — they cannot forge the recipient's correspondence history. Its benefit under attack is argued rather than measured: no experiment removes it and then attacks. | §7.5, [ADR-001](adr/001-tri-modal-fusion.md) |
| 6 | What stops your feedback endpoint being a poisoning vector? | Feedback is recorded and surfaced for human review and is **never** used to retrain automatically; retraining is a deliberate, reviewed action, and this is recorded as out-of-scope threat `OOS-3` rather than left implicit. | §9.5, §4.9 |
| 7 | You attack the raw pre-calibration score, not what the API returns. Isn't that cheating in your favour? | The opposite — it gives the attacker a finer oracle than any real client has, and on this run both surfaces give 0.000 at 10 queries. It is not the whole story, because the deployed decision also asks whether the members agree, which is why the PG-HARD attack is graded by the deployed decision instead; that is where the 3 of 48 comes from. | §7.4 |
| 8 | Your ECE is 0.0077. Is the model well calibrated? | Less than it looks: almost every message scores near 0 or 1, which keeps calibration error small almost for free; the telling detail is the 19 test messages the calibrator places at exactly 0.40 — 16 of them phishing, and 16 of the 22 missed phishing messages overall. On real mail it would be worse. | §7.7 |
| 9 | 23 errors in 1 938 messages. What does your error analysis establish? | Where the design is weakest, not how often it fails: 19 are cloned brand templates whose only signal is the header and the URL, 2 are thread hijacks, 1 is business email compromise and 1 is a false alarm on a legitimate rebrand. The category is identified; its real-world frequency is not. | §7.10 |
| 10 | You designed both the attacks and the defences. How is that a valid robustness evaluation? | It is a valid *lower bound on attack difficulty* and nothing more: a novel family is untested by construction, and D-ADVTRAIN trains on the same 35 transforms it is evaluated against, so part of the measured robustness is a defence sitting its own examination paper. | §7.12, §7.13 |
| 11 | How would you fix that? | An independent red team with no knowledge of the transform list, and — available immediately — leave-one-family-out adversarial training, where D-ADVTRAIN trains on seven families and is evaluated on the eighth. | §7.13 |
| 12 | Your slice table shows macro F1 near 0.5 for most lure types. Is your model broken? | No — it is a metric artefact: each lure type is single-class by construction, and macro F1 averages over a class that is not present; for those slices read recall, FPR and error count. | §7.11 |
| 13 | Why three training pools rather than a train/test split? | Because a fusion fitted on member scores produced in sample learns weights for a regime that never recurs at inference, and the calibrator needs a third pool for the same reason one step later — it must see fusion outputs it did not shape. | §7.2 |
| 14 | Your hard subset scores 0.9547. What makes it hard? | Cloned templates, BEC, thread hijacking and legitimate mail with a phishing-shaped surface; it holds all 22 missed phishing messages. But the same generator made it, which is why PG-HARD exists — hand-written cases, each defeating a named cue, graded by band. Read both as directional evidence, not as a ceiling. | §7.12 |
| 15 | Where do 0.40 and 0.80 come from? | They are defaults that are priced, not tuned: the cost model puts the deployed policy at 262 analyst reviews per 1 000 messages against 191 at the cost optimum — which is cheaper because it lets twice as many adaptive attacks through (6 of 48 against 3). Neither candidate is adopted, because each was chosen on the data it is scored on; an organisation reruns `phishguard cost --attack` on its own traffic. | §7.0, §7.8 |
| 16 | 11% of your mail goes to a human. Would a SOC accept that? | Not without evidence from real traffic: it is the price of abstaining when the readers contradict each other, and ADR-006's own revisit trigger (1% of volume) has fired on test data. It was 16% until 1.4.0, when the rule stopped escalating on one lukewarm reader — the change was measured before it was kept, and it cost nothing on PG-HARD. What exists is a cost model that prices it, a review queue with owners and service levels, and an alert at a sustained 35%; the rate has to be re-measured on live mail. | §7.8, [ADR-006](adr/006-abstention-band.md) |
| 17 | Why not just use a transformer, or an LLM? | A transformer member is supported as an optional extra, but it is another *text* model — it would improve the channel the attacker fully controls and leave the decorrelation argument untouched, at a latency cost against a 150 ms inline budget where one message takes 17–32 ms at p95 with evidence depending on the host, and eight requests waiting on one process already reach 134–234 ms. | §7.9, §7.14, [ADR-001](adr/001-tri-modal-fusion.md) |
| 18 | Does it work on real email? | Partly, and honestly measured: mail from a mailbox carries no sender history, so the behavioural family is silent and the text and URL readers decide. On the test set scored that way the policy sends 12.1% to a person and delivers 5 of 900 phishing messages unwarned, against 2 with history. Real corpora can be mixed into training (`--data-source synthetic,…`), an inbox can be watched over IMAP, and the first thing the real-mail rule change fixed was an ordinary college email escalated because one word reader was lukewarm. | §7.8, §9.19, §11 |
| 19 | What is the single biggest weakness in this project? | That the behavioural features are simulated by the same generator that assigns the labels, so the correlation the central claim leans on is partly a design choice rather than an empirical finding — the *asymmetry* argument still holds, because an attacker genuinely cannot forge two years of correspondence, but its measured magnitude should not be expected to survive contact with a real gateway. | §7.12 |

### Questions to be ready for that have no single answer

Expect at least one of these. They test whether you can reason about the system
rather than recall figures.

- *"If you had another hundred hours, what would you do first?"* — Run the
  defence ablation against the deployed decision rather than the raw score, and
  the PG-HARD adaptive attack against every arm, because five of six controls
  register nothing at a 10-query budget; then more seeds with bootstrap
  intervals, since three seeds give a range, not a confidence interval, and
  nothing below 0.01 in the dossier is resolved (§7.12, §7.13).
- *"Would you deploy this?"* — In front of a mail gateway with a human reading
  the REVIEW queue, on the understanding that the absolute numbers are unproven
  and the review rate must be re-measured on live traffic; not as an unattended
  auto-block with no oversight.
- *"What did you get wrong and have to redo?"* — Have a real answer ready. An
  examiner is more suspicious of a project with no dead ends than of one with
  several.
- *"Which part of this is not your own work?"* — Name the libraries, any
  borrowed lexicons or brand lists, and anything generated with assistance.
  Answer this one before you are pushed on it.

### Practical preparation

1. Run the demonstration script in [§8](08-deployment-guide.md) end to end at
   least twice, including `docker compose down -v` so the first start trains a
   model in front of the examiner.
2. Have `artifacts/reports/evaluation.md` open in a browser tab for any question
   about numbers, and know where in it each figure lives.
3. Know these six figures cold, and know the limitation attached to each:
   **0.9880** clean macro F1; on PG-HARD **0 of 96** hard phishing unwarned
   and **8 of 96** legitimate blocked (the text-only filter: 0 and **49**);
   **3 of 48** against **43 of 48** under the adaptive attack; **0.000**
   against **0.293** escape-block ASR on ordinary phishing; **11.0%** of mail
   sent to a human; **32 ms** p95 per message on the evaluation host (17 ms
   on a faster one).
4. Be able to open, at a moment's notice: the transform list
   (`src/phishguard/adversarial/transforms.py`), the leakage audit
   (`src/phishguard/data/splits.py`), the acceptance gates
   (`src/phishguard/eval/acceptance.py`) and the audit schema
   (`src/phishguard/service/store.py`).
5. Rehearse saying the uncomfortable sentence out loud: *"the corpus is
   synthetic, the clean numbers are an upper bound, and what this project
   establishes is the comparative result."* Said first, it is rigour. Said only
   after being pushed, it is damage control.

---

**Next:** [§1 Industry problem brief →](01-industry-problem-brief.md)
