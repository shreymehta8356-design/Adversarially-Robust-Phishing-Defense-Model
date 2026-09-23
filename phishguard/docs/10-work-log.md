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
| Synthetic corpus generator | `src/phishguard/data/synthetic.py` | 35 lure types, campaign structure, difficulty balancing — the annotation strategy, since it assigns the labels |
| Splitting and leakage audit | `src/phishguard/data/splits.py` | Campaign-grouped split, MinHash/LSH near-duplicate scrub, the four-check leakage audit |
| External corpus loaders | `src/phishguard/data/loaders.py` | mbox/directory loaders for real public corpora |
| Brand and reputation tables | `src/phishguard/data/banks.py` | Brand domains, high-abuse TLDs, disposable and free-hosting suffixes |
| Lexicons | `src/phishguard/features/lexicons.py` | The eight social-engineering lexicons |
| Email feature extraction | `src/phishguard/features/email.py` | 125 header, subject, body, HTML and attachment features |
| URL feature extraction | `src/phishguard/features/urls.py` | 107 URL features, public-suffix handling, canonicalisation |
| Behavioural feature extraction | `src/phishguard/features/behavioral.py` | 33 relationship, timing, distribution and campaign-shape features |
| Tests | `tests/unit/test_splits.py`, `tests/unit/test_features.py`, `tests/unit/test_urls.py` | 41 tests |
| Documents | `docs/06-data-dictionary.md`, `docs/adr/002-synthetic-corpus.md` | |

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
| Attack taxonomy and transforms | `src/phishguard/adversarial/taxonomy.py`, `transforms.py` | 6 families, 30 transforms |
| Attacker and reporting | `src/phishguard/adversarial/attacker.py`, `report.py` | Budgeted black-box attacker, raw-score surface, per-family and residual-risk reporting |
| Defensive controls | `src/phishguard/defenses/controls.py`, `normalize.py` | D-NORM, D-URL, D-ADVTRAIN, D-ENSEMBLE, D-ABSTAIN, D-VELOCITY |
| Explanations | `src/phishguard/explain/attributions.py`, `evidence.py` | Occlusion counterfactuals, analyst evidence cards |
| Evaluation harness | `src/phishguard/eval/run_eval.py`, `metrics.py`, `acceptance.py`, `error_analysis.py` | The dossier, both ablations, the ten acceptance gates |
| Tests | `tests/unit/test_metrics.py`, `tests/unit/test_transforms.py`, `tests/unit/test_normalize.py` | 47 tests |
| Documents | `docs/04-threat-model.md`, `docs/07-evaluation-dossier.md`, `docs/adr/001`, `003`, `005`, `006` | |

### Systems engineer

*Edge/cloud integration, interface, safety controls, deployment and testing.*

| Module | Path | What it is |
|---|---|---|
| HTTP API | `src/phishguard/service/app.py` | 12 endpoints, dependency wiring, middleware, security headers |
| Scan orchestration | `src/phishguard/service/scanning.py` | `ScanService` — the framework-free decision path |
| Request/response contracts | `src/phishguard/service/contracts.py` | Pydantic models, validation bounds |
| Security | `src/phishguard/service/security.py` | API-key auth, the two roles, token-bucket rate limiting |
| Audit store | `src/phishguard/service/store.py` | SQLite/WAL schema, pseudonymisation, retention sweep |
| Telemetry | `src/phishguard/service/telemetry.py` | JSON logging, Prometheus registry |
| Analyst console | `ui/index.html` | Four tabs, zero build step |
| CLI | `src/phishguard/cli.py` | `data`, `train`, `evaluate`, `attack`, `scan`, `models`, `card`, `serve` |
| Container and stack | `docker/api.Dockerfile`, `docker/entrypoint.sh`, `docker-compose.yml` | Non-root image, bootstrap training, three-service stack |
| Monitoring | `docker/prometheus.yml`, `docker/alerts.yml`, `docker/grafana/` | 8 alert rules, 12 dashboard panels |
| CI and tooling | `.github/workflows/ci.yml`, `Makefile`, `scripts/run_tests.py` | |
| Tests | `tests/integration/test_service.py`, `tests/security/test_security.py` | 47 tests |
| Documents | `docs/03-api-contract.md`, `docs/08-deployment-guide.md`, `docs/09-admin-user-guide.md`, `docs/adr/004` | |

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
| 2 | Architecture, UI/data design and technical spike | 15 | C4 levels 1–3; the feature schema; the three-pool training design; the six ADRs; a throwaway spike proving the attack loop is feasible |
| 3 | Owned module implementation and unit testing | 40 | Your columns from §10.2, with tests written alongside rather than afterwards |
| 4 | Integration, security, performance and acceptance testing | 15 | End-to-end path, the 24 security tests, latency measurement against the 150 ms gate, the ten acceptance gates |
| 5 | Deployment, documentation, demonstration and viva preparation | 15 | Container and compose stack, monitoring, the ten documents, the demonstration script, §10.8 |

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
- [ ] **Test authorship.** Which of the 153 tests you wrote. This is the most
      persuasive evidence available, because a test proves you understood the
      failure it prevents. `tests/unit/test_transforms.py` is a good example to
      be able to speak to: it exists to stop an attack transform being written
      that cheats — for instance by fabricating the victim's correspondence
      history — which would silently invalidate every robustness number.
- [ ] **The evaluation dossier, regenerated by you.** Run
      `phishguard evaluate --n 9000 --budget 12 --max-attacked 120 --defense-ablation`
      yourself, on your own machine, and keep the console output. Being able to
      say "I ran this and it took 34 minutes and G6 came out at 0.0671 on my
      seed" is worth more than any table you can quote.
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

Eighteen questions an examiner is likely to ask about **this** project, with the
honest answer in one line and where the full version lives. The uncomfortable
ones are here deliberately — an examiner who finds a weakness you have not
already named will assume you did not know about it.

The general rule: **never defend a number you cannot criticise.** Every strong
result in this project has a matching limitation, and stating the limitation
before you are asked is what distinguishes understanding from recital.

| # | Question | Honest one-line answer | Where |
|---|---|---|---|
| 1 | Your clean macro F1 is 0.99948. Why should I believe any of it? | You should not believe it as a real-world number — the corpus is synthetic and the model can learn the generator, so it is an upper bound; what transfers is the comparative results, because they are measured under identical conditions. | [§7.12](07-evaluation-dossier.md) |
| 2 | Then what *is* your result? | That the tri-modal fusion loses 6.7% of phishing to a budgeted attacker where the text-only baseline loses 55%, and 0.8% to silent delivery where the baseline loses 16.7% — a 0.48333 advantage measured on the same messages under the same budget. | §7.4 |
| 3 | Your defence ablation shows three of six controls doing nothing. Defend keeping them. | D-ABSTAIN and D-VELOCITY act downstream of the raw score the ablation attacks, so they cannot register in that metric *by construction* — it is a measurement limitation, and D-ABSTAIN's effect is plainly visible in the banded table, where six of seven messages escaping BLOCK stop in REVIEW; D-NORM is most likely masked because D-ADVTRAIN and the ensemble already handle the unicode family. | §7.6 |
| 4 | Why measure attack success at 0.80 rather than 0.5? | Because the deployed policy has no 0.5 boundary in it: dragging a message from 0.99 to 0.79 takes it out of auto-quarantine, which is a real gain for the attacker that a 0.5-anchored metric scores as total failure. | §7.4 |
| 5 | Your behavioural family reduces clean accuracy. Justify it. | It costs 0.00104 macro F1 — two messages — and it was never bought for clean accuracy: it is the only family the attacker cannot rewrite, A-BEH has the lowest attack success rate (0.00833) and the only "High" attacker cost in the taxonomy, and dropping it would change the robustness table, which is the one that matters. | §7.5 |
| 6 | What stops your feedback endpoint being a poisoning vector? | Feedback is recorded and surfaced for human review and is **never** used to retrain automatically; retraining is a deliberate, reviewed action, and this is recorded as out-of-scope threat `OOS-3` rather than left implicit. | §9.5, §7.4 |
| 7 | You attack the raw pre-calibration score, not what the API returns. Isn't that cheating in your favour? | The opposite — it grants the attacker a finer oracle than any real client has, which is why the headline 0.06667 is an upper bound; the calibrated-surface figure is 0.01667 and is reported alongside it. | §7.4 |
| 8 | Your ECE is 0.00099. Is the model perfectly calibrated? | No — that number reflects a near-degenerate score distribution (1 931 of 1 937 messages in the top decile), so isotonic regression approaches a step function and scores well almost trivially; on real mail it would be materially worse. | §7.7 |
| 9 | One error in 1 937 messages. What does your error analysis actually establish? | Statistically, almost nothing — one data point identifies a category worth watching (a cloned template where the signal is header and URL only, scored 0.0) but cannot support any claim about its frequency. | §7.10 |
| 10 | You designed both the attacks and the defences. How is that a valid robustness evaluation? | It is a valid *lower bound on attack difficulty* and nothing more: a novel family is untested by construction, and D-ADVTRAIN trains on the same 30 transforms it is evaluated against, so part of the measured robustness is a defence sitting its own examination paper. | §7.12, §7.13 |
| 11 | How would you fix that? | An independent red team with no knowledge of the transform list, and — available immediately — leave-one-family-out adversarial training, where D-ADVTRAIN trains on five families and is evaluated on the sixth. | §7.13 |
| 12 | Your slice table shows macro F1 near 0.5 for most lure types. Is your model broken? | No — it is a metric artefact: each lure type is single-class by construction, and macro F1 averages over a class that is not present; for those slices read recall, FPR and error count. | §7.11 |
| 13 | Why three training pools rather than a train/test split? | Because a fusion fitted on member scores produced in sample learns weights for a regime that never recurs at inference, and the calibrator needs a third pool for the same reason one step later — it must see fusion outputs it did not shape. | §7.2 |
| 14 | Your "hard subset" scores 0.99846, barely below the full set. What makes it hard? | Not enough — that is the honest answer; the generator cannot manufacture the ambiguity that makes real cases hard, so treat it as evidence the difficulty controls worked directionally, not as a measurement of the ceiling. | §7.12 |
| 15 | Your `at_operating_point` block reports a false-positive rate of 1.0. Explain. | It is degenerate and should not be quoted: legitimate messages score so close to zero that their 98th percentile *is* zero, so the derived threshold is 0.0 and everything is classified as phishing — an artefact of corpus separability, documented rather than deleted. | §7.7 |
| 16 | Your review rate is 0.1%. Would an analyst ever see anything? | On this corpus, almost nothing, which is again separability rather than design; the operationally meaningful review rate can only be measured on real traffic, which is why the alert threshold is set at a sustained 35% rather than derived from the dossier. | §7.8 |
| 17 | Why not just use a transformer, or an LLM? | A transformer member is supported as an optional extra, but it is another *text* model — it would improve the channel the attacker fully controls and leave the decorrelation argument untouched, at a latency cost against a 150 ms inline budget where scoring currently takes 8 ms. | §7.9, [ADR-001](adr/001-tri-modal-fusion.md) |
| 18 | What is the single biggest weakness in this project? | That the behavioural features are simulated by the same generator that assigns the labels, so the correlation the central claim leans on is partly a design choice rather than an empirical finding — the *asymmetry* argument still holds, because an attacker genuinely cannot forge two years of correspondence, but its measured magnitude should not be expected to survive contact with a real gateway. | §7.12 |

### Questions to be ready for that have no single answer

Expect at least one of these. They test whether you can reason about the system
rather than recall figures.

- *"If you had another hundred hours, what would you do first?"* — Multi-seed
  runs with confidence intervals, because nothing below 0.01 in the dossier is
  currently resolved, and the modality ablation's headline finding is a
  two-message gap that a different seed could reverse (§7.13).
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
   **0.99948** clean macro F1, **0.06667** escape-block ASR, **0.55** for B1,
   **0.48333** robustness advantage, **44.816 ms** p95, **0.00104** the
   behavioural family's clean-accuracy cost.
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
