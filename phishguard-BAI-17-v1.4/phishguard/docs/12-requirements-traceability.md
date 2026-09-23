# 12. Requirements traceability matrix

Every requirement in the BAI-17 portfolio brief, where it is met, and how an
examiner can check it in a minute. Nothing here is a claim without a pointer:
each row names a file, a test, a command or a section.

| Status | Meaning | Count |
|---|---|---|
| ✅ **Met** | Implemented and evidenced in the repository | 109 |
| ◐ **Met, with a stated limitation** | Implemented; the limitation is written down where the evidence is | 4 |
| ✍ **Needs the student** | Cannot be produced by software: a recording, a real Git history, your own hours | 5 |
| — **Not used, by decision** | A suggested tool the design does not need, with the reason | 2 |

---

## A. The project brief (BAI-17)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| A1 | A working prototype stakeholders can test | ✅ | `python start.py` or `docker compose up --build`; console at `/`, report page at `/report` ([§8](08-deployment-guide.md)) |
| A2 | Email feature extraction | ✅ | 125 email features: headers, authentication, subject, body, HTML, attachment metadata — `src/phishguard/features/email.py`; `tests/unit/test_features.py` ([§2.6](02-architecture.md), [§6.5](06-data-dictionary.md)) |
| A3 | URL feature extraction | ✅ | 107 URL features with offline canonicalisation (percent, punycode, redirect unwrapping) — `features/urls.py`; `tests/unit/test_urls.py` |
| A4 | Behavioural features | ✅ | 33 sender-relationship, timing and campaign features — `features/behavioral.py` |
| A5 | Baseline model(s) | ✅ | B0: 37-rule analyst checklist; B1: TF-IDF + logistic regression — `models/baseline.py` ([§7.3](07-evaluation-dossier.md)) |
| A6 | ML models | ✅ | Four members (rules, gradient-boosted engineered features, character and word n-gram models), stacked fusion, isotonic calibration — `models/detector.py`, `models/members.py` |
| A7 | Explanation view | ✅ | Plain-language evidence with counterfactual weights and member scores on every verdict, in the console and the API — `explain/`; `test_evidence_is_human_readable_not_feature_names` |
| A8 | Adversarial transformation suite | ✅ | 35 semantic-preserving transforms in eight families, a budgeted decision-based attacker and an adaptive attacker — `adversarial/`; `tests/unit/test_transforms.py` |
| A9 | Confidence thresholds | ✅ | Calibrated probability; ALLOW / REVIEW / BLOCK at 0.40 / 0.80, chosen against a false-positive budget and priced by a cost model; abstention on a contradiction between readers sends 11.0% of ordinary test mail to a human (12.1% without sender history) — [ADR-006](adr/006-abstention-band.md), [§7.8](07-evaluation-dossier.md), `phishguard cost` |
| A10 | Analyst feedback | ✅ | `POST /api/v1/feedback`; resolving a review case records feedback; disagreement metric; never retrains automatically (`OOS-3`) |
| A11 | Innovation: threat-informed adversarial testing | ✅ | Attacks derived from an explicit adversary capability model — [§4.4](04-threat-model.md) |
| A12 | Innovation: attack taxonomy | ✅ | A-LEX, A-UNI, A-URL, A-STRUCT, A-HDR, A-BEH, A-TRUST, A-CHANNEL with capability and cost — [§4.5](04-threat-model.md), `adversarial/taxonomy.py` |
| A13 | Innovation: defensive controls | ✅ | Six named controls, each ablatable and measured — [§4.6](04-threat-model.md), [§7.6](07-evaluation-dossier.md) |
| A14 | Innovation: residual-risk reporting | ✅ | Residual-risk register per attack family, generated from measurements — `robustness.residual_risk_register` in `evaluation.json`; [§4.7](04-threat-model.md) |
| A15 | Realistic or simulated data | ◐ | Campaign-structured synthetic corpus plus loaders and a fetcher for public corpora (Nazario, SpamAssassin); real and synthetic mail can be trained together, and real mail can be imported or read from a live inbox. *Limitation:* the full tri-modal model is evaluated on synthetic data; public corpora and mailboxes carry no behavioural context, and the dossier reports that condition separately ([§7.8](07-evaluation-dossier.md), [§7.12](07-evaluation-dossier.md), [§11](11-real-data.md), [§9.19](09-admin-user-guide.md)) |
| A16 | Failure and edge cases | ✅ | PG-HARD (192 curated hard records), error analysis, subgroup slices, hostile-input tests — [§7.10–7.11](07-evaluation-dossier.md), `data/hardcases.py` |
| A17 | Security and privacy | ✅ | [§7.15](07-evaluation-dossier.md) (19 checks with test evidence), [§4.8](04-threat-model.md) STRIDE, `tests/security/` |
| A18 | Metric: macro F1 | ✅ | Gate G1 — `evaluation.json` → `clean.macro_f1` |
| A19 | Metric: PR-AUC | ✅ | Gate G2 — `clean.pr_auc` |
| A20 | Metric: robustness drop | ✅ | Gates G5, G6, G9 — `robustness.macro_f1_drop`, `attack_success_rate` |
| A21 | Metric: calibration | ✅ | Gate G4 — ECE and a reliability diagram (figure 6) |
| A22 | Metric: false positives | ✅ | Gate G3 — false-positive rate at the operating point; false blocks on PG-HARD |
| A23 | Metric: inference speed | ✅ | Gate G7 (p95 ≤ 150 ms; observed 30.5 ms with evidence on the 1.4.0 dossier's slower two-core container, 17.2 ms for the same model on the 1.3.0 host) and the load test (p95 inside the budget up to four requests in flight per process; two processes 1.97×) — [§7.9](07-evaluation-dossier.md), [§7.14](07-evaluation-dossier.md) |
| A24 | Workflow: intake | ✅ | `POST /api/v1/scan` (gateway), `/scan/batch`, `POST /api/v1/reports` (employees) |
| A25 | Workflow: decision | ✅ | Score, band, evidence; REVIEW opens a case |
| A26 | Workflow: user action | ✅ | Analyst claims, resolves, escalates, releases; reporter sees the outcome — [§2.9](02-architecture.md), [§3.10](03-api-contract.md) |
| A27 | Workflow: audit trail | ✅ | Content-free decision records and a case-event history — [§2.10](02-architecture.md) |
| A28 | Workflow: operational monitoring | ✅ | Prometheus metrics, Grafana dashboard, alert rules, drift detection, traces — [§9.12](09-admin-user-guide.md) |

### Suggested technology stack

| Tool | Status | How it is used, or why not |
|---|---|---|
| Python | ✅ | The whole system (3.10–3.12, tested in CI) |
| scikit-learn | ✅ | Members, stacking, calibration, baselines |
| FastAPI | ✅ | The service; OpenAPI at `/openapi.json` and `/docs` |
| Docker | ✅ | `docker/api.Dockerfile`, `docker-compose.yml` with Prometheus and Grafana; the same image deploys to Render (`render.yaml`), a Hugging Face Space or Fly.io ([deploy/README.md](../deploy/README.md)) |
| Git | ✅ | Repository with CI, templates and a backlog ready to import ([§E](#e-engineering-evidence-pack)) |
| MLflow | ✅ | Optional: `--mlflow` on `train` and `evaluate` (`pip install -e ".[tracking]"`) — `src/phishguard/tracking.py` |
| Hugging Face transformers + PyTorch | ◐ | An optional DistilBERT member (`--with-transformer`, `pip install -e ".[transformer]"`). Off by default: it needs a GPU to be practical and downloads a pretrained model, and the ablation shows what it would have to beat |
| TensorFlow | — | Not needed: PyTorch covers the optional deep member, and one deep-learning framework is enough |
| OpenCV | — | The system reads mail, not images: attachments are metadata only, and opening them is out of scope by design (SSRF and privacy, [§1.7](01-industry-problem-brief.md)). The QR-code attack (A-CHAN-02) is measured precisely *because* a text-and-URL detector cannot see it; decoding QR images with OpenCV in a separate sandbox is listed as future work |

## B. Capstone objectives

| # | Objective | Status | Evidence |
|---|---|---|---|
| B1 | Personas | ✅ | Four personas and an adversarial persona — [§1.3](01-industry-problem-brief.md) |
| B2 | Misuse and abuse cases | ✅ | M1–M11, each with a design response — [§1.6](01-industry-problem-brief.md), [§4.10](04-threat-model.md) |
| B3 | Success criteria | ✅ | Ten automated gates plus operational metrics — [§1.8](01-industry-problem-brief.md) |
| B4 | Non-functional requirements | ✅ | Availability, performance, reproducibility, privacy, portability, observability, security, auditability — each with its verification — [§1.8](01-industry-problem-brief.md) |
| B5 | Agile backlog | ✅ | MoSCoW-prioritised, estimated backlog — [§1.9](01-industry-problem-brief.md), [`backlog.csv`](backlog.csv) |
| B6 | Modular architecture | ✅ | C4 levels 1–3; decision logic free of the web framework — [§2.1–2.3](02-architecture.md) |
| B7 | API contracts | ✅ | [§3](03-api-contract.md); pydantic contracts with `extra="forbid"`; OpenAPI generated from the same models |
| B8 | Authentication and authorisation | ✅ | Three roles, constant-time key check, object-level checks on cases — `service/security.py`, `service/workflow.py` |
| B9 | Auditability | ✅ | Every decision and every case transition is a record with actor, role and reason |
| B10 | Failure handling | ✅ | Liveness independent of the model; `/readyz` says why; bounded inputs; permissive parsers; uniform error shape; preflight `phishguard doctor` |
| B11 | Operational workflow with realistic state transitions | ✅ | Review-queue state machine with owners, priorities and SLAs — [§2.9](02-architecture.md), [ADR-007](adr/007-review-queue-state-machine.md) |
| B12 | Role-based user journeys | ✅ | Reporter → analyst → administrator, drawn as a sequence diagram — [§2.8](02-architecture.md) |
| B13 | Innovation compared with a baseline | ✅ | Fusion vs text-only vs checklist, clean, under attack and on PG-HARD — [§7.4](07-evaluation-dossier.md) |
| B14 | Production controls: tests | ✅ | 289 automated tests — [§5](05-test-strategy.md) |
| B15 | Production controls: input validation | ✅ | `test_oversized_input_is_rejected_by_the_contract`, `test_unknown_fields_are_rejected` |
| B16 | Production controls: secrets | ✅ | Keys from the environment only, digests in memory, refusal to start without keys in production, CI secret scan, `.gitignore` |
| B17 | Production controls: dependency checking | ✅ | `pip-audit --strict` in CI, Dependabot, CodeQL |
| B18 | Production controls: CI/CD | ✅ | `.github/workflows/ci.yml` (lint, tests on 3 Pythons, security, gates, container smoke test), `release.yml` (build, smoke-test, publish) |
| B19 | Production controls: containers | ✅ | Multi-stage, non-root image; compose stack with health checks and resource limits |
| B20 | Production controls: logs, metrics, traces | ✅ | JSON logs, Prometheus metrics, W3C trace context — [§2.12](02-architecture.md) |
| B21 | Evaluation: stress and robustness | ✅ | Attack suite, adaptive attacker, budget sweep, load test — [§7.4](07-evaluation-dossier.md), [§7.14](07-evaluation-dossier.md) |
| B22 | Evaluation: subgroups and edge cases | ◐ | Slices by lure type, brand, family and context; PG-HARD. *Limitation:* slices are the generator's own categories; real-world subgroups (sender language, new businesses) are named as the first pilot measurement ([§7.16](07-evaluation-dossier.md) RAI-1, RAI-2) |
| B23 | Evaluation: limitations | ✅ | Threats to validity — [§7.12](07-evaluation-dossier.md) |
| B24 | Evaluation: go / no-go | ✅ | [§7.17](07-evaluation-dossier.md): GO for the prototype, conditional GO for a tag-only pilot, NO-GO for autonomous quarantine yet |

## C. Mandatory deliverables

### 1. Industry problem brief — [§1](01-industry-problem-brief.md)

| Item | Status | Where |
|---|---|---|
| Stakeholder map | ✅ | §1.2, with an influence/interest grid |
| Current-process evidence | ✅ | §1.4: cited FBI IC3 2025, Verizon DBIR 2026, APWG Q2 2026 and Ministry of Home Affairs figures; the as-is process; the measured rule-checklist baseline |
| User stories | ✅ | §1.5, US-01 to US-14, with acceptance criteria and the test that proves each |
| Misuse / abuse cases | ✅ | §1.6 |
| Scope exclusions | ✅ | §1.7, each with its reason |
| Risks | ✅ | §1.10 |
| Success metrics | ✅ | §1.8 |
| Prioritised backlog | ✅ | §1.9 and `backlog.csv` |

### 2. Solution design pack — [§2](02-architecture.md)

| Item | Status | Where |
|---|---|---|
| C4 architecture | ✅ | §2.1–2.3 |
| Sequence and data-flow diagrams | ✅ | §2.4, §2.5, §2.8 (three sequences) |
| Database and feature schema | ✅ | §2.10 (ER diagram), §2.6 and [§6.5](06-data-dictionary.md) |
| API and data contracts | ✅ | [§3](03-api-contract.md) |
| UI prototype | ✅ | §2.11: the working console and report page, with screenshots |
| Threat model | ✅ | [§4](04-threat-model.md) |
| Test strategy | ✅ | [§5](05-test-strategy.md) |
| Architecture decisions | ✅ | Eight ADRs in [`adr/`](adr/) |

### 3. Integrated MVP

| Item | Status | Where |
|---|---|---|
| End-to-end system | ✅ | `src/phishguard/` — intake, features, models, defences, decision, evidence, audit, queue, monitoring |
| Runs from the documentation | ✅ | [QUICKSTART](../QUICKSTART.md), [§8](08-deployment-guide.md); `phishguard doctor --self-test` |

### 4. Innovation module and comparison study

| Item | Status | Where |
|---|---|---|
| Baseline results | ✅ | [§7.3](07-evaluation-dossier.md), `evaluation.json` → `baselines` |
| Experiment configuration | ✅ | [§7.1–7.2](07-evaluation-dossier.md): corpus, seeds, split, budgets, thresholds; every report records its parameters |
| Failure analysis | ✅ | [§7.10](07-evaluation-dossier.md) error analysis; PG-HARD failures by case; the D-URL anomaly |
| Ablations | ✅ | Modality ([§7.5](07-evaluation-dossier.md)) and defence ([§7.6](07-evaluation-dossier.md)) |

### 5. Data and model package — [§6](06-data-dictionary.md)

| Item | Status | Where |
|---|---|---|
| Public corpora | ◐ | Loaders, audit and fetcher for Nazario and SpamAssassin ([§11](11-real-data.md)). *Limitation:* not bundled — they contain real people's mail and may not be redistributed |
| Safe synthetic variants | ✅ | `data/synthetic.py`, campaign-structured, deterministic |
| Provenance | ✅ | Provenance in every model manifest; `data/PROVENANCE.json` for downloads |
| Permissions and licensing | ✅ | [§6.2](06-data-dictionary.md); terms acknowledged before any download |
| Data dictionary | ✅ | [§6.5](06-data-dictionary.md), every feature |
| Versioning | ✅ | Content-addressed dataset fingerprints; content-addressed model versions; registry with promote and rollback |
| Annotation / simulator protocol | ✅ | Generator design in [§6.3](06-data-dictionary.md); label conventions for real corpora in [§11](11-real-data.md) |
| Reproducible setup | ✅ | Fixed seeds; `phishguard data`, `train`, `evaluate` reproduce the dossier |
| Model card | ✅ | `artifacts/reports/model_card.md`, regenerated by `phishguard card` |

### 6. Engineering evidence pack

| Item | Status | Where |
|---|---|---|
| Issue board | ✅ | `docs/backlog.csv` and `scripts/bootstrap_github.py`, which creates labels, milestones and issues on your repository |
| Branch and pull-request history | ✍ | The workflow is defined ([CONTRIBUTING](../CONTRIBUTING.md), PR template, CODEOWNERS); the history itself must come from your own commits — it is not fabricated |
| Code review records | ✍ | The review checklist is in CONTRIBUTING §6 and the PR template; the reviews are yours to write |
| Automated tests | ✅ | 289 tests; `pytest` or `python scripts/run_tests.py` |
| Dependency scan | ✅ | `pip-audit` job in CI; Dependabot; CodeQL |
| Container image | ✅ | Built and smoke-tested in CI and on release |
| CI pipeline | ✅ | `.github/workflows/` |
| Release notes | ✅ | [CHANGELOG](../CHANGELOG.md); the release workflow publishes them |

### 7. Evaluation dossier — [§7](07-evaluation-dossier.md)

| Item | Status | Where |
|---|---|---|
| Acceptance thresholds | ✅ | Ten gates, enforced by the exit code |
| Edge cases | ✅ | PG-HARD, error analysis, slices, hostile input |
| Load / latency / resource measurements | ✅ | §7.9, §7.14 |
| Security and privacy checks | ✅ | §7.15 |
| Responsible-AI review | ✅ | §7.16 |

### 8. Deployable demonstration

| Item | Status | Where |
|---|---|---|
| OpenAPI or model/system card | ✅ | `/openapi.json` and `/docs` on a running service; `make openapi` exports it; the model card |
| Administrator and user guide | ✅ | [§9](09-admin-user-guide.md) (analyst, administrator and email-user parts) |
| Demo video, 5–8 minutes | ✍ | The timed script is in [§8](08-deployment-guide.md#demonstration-script); the recording is yours |
| Final report | ✅ | `PhishGuard_Final_Report.docx` (delivered with this version) |
| Presentation | ✅ | `PhishGuard_Presentation.pptx` |
| Individual contribution evidence | ✍ | Template and evidence checklist in [§10](10-work-log.md); the hours and entries are yours |

## D. Industry acceptance gates

| Gate | Status | Evidence |
|---|---|---|
| Not a CRUD-only portal, dashboard, copied notebook or API wrapper | ✅ | An original detector (265 features, calibrated fusion, 35-transform attack suite, six defences) and an operational workflow, all implemented here |
| At least one meaningful baseline | ✅ | Two baselines, B0 and B1 |
| At least one failure-mode, security or robustness experiment | ✅ | Adversarial suite, adaptive attack, defence and modality ablations, PG-HARD, load test, security tests |
| Runs from documented setup on a clean machine or container | ✅ | `python start.py`; `docker compose up --build`; CI builds and smoke-tests the container from scratch |
| Secrets and personal data not committed | ✅ | `.gitignore`, CI secret scan, no content in the audit store; corpora never committed |
| Operational evidence: logs, metrics, traces, model monitoring | ✅ | JSON logs, Prometheus, W3C traces, drift detection, Grafana, alert rules |
| AI projects: leakage checks, reproducible splits, baselines, explainability and error analysis, model or system card | ✅ | Leakage audit that fails the build, campaign-grouped seeded splits, two baselines, counterfactual evidence, error analysis, generated model card |

## E. Engineering evidence pack

What a reviewer will find, file by file:

| Evidence | File |
|---|---|
| Contribution workflow (branches, commits, reviews, definition of done, releases) | `CONTRIBUTING.md` |
| Security policy and disclosure | `SECURITY.md` |
| Release notes | `CHANGELOG.md` |
| Code ownership by role | `.github/CODEOWNERS` |
| Issue templates (story, bug, experiment) and PR template | `.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md` |
| Automated dependency updates | `.github/dependabot.yml` |
| CI, CodeQL, release pipelines | `.github/workflows/` |
| Backlog and board bootstrap | `docs/backlog.csv`, `scripts/bootstrap_github.py` |

## F. Effort and roles

| Requirement | Status | Where |
|---|---|---|
| 100 hours per student, across five phases | ✍ | [§10](10-work-log.md): phase definitions, a worked example and the log template |
| Roles: AI data engineer, model engineer, systems engineer | ✅ | Role-to-module map in [§10.2](10-work-log.md), mirrored in `CODEOWNERS` |

---

**The five ✍ items** are the ones software cannot produce honestly: a real
commit and review history, your own recorded hours, and the demo recording.
Everything they need — the workflow, the templates, the script, the checklist —
is in place.
