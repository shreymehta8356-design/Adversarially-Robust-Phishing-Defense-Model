# Changelog

All notable changes to PhishGuard. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/): a new major version would mean an
incompatible API or model-registry change.

Each release lists what changed, why, and what it did to the measured results,
because in this project a change that moves a number is a finding, not a detail.

## [1.3.0] — 2026-09-22 — Operational workflow and professional hardening

### Added

- **Review queue** for held and reported messages: cases with states
  (`open`, `in_review`, `escalated`, `resolved`), owners, priorities P1–P3 and
  service levels (1 h / 4 h / 24 h). Object-level authorisation (only the
  assignee or an admin may act on a claimed case), admin-only release of
  messages scored at or above the block threshold, and a full event history per
  case. Resolving a case records analyst feedback. [ADR-007]
- **Reporter role and report page** (`/report`) so any employee can report a
  suspicious message and see what became of it — in plain words, never with a
  score. Endpoints `POST /api/v1/reports`, `GET /api/v1/reports/mine`,
  `GET /api/v1/whoami`.
- **Request tracing** with W3C Trace Context: `traceparent` continued or
  started, per-stage spans, `Server-Timing` header, `trace_id` and `stage_ms` in
  every scan response and on the audit record, recent traces at
  `GET /api/v1/traces/recent`, and a per-stage Prometheus histogram. [ADR-008]
- **Load test** (`phishguard loadtest`): in-process at increasing concurrency,
  multi-process (`--processes`), or against a running service (`--url`).
  Results in the evaluation dossier (§7.14).
- `phishguard serve --workers N` and `PG_API_WORKERS`: several server processes.
- **Dataset versions**: a content-addressed fingerprint of every training and
  test set, recorded in the model manifest and the dossier.
- **Optional MLflow tracking** (`--mlflow` on `train` and `evaluate`,
  `pip install -e ".[tracking]"`).
- **Public-corpus fetcher** (`phishguard fetch-public`) with terms
  acknowledgement, safe archive extraction and a provenance record.
- Review-queue and per-stage panels in the Grafana dashboard; alert rules for
  cases past their service level and for queue backlog.
- Documentation: personas, cited current-process evidence, user stories with
  acceptance criteria, sequence diagrams, the review-queue state machine, the
  database schema, security and privacy checks, a responsible-AI review, a
  go/no-go recommendation and a requirements traceability matrix (docs/12).
  ADRs 001–003, 005 and 006 gain an "Evidence at release 1.3.0" section giving
  the current figures and saying which revisit triggers have fired; their
  original text is kept as the record of the decision.
- Engineering evidence pack: contribution guide, security policy, code owners,
  issue and pull-request templates, Dependabot, CodeQL, a release workflow, a
  prioritised backlog (`docs/backlog.csv`) and a script that creates the issue
  board from it (`scripts/bootstrap_github.py`).

### Changed

- **Scoring runs one request at a time per process, first come first served**
  (`PG_SCORING_CONCURRENCY`, default 1). Measured on two cores with eight
  concurrent requests: throughput 42.9 → 70.0 messages/s, p95 284.8 → 133.7 ms.
  Two server processes give 151.6 messages/s, 2.04 times one process.
  Concurrent threads were taking turns on the interpreter lock and paying for
  every switch; they now wait in line instead. A plain semaphore was tried first
  and rejected: unfair wake-ups pushed p99 to 2.2 s.
- `phishguard serve` sets `OMP_NUM_THREADS=1` for its worker processes.
- Code formatted and linted with ruff, including the flake8-bandit security
  rules, with zero findings; CI pins the ruff version.

### Fixed

- **Two attack transforms shared one implementation.** A second function named
  `t_open_redirect` replaced the first, so A-URL-02 ("open-redirect chaining")
  silently ran A-TRUST-02's code and the query-string redirect was never tested
  or trained against. Found by static analysis (ruff F811). The trusted-domain
  variant is now `t_trusted_redirect`, and a regression test fails if any two
  transforms share a function. Robustness figures in this release are measured
  with the corrected suite.
- **`GET /api/v1/model` returned a server error.** Since the thresholds gained
  a sentence saying where they came from, the endpoint's output no longer
  matched its declared response model, so every model trained after that change
  failed validation. The explanation is now its own `threshold_source` field,
  and a regression test validates the service output against the route's
  contract. Found by rendering the console against the real service.
- **The campaign-burst guard (D-VELOCITY) could lower a score.** Its 0.99 cap
  was applied unconditionally, so a message already scored 1.0 was lowered to
  0.99 and the evidence read "raised score by -0.010". The guard is now
  monotone, as documented; decisions were unaffected because both values are
  above the block threshold.
- **Console:** the member-score and stage-timing bars never drew (an inline
  element ignored its width), and the comparison panel said "both systems
  reached the same band" when they had not.
- **The defence catalogue and the attack taxonomy disagreed** on which attack
  families each control counters, for five of the six controls; the catalogue's
  lists predated A-TRUST and A-CHANNEL. The mapping is now written once, per
  family, in the taxonomy, and the catalogue is derived from it, with a test.
  The committed `evaluation.json` was produced before this fix, so its
  `defense_catalogue` section still shows the old lists until the next
  `phishguard evaluate`.
- **Text evidence named character fragments** such as "ypa". The word model's
  terms are now shown first, and character fragments are mapped back to the
  whole word they came from ("paypal").

### Security

- Reporters never receive a score or band (the report endpoint cannot be used
  as a scoring oracle).
- Releasing a message the model was confident about needs an administrator
  and a written reason.
- Traces and logs are tested to carry no message content.

## [1.2.0] — September 2026 — Evidence you can put in a report

### Added

- `phishguard figures`: nine report figures (PNG and SVG) with data-driven
  titles and captions, drawn from `evaluation.json`.
- Expected-cost model for the thresholds (`phishguard cost`), including an
  attacked variant and a minimax-regret policy.
- Real public corpora end to end: mbox and maildir loaders, a corpus audit that
  catches era and label confounds before training, and a triage command.
- Statistical drift detection on live traffic, calibrated against stable
  campaign-structured windows, in the console, the API and the CLI.
- A fast vectorised batch path.

### Changed

- Training pools (fit, stack, calibration) are drawn by campaign rather than by
  row, which removed an optimism in the calibration pool; the change was
  measured over three seeds before it was kept.
- Seed sensitivity: every evaluation retrains with two further seeds and
  reports the range.

## [1.1.0] — September 2026 — Harder evaluation, deeper attacks, runs anywhere

### Added

- **PG-HARD**, a curated hard-case benchmark (96 hard phishing and 96 hard
  legitimate records) that the ordinary test set lacks.
- Deeper adversarial suite: out-of-band (callback, QR) and trusted-hosting
  families, and an adaptive attacker that targets the abstention band.
- Disagreement-based abstention (D-ABSTAIN), text-only comparison in the
  console, the hard-case benchmark tab, and worked examples.
- `phishguard doctor` preflight checks, friendly failure messages, and
  memory-adaptive training for small machines; `python start.py` as a
  one-command start on Windows, macOS and Linux.

### Changed

- A harder synthetic generator: the 1.0 corpus was separable enough that the
  test set had one error in 1 937, which is not a measurement.

## [1.0.0] — 2026-09-07 — First complete system

### Added

- Tri-modal detector: 265 email, URL and behavioural features; four members
  (rule checklist, gradient-boosted engineered features, character and word
  n-gram models) fused by a stacker, isotonic calibration and a three-way
  ALLOW / REVIEW / BLOCK decision.
- Threat-informed adversarial suite (six families, 30 transforms,
  budgeted decision-based attacker) and six named, ablatable defences.
- Two baselines (37-rule checklist, TF-IDF + logistic regression), modality and
  defence ablations, ten automated acceptance gates.
- FastAPI service with role-based API keys, rate limiting, a content-free audit
  trail, Prometheus metrics, the analyst console, Docker Compose with
  Prometheus and Grafana, and CI.
- Documentation set: problem brief, design pack, API contract, threat model,
  test strategy, data dictionary, evaluation dossier, deployment and user
  guides, work log.

[1.3.0]: docs/07-evaluation-dossier.md
[1.2.0]: docs/07-evaluation-dossier.md
[1.1.0]: docs/07-evaluation-dossier.md
[1.0.0]: docs/07-evaluation-dossier.md
