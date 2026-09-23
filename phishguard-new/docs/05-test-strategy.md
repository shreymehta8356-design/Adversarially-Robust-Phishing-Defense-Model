# 5. Test strategy

What is tested, why those things and not others, how the suite runs, and what
CI refuses to merge. Every count in this document comes from the suite itself:
`python scripts/run_tests.py` reports **281 passed, 0 failed, 0 skipped**.

---

## 5.1 What is being tested and why

The architectural line drawn in [§2.3](02-architecture.md) is what makes this
test suite possible. Everything that decides anything lives in `ScanService`
and below, and no module in that region imports a web framework. The
consequence is that the entire decision path — canonicalization, feature
assembly, four members, fusion, calibration, banding, evidence, audit write —
is reachable from a plain function call. There is no HTTP server to start, no
event loop, no fixture graph, and no mocking of the thing under test.

That buys two properties worth more than a coverage percentage:

**The tests assert properties, not outputs.** A phishing detector's accuracy
figure is a fact about one corpus on one day. What has to hold on every run is
different: that the split cannot leak, that an "attack" cannot cheat, that the
audit trail cannot retain message content, that a model cannot load against the
wrong feature layout. Those are invariants, and they are what the suite spends
its assertions on.

**The tests are the threat model, mechanically enforced.** The adversarial
transforms in `src/phishguard/adversarial/transforms.py` are ordinary Python
functions with no constraint solver behind them, so nothing stops one from
being written that fabricates the victim's correspondence history or moves the
sender to the brand's genuine domain. Both would silently make the robustness
numbers meaningless. `tests/unit/test_transforms.py` is what stops it.

The suite is 281 tests across three layers, runs in about a minute end to end
on a recent machine, and needs no network, no database and no running service.

| Layer | Tests | Share |
|---|---|---|
| Unit — features, normalization, URLs, splits, transforms, metrics, PG-HARD, cost model, drift, real-corpus loading, portability, review-queue state machine, tracing, load testing, corpus fetching, dataset versions, experiment tracking, decision-time defences | 233 | 83% |
| Integration — detector, service, audit trail, registry, adversarial path, response contracts | 24 | 9% |
| Security — auth, authz, abuse, injection, privacy, SSRF | 24 | 9% |
| **Total** | **281** | |

## 5.2 Test pyramid

| Layer | File | Tests | What it covers |
|---|---|---|---|
| Unit | `tests/unit/test_features.py` | 17 | The three feature families and the assembler contract: display-name/brand mismatch, double extensions, lexicon separation, HTML password fields, behavioural absence as a first-class signal, relationship-strength saturation, trust deficit bounds, family ablation arithmetic, contract verification, edit distance and brand lookalikes |
| Unit | `tests/unit/test_normalize.py` | 11 | Defence `D-NORM`: Cyrillic confusable folding, zero-width stripping, diacritics, leetspeak (including the identifiers it must *not* fold — `office365`, `sha256`, `x509`), separator rejoining, run collapsing, idempotence, the obfuscation-delta signals |
| Unit | `tests/unit/test_urls.py` | 14 | Public-suffix splitting including multi-label and free-hosting suffixes, `D-URL` canonicalization (open-redirect unwrapping, host homoglyphs), IP hosts and non-standard ports, brand squatting vs the genuine domain, link extraction with anchor text, link-text/href mismatch, neutral defaults for distance-like features, malformed-URL safety, name stability |
| Unit | `tests/unit/test_splits.py` | 12 | MinHash similarity and LSH near-duplicate detection, campaign disjointness, class-balance preservation, temporal ordering, the leakage-audit cases, and that the training pools (fit / stack / calibration) never split a campaign either |
| Unit | `tests/unit/test_transforms.py` | 21 | Taxonomy completeness (every transform has a family, every family has a transform), non-mutation, payload preservation, the validity constraints on the `A-BEH` and `A-HDR` families, that `D-NORM` actually undoes `A-UNI`, and that no two transforms share one implementation (a regression found by static analysis) |
| Unit | `tests/unit/test_metrics.py` | 22 | Confusion/PRF on hand-checked cases, ROC and PR AUC including ties and the no-positives case, FPR-targeted thresholding, banded outcomes, ECE and reliability curves, isotonic calibration with its Platt and no-op fallbacks, latency percentiles, and the ten acceptance gates |
| Unit | `tests/unit/test_hardcases.py` | 20 | PG-HARD: every case inverts the cue it names, variants are deterministic, tolerated bands, grading against matched false-alarm budgets |
| Unit | `tests/unit/test_cost.py` | 12 | The expected-cost model: prior-shift reweighting, analyst error, the escalate-only abstention mode, minimax regret, and configuration validation |
| Unit | `tests/unit/test_drift.py` | 19 | PSI with ties and empty bins, calibrated thresholds never below the textbook bands, the exact-window null, quiet on stable campaign-structured windows and firing on a shift, false-alarm rate near nominal, audit-trail reconstruction without message text, models saved before monitoring, and windows larger than the reference can calibrate |
| Unit | `tests/unit/test_real_corpora.py` | 20 | Public-corpus loading: declared charsets, RFC 2047 subjects, HTML-only mail, the topmost `Authentication-Results` only, UCI and Kaggle label conventions, spam never relabelled as phishing, and the audit that refuses an era-confounded corpus |
| Unit | `tests/unit/test_portability.py` | 19 | Runs anywhere: packaged console, encodings declared, dependency floors, deterministic features across processes, old saved models still loading, and `start.py` retraining a model from an older training format |
| Unit | `tests/unit/test_workflow.py` | 16 | The review queue: every action × state pair is either allowed or refused explicitly; object-level authorisation (an analyst cannot work another's case); high-risk release and reopening need an admin; priorities; reporters never see a score; compare-and-set refuses a stale transition; a version-1 database is upgraded in place |
| Unit | `tests/unit/test_tracing.py` | 8 | W3C `traceparent` continued or ignored when invalid; spans nest and sum by stage; one trace id on the response, the audit record and the stage timings; recent traces bounded and content-free; the per-stage Prometheus histogram; OpenMP limited on serving threads only |
| Unit | `tests/unit/test_loadtest.py` | 6 | Every level accounted for; server errors counted rather than hidden; only HTTP URLs accepted; real worker processes sharing one audit store; first-come-first-served scoring slots; one slot serialises scoring without losing requests |
| Unit | `tests/unit/test_fetch.py` | 5 | Terms must be acknowledged; HTTPS only; archive members that escape the folder, links and device nodes are refused; provenance recorded with SHA-256 |
| Unit | `tests/unit/test_fingerprint.py` | 3 | Dataset versions are order-independent and change when one label or one message changes |
| Unit | `tests/unit/test_tracking.py` | 3 | MLflow logging is optional, logs numbers not messages, and says how to install it when absent |
| Unit | `tests/unit/test_defenses.py` | 5 | The campaign-burst guard raises burst campaigns within its bound, never lowers a score (a regression: it once capped 1.0 down to 0.99), and stays out of the way without context; text evidence names whole words, not character fragments; the defence catalogue and the attack taxonomy agree on which control counters which family (a regression: they once disagreed for five of six controls) |
| Integration | `tests/integration/test_service.py` | 24 | Training and separation on a held-out grouped split, false-positive ceiling, evidence quality, determinism, batch/single agreement, registry round-trip with identical scores, audit-trail writes, feedback, filtering, URL scanning, operational stats, the model-information response contract (a regression: it once failed its own schema), the adversarial probe, the fusion-vs-baseline claim, and phishing-only augmentation |
| Security | `tests/security/test_security.py` | 24 | API-key authentication, role authorisation, production key refusal, token-bucket rate limiting, request-size and batch bounds, extra-field rejection, hostile payloads, SQL injection through a filter, decision-id unguessability, log and audit privacy, pseudonymisation, and the network-access prohibition |
| Helpers | `tests/helpers.py` | — | Message builders and cached expensive objects: a 1 400-message corpus, one grouped split, one trained detector, one `ScanService` over a temporary SQLite store |

**Why the helpers are plain functions.** `tests/helpers.py` uses
`functools.lru_cache` rather than pytest fixtures, so the same files run under
both runners (§5.5) with no conftest and no markers. The trained detector is
built once and shared, which is why 281 tests that include real model training
finish in about a minute rather than an hour.

**Where the time actually goes.** Three tests dominate:
`test_hostile_payloads_do_not_crash_the_scanner` (about 19 s — it scores a
100 000 character body and ten malformed payloads through the full path),
`test_detector_trains_and_separates_the_classes` (about 7 s, the one-off
training), and the three corpus-wide split tests (2–3 s each, dominated by
MinHash over the corpus). Everything else is milliseconds.

## 5.3 Notable test cases

The tests worth reading, and what each one stops.

| Test | Protects against |
|---|---|
| `test_leakage_audit_catches_a_deliberately_broken_split` | A row-level split that shares campaigns between train and test |
| `test_leakage_audit_flags_a_planted_label_feature` | Any feature that encodes the label, in the corpus or in a future feature |
| `test_no_single_feature_dominates_the_corpus` | A generator artefact turning the task into a lookup |
| `test_behavioral_transforms_touch_only_attacker_controlled_state` | Robustness numbers earned by an attacker with impossible powers |
| `test_header_transforms_cannot_move_to_the_brands_real_domain` | Domain compromise (OOS-1) being scored as an evasion |
| `test_payload_check_rejects_a_message_with_the_link_removed` | Counting a broken email as a successful attack |
| `test_the_fusion_is_harder_to_evade_than_a_text_only_baseline` | The project's central claim quietly becoming false |
| `test_audit_trail_stores_no_message_content` | The audit database becoming a copy of everyone's mail |
| `test_logs_never_carry_message_content` | The same leak through the logging path |
| `test_the_model_never_fetches_anything_from_the_network` | An SSRF primitive and victim-telemetry leak (OOS-4) |
| `test_feature_contract_mismatch_is_a_hard_failure` | A model served against the wrong feature layout |
| `test_no_transform_raises_on_a_realistic_message` | A crashing transform silently shrinking the attack surface |
| `test_transforms_do_not_mutate_the_original_message` | An attack corrupting the baseline it is measured against |

Four of these deserve more than a table row.

**The leakage audit is tested by breaking it on purpose.**
`test_leakage_audit_catches_a_deliberately_broken_split` constructs the exact
split a careless researcher would produce — even indices train, odd indices
test — and asserts that `audit_leakage` refuses it with `group_overlap > 0`.
Its sibling goes further: it column-stacks the label vector onto the real
feature matrix under the name `planted_label` and requires the audit to name
that feature in `suspicious_features`. A guard that has never been shown to
fire is not a guard, and these two tests are the difference.

**`test_no_single_feature_dominates_the_corpus` is a test about the corpus, not
the code.** It extracts all 265 features over the whole corpus and asserts that
the best single-feature AUC is below 0.985. If any one signal separated the
classes on its own, every downstream number — the ablations, the robustness
comparison, the acceptance gates — would be measuring a lookup table rather
than a classifier. The same check, running inside the leakage audit, caught
four generator artefacts during development, each documented in
[§6.3](06-data-dictionary.md); this test is the standing regression guard.

**Attack validity is enforced, not assumed.** An adversarial evaluation is only
as honest as its constraints. Three tests carry that weight:
`test_behavioral_transforms_touch_only_attacker_controlled_state` builds a
message with a rich correspondence history and asserts that every `A-BEH`
transform leaves `prior_messages_from_sender`, `prior_replies_to_sender`,
`domain_age_days` and `domain_report_count` exactly as they were — the attacker
may re-time and re-shape their sending, but they cannot retroactively have had
a two-year relationship with the victim.
`test_header_transforms_cannot_move_to_the_brands_real_domain` asserts that
`A-HDR` transforms preserve `sender_domain`, because sending from `paypal.com`
is domain compromise, which is out of scope by declaration (OOS-1) rather than
by convenience. And `test_payload_check_rejects_a_message_with_the_link_removed`
pins down what an attack even is: a candidate that deletes the link scores
beautifully and delivers nobody to the landing page, so `payload_preserved`
rejects it. The complementary cases are tested too — shortener wrapping and
the text-as-image attack are both accepted, because in both the victim still
reaches the page.

**The central claim is a test.**
`test_the_fusion_is_harder_to_evade_than_a_text_only_baseline` trains a TF-IDF
baseline on the same split, runs the same `BudgetedAttacker` with the same seed
and budget against both surfaces over 40 held-out phishing messages, and
asserts `fusion_asr <= baseline_asr`. If the tri-modal design ever stops
buying robustness, the suite goes red rather than the dossier quietly
reporting a smaller advantage.

## 5.4 Failure-mode and robustness experiments

The brief requires at least one failure-mode, security or robustness
experiment. Five were run. The figures below are from
`artifacts/reports/evaluation.json`, generated on a 9 000-message corpus
(seed 20260907, 6 750 train / 1 938 test, 1 256 campaigns) against model
`pg-0e0dffa24f`.

**1. The adversarial suite.** The transforms of the attack taxonomy's 8
families, driven by a decision-based black-box attacker that sees only a
score: the raw fusion score for the headline rows, the probability the API
returns for the calibrated-surface row.

| Experiment | Setup | Result |
|---|---|---|
| Composed attack | Greedy search, budget 10, 150 phishing messages | ASR **0.0**, silent-delivery rate **0.0**, mean 18.6 queries; macro F1 0.98805 clean, 0.99481 under attack (different score surfaces; on one surface no decision changes at 0.5 — §7.4) |
| Per-family isolation | Same messages, one family at a time | All 8 families 0.0; largest mean score drop A-URL 0.00185, smallest A-HDR 0.00006 |
| Single-transform sweep | Each transform alone, via `phishguard attack --sweep` | Ranks the primitives by mean score drop and evasion rate; run on demand rather than written into the dossier |
| Calibrated surface | Attack the probability the API actually returns | ASR **0.0**, macro F1 drop 0.0 |
| Text-only baseline | Same attacker, same budget, TF-IDF + logistic regression | ASR **0.29333**, silent delivery 0.0 — an advantage of **0.29333** to the fusion |
| PG-HARD adaptive attack | 48 hard phishing records, budgets 10 / 40 / 120, an attacker that targets abstention | PhishGuard delivers 0 / 3 / 3 unwarned; the text-only filter 3 / 29 / 43 |

At a budget of 10 the per-family rows cannot rank the families: none succeeds,
and the mean score drops differ in the third and fourth decimal place. A-BEH —
the family that mimics timing and sending shape — is no longer the least
effective by that measure (its mean drop, 0.00141, is second only to A-URL's),
and on PG-HARD at 40 queries it is one of the two families that got a hard
phishing record past PhishGuard. What still holds is its cost: the register
marks it high, since low-and-slow sending cuts campaign reach. The PG-HARD row
is where the systems separate, which is why the dossier treats it as the
discriminating test.

**2. Defence ablation.** Eight arms, each retrained from scratch with one
control removed, attacked at budget 10 on the first 120 of the 150 messages:

| Arm | Clean macro F1 | ASR | Δ ASR vs all defences |
|---|---|---|---|
| All defences | 0.98805 | 0.0 | — |
| without D-NORM | 0.98857 | 0.0 | 0.0 |
| without D-URL | 0.99118 | 0.0 | 0.0 |
| without D-ADVTRAIN | 0.99429 | 0.0 | 0.0 |
| without D-ENSEMBLE | 0.97826 | **0.1000** | **+0.1000** |
| without D-ABSTAIN | 0.98805 | 0.0 | 0.0 |
| without D-VELOCITY | 0.98805 | 0.0 | 0.0 |
| No defences | 0.97358 | **0.0917** | **+0.0917** |

Every arm, including the reference one, is retrained from scratch — several of
these controls change what the model learns and cannot be switched off at
inference time — so the meaningful comparison is between arms, not against the
headline figure in the previous table, which attacks the registered model on
150 messages.

At this budget the ensemble is the only control whose removal registers:
without it, 12 of the 120 attacked messages escape auto-block, all 12
silently, and removing every control is no worse (0.0917). `D-NORM`, `D-URL`,
`D-ADVTRAIN`, `D-ABSTAIN` and `D-VELOCITY` move the attack success rate not at
all — which says the ordinary test set at a budget of 10 is not hard enough to
separate them, not that they are inert; `D-ABSTAIN` and `D-VELOCITY` act after
the raw score the ablation attacks and cannot register by construction.
`D-URL` and `D-ADVTRAIN` share an odd pattern: removing either raises clean
macro F1 at a 0.5 cut-off while raising the clean false-positive rate (from
0.10% to 0.29% and 0.39%). On this run they are buying clean precision, not
measurable robustness. That is an honest result and it is in the dossier
rather than filtered out of it.

**3. Modality ablation.** Seven family combinations retrained on the same
split, which is the experiment the project title implies:

| Families | Features | Macro F1 | FPR |
|---|---|---|---|
| email | 125 | 0.98446 | 0.0212 |
| url | 107 | 0.94080 | 0.0472 |
| behavioral | 33 | 0.93434 | 0.0347 |
| email + url | 232 | 0.98446 | 0.0222 |
| email + behavioral | 158 | 0.98391 | 0.0116 |
| url + behavioral | 140 | 0.98598 | 0.0048 |
| all three | 265 | 0.98651 | 0.0096 |

On clean traffic all three families together are now the best combination,
but only just: 0.00053 macro F1 ahead of `url + behavioral`, which is one
message, and 0.00205 ahead of `email + url`. On 7 September the sign was the
other way, with `email + url` ahead of the full set. Either way the gap is
inside the noise; the behavioural family is not there for clean accuracy.
Whether it earns its place under attack is what this experiment cannot say,
because it is run on clean data only.

**4. Hostile input.** `test_hostile_payloads_do_not_crash_the_scanner` pushes
ten payload classes through the full decision path — SQL injection, script
tags, template and JNDI injection, path traversal, null bytes, 500 emoji,
format-string specifiers, RTL-override filenames, and an XXE doctype — plus a
100 000 character body at the size limit, and asserts that every one returns a
score in [0, 1]. Anything larger is rejected by the request contract before it
reaches the model, which is a separate test.

**5. SSRF and telemetry leakage.**
`test_the_model_never_fetches_anything_from_the_network` monkeypatches
`socket.socket` with a class that raises on construction, then scans a message
whose body contains a link to an internal metadata endpoint. If any code path
in feature extraction ever resolved a URL, the test fails. This is the
mechanical enforcement of OOS-4: fetching attacker-controlled content from a
mail gateway would be both an SSRF primitive and a read receipt delivered to
the attacker.

## 5.5 Running the tests

Two runners, the same tests.

```bash
pytest -q                              # the supported runner
pytest tests/unit tests/security -q    # unit + security, as CI runs them first
pytest tests/unit -q                   # no model training at all
make test                              # pytest -q inside the project venv
make test-fast                         # unit + security only
```

```bash
python scripts/run_tests.py            # everything, no dependencies
python scripts/run_tests.py unit       # one directory
python scripts/run_tests.py -k normalize   # match by name
python scripts/run_tests.py -v         # per-test timings
python scripts/run_tests.py -x         # stop at the first failure
```

**Why there are two.** `pytest` is the supported runner and is what CI uses.
`scripts/run_tests.py` exists so the suite can also run where pytest is not
installed — a minimal container, a locked-down build agent, an examiner's
machine with a bare Python — without changing a line of the tests. It is 157
lines: it collects `test_*.py` files, calls every module-level `test_` function,
supplies a temporary directory to any test that declares `tmp_path`, treats a
`Skipped`/`SkipTest` exception as a skip, and prints the same
passed/failed/skipped summary.

**The design choice that makes this work.** The test files use plain functions
and plain `assert` statements. No fixtures, no `conftest.py`, no
`pytest.mark`, no parametrisation, no plugins. Shared state is built by cached
helper functions in `tests/helpers.py` instead. Both runners therefore see
exactly the same thing, which means the fallback runner is a genuine fallback
rather than a second, weaker suite that drifts from the first.

## 5.6 CI pipeline

`.github/workflows/ci.yml` runs five jobs on every push and pull request to
`main` and `develop`, with `PYTHONHASHSEED=0` and `PG_ENVIRONMENT=test` set
globally, read-only repository permissions, and in-progress runs cancelled on a
new push. Two more workflows complete the pipeline: `codeql.yml` (static
security analysis, weekly and on every pull request) and `release.yml` (on a
version tag: build, smoke-test and publish the image, and create a release
with the changelog as its notes).

| Job | Needs | What it does |
|---|---|---|
| `lint` | — | `ruff check src tests scripts` (including the flake8-bandit security rules) and `ruff format --check src tests scripts`, with ruff pinned so an unchanged tree cannot start failing |
| `test` | — | Matrix over Python 3.10, 3.11 and 3.12 (`fail-fast: false`): unit and security tests with `--cov=phishguard --cov-report=term-missing`, then the integration tests; uploads `.coverage` from the 3.11 leg |
| `security` | — | `pip-audit --strict` against the installed dependency set, then a grep that fails the build if anything matching `PG_API_KEYS` or `PG_PSEUDONYMIZATION_SALT` followed by a 16+ character value is committed (excluding `change-me` and `example` placeholders) |
| `acceptance` | `lint`, `test` | The full pipeline: build and audit a 9 000-message corpus, train, evaluate with budget 10 over 150 attacked messages, regenerate the model card and the report figures, run the load test, export the OpenAPI document, upload the dossier, and write a gate table to the job summary |
| `container` | `lint`, `test` | Build `docker/api.Dockerfile` with buildx and GitHub Actions layer caching, start the image, poll `/readyz` for up to 15 minutes, then smoke-test the API |

**The acceptance job is the merge gate.** `phishguard evaluate` returns a
non-zero exit code when any blocking acceptance gate fails, and all ten gates
are blocking. Two of them are robustness gates — G5 caps the macro F1 drop
under attack at 0.15 (observed 0.0) and G6 caps attack success rate at 0.35
(observed 0.0) — and G9 requires the fusion's attack success rate to be no
higher than the text-only baseline's (observed advantage 0.293). A change
that improved clean accuracy while making the model easier to evade would fail
the build. G10 does the same for leakage: if the audit does not pass, nothing
downstream is believed.

The job summary is written with `if: always()`, so a failing run still
publishes the gate table and the robustness figures rather than only a stack
trace, and the dossier is uploaded as an artefact either way.

**The container job tests the layer the unit tests do not.** After readiness it
asserts: `/healthz` reports `"status":"ok"`; `/metrics` exposes
`phishguard_uptime_seconds`; an authenticated scan of a credential-harvesting
message comes back `BLOCK` or `REVIEW`; an unauthenticated `POST /api/v1/scan`
returns **401**; an analyst key against the admin-only
`GET /api/v1/decisions` returns **403**; a reporter can report a message and
the receipt contains no score or band; a reporter key cannot scan (**403**);
the reported message appears in the analysts' queue; and a scan that sends a
W3C `traceparent` gets the same trace id back, with a `Server-Timing` header.
Container logs are dumped and the container removed with `if: always()`.

## 5.7 Coverage and what is deliberately not tested

Coverage is measured (`--cov=phishguard`, branch coverage configured in
`pyproject.toml`) and uploaded, but no `fail_under` threshold is enforced. The
bar for this project is the property assertions in §5.3, not a percentage —
a suite can reach 90% coverage while asserting nothing that would catch a
leaking split. What follows is the honest list of what the suite does not
cover.

**The FastAPI adapter layer.** `src/phishguard/service/app.py` is 482 lines of
routing, dependency wiring, exception handlers and response shaping. No test
imports it; there is no `TestClient` in the suite. This is deliberate — the
adapter contains no decision logic, and testing it in-process would mostly
test FastAPI — but it does mean the adapter's behaviour is verified only by
the container smoke test, which checks five things. Auth and authorisation
themselves are unit-tested at the `ApiKeyAuthenticator` level, so what is
untested is specifically the wiring between HTTP and those checks, plus error
mapping and response serialisation.

**The transformer member.** `TransformerMember` is a guarded optional
DistilBERT head behind the `transformer` extra. It is not installed in CI, is
not trained in any test, and would need a GPU to be worth training at all. It
is off by default (`--with-transformer` opts in, and the CLI degrades to a
warning if the extra is absent), so nothing in the dossier depends on it — but
the code path is genuinely unexercised.

**The observability stack.** The Prometheus scrape config, the alert rules in
`docker/alerts.yml` and the provisioned Grafana dashboard
(`docker/grafana/provisioning/dashboards/phishguard.json`) are shipped and
work when the stack is brought up with `make up`, but nothing asserts that a
panel query matches a metric name the service actually emits. The only
automated check is the container smoke test grepping `/metrics` for
`phishguard_uptime_seconds`.

**The analyst console.** `ui/index.html` is a zero-build page served by the
API. It has no tests of any kind.

**Performance under load.** Latency is measured in the evaluation harness on a
single-message path (p95 17.2 ms with explanations, 10.2 ms without) and gated
at 150 ms by G7. Since 1.3.0 `phishguard loadtest` also measures throughput and
tail latency at up to eight concurrent requests (§7.14), and the CI acceptance
job runs it at 1, 4 and 8, failing only if a request errors; nothing asserts on
its latency — the evaluation's own load run measured a p95 of 150.7 ms at eight
in flight, just over the budget, and nothing failed, because G7 gates only the
single-message path — and there is no soak or backpressure test. The rate limiter is
unit-tested for its arithmetic, not for its behaviour under a real burst.

**Real corpora.** Every number in the dossier comes from the synthetic corpus.
The loaders for Nazario, Enron, SpamAssassin, PhishTank and the UCI URL sets
exist and are documented in [§6.1](06-data-dictionary.md), but they read from
paths the operator supplies, so nothing in CI can exercise them. Their format
handling is therefore untested against the real files.

---

**Next:** [§6 Data and model package →](06-data-dictionary.md)

---

## 5.8 Portability regressions

`tests/unit/test_portability.py` pins bugs that made the project fail on a
machine other than the one it was written on. Every one was found by an audit
rather than by a user, which is the order it should happen in.

| Test | The bug it pins |
|---|---|
| `test_analyst_console_ships_inside_the_package` | The console was resolved as `Path(__file__).parents[3] / "ui"`, correct in a source checkout and wrong everywhere else. In the container it resolved to `/install/lib/python3.11/ui/index.html`, so the primary interface returned "asset not found" in the deployment the guide recommends first. It is now package data. |
| `test_project_root_never_resolves_into_site_packages` | The same arithmetic made `PROJECT_ROOT` — and therefore the default artifacts directory — resolve into the interpreter's own tree after `pip install`. `phishguard train` would have tried to write a model registry into `site-packages`. The root is now confirmed by looking for `pyproject.toml` and otherwise falls back to the working directory. |
| `test_all_text_file_access_declares_an_encoding` | Windows defaults to cp1252. This project's own files contain homoglyphs by design, so an unqualified `read_text()` is a guaranteed `UnicodeDecodeError` there. |
| `test_email_utils_is_imported_explicitly` | `import email` does not bind `email.utils`. It worked only because `email.policy` imports it as a side effect — a CPython implementation detail, not a promise. |
| `test_nothing_newer_than_the_declared_minimum_python_is_used` | `requires-python` says 3.10; this asserts nothing from 3.11+ has crept in. |
| `test_minhash_survives_uint64_wraparound` | The near-duplicate sketch relies on silent `uint64` overflow, which NEP 50 changed between numpy 1.x and 2.x. If a future version raises instead of wrapping, leakage detection would silently weaken. |
| `test_sklearn_constructor_parameters_still_exist` | A quiet upstream API removal would otherwise appear as a `TypeError` during training. |
| `test_memory_scaling_is_monotone_and_bounded` | The low-memory path must never penalise an ordinary machine, and must never shrink the vocabulary below a usable size. |
| `test_every_declared_dependency_is_actually_used` | An unused dependency is a supply-chain and version-conflict surface for nothing in return. This is how `pandas` was found and removed; `scipy` is retained with a documented reason, since `models/members.py` uses its sparse API without importing it by name. |
| `test_doctor_runs_and_reports_without_raising` | The diagnostic has to work in exactly the situations where everything else has stopped working — including the requirement that every failure carries a fix. |

### The preflight command

`phishguard doctor` exists because when this project does not work on somebody's
machine, they should get a diagnosis rather than a traceback. It checks the
interpreter version, every dependency and its version, SQLite, writable paths,
the memory budget (honouring a container limit, which is what actually kills a
training run), free disk, the console asset, the model registry, the API keys
and the audit salt, and the console encoding. Each failure carries the command
that fixes it, and the exit code is non-zero when something is genuinely broken,
so it can gate a setup script.

`--self-test` goes further and runs the real pipeline on a 400-message corpus:
generate, extract, split, train, score, explain, attack, and write to the audit
store. That is the fastest way to catch a library version that imports cleanly
and then misbehaves — the failure mode a version check alone cannot see.

Unhandled failures in the CLI are also translated: `MemoryError`,
`PermissionError`, `FileNotFoundError`, `OSError` and `ImportError` each print
what happened and what to do about it. Anything genuinely unanticipated keeps
its traceback, because silently swallowing an unknown failure would be worse
than showing it; `PG_TRACEBACK=1` restores the traceback in all cases.
