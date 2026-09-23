# 8. Deployment guide

> **Just want it running?** Don't read this. Run `python start.py` and follow
> [QUICKSTART.md](../QUICKSTART.md) — six steps, about five minutes.
>
> This document is the reference: every path, every setting, every failure
> mode, and how to operate the system once it is up.

Three paths, in the order they appear below:

| Path | Choose it when | Effort |
|---|---|---|
| **A — Docker** | You already have Docker Desktop | One command, but Docker is a large install |
| **B — Local Python** | Almost always. `python start.py` does every step | Least to install |
| **C — Cloud** | You need a public URL | Most setup |

If you are not sure, use **B**.

Everything runs offline after the first install. Nothing is downloaded at
runtime, no third-party API keys are needed, and no dataset has to be fetched.

---

## Path A — Docker Compose

Satisfies the "reproducible container" acceptance gate. Choose this if you
already have Docker; otherwise Path B is less to install.

### A.1 Prerequisites

| Requirement | Check it with | If missing |
|---|---|---|
| Docker Engine 24+ | `docker --version` | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| Docker Compose v2 | `docker compose version` | Bundled with Docker Desktop; on Linux install `docker-compose-plugin` |
| ~1 GB free RAM | `free -h` (Linux) / Docker Desktop → Resources | Training peaks at 379 MB; give Docker 1 GB or more |
| 3 GB free disk | `df -h` | |

> On Windows, run these commands in **PowerShell** or **WSL2**, not `cmd.exe`.
> If your terminal mangles output, set `PYTHONUTF8=1`.

### A.2 Get the code

```bash
git clone <your-repository-url> phishguard
cd phishguard
```

Or, if you were given a zip:

```bash
unzip phishguard.zip && cd phishguard
```

### A.3 Set your own credentials

The committed values are placeholders and the service says so in its logs.
Generate real ones:

```bash
python3 -c "import secrets; print('analyst:pg_an_'  + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('admin:pg_ad_'    + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('reporter:pg_rp_' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # salt
```

Create a `.env` file next to `docker-compose.yml`:

```bash
cat > .env <<'EOF'
PG_API_KEYS=analyst:pg_an_PASTE_YOURS,admin:pg_ad_PASTE_YOURS,reporter:pg_rp_PASTE_YOURS
PG_PSEUDONYMIZATION_SALT=PASTE_THE_SALT
EOF
```

The **reporter** key is for the report page (`/report`) that employees use; it
can report messages and read its own reports, and never sees a score.

Two notes that matter:

- **Keep the salt.** It is what makes sender identifiers in the audit trail
  correlatable across records. Changing it later does not break anything, but
  old rows stop matching new ones.
- **`.env` is gitignored.** Do not commit it. CI fails the build if a
  credential-shaped value appears in the tree.

For a purely local trial you can skip this step entirely; the compose file ships
working development keys and warns loudly that it is using them.

### A.4 Start

```bash
docker compose up --build -d
```

Or `make up`, which prints the URLs afterwards.

**The first start trains a model.** The entrypoint sees an empty registry,
generates a 12 000-message corpus, trains, and registers the result. This takes
**three to eight minutes** depending on the machine. Subsequent starts are
immediate because the model lives in a named volume.

Watch it happen:

```bash
docker compose logs -f api
```

You are waiting for:

```json
{"ts":"...","level":"INFO","logger":"entrypoint","message":"no model in the registry - training one (n=12000, a few minutes)"}
{"ts":"...","level":"INFO","logger":"entrypoint","message":"bootstrap training complete"}
{"ts":"...","level":"INFO","logger":"phishguard.api","message":"model loaded","model_version":"pg-...","members":"rules,engineered,charngram,wordtfidf"}
```

### A.5 Verify

```bash
curl -s http://localhost:8000/healthz | python3 -m json.tool
curl -s http://localhost:8000/readyz  | python3 -m json.tool
```

`readyz` returning `200` with a `model_version` means the system is live. If it
returns `503`, the message says exactly why.

Now score something. Replace the key with your analyst key:

```bash
curl -s -X POST http://localhost:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-analyst-key-change-me' \
  -d '{
    "subject": "URGENT: Your Microsoft 365 account will be suspended",
    "body": "Dear Customer,\n\nWe detected unauthorized access. Verify your identity within 24 hours or your account will be permanently closed.\n\nhttp://microsoft-verify-9f2x.tk/account/login\n\nMicrosoft Security Team",
    "sender": "Microsoft 365 Security <security@microsoft-verify-9f2x.tk>",
    "reply_to": "recovery.team@mail.ru",
    "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
    "behavioral": {"sender_first_seen": true, "hour_local": 3,
                   "domain_age_days": 4, "burst_count_1h": 220,
                   "display_name_alias_count": 6}
  }' | python3 -m json.tool
```

Expect `"band": "BLOCK"` with a score near 1.0 and an evidence list naming the
brand impersonation, the young domain and the failed DMARC.

Then check the opposite direction — a legitimate message must come back `ALLOW`:

```bash
curl -s -X POST http://localhost:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-analyst-key-change-me' \
  -d '{
    "subject": "Weekly status - Warehouse",
    "body": "Status for this week:\n\nDone: supplier list verified.\nBlocked: waiting on the partner API key.\n\nThanks,\nPriya",
    "sender": "Priya Sharma <priya.sharma@northgate-industries.example>",
    "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
    "behavioral": {"sender_first_seen": false, "prior_messages_from_sender": 84,
                   "prior_replies_to_sender": 30, "hour_local": 10,
                   "domain_age_days": 3200, "burst_count_1h": 2}
  }' | python3 -m json.tool
```

### A.6 Open the interfaces

| What | URL | Credentials |
|---|---|---|
| **Analyst console** | http://localhost:8000 | paste your analyst or admin key into the header field |
| **API documentation** | http://localhost:8000/docs | interactive OpenAPI |
| **Prometheus** | http://localhost:9090 | try `phishguard_scans_total` |
| **Grafana** | http://localhost:3000 | `admin` / `admin`; the dashboard is pre-provisioned |

In the console: paste the admin key, press **Connect**, choose an example from
the dropdown, and press **Assess message**. The **Adversarial probe** tab
attacks whatever is currently in the assessment form.

### A.7 Stop and clean up

```bash
docker compose down          # stop, keep the model and audit trail
docker compose down -v       # stop and delete the volumes (next start retrains)
```

---

## Path B — Local Python

Use this to develop, to run the test suite, or to reproduce the evaluation.

### B.1 Prerequisites

Python **3.10, 3.11 or 3.12**. Check with `python3 --version`.

Once installed, the fastest way to find out whether this machine will work is
to ask it rather than to guess:

```bash
phishguard doctor --self-test
```

```
  [OK  ] python             3.11.9 (CPython)
  [OK  ] scikit-learn       1.5.1
  [OK  ] artifacts dir      /home/you/phishguard/artifacts
  [OK  ] memory             7328 MB available
  [WARN] API keys           using the built-in development keys
                            -> set PG_API_KEYS before exposing this beyond localhost
  [OK  ] analyst console    .../phishguard/static/index.html

  Running a full pipeline self-test on a small corpus...
  [OK  ] corpus generation        400 messages, 245 phishing
  [OK  ] model training           model pg-f14de84895 trained on 279 messages
  [OK  ] adversarial suite        5 messages attacked, suite functional
```

Every failure names the command that fixes it, and the exit code is non-zero
when something is genuinely broken, so it works in a setup script. The
self-test trains and attacks a real model on a small corpus, which catches a
subtly incompatible library version that imports cleanly and then misbehaves.

### B.2 Install

```bash
git clone <your-repository-url> phishguard
cd phishguard

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install -e ".[dev]"
```

Or simply `make setup`, which does all of the above.

Verify the install:

```bash
phishguard --version
```

### B.3 Build and audit the corpus

```bash
phishguard data --n 12000 --show-kinds
```

This generates the corpus, splits it by campaign, and runs the leakage audit.
Look for `leakage audit: PASSED`. If it fails, it prints exactly which check
failed, and training will refuse to run.

### B.4 Train

```bash
phishguard train --n 12000 --save
```

About 40 seconds on a modern laptop. `--save` registers the model and makes it
the one the API serves.

### B.5 Evaluate

```bash
phishguard evaluate --n 12000 --budget 10
```

Ten to thirty minutes, depending on the machine; the dossier's own run, which
also retrains eight ablation arms (`--defense-ablation`), took about 31 minutes
(1 863.5 s) on a slow two-core container (about 19 minutes on the faster host of the 1.3.0
run). Produces `artifacts/reports/evaluation.json` and
`evaluation.md`, and prints the acceptance-gate table. **The command exits
non-zero if any blocking gate fails**, which is what makes it usable in CI.

Add `--defense-ablation` to retrain one arm per defensive control and measure
what each is worth. That takes considerably longer (roughly 20–40 minutes)
because eight models are trained and attacked.

### B.6 Run the API

```bash
phishguard serve --port 8000
```

Then open http://localhost:8000.

### B.7 Everything at once

```bash
make all           # train, evaluate, model card, OpenAPI
make deliverables  # the above plus tests and the defence ablation
```

---

## Path C — Cloud

The API is a single stateless container plus one volume, so any container host
works. Two worked examples.

### C.1 Render — one click

`render.yaml` at the repository root is a Render Blueprint: it declares the
service, generates the four secrets and sets the free-plan memory-safe
defaults.

1. Push the repository to GitHub.
2. In Render, choose **New → Blueprint**, pick the repository, click **Apply**.
3. Wait for the build (a few minutes) and the first-start training (about
   three). The log ends with `starting API`.
4. Copy `PG_ADMIN_KEY` from the service's **Environment** tab. That is the key
   for the console at `https://<service>.onrender.com`; `PG_REPORTER_KEY` is
   for `/report`.

The free plan has no disk, so the model is retrained on every deploy and the
audit trail lives as long as the instance; it also sleeps after 15 idle
minutes, so open the address a few minutes before a demonstration. A paid
instance can mount a disk at `/data` to keep both.

### C.1b Hugging Face Space and Fly.io

`deploy/README.md` gives the same steps for a **Hugging Face Space** (free,
16 GB of memory, `deploy/huggingface-space/`) and for **Fly.io** (`fly.toml`,
with a persistent volume). All three hosts run the same container; the
differences are memory, persistence and price.

### C.2 Any Kubernetes cluster

```bash
docker build -f docker/api.Dockerfile -t <registry>/phishguard:1.4.0 .
docker push <registry>/phishguard:1.4.0
```

The container needs: a `ReadWriteOnce` volume at `/data`, `PG_API_KEYS` and
`PG_PSEUDONYMIZATION_SALT` from a `Secret`, a liveness probe on `/healthz`, a
readiness probe on `/readyz`, and a generous `startupProbe` (`failureThreshold:
60`, `periodSeconds: 10`) so the bootstrap training is not mistaken for a crash
loop. It already runs as a non-root user with all capabilities dropped.

### C.3 Ship a pre-trained model instead of bootstrapping

Preferable for anything resource-constrained: train once, ship the artefact.

```bash
phishguard train --n 12000 --save          # locally
tar czf model.tgz -C artifacts models      # ~40 MB
```

Copy `model.tgz` onto the deployment's `/data` volume, extract it, and set
`PG_BOOTSTRAP_TRAIN=0`. The container then starts in seconds.

---

## Configuration reference

Every setting is an environment variable prefixed `PG_`. `.env.example` is the
annotated master list; these are the ones you are most likely to change.

| Variable | Default | What it does |
|---|---|---|
| `PG_ENVIRONMENT` | `dev` | `prod` makes the service **refuse to start** without `PG_API_KEYS` |
| `PG_API_KEYS` | *(dev fallback)* | `analyst:<key>,admin:<key>,reporter:<key>` — any number of each |
| `PG_PSEUDONYMIZATION_SALT` | `change-me…` | Salt for audit-trail identifiers |
| `PG_REVIEW_THRESHOLD` | `0.40` | Below this: deliver |
| `PG_BLOCK_THRESHOLD` | `0.80` | At or above this: quarantine |
| `PG_RATE_LIMIT_PER_MINUTE` | `120` | Per API key |
| `PG_MAX_BODY_BYTES` | `1000000` | Request-size cap |
| `PG_AUDIT_RETENTION_DAYS` | `90` | Swept at startup |
| `PG_LOG_FORMAT` | `json` | `text` is easier to read while developing |
| `PG_BOOTSTRAP_N` | `12000` | Corpus size for the container's first-run training |
| `PG_BOOTSTRAP_TRAIN` | `1` | `0` if you are shipping a pre-trained model |
| `PG_API_WORKERS` | `1` | Server processes; about 45 messages/s each on the dossier's two-core container (70 on a faster host), up to one per core; two processes gave 1.97× ([§9.17](09-admin-user-guide.md)) |
| `PG_SCORING_CONCURRENCY` | `1` | Messages scored at once per process; leave at 1 |

### Tuning the thresholds

They are **policy decisions, not model decisions**, and the right way to set
them is against a false-positive budget rather than by picking a probability.
`phishguard evaluate` reports the threshold that achieves your target
false-positive rate under `at_operating_point` — read it as the floor below
which the budget is breached, not as a recommendation; see
[§9](09-admin-user-guide.md) for how to set thresholds from your own traffic. Raising the review threshold
reduces analyst workload and increases silent delivery; lowering the block
threshold catches more phishing and more legitimate mail. Both directions are
measured in the dossier, and the effect is visible immediately in
`/api/v1/stats`.

---

## Operating the system

### Retraining

```bash
docker compose run --rm api train --n 12000 --save
docker compose restart api
```

The model registry keeps every version. List, promote and prune:

```bash
docker compose run --rm api models
docker compose run --rm api models --promote pg-0e0dffa24f
docker compose run --rm api models --prune 5
```

Retrain when `/api/v1/stats` shows the analyst-disagreement rate climbing, or
when the score distribution in Grafana shifts. Both are drift signals the
system produces from its own operation.

### Checking robustness after a change

```bash
docker compose run --rm api attack --budget 10 --sweep
```

Reports the attack success rate, the per-family breakdown and which individual
transforms move the score most. Run it on every model change; the acceptance
gates will block a release whose robustness regressed.

### Backing up

Everything durable is in the `phishguard-data` volume:

```bash
docker run --rm -v phishguard_phishguard-data:/data -v "$PWD":/backup \
  alpine tar czf /backup/phishguard-backup.tgz -C /data .
```

### Reading the logs

Logs are one JSON object per line with a `request_id` on every entry, so a
decision can be traced end to end and no message content is ever written:

```bash
docker compose logs api | grep '"message":"scan"' | tail -20
docker compose logs api | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get('message') == 'scan':
        print(e['request_id'], e['band'], e['score'], e.get('sender_domain'))
"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/readyz` returns 503, "no model found" | Bootstrap training has not finished or was disabled | `docker compose logs -f api`; wait, or run `docker compose run --rm api train --save` |
| Container exits during first start | Out of memory during training | Give Docker 1 GB+, or set `PG_BOOTSTRAP_N=6000`. `phishguard doctor` reports the budget it can see |
| `401` on every request | Missing or wrong `X-API-Key` | Check the header name and that your key matches `PG_API_KEYS` |
| `403` on `/api/v1/decisions` | Using an analyst key on an admin endpoint | Use the admin key |
| `429` | Rate limit | Raise `PG_RATE_LIMIT_PER_MINUTE`, or honour the `Retry-After` header |
| Service refuses to start: "PG_API_KEYS must be set" | `PG_ENVIRONMENT=prod` with no keys | Set `PG_API_KEYS`, or use `dev` for local work |
| `feature contract mismatch` on startup | The saved model predates a feature change | Retrain: `phishguard train --save` |
| Console shows "Cannot reach the API" | Wrong port, or the container is not up | `docker compose ps`; check port 8000 is free |
| Prometheus target is down | The API container is not healthy yet | Wait for bootstrap training; check http://localhost:9090/targets |
| `phishguard: command not found` | Virtualenv not activated | `source .venv/bin/activate` |
| Console shows "asset was not found" | The console HTML could not be located | It ships inside the package; if you moved it, set `PG_UI_PATH` to its path |
| Artifacts written somewhere unexpected | No `pyproject.toml` above the package, so the root falls back to the working directory | Set `PG_ARTIFACTS_DIR` explicitly |
| `UnicodeDecodeError` reading a file on Windows | Non-UTF-8 locale | `set PYTHONUTF8=1`, then retry |
| Anything else | — | `phishguard doctor --self-test` diagnoses the environment; `PG_TRACEBACK=1` restores the full traceback |
| Training is very slow | Small machine | `--n 6000` is enough to reproduce the qualitative results |

---

## Demonstration script

A **seven-minute** walkthrough, inside the portfolio's five-to-eight-minute
window, for the recorded demo and the viva. Start it with the service already
running — first-run training takes a few minutes and is not worth filming — and
with three browser tabs open: the console (`http://localhost:8000`), the report
page (`/report`), and `artifacts/reports/evaluation.md`.

Development keys, if you used `python start.py` or the compose file:
analyst `dev-analyst-key-change-me`, admin `dev-admin-key-change-me`, reporter
`dev-reporter-key-change-me`.

| Time | Scene | Do | Say |
|---|---|---|---|
| 0:00 | **The problem** | Show the README's first screen | Filters score well on a fixed dataset and fail when attackers change spelling, domains and style. PhishGuard is built and measured against that attacker |
| 0:40 | **An obvious phish** | Console → connect with the analyst key → **Credential phishing (obvious)** → **Assess message** | The band, the evidence in sentences (never feature names), four readers agreeing, and *where the time went* — about 12 ms |
| 1:30 | **The hard case** | Load **Cloned brand template (hard)** → **Compare with a text-only filter** | The words are the brand's own, so a text-only filter cannot tell; the domain and the sender history decide it, and those are what the attacker controls least |
| 2:30 | **Honest uncertainty** | Load **Compromised internal account (hard)** | The readers disagree, so PhishGuard sends it to a person (REVIEW) instead of guessing, and says which signals disagreed |
| 3:00 | **A hard negative** | Load **Legitimate password reset (hard negative)** | Same vocabulary, opposite verdict. The false-positive rate decides whether a filter stays switched on |
| 3:30 | **An employee reports** | Report page → reporter key → paste a payment-request message → **Send to the security team** | Rohan gets a case number and a plain-language status. No score — so the page cannot be used to test phishing |
| 4:10 | **The analyst works the queue** | Console → **Review queue** → open the new case → **Claim** → read evidence and timeline → **Confirm phishing** | Owned, prioritised, timed. Only the claimant or an admin can decide it; releasing something the model was sure about needs an admin |
| 5:00 | **The loop closes** | Report page → **Refresh** under *My reports* | "Confirmed as phishing and removed" — and the decision was recorded as analyst feedback, with no retraining behind anyone's back |
| 5:30 | **The attacker tries harder** | Reconnect with the admin key → back to the obvious phish → **Adversarial probe** → **Run probe** | The edits the attacker tried, the score after each, and whether it escaped. In the evaluation, the text-only filter is evaded far more often than PhishGuard |
| 6:20 | **Operations and evidence** | **Model & monitoring** → **Check drift**; then `evaluation.md` | Drift, metrics and traces for the operator; ten acceptance gates, all passing, re-run by one command |
| 7:00 | **Close** | — | The corpus is synthetic, so absolute accuracy is an upper bound; what transfers is the comparison — fusion against both baselines, under attack — and the go/no-go: ready for a supervised pilot, not yet for autonomous blocking |

**Before recording:** run the whole script once. Keep the browser zoom at 100–110%
so text is readable in the video. If Docker is running, a ten-second cut to the
Grafana dashboard (`http://localhost:3000`) at 6:20 shows the review-queue and
per-stage panels.

**Questions to expect,** and where the answer is: *Why not a transformer?*
([ADR-001](adr/001-tri-modal-fusion.md)); *Is synthetic data cheating?*
([ADR-002](adr/002-synthetic-corpus.md), [§7.12](07-evaluation-dossier.md));
*What gets through?* ([§4.7](04-threat-model.md)); *Who can release a held
message?* ([§2.9](02-architecture.md)); *How fast under load?*
([§7.14](07-evaluation-dossier.md)).

---

**Next:** [§9 Administrator and user guide →](09-admin-user-guide.md)
