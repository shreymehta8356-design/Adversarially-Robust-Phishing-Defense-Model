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
python3 -c "import secrets; print('analyst:pg_an_' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('admin:pg_ad_'   + secrets.token_urlsafe(32))"
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # salt
```

Create a `.env` file next to `docker-compose.yml`:

```bash
cat > .env <<'EOF'
PG_API_KEYS=analyst:pg_an_PASTE_YOURS,admin:pg_ad_PASTE_YOURS
PG_PSEUDONYMIZATION_SALT=PASTE_THE_SALT
EOF
```

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
phishguard evaluate --n 12000 --budget 12
```

Five to ten minutes. Produces `artifacts/reports/evaluation.json` and
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

### C.1 Render

1. Push the repository to GitHub.
2. In Render, create a **Web Service** from the repo.
3. Set **Runtime** to Docker and **Dockerfile Path** to `docker/api.Dockerfile`.
4. Add a **Persistent Disk** mounted at `/data`, at least 2 GB.
5. Environment variables:

   | Key | Value |
   |---|---|
   | `PG_ENVIRONMENT` | `prod` |
   | `PG_API_KEYS` | `analyst:...,admin:...` |
   | `PG_PSEUDONYMIZATION_SALT` | your salt |
   | `PG_ARTIFACTS_DIR` | `/data` |
   | `PG_BOOTSTRAP_N` | `6000` (smaller, for a free instance) |
   | `PG_CORS_ORIGINS` | `["https://your-service.onrender.com"]` |

6. Set the health-check path to `/healthz`.

On a free instance the first boot trains a model and may take ten minutes or
more. If the instance has under 2 GB of RAM, lower `PG_BOOTSTRAP_N` to 4000, or
better: train locally and commit the model to the disk (see C.3).

### C.2 Any Kubernetes cluster

```bash
docker build -f docker/api.Dockerfile -t <registry>/phishguard:1.0.0 .
docker push <registry>/phishguard:1.0.0
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
| `PG_API_KEYS` | *(dev fallback)* | `analyst:<key>,admin:<key>` |
| `PG_PSEUDONYMIZATION_SALT` | `change-me…` | Salt for audit-trail identifiers |
| `PG_REVIEW_THRESHOLD` | `0.40` | Below this: deliver |
| `PG_BLOCK_THRESHOLD` | `0.80` | At or above this: quarantine |
| `PG_RATE_LIMIT_PER_MINUTE` | `120` | Per API key |
| `PG_MAX_BODY_BYTES` | `1000000` | Request-size cap |
| `PG_AUDIT_RETENTION_DAYS` | `90` | Swept at startup |
| `PG_LOG_FORMAT` | `json` | `text` is easier to read while developing |
| `PG_BOOTSTRAP_N` | `12000` | Corpus size for the container's first-run training |
| `PG_BOOTSTRAP_TRAIN` | `1` | `0` if you are shipping a pre-trained model |

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
docker compose run --rm api models --promote pg-0bcb098e45
docker compose run --rm api models --prune 5
```

Retrain when `/api/v1/stats` shows the analyst-disagreement rate climbing, or
when the score distribution in Grafana shifts. Both are drift signals the
system produces from its own operation.

### Checking robustness after a change

```bash
docker compose run --rm api attack --budget 12 --sweep
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

A ten-minute walkthrough for the viva. Practise it once; every step is a single
command or click.

**1 — From nothing to running (2 min).** Start with `docker compose down -v` to
prove nothing is cached, then `docker compose up --build -d` and tail the logs.
Say while it trains: the container found an empty registry, generated a corpus,
and is training four models plus a fusion and a calibrator on three disjoint
data pools.

**2 — An obvious phish (1 min).** Console → **Credential phishing (obvious)** →
**Assess message**. Point at the band, then at the evidence: the analyst never
sees a feature name, only sentences. Note the member scores agreeing.

**3 — A hard case (3 min). This is the demonstration that matters.** Load
**Cloned brand template (hard)**. The body is PayPal's genuine password-reset
email, word for word, because that is what a real credential-phishing kit ships:
it copies the brand's template and changes the link and the sending domain.

Point at the member scores, which on this message read roughly:

| Member | Score | What it is seeing |
|---|---|---|
| `charngram` | **0.03** | PayPal's own words. Correctly finds nothing wrong |
| `wordtfidf` | **0.03** | Likewise |
| `rules` | **0.83** | `paypal-secure-mail.com` is not PayPal's domain |
| `engineered` | **0.76** | Brand squat, 41-day-old domain, unknown sender, burst of 34 |
| **fusion** | **0.41 → REVIEW** | The views disagree, so a human decides |

Say the three things this shows. First, a text-only detector is not merely
weaker here — it is *confidently wrong*, at 0.03. Second, the signal that
survives lives in the channels the attacker controls least: the domain they had
to register and the correspondence history they cannot fabricate. Third, the
system does not pretend to certainty it does not have; it routes the message to
an analyst rather than guessing, and the evidence list tells them exactly which
signals disagreed.

If someone asks why the fusion did not simply block it: because 0.41 is an
honest answer. Blocking at that score would mean blocking genuine password
resets from small providers, and the false-positive rate is the number that
decides whether a filter stays switched on.

**4 — A hard negative (1 min).** Load **Legitimate password reset (hard
negative)**. Same vocabulary, opposite verdict. Say: a keyword filter cannot
separate these two, and the false-positive rate is the number that decides
whether a filter stays switched on.

**5 — The adversarial probe (2 min).** Go back to the obvious phish, open the
**Adversarial probe** tab, budget 12, run it. Walk through the trajectory: the
attacker tried homoglyph substitution and redirect chaining, the score moved by
a few hundredths, and the message stayed blocked. Then say what happens to the
text-only baseline under the same attack — it escapes auto-block 55% of the
time against the fusion's 6.7%.

**6 — Human oversight (1 min).** Click **Confirm phishing**, then open
**Decision history**. Show that the audit trail contains a salted subject
digest, a pseudonymised sender and the domain, and no message content at all.

**7 — Operations (1 min).** **Model & monitoring** tab for the score
distribution and the attack taxonomy, then Grafana for the live dashboard.

Have `artifacts/reports/evaluation.md` open in a tab for any question about the
numbers, and be ready to say plainly that the corpus is synthetic, that clean
accuracy on it is an upper bound, and that the comparative results — fusion
against baselines, and the two ablations — are what transfer.

---

**Next:** [§9 Administrator and user guide →](09-admin-user-guide.md)
