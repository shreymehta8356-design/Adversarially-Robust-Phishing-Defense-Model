# Evaluation dossier

Generated: 2026-09-22T08:57:54Z  
Model version: `pg-0e0dffa24f`  
Active defences: D-NORM, D-URL, D-ADVTRAIN, D-ENSEMBLE, D-ABSTAIN, D-VELOCITY

## 1. Verdict

**GO** - 10/10 acceptance gates passed.

| Gate | Criterion | Observed | Threshold | Dir | Pass |
|---|---|---|---|---|---|
| G1 | Detection quality | 0.9880 | 0.9000 | min | True |
| G2 | Ranking quality | 0.9983 | 0.9300 | min | True |
| G3 | False positives | 0.0010 | 0.0200 | max | True |
| G4 | Calibration | 0.0077 | 0.0800 | max | True |
| G5 | Adversarial robustness | 0.0000 | 0.1500 | max | True |
| G6 | Attack success (escapes auto-block) | 0.0000 | 0.3500 | max | True |
| G7 | Inference latency | 17.2280 | 150.0000 | max | True |
| G8 | Beats the manual baseline | 0.0926 | 0.0100 | min | True |
| G9 | Robustness advantage over the text-only baseline | 0.2933 | 0.0000 | min | True |
| G10 | No data leakage | 1.0000 | 1.0000 | min | True |

## 2. Dataset and split

- Train: 6750 messages (43.3% phishing), dataset version `a1c09c445b31`
- Test: 1938 messages (46.4% phishing), dataset version `f67d182863fb`
- Leakage audit: **PASSED**

## 3. Clean performance

- Macro F1: **0.9880**
- PR-AUC: **0.9983**, ROC-AUC: 0.9983
- Recall (phishing): 0.9756, False-positive rate: 0.0010
- Confusion: TN=1037 FP=1 FN=22 TP=878

### The cases that are actually hard

489 messages: cloned brand templates, business email compromise, thread hijacking, and legitimate mail with a phishing-shaped surface.

- Macro F1 **0.9547** (vs 0.9880 over the whole test set)
- Recall 0.9072, FPR 0.0000

### Baselines and ensemble members

| System | Macro F1 | PR-AUC | Recall | FPR |
|---|---|---|---|---|
| B0 rule checklist | 0.8954 | 0.9559 | 0.8411 | 0.0549 |
| B1 TF-IDF + logreg | 0.9771 | 0.9985 | 0.9511 | 0.0000 |
| member: rules | 0.8954 | 0.9559 | 0.8411 | 0.0549 |
| member: engineered | 0.9762 | 0.9980 | 0.9878 | 0.0337 |
| member: charngram | 0.9756 | 0.9986 | 0.9567 | 0.0077 |
| member: wordtfidf | 0.9682 | 0.9958 | 0.9389 | 0.0058 |
| **fusion (deployed)** | 0.9880 | 0.9983 | 0.9756 | 0.0010 |

## 4. PG-HARD - the number that is not inflated by easy mail

Section 3 is dominated by the easy majority of a representative corpus. This section is the counterweight: every record is hard by construction and each case names the detection cue it inverts.

### PG-HARD-1 — curated hard-case benchmark

24 hand-designed cases (12 hard negatives, 12 hard positives), 8 deterministic variants each = **192 records**. Every case inverts a named detection cue; none of this set is easy.

All three systems are tuned to the same false-alarm budget on the ordinary held-out test set (review 0.0039 FPR, block 0.0010 FPR) before being measured here, so the columns are comparable.

#### Headline — the two failures that cost money

| System | Silent delivery | False block | Acceptable outcome | Sent to a human |
|---|---|---|---|---|
| PhishGuard (full tri-modal ensemble) | **0.0%** (0) | **8.3%** (8) | 95.8% | 70.8% |
| Text-only filter (TF-IDF + logistic regression) | **0.0%** (0) | **51.0%** (49) | 74.5% | 4.2% |
| Hand-written rule checklist | **77.1%** (74) | **0.0%** (0) | 61.5% | 4.2% |

On **ordinary** mail the same policy sends 16.1% of messages to a human, blocks 0.00% of legitimate mail and lets 0.22% of phishing through silently (n=1938). The hard-case result above is bought with that review queue; without this line it would be an overclaim, because a system that escalates everything scores perfectly on PG-HARD and is useless in production.

*Silent delivery* = a hard phish the user received with no warning. *False block* = legitimate mail the user never saw. Routing a hard case to human review counts as an acceptable outcome for both labels, because that is what the middle band is for.

#### Where the system is weakest

| Defeated cue | Cases | Records | Pass rate |
|---|---|---|---|
| domain age | 2 | 16 | 50.0% |
| URL reputation | 4 | 32 | 100.0% |
| text content | 4 | 32 | 100.0% |
| sender history | 3 | 24 | 100.0% |
| URL structure | 1 | 8 | 100.0% |
| sender reputation | 1 | 8 | 100.0% |
| behavioural timing | 1 | 8 | 100.0% |
| SMTP authentication | 1 | 8 | 100.0% |
| domain reputation | 1 | 8 | 100.0% |
| URL and attachment features | 1 | 8 | 100.0% |
| human reading | 1 | 8 | 100.0% |
| URL features entirely | 1 | 8 | 100.0% |
| thread and history context | 1 | 8 | 100.0% |
| URL extraction | 1 | 8 | 100.0% |
| behavioural campaign signals | 1 | 8 | 100.0% |

#### Case-by-case

| Case | Label | Defeats | Mean | Worst | Pass |
|---|---|---|---|---|---|
| `HN-REBRAND` Legitimate supplier on a three-week-old domain ⚠ | legit | domain age | 1.000 | 1.000 | 0% |
| `HN-ESP-REDIRECT` Genuine sign-in code behind an ESP click-tracker | legit | URL reputation | 0.702 | 1.000 | 100% |
| `HN-IT-REAUTH` Real IT notice demanding MFA re-enrolment by Friday | legit | text content | 0.993 | 1.000 | 100% |
| `HN-NEW-SUPPLIER` First invoice from a genuine new supplier | legit | sender history | 0.000 | 0.000 | 100% |
| `HN-ESIGN` Genuine e-signature request with a unique token link | legit | URL structure | 0.228 | 0.400 | 100% |
| `HN-RECRUITER` Cold recruiter outreach from a free-mail address | legit | sender reputation | 1.000 | 1.000 | 100% |
| `HN-BANK-NIGHT` Real bank fraud alert received at 03:00 | legit | behavioural timing | 0.345 | 0.400 | 100% |
| `HN-SHORTLINK` Colleague sharing a bit.ly link in a live thread | legit | URL reputation | 0.111 | 0.111 | 100% |
| `HN-NEWSLETTER` Marketing newsletter with deadline pressure | legit | text content | 0.000 | 0.000 | 100% |
| `HN-LIST-DMARC` Mailing-list post that fails SPF, DKIM and DMARC | legit | SMTP authentication | 0.000 | 0.000 | 100% |
| `HN-CONFERENCE` Academic committee invitation from an unknown domain | legit | domain reputation | 0.363 | 0.400 | 100% |
| `HN-REAL-RESET` The genuine password reset the clone copies | legit | text content | 1.000 | 1.000 | 100% |
| `HP-CLONE` Word-perfect brand clone, fully authenticated | phish | text content | 1.000 | 1.000 | 100% |
| `HP-BEC` Business email compromise with no link and no attachment | phish | URL and attachment features | 1.000 | 1.000 | 100% |
| `HP-COMPROMISED` Phish from a genuine internal account, 318 prior messages | phish | sender history | 1.000 | 1.000 | 100% |
| `HP-TRUSTED-HOST` Credential page hosted on a reputable platform | phish | URL reputation | 1.000 | 1.000 | 100% |
| `HP-REDIRECT` Attack laundered through an open redirect on a trusted domain | phish | URL reputation | 0.500 | 0.000 | 100% |
| `HP-AGED` Attack from a six-year-old repurposed domain | phish | domain age | 1.000 | 1.000 | 100% |
| `HP-HOMOGLYPH` Lookalike domain using character substitution | phish | human reading | 1.000 | 1.000 | 100% |
| `HP-CALLBACK` Callback phishing: a phone number instead of a link | phish | URL features entirely | 1.000 | 1.000 | 100% |
| `HP-HIJACK` Reply injected into a real, ongoing thread | phish | thread and history context | 0.056 | 0.000 | 100% |
| `HP-IBAN` Invoice fraud: correct relationship, changed bank details | phish | sender history | 0.442 | 0.400 | 100% |
| `HP-QR` QR-code phishing with no textual URL | phish | URL extraction | 1.000 | 1.000 | 100% |
| `HP-SLOWDRIP` Low-volume spear phish with no urgency cues | phish | behavioural campaign signals | 1.000 | 1.000 | 100% |

### Under attack — hard positives, adaptive attacker

48 hard-positive records attacked at increasing query budgets. Every attacker is graded by the same judge — the deployed decision, calibrated score then abstention — so a message counts as delivered only if the real policy would have delivered it.

| Attacker vs system | budget 0 | budget 10 | budget 40 | budget 120 |
|---|---|---|---|---|
| PhishGuard vs a score-minimising attacker | 0.0% | 0.0% | 0.0% | 0.0% |
| PhishGuard vs an attacker that knows about abstention | 0.0% | 0.0% | 6.2% | 6.2% |
| Text-only filter vs the same attacker | 0.0% | 6.2% | 60.4% | 89.6% |

Cells are the **silent-delivery rate**: the fraction of attacked phishing that reaches the user with no warning.

The attack is not without effect on PhishGuard. At budget 120 the adaptive attacker moves the share of these messages that are *auto-blocked* from 41.7% to 2.1% — the rest are escalated to review rather than delivered. The attack's cost lands on the analyst queue, not on the victim.

Which readers the strongest attack (budget 120) could move:

| Member | Mean score before | After | Drop |
|---|---|---|---|
| `rules` | 0.477 | 0.141 | +0.336 |
| `engineered` | 0.691 | 0.376 | +0.315 |
| `charngram` | 0.821 | 0.758 | +0.064 |
| `wordtfidf` | 0.846 | 0.780 | +0.067 |

Per attack family, budget 40:

| Family | PhishGuard silent delivery | PhishGuard still auto-blocked | Text-only silent delivery |
|---|---|---|---|
| A-LEX Lexical and semantic perturbation | 0.0% | 33.3% | 6.2% |
| A-UNI Unicode and homoglyph obfuscation | 0.0% | 37.5% | 14.6% |
| A-URL URL obfuscation and redirection | 0.0% | 35.4% | 4.2% |
| A-STRUCT Structural and HTML manipulation | 0.0% | 41.7% | 2.1% |
| A-HDR Header and identity shaping | 2.1% | 31.2% | 0.0% |
| A-BEH Behavioral and timing mimicry | 2.1% | 16.7% | 2.1% |
| A-TRUST Payload relocation onto reputable infrastructure | 0.0% | 29.2% | 12.5% |
| A-CHANNEL Out-of-band payload delivery | 0.0% | 33.3% | 0.0% |

#### Honest failures

These cases are not fully handled. They are reported rather than removed, and each names the cue the system is still leaning on.

- **HN-REBRAND** — Legitimate supplier on a three-week-old domain (pass 0%, worst score 1.000); defeats *domain age*.

#### Seed sensitivity

Same data, same configuration, different training seed. The seed decides which campaigns fall in each training pool, which messages are adversarially augmented, and where the members' optimisers stop. 3 runs:

| Run | PG-HARD phish delivered unwarned | PG-HARD legitimate blocked | PG-HARD review load | Ordinary phish unwarned | Ordinary review load |
|---|---|---|---|---|---|
| evaluated model | 0 / 96 | 8 / 96 (HN-REBRAND ×8) | 70.8% | 0.22% | 16.1% |
| retrained, seed 101 | 1 / 96 (HP-HIJACK ×1) | 0 / 96 | 71.4% | 0.44% | 14.7% |
| retrained, seed 202 | 0 / 96 | 0 / 96 | 80.2% | 0.44% | 16.5% |

Across the 3 runs, 0–1 hard phishing records were delivered with no warning and 0–8 hard legitimate records were blocked. Every silent delivery came from HP-HIJACK (in 1 of 3 runs). Every false block came from HN-REBRAND (in 1 of 3 runs). Quote the range, not the evaluated model's single value.

## 5. Calibration

- Method: isotonic
- ECE: 0.00771 (uncalibrated: 0.00929), MCE: 0.00191
- Isotonic calibration on a well-separated calibration pool approaches a step function, so a near-zero ECE here reflects strong separation rather than a difficult calibration problem being solved.

## 6. Operational decision bands

- ALLOW 928 / REVIEW 312 / BLOCK 698 (16.1% routed to a human)
- Auto-decided macro F1: 0.9988, auto FPR: 0.0000
- Phishing auto-allowed (missed): **2**; legitimate auto-blocked: **0**

### Operating point — an expected-cost justification

Costs are in units of **one analyst review**. Assumed, illustratively — an organisation substitutes its own: a phish delivered with no warning costs **200** reviews, a wrongly quarantined legitimate message **10**; analysts miss 5% of the phishing they review. Traffic: 2.0% of inbound mail is phishing; 10% of phishing and 10% of legitimate mail behaves like PG-HARD. Class behaviour is measured on the test data and re-weighted to that prevalence.

| Policy | Review ≥ | Block ≥ | Abstain at spread ≥ | Cost / 1,000 | Sent to a human / 1,000 |
|---|---|---|---|---|---|
| **Deployed** | 0.40 | 0.80 | 0.45 (symmetric) | **341.0** | 182.0 |
| Cost-optimal under these assumptions | 0.15 | 0.45 | 0.55 (symmetric) | **307.5** | 138.6 |
| Cost-optimal, abstention disabled | 0.25 | 0.45 | off | **485.5** | 22.3 |
| Text-only filter, cost-optimal | 0.25 | 0.95 | off | **206.2** | 111.5 |

**What the two policies trade.** The deployed policy is the safety-first end of the frontier: 0.040 silently delivered phish per 1,000 messages, at the price of sending 182 in every 1,000 to a human. The cost-optimal policy cuts that review load to 139 per 1,000 and accepts 0.164 silent deliveries per 1,000 in exchange. Neither is 'correct': the choice depends on what a missed phish costs *this* organisation, which is why the next table exists.

#### Candidate defaults, priced and attacked

Three candidate defaults, priced on benign traffic and then attacked. *Worst-case regret* is how much more a policy costs than the best possible policy, for whichever of four organisation profiles it fares worst on. *Under attack* is the share of hard phishing the adaptive attacker gets delivered with no warning.

| Candidate | Review / block / abstain | Cost / 1,000 | Worst-case regret / 1,000 | Delivered under attack (worst budget) |
|---|---|---|---|---|
| Deployed default | 0.40 / 0.80 / 0.45 (symmetric) | 341.0 | 3306.6 | **6.2%** (3 of 48) |
| Minimax-regret choice | 0.40 / 0.40 / 0.25 (symmetric) | 370.4 | 62.9 | **0.0%** (0 of 48) |
| Cost-optimal at the stated assumptions | 0.15 / 0.45 / 0.55 (symmetric) | 307.5 | — | **12.5%** (6 of 48) |

**The finding.** The cost-optimal policy is cheaper on benign traffic partly because it leaves an attacker room: it delivers 12% of hard phishing under the adaptive attack (6 of 48 against 3 for the deployed default). The minimax-regret choice delivers less under attack (0 of 48 against 3 for the deployed default), so on this run it is the stronger policy. Most of the gap in worst-case regret is false blocks: at the stated share of hard traffic the deployed default quarantines 8.2 legitimate messages per 1,000 against 0.0 for the minimax-regret choice, and the Regulated, zero tolerance profile prices each at 500 reviews. Because every PG-HARD case stands for a slice of real traffic, one case that is blocked in all its variants moves this figure on its own (section 4 names it). The default is **not** re-tuned from this table: the candidates are chosen on the same test mail and PG-HARD records they are scored on, so adopting one here would tune the policy to the benchmark. The way to move it is `phishguard cost --attack` on an organisation's own traffic. The deployed default's price on benign traffic is stated either way: a worst-case regret of 3307 cost units per 1,000 messages across the four profiles below.

Profiles used for the regret calculation (illustrative):

- **Lean IT team** — missed phish 200, false block 10 reviews
- **Finance / legal - invoices matter** — missed phish 500, false block 200 reviews
- **Staffed SOC, high stakes** — missed phish 2000, false block 100 reviews
- **Regulated, zero tolerance** — missed phish 5000, false block 500 reviews

#### Which policy for which organisation

| If a missed phish costs … reviews | Review ≥ | Block ≥ | Abstain | Cost / 1,000 | Sent to a human / 1,000 |
|---|---|---|---|---|---|
| 20 | 0.45 | 0.45 | 0.60 (symmetric) | 220.8 | 116.9 |
| 50 | 0.45 | 0.45 | 0.60 (symmetric) | 237.3 | 116.9 |
| 100 | 0.20 | 0.45 | 0.60 (symmetric) | 263.1 | 124.1 |
| 200 | 0.15 | 0.45 | 0.55 (symmetric) | 307.5 | 138.6 |
| 500 | 0.15 | 0.15 | 0.50 (symmetric) | 408.8 | 164.0 |
| 1000 | 0.10 | 0.15 | 0.50 (symmetric) | 544.1 | 187.8 |
| 5000 | 0.15 | 0.45 | 0.30 (escalate) | 814.0 | 199.0 |

**Where abstention earns its place.** On ordinary mail alone the cost-optimal policy disables abstention — on easy mail, escalation is mostly cost. It pays for itself once **2.8%** of traffic (in both classes) is hard.

Under these assumptions the text-only filter, at its own cost-optimal policy, is **cheaper** on benign traffic, by 101.3 cost units per 1,000 messages. That price leaves out the attacker: under the adaptive attack the text-only filter delivers 90% of hard phishing unwarned at budget 120 (section 4).

#### Sensitivity

| Miss cost | Hard share | Optimal review / block / abstain | Optimal cost | Deployed cost | Abstention pays? |
|---|---|---|---|---|---|
| 20 | 0% | 0.45 / 0.45 / 0.60 | 216.3 | 286.0 | yes |
| 20 | 2% | 0.45 / 0.45 / 0.60 | 217.2 | 286.2 | yes |
| 20 | 5% | 0.45 / 0.45 / 0.60 | 218.6 | 286.6 | yes |
| 20 | 10% | 0.45 / 0.45 / 0.60 | 220.8 | 287.3 | yes |
| 20 | 25% | 0.45 / 0.45 / 0.60 | 227.6 | 289.4 | yes |
| 50 | 0% | 0.45 / 0.45 / 0.60 | 226.5 | 294.0 | yes |
| 50 | 2% | 0.45 / 0.45 / 0.60 | 228.6 | 294.4 | yes |
| 50 | 5% | 0.45 / 0.45 / 0.60 | 231.9 | 295.1 | yes |
| 50 | 10% | 0.45 / 0.45 / 0.60 | 237.3 | 296.3 | yes |
| 50 | 25% | 0.45 / 0.45 / 0.60 | 253.5 | 299.7 | yes |
| 100 | 0% | 0.20 / 0.45 / 0.60 | 243.0 | 307.3 | yes |
| 100 | 2% | 0.20 / 0.45 / 0.60 | 247.0 | 308.1 | yes |
| 100 | 5% | 0.20 / 0.45 / 0.60 | 253.0 | 309.2 | yes |
| 100 | 10% | 0.20 / 0.45 / 0.60 | 263.1 | 311.2 | yes |
| 100 | 25% | 0.15 / 0.45 / 0.55 | 289.7 | 317.0 | yes |
| 200 | 0% | 0.20 / 0.45 / 0.60 | 268.5 | 334.0 | yes |
| 200 | 2% | 0.20 / 0.45 / 0.60 | 276.5 | 335.4 | yes |
| 200 | 5% | 0.20 / 0.45 / 0.60 | 288.5 | 337.5 | yes |
| 200 | 10% | 0.15 / 0.45 / 0.55 | 307.5 | 341.0 | yes |
| 200 | 25% | 0.15 / 0.15 / 0.50 | 330.9 | 351.6 | yes |
| 500 | 0% | 0.20 / 0.45 / 0.60 | 345.2 | 414.0 | yes |
| 500 | 2% | 0.20 / 0.45 / 0.60 | 365.0 | 417.3 | yes |
| 500 | 5% | 0.15 / 0.45 / 0.55 | 387.4 | 422.2 | yes |
| 500 | 10% | 0.15 / 0.15 / 0.50 | 408.8 | 430.5 | yes |
| 500 | 25% | 0.15 / 0.15 / 0.50 | 433.1 | 455.4 | yes |
| 1000 | 0% | 0.25 / 0.45 / 0.80 | 453.4 | 547.3 | yes |
| 1000 | 2% | 0.10 / 0.45 / 0.55 | 490.4 | 553.8 | yes |
| 1000 | 5% | 0.10 / 0.15 / 0.50 | 526.2 | 563.5 | yes |
| 1000 | 10% | 0.10 / 0.15 / 0.50 | 544.1 | 579.7 | yes |
| 1000 | 25% | 0.10 / 0.15 / 0.50 | 598.0 | 628.3 | yes |

### Drift monitoring

10 simulated weeks of 400 messages at 2% phishing; from week 6, a quarter of traffic is PG-HARD-style mail the model was not trained on. Reference: captured at training from the legitimate mail of the stacking and calibration pools (whole campaigns the members never fitted on). Alarm thresholds are calibrated from campaign-structured stable windows (moderate ≥ 0.358, significant ≥ 0.533 worst-quantity PSI), because the textbook 0.10 / 0.25 assume independent samples and mail arrives in campaigns. *Moderate* is the 95th percentile of stable windows, so about one stable week in twenty is expected to reach it; *significant* is the 99th.

| Week | Traffic | Worst PSI | Quantity | Status |
|---|---|---|---|---|
| 1 | stable | 0.148 | member:wordtfidf | **stable** |
| 2 | stable | 0.186 | member:charngram | **stable** |
| 3 | stable | 0.264 | member:charngram | **stable** |
| 4 | stable | 0.298 | member:wordtfidf | **stable** |
| 5 | stable | 0.324 | member:charngram | **stable** |
| 6 | shifted | 0.495 | member:engineered | **moderate** |
| 7 | shifted | 0.521 | member:wordtfidf | **moderate** |
| 8 | shifted | 0.612 | member:wordtfidf | **significant** |
| 9 | shifted | 0.532 | member:charngram | **moderate** |
| 10 | shifted | 0.486 | member:engineered | **moderate** |

## 7. Latency

- p50 11.90 ms, p95 **17.23 ms**, p99 21.51 ms (single message, with explanation)
- Without explanation: p95 10.22 ms

### Load and resource measurements

Mode: **in-process**, explanations on; 2 CPU cores; peak memory 254.0 MB.

| Concurrent requests | Throughput / s | p50 ms | p95 ms | p99 ms | Errors |
|---|---|---|---|---|---|
| 1 | 70.2 | 13.7 | 19.0 | 19.8 | 0 |
| 4 | 67.1 | 58.3 | 70.6 | 91.2 | 0 |
| 8 | 70.3 | 111.7 | 150.7 | 154.5 | 0 |

Peak throughput **70.3 messages/s** at 8 concurrent requests; p95 stays within the 150 ms budget up to **4 concurrent requests**; 0 errors across all levels. ScanService called directly from a thread pool: the full decision path including the audit write and the review queue, without the web framework. Scoring is CPU-bound, so one process serves requests one at a time in order of arrival (PG_SCORING_CONCURRENCY=1): extra concurrency lengthens the wait, not the work. More throughput comes from more processes ('phishguard serve --workers N'), up to the number of cores.

## 8. Adversarial robustness

Success is measured against the *deployed* policy, not against a 0.5 cut-off: a message the attacker drags below the block threshold (0.8) escapes auto-quarantine, and one below the review threshold reaches the inbox with no human review. Both are reported.

- Attack budget: 10 queries with restarts; 150 phishing messages attacked
- **Escaped auto-block: 0.000** (raw-score surface, an upper bound on real attacker success)
- **Delivered with no human review: 0.000**
- Calibrated surface (what the API actually exposes): 0.000
- Mean score after attack: 0.9958 (mean drop 0.0033, max 0.0589)
- Macro F1: 0.9880 clean -> 0.9948 adversarial (**drop 0.0000**)
- Recall: 0.9756 -> 0.9933

### What the decision policy does under attack

| Traffic | ALLOW | REVIEW | BLOCK | Phishing allowed | Legitimate blocked |
|---|---|---|---|---|---|
| clean | 928 | 312 | 698 | 2 | 0 |
| under attack | 928 | 323 | 687 | 2 | 0 |

Movement from BLOCK into REVIEW is where an attacker's effort shows up first: the message is no longer auto-quarantined, and the cost lands on the analyst queue rather than on the recipient.

### Comparison with the conventional text-only model

| System | Clean F1 | Adversarial F1 | Drop | Escaped block | Silent delivery |
|---|---|---|---|---|---|
| B1 TF-IDF + logreg | 0.9771 | 0.9766 | 0.0005 | 0.2933 | 0.0000 |
| Fusion (this project) | 0.9880 | 0.9948 | 0.0000 | 0.0000 | 0.0000 |

### Attack family effectiveness

| ID | Family | Escaped block | Silent delivery | Mean drop | Attacker cost |
|---|---|---|---|---|---|
| A-LEX | Lexical and semantic perturbation | 0.0000 | 0.0000 | 0.0008 | Low |
| A-UNI | Unicode and homoglyph obfuscation | 0.0000 | 0.0000 | 0.0009 | Low |
| A-URL | URL obfuscation and redirection | 0.0000 | 0.0000 | 0.0019 | Low to medium |
| A-STRUCT | Structural and HTML manipulation | 0.0000 | 0.0000 | 0.0001 | Low |
| A-HDR | Header and identity shaping | 0.0000 | 0.0000 | 0.0001 | Medium |
| A-BEH | Behavioral and timing mimicry | 0.0000 | 0.0000 | 0.0014 | High - low-and-slow sending cuts campaign reach |
| A-TRUST | Payload relocation onto reputable infrastructure | 0.0000 | 0.0000 | 0.0001 | Medium - accounts are cheap, takedowns are fast |
| A-CHANNEL | Out-of-band payload delivery | 0.0000 | 0.0000 | 0.0002 | High - callback fraud needs live operators |

### Residual-risk register

| ID | Attack family | ASR | Likelihood | Impact | Residual | Controls |
|---|---|---|---|---|---|---|
| A-LEX | Lexical and semantic perturbation | 0.0000 | Very low | High | Low | D-NORM, D-ADVTRAIN, D-ENSEMBLE, D-ABSTAIN |
| A-UNI | Unicode and homoglyph obfuscation | 0.0000 | Very low | High | Low | D-NORM, D-ADVTRAIN |
| A-URL | URL obfuscation and redirection | 0.0000 | Very low | High | Low | D-URL, D-ADVTRAIN, D-ENSEMBLE |
| A-STRUCT | Structural and HTML manipulation | 0.0000 | Very low | High | Low | D-NORM, D-ENSEMBLE, D-ADVTRAIN |
| A-HDR | Header and identity shaping | 0.0000 | Very low | Medium | Very low | D-ENSEMBLE, D-ABSTAIN |
| A-BEH | Behavioral and timing mimicry | 0.0000 | Very low | Medium | Very low | D-VELOCITY, D-ENSEMBLE, D-ABSTAIN |
| A-TRUST | Payload relocation onto reputable infrastructure | 0.0000 | Very low | Medium | Very low | D-URL, D-ENSEMBLE, D-ABSTAIN |
| A-CHANNEL | Out-of-band payload delivery | 0.0000 | Very low | Medium | Very low | D-ENSEMBLE, D-ABSTAIN, D-VELOCITY |

## 9. Modality ablation

What each feature family contributes, holding the model fixed.

| Families | Features | Macro F1 | PR-AUC | vs full |
|---|---|---|---|---|
| email | 125 | 0.9845 | 0.9995 | -0.0021 |
| url | 107 | 0.9408 | 0.9890 | -0.0457 |
| behavioral | 33 | 0.9343 | 0.9872 | -0.0522 |
| email + url | 232 | 0.9845 | 0.9996 | -0.0021 |
| email + behavioral | 158 | 0.9839 | 0.9993 | -0.0026 |
| url + behavioral | 140 | 0.9860 | 0.9993 | -0.0005 |
| email + url + behavioral | 265 | 0.9865 | 0.9996 | 0.0000 |

## 10. Defence ablation

Each arm is retrained from scratch with one control disabled.

| Arm | Clean F1 | Adv F1 | Drop | ASR | ASR vs full |
|---|---|---|---|---|---|
| all defences | 0.9880 | 0.9948 | 0.0000 | 0.0000 | 0.0000 |
| without D-NORM | 0.9886 | 0.9953 | 0.0000 | 0.0000 | 0.0000 |
| without D-URL | 0.9912 | 0.9943 | 0.0000 | 0.0000 | 0.0000 |
| without D-ADVTRAIN | 0.9943 | 0.9948 | 0.0000 | 0.0000 | 0.0000 |
| without D-ENSEMBLE | 0.9783 | 0.9689 | 0.0094 | 0.1000 | 0.1000 |
| without D-ABSTAIN | 0.9880 | 0.9948 | 0.0000 | 0.0000 | 0.0000 |
| without D-VELOCITY | 0.9880 | 0.9948 | 0.0000 | 0.0000 | 0.0000 |
| no defences | 0.9736 | 0.9679 | 0.0057 | 0.0917 | 0.0917 |

## 11. Error analysis

23 errors (1.19% of the test set).

| Failure mode | Count |
|---|---|
| missed: cloned legitimate template, signal is header/URL only | 19 |
| missed: thread hijack inside an existing conversation | 2 |
| missed: business email compromise, no link and no lexical tells | 1 |
| false alarm: unknown but legitimate sender | 1 |

Most confident mistakes:

| Lure | True | Score | Sender domain | Subject |
|---|---|---|---|---|
| legit_rebrand | 0 | 1.0000 | bluestudio.biz | Bluestudio is now part of a new group |
| clone | 1 | 0.0000 | ttk-legal.nl | Shipment AMJ-759873 is out for delivery |
| thread_hijack | 1 | 0.0000 | harbourline-freight.example | Re: Re: next week's sprint planning |
| clone | 1 | 0.1111 | id-ww6ifb.icu | New sign-in to your Microsoft 365 account |
| clone | 1 | 0.1111 | ttk-legal.nl | Your parcel 28X9DDEUAM arrives today |
| clone | 1 | 0.1111 | ttk-legal.nl | Shipment 728603 is out for delivery |
| thread_hijack | 1 | 0.2443 | kestrel-logistics.example | Re: Re: Thursday's safety walkthrough |
| clone | 1 | 0.4000 | google.verify-gu4x5.icu | Shipment SGC-853282 is out for delivery |

## 12. Subgroup slices

### Lure Type

| Slice | n | Macro F1 | Recall | FPR | Errors |
|---|---|---|---|---|---|
| clone | 209 | 0.4762 | 0.9091 | 0.0000 | 19 |
| legit_rebrand | 14 | 0.4815 | 0.0000 | 0.0714 | 1 |
| doc_share_ok | 253 | 0.5000 | 0.0000 | 0.0000 | 0 |
| code_review | 194 | 0.5000 | 0.0000 | 0.0000 | 0 |
| credential | 122 | 0.5000 | 1.0000 | 0.0000 | 0 |
| package | 97 | 0.5000 | 1.0000 | 0.0000 | 0 |
| newsletter | 87 | 0.5000 | 0.0000 | 0.0000 | 0 |
| receipt | 85 | 0.5000 | 0.0000 | 0.0000 | 0 |
| real_password_reset | 82 | 0.5000 | 0.0000 | 0.0000 | 0 |
| suspicious_ham | 70 | 0.5000 | 0.0000 | 0.0000 | 0 |
| storage_full | 68 | 0.5000 | 1.0000 | 0.0000 | 0 |
| legit_list_mail | 63 | 0.5000 | 0.0000 | 0.0000 | 0 |

### Links

| Slice | n | Macro F1 | Recall | FPR | Errors |
|---|---|---|---|---|---|
| with links | 1845 | 0.9880 | 0.9757 | 0.0010 | 22 |
| no links | 93 | 0.9885 | 0.9714 | 0.0000 | 1 |

### Behavioural Context

| Slice | n | Macro F1 | Recall | FPR | Errors |
|---|---|---|---|---|---|
| behavioural context | 1938 | 0.9880 | 0.9756 | 0.0010 | 23 |

### Body Length

| Slice | n | Macro F1 | Recall | FPR | Errors |
|---|---|---|---|---|---|
| short (<250) | 889 | 0.9715 | 0.9141 | 0.0000 | 17 |
| medium (250-800) | 1049 | 0.9936 | 0.9929 | 0.0029 | 6 |

### Html

| Slice | n | Macro F1 | Recall | FPR | Errors |
|---|---|---|---|---|---|
| text only | 1584 | 0.9848 | 0.9652 | 0.0010 | 23 |
| html part | 354 | 1.0000 | 1.0000 | 0.0000 | 0 |

### Attachments

| Slice | n | Macro F1 | Recall | FPR | Errors |
|---|---|---|---|---|---|
| with attachment | 171 | 0.9812 | 0.9936 | 0.0000 | 1 |
| no attachment | 1767 | 0.9872 | 0.9717 | 0.0010 | 22 |

### Authentication

| Slice | n | Macro F1 | Recall | FPR | Errors |
|---|---|---|---|---|---|
| auth imperfect | 823 | 0.9793 | 0.9764 | 0.0000 | 14 |
| auth all pass | 1115 | 0.9898 | 0.9739 | 0.0012 | 9 |

## 13. Limitations

1. **The corpus is synthetic.** It is generated to be campaign-structured,
   difficulty-balanced and leakage-audited, and no single feature separates the
   classes by more than ~0.84 AUC. It is nevertheless a model of phishing, not
   a sample of it. Clean metrics on it should be read as an upper bound; the
   comparative results (fusion vs baselines, defence ablation, modality
   ablation) transfer more reliably than the absolute numbers.
2. **Robustness is measured against this attack suite.** 35 transforms
   across 8 families, composed under a query budget, is a serious test but
   not an exhaustive one. A genuinely novel attack family is by definition not
   represented, and the residual-risk register records that.
3. **The threat model excludes domain compromise.** Mail genuinely originating
   from a compromised brand or partner domain passes every header and
   reputation check by construction; it is an authentication problem, not a
   content-classification one. See `OOS-1` in the taxonomy.
4. **Behavioural features assume a mail gateway.** Correspondence history,
   campaign burstiness and domain age come from the deployment environment. In
   their absence the system degrades to email and URL evidence and records that
   it did so, but the ablation shows what that costs.
5. **No URL is resolved and no attachment is opened.** This is deliberate -
   fetching attacker-controlled content from the gateway would create an SSRF
   surface and leak victim telemetry - but it means a benign-looking URL
   serving a malicious page is invisible to this layer.
6. **Calibration is measured on the same distribution as training.** Under
   genuine distribution shift the probabilities will drift, which is why the
   monitoring endpoint tracks score distribution over time rather than assuming
   calibration holds.
