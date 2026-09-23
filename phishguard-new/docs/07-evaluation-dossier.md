# 7. Evaluation dossier

What was measured, what the numbers mean, and — the part that matters more —
what they do not show.

The machine-generated tables live in
[`artifacts/reports/evaluation.md`](../artifacts/reports/evaluation.md), and
every figure in both documents comes from
[`artifacts/reports/evaluation.json`](../artifacts/reports/evaluation.json),
except the load measurements in §7.14, which come from
`artifacts/reports/loadtest.json` and `loadtest-processes.json`.
This document does not restate those tables for their own sake. It interprets
them: which result carries the project's claim, which result is an artefact of
the corpus, and which of the six defensive controls the evidence actually
supports.

The whole dossier interprets one run: the evaluation generated at
**2026-09-22T08:57:54Z** against model **`pg-0e0dffa24f`**. Where it mentions
the first complete run, of 7 September, it says so; §7.0 records what changed
between the two and why.

---

## 7.0 The current run (22 September 2026)

Model **`pg-0e0dffa24f`**, trained 2026-09-22T08:49:03Z on a 9 000-message
synthetic corpus with a campaign-grouped split (6 750 train / 1 938 test).
**GO — 10 of 10 acceptance gates.** Every number below is in
`artifacts/reports/evaluation.json`, and every figure in
`artifacts/reports/figures/` is drawn from it.

### What changed since 7 September, and why

| Change | Why | Effect on the numbers |
|---|---|---|
| A harder synthetic generator | The 7 September corpus was separable enough that the test set had one error in 1 937, which is not a measurement | Clean macro F1 falls from 0.9995 on 7 September to **0.9880** at a 0.5 cut-off; 23 errors, 19 of them cloned brand templates |
| **PG-HARD**, a 192-record hard-case benchmark | The ordinary test set is mostly easy mail | Now the primary result (below) |
| Disagreement-based abstention (D-ABSTAIN) and an adaptive attacker | An attacker who knows about abstention targets it | Robustness is reported against both attackers; the REVIEW band now holds 16.1% of ordinary test mail, most of it routed there by abstention (§7.8) |
| Training pools drawn **by campaign** | Row-level pools leaked near-identical siblings from the fitting pool into calibration, so the calibration pool looked perfectly separated | Honest calibration pool; the drift monitor's reference is whole campaigns |
| Seed sensitivity | 7.12 lists "single run, no confidence intervals" as a threat | Every evaluation now retrains with two further seeds and reports the range |
| Expected-cost model | 7.13 item 5 asks for a cost model for the REVIEW band | The operating point is priced, and the cheaper policies are attacked |
| Drift monitoring | 7.12: "calibration is measured on the training distribution" | A calibrated alarm on live traffic, from the audit trail alone |
| A defect in the attack suite, fixed in 1.3.0 | A second function named `t_open_redirect` replaced the first, so transform A-URL-02 ("open-redirect chaining") silently ran A-TRUST-02's code, and the query-string redirect was neither tested nor trained against. Found by static analysis (ruff F811) | All robustness figures in this dossier use the corrected suite, so they are not strictly comparable with 7 September's |
| Scoring runs one request at a time per process, in arrival order (1.3.0) | Concurrent requests took turns on the interpreter lock and paid for every switch; the load test found it (§7.14) | At eight concurrent requests: 70.0 messages/s and p95 133.7 ms in the CLI load test, but 150.7 ms in the evaluation's own load run — right at the 150 ms budget (§7.14) |

### Headline results

| | Value |
|---|---|
| Clean macro F1 / PR-AUC (0.5 cut-off) | 0.9880 / 0.9983 |
| Deployed policy on ordinary test mail | 16.1% to a human; 2 of 900 phishing delivered unwarned; 0 legitimate blocked |
| PG-HARD, PhishGuard | 0 of 96 hard phish delivered unwarned; 8 of 96 hard legitimate blocked (all HN-REBRAND); 95.8% acceptable; 70.8% sent to a human |
| PG-HARD, text-only filter | 0 delivered unwarned; 49 blocked; 74.5% acceptable |
| PG-HARD, rule checklist | 74 delivered unwarned; 0 blocked; 61.5% acceptable |
| PG-HARD across three training seeds | **0–1** delivered unwarned (HP-HIJACK), **0–8** blocked (HN-REBRAND) |
| Adaptive attack on 48 hard phish, 40 / 120 queries | PhishGuard 6.2% (3) / 6.2% (3); text-only 60.4% (29) / 89.6% (43) |
| Ordinary phish under attack (10 queries, 150 messages) | escapes auto-block: PhishGuard 0.000, text-only 0.293; silent delivery 0.000 for both |
| Drift demonstration | 0 of 5 stable weeks flagged; 5 of 5 shifted weeks flagged, 1 at the significant level |
| Latency, single message with explanation | p95 17.2 ms |
| Load, one process, 1–8 concurrent requests | 68.7–78.6 messages/s, 0 errors; p95 at 8: 133.7 ms in the CLI load test, 150.7 ms in the evaluation's own (§7.14) |

### Which earlier conclusions changed

- **"One error in 1 937"**, the 7 September result, no longer applies: that
  was the old generator. The error analysis now has 23 cases to work with (22
  missed phishing messages and one false alarm at a 0.5 cut-off), and it says
  the same thing more convincingly — 19 of the 22 misses are cloned templates
  whose only signal is the header and the URL (§7.10).
- **"Single run, no confidence intervals"** (7.12) is now partly answered. The
  seed-sensitivity table shows why it mattered: on PG-HARD a single borderline
  case (HP-HIJACK or HN-REBRAND) tips with the seed, so the result is quoted as
  a range. Corpus and split seeds are still fixed.
- **The robustness claim is weaker, and more honest.** Against an attacker who
  targets the abstention control, PhishGuard is no longer at 0%: it lets 3 of
  48 hard phishing records through at 40 queries, and 3 at 120. The text-only
  filter lets 29 and 43 through. The gap is the claim; "zero" was never a claim
  a finite benchmark could support. On ordinary phishing at 10 queries neither
  system delivers anything silently, so the ordinary set no longer
  discriminates between them on that measure (§7.4).
- **The defence ablation no longer singles out adversarial training.** On
  7 September removing D-ADVTRAIN tripled attack success. At this run's budget
  only removing D-ENSEMBLE, or every control at once, lets any attack through;
  the other single-control removals do not register (§7.6).
- **The behavioural family no longer costs clean accuracy.** On 7 September
  email + url beat all three families by 0.001 macro F1; on this run all three
  together are the best combination, by one message (§7.5). Neither gap is big
  enough to argue from.
- **The REVIEW band is a real workload.** On 7 September it held 0.1% of test
  mail; it now holds 16.1%, which is why the cost model prices analyst time
  (§7.8).
- **The cost model does not endorse re-tuning the default.** On this run the
  minimax-regret policy delivers none of the 48 attacked hard phishing records,
  against 3 for the default, but costs more on benign traffic (370.4 against
  341.0 cost units per 1 000 messages); the cost-optimal policy is cheaper
  (307.5) and delivers 6 of 48 (12.5%). The default is kept, and the reason is
  stated in the dossier: candidates chosen on the evaluation data cannot be
  adopted on the strength of the same data.

---

## 7.1 How to reproduce

Three commands from a clean checkout. `evaluate` writes both report files and
exits non-zero if any blocking acceptance gate fails, which is what makes it
usable in CI rather than only in a viva.

```bash
phishguard data     --n 9000                                   # build + audit the corpus
phishguard train    --n 9000 --save                            # train and register
phishguard evaluate --n 9000 --budget 10 --max-attacked 150 \
                    --defense-ablation                         # the dossier
```

The settings in force for this run. Corpus size, attack budget and the number
of attacked messages are passed on the command line above; everything else is a
default:

| Setting | Value | Where it comes from |
|---|---|---|
| Corpus | `synthetic(n=9000, seed=20260907)` | `--n`, `--seed` |
| Phishing ratio | 0.42 | `--phish-ratio` |
| Split | grouped, `--test-size 0.25`, `--split-seed 11` | `--split grouped` |
| Attack | budget 10 queries; 150 phishing messages attacked, of which the defence ablation attacks the first 120 | `--budget`, `--max-attacked` |
| Attack seed | 7 | `PG_ATTACK_SEED` |
| Review / block thresholds | 0.40 / 0.80 | `PG_REVIEW_THRESHOLD`, `PG_BLOCK_THRESHOLD` |
| Random seed | 20260907 | `PG_RANDOM_SEED` |
| Seed-sensitivity retrains | two further training seeds, 101 and 202 | `--seed-runs` |
| PG-HARD | 192 records (24 cases × 8 variants), seed 20260912 | the benchmark definition |

Equivalent `make` targets: `make ablation N=9000` runs the same evaluation,
except that it leaves `--max-attacked` at its default and so attacks more
messages than this run did; `make deliverables N=9000` adds the tests,
training, the model card and the OpenAPI document. The adversarial suite can
also be run on its own against whatever model is currently registered; pass the
budget explicitly so that the result is comparable with this dossier:

```bash
phishguard attack --budget 10 --sweep
```

Two caveats about reproduction. The defence ablation retrains eight models and
attacks each one, and it is the most expensive part of the evaluation; this
whole run, ablation included, took 1 115.4 seconds (about 19 minutes) on the
evaluation host. And the numbers reproduce exactly only with the same seeds:
change `--seed`, `--split-seed` or `PG_ATTACK_SEED` and the third decimal place
will move. That is a property of the measurement, not a defect. The
seed-sensitivity table (§7.12) retrains with two further training seeds and
reports the range, but it varies only the training seed: the corpus and the
split are the same in all three runs and none of them repeats the attack, so
the variation from the other three seeds is not measured.

## 7.2 Experimental design

### The corpus

9 000 generated messages, of which 8 688 survive near-duplicate scrubbing:
**6 750 train** (43.29% phishing) and **1 938 test** (46.44% phishing). The
generator produces campaign-structured mail across many lure types — phishing
ones such as `clone`, `bank`, `crypto`, `invoice_fraud`, `sextortion`,
`callback_phish` and `trusted_host`, and legitimate ones such as `receipt`,
`newsletter`, `code_review`, `real_password_reset`, `suspicious_ham` and
`legit_rebrand`. Thirty lure types are large enough in this test split to get
their own row in the slice table (§7.11). The
rationale for a synthetic corpus, and its cost, is [ADR-002](adr/002-synthetic-corpus.md);
the honest reading of what it can and cannot support is §7.12.

### Campaign-grouped splitting

Messages are grouped by campaign — 1 256 groups, 284 of them held out — and the
split is at group level, not message level. A random message-level split would
put near-identical siblings of the same campaign on both sides of the
partition, and the resulting test score would measure template memorisation.
Grouping guards against that.

Near-duplicate scrubbing runs afterwards, dropping test messages whose
similarity to any training message exceeds `PG_NEAR_DUPLICATE_THRESHOLD` (0.85).
Grouping catches campaign siblings; scrubbing catches accidental collisions
between campaigns that grouping cannot see.

### The leakage audit, which must pass before training

`phishguard train` refuses to run if the audit fails, and the failure has to be
overridden explicitly with `--allow-leakage`. Four checks, all clean on this
run:

| Check | Result |
|---|---|
| Exact duplicate pairs across the split | 0 |
| Near-duplicate pairs across the split | 0 |
| Group overlap between train and test | 0 |
| Single features separating the classes suspiciously well | none flagged |

The fourth check is the interesting one. A single feature with a very high
solo AUC usually means the generator has leaked a label into the surface — a
tell that would make every other number in this report meaningless. The
generator is built so that no single feature separates the classes by more than
about 0.84 AUC, and the audit flags none of the 265 as separating them almost
perfectly on its own, which is what licenses the claim that the fusion is doing
work rather than reading a giveaway.

Gate **G10** encodes this: leakage failing is a build failure, not a footnote.

### Three disjoint training pools

*(Since 1.2.0 the pools are drawn by whole campaign rather than by row — see
7.0.)*

The 6 750 training messages are split again, and nothing sees the same rows
twice:

| Pool | Size | Share | Fits |
|---|---|---|---|
| `fit` | 4 025 | 60% | the four ensemble members |
| `stack` | 1 492 | 22% | the logistic fusion over member scores |
| `cal` | 1 233 | 18% | the isotonic calibrator over fusion output |

D-ADVTRAIN augments the `fit` pool only, adding **1 747** adversarially
perturbed copies of phishing messages.

Each boundary guards against a specific and well-known failure. Fitting the
fusion on member scores produced *in sample* gives a stacker excellent
apparent weights for a regime it will never encounter again — the members are
near-perfect on their own training rows, so the fusion learns from a
distribution that does not exist at inference time. The calibrator needs a
third pool for the same reason one step later: it must see fusion outputs it
did not itself shape. The learned fusion weights (`charngram` 5.04,
`wordtfidf` 4.37, `engineered` 4.06, `rules` 2.22, intercept −6.71) are only
meaningful because they were fitted out of sample.

## 7.3 Headline results

The deployed fusion on the held-out test set, at a 0.5 cut-off, n = 1 938:

| Metric | Value |
|---|---|
| Macro F1 | **0.98805** |
| PR-AUC | 0.99826 |
| ROC-AUC | 0.99833 |
| Recall (phishing) | 0.97556 |
| Precision (phishing) | 0.99886 |
| False-positive rate | 0.00096 |
| False-negative rate | 0.02444 |
| Accuracy | 0.98813 |

Confusion matrix:

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Actually legitimate** | TN 1 037 | FP 1 |
| **Actually phishing** | FN 22 | TP 878 |

Twenty-three errors in 1 938 messages: 22 missed phishing messages and one
false alarm. A 0.5 cut-off is not the deployed policy, and it overstates the
misses: 16 of the 22 are phishing messages the calibrator scores at exactly
0.40, the review threshold, so the deployed policy does not deliver them
(§7.8). These numbers are discussed properly in §7.12; read it there before
quoting them anywhere.

On the **hard subset** — 489 messages of cloned brand templates, business email
compromise, thread hijacking and legitimate mail with a phishing-shaped
surface — macro F1 is **0.95475**, recall 0.90717, FPR 0.00000, PR-AUC 0.99530,
and it holds all 22 of the test set's missed phishing messages (TN 252, FP 0,
FN 22, TP 215).

### Baselines and members

| System | Macro F1 | PR-AUC | Recall | FPR | Δ macro F1 vs fusion |
|---|---|---|---|---|---|
| B0 — rule checklist | 0.89540 | 0.95587 | 0.84111 | 0.05491 | **−0.09265** |
| B1 — TF-IDF + logistic regression | 0.97709 | 0.99852 | 0.95111 | 0.00000 | **−0.01096** |
| member: `rules` | 0.89540 | 0.95587 | 0.84111 | 0.05491 | −0.09265 |
| member: `engineered` | 0.97618 | 0.99800 | 0.98778 | 0.03372 | −0.01187 |
| member: `charngram` | 0.97556 | 0.99857 | 0.95667 | 0.00771 | −0.01249 |
| member: `wordtfidf` | 0.96823 | 0.99582 | 0.93889 | 0.00578 | −0.01982 |
| **fusion (deployed)** | **0.98805** | 0.99826 | 0.97556 | 0.00096 | — |

B0 is the analyst checklist the system replaces, and it is the same code as the
`rules` member; the delta over it (0.09265) is gate **G8**. B0's real cost is
visible in the confusion matrix rather than the F1: it misses 143 of 900
phishing messages and blocks 57 of 1 038 legitimate ones, and it is the false
positives that get a filter switched off.

B1 is the conventional strong baseline: word and character TF-IDF into a
logistic regression, i.e. the text-only model that a competent
final-year project would build. On clean data it is **0.01096** behind the
fusion. That gap is small, and it should be small — on a corpus this separable
almost anything reasonable scores well. B1 even wins on two columns: it makes
no false positive at the 0.5 cut-off where the fusion makes one, and it ranks
marginally better (PR-AUC 0.99852 against 0.99826). What it gives up is recall:
it misses 44 phishing messages to the fusion's 22. On clean accuracy alone, the
tri-modal design is not obviously worth its complexity.

That is the correct place to be sceptical, and §7.4, with PG-HARD in §7.0, is
the answer.

## 7.4 The result that matters: robustness

### Why 0.5 would have been a meaningless place to measure

Attack success is conventionally reported as the fraction of positives dragged
below a 0.5 decision boundary. Measured that way, this system's attack success
rate would be close to zero and the number would mean nothing, for two
compounding reasons.

First, the deployed policy has no 0.5 boundary in it. It auto-quarantines at
**0.80** and auto-delivers below **0.40**. An attacker who moves a message from
0.99 to 0.79 has achieved something real — the message is no longer
quarantined, it lands in a human queue — and a 0.5-anchored metric scores that
as a total failure for the attacker.

Second, the clean score distribution is close to degenerate: **1 029 of 1 938**
test messages have a calibrated score below 0.067 and **878** above 0.933,
leaving 31 anywhere in between. Against that distribution, a 0.5-anchored ASR
asks whether an attacker can cross a chasm, when the operationally interesting
question is whether they can take one step.

So success is defined against the deployed policy, in two tiers:

| Definition | Meaning | Rate | Count |
|---|---|---|---|
| **Escapes auto-block** (score < 0.80) | no longer quarantined; lands in the analyst queue | **0.00000** | 0 of 150 |
| **Silent delivery** (score < 0.40) | reaches the inbox with no human ever seeing it | **0.00000** | 0 of 150 |

Both are reported because they cost different things. The first costs analyst
time; the second costs a victim.

Attack conditions: 150 phishing messages, a black-box decision-based attacker
with a **10-query budget** and restarts, able to draw on all eight families.
Mean queries spent per message 18.6. No message evaded, so there is no median
cost of a successful evasion to report. Mean final score after attack
**0.99583**, mean score drop **0.00330**, median drop **0.00007**, maximum drop
**0.05894**.

The median tells the real story: for half the attacked messages the entire
10-query budget moved the score by less than 0.0001, and no drop, the largest
included, took a message below the 0.80 block threshold.

How much of a search this is matters for reading the zero. Scoring the original
costs one query, so each start of the search can try at most nine candidate
edits before the budget runs out, and it takes them in the suite's fixed order:
lexical transforms first, then unicode, then URL. The composed attacker
recorded 149 accepted edits across the 150 messages — about one per message —
and every one came from A-UNI (83 messages), A-LEX (51) or A-URL (15); the most
used were `A-UNI-01` (57 uses) and `A-LEX-01` (25). At a budget of 10 the
composed attack is close to a single-edit attack, and the other five families
are at the back of the queue: none of them was ever the accepted edit, and they
are reached mainly through the random restarts. The per-family runs below test
each family on its own, and the adaptive attack on PG-HARD, at 40 and 120
queries, is the longer search — it is where PhishGuard's zero stops being zero
(§7.0).

Aggregate quality under attack:

| Metric | Clean | Under attack | Reported drop |
|---|---|---|---|
| Macro F1 | 0.98805 | 0.99481 | **0.00000** |
| Recall (phishing) | 0.97556 | 0.99333 | 0.00000 |
| FP / FN | 1 / 22 | 4 / 6 | — |

Quality appears to *improve* under attack. That is a measurement artefact, not
a finding: the attacked column is scored on the raw fusion score — the surface
the attacker searched — and the clean column on the calibrated score, both at a
0.5 cut-off. The calibrator places 16 phishing messages at exactly 0.40, so they
count as misses in the clean column (§7.3); on the raw surface they sit above
0.5. The raw-score histogram in `evaluation.json` gives the like-for-like
comparison: before the attack, 4 legitimate messages score at or above 0.5 on
the raw surface and 6 phishing messages below it — exactly the 4 / 6 after it.
On one surface, the attack changed no decision at the 0.5 cut-off.

Gate **G5** requires the macro F1 drop to stay under 0.15; the reported drop is
clipped at zero and reads 0.00000 either way. Gate **G6** requires the
escape-block rate to stay under 0.35; observed 0.00000.

### Fusion versus the text-only baseline — the central claim

The same attacker, the same budget, the same 150 messages, against B1:

| System | Clean F1 | Adversarial F1 | Drop | Escapes auto-block | Silent delivery |
|---|---|---|---|---|---|
| B1 — TF-IDF + logreg | 0.97709 | 0.97657 | 0.00052 | **0.29333** | **0.00000** |
| Fusion (this project) | 0.98805 | 0.99481 | **0.00000** | **0.00000** | **0.00000** |

This is the project's result on ordinary phishing, and at this budget it is a
narrower one than on 7 September. On clean data the fusion beats B1 by 0.011
macro F1, which is not an argument for anything. Under attack, B1 loses
**29.3%** of the attacked phishing (44 of 150) from auto-quarantine to the
analyst queue; none of it reaches the inbox silently at this budget. The fusion
loses none. The ASR advantage of **0.29333** is gate **G9**, and it is the
number the title of this project has to earn.

Two cautions keep it in proportion. B1 is graded at the fusion's thresholds,
0.40 and 0.80, applied to its own score, not at thresholds tuned for it;
PG-HARD tunes every system to the same false-alarm budget first and is the
fairer comparison. And at a budget of 10 neither system delivers a single
ordinary phishing message silently, so the gap that costs a victim is visible
only on PG-HARD: at 120 queries the attacker gets 43 of 48 hard phishing
records into the inbox unwarned through the text-only filter, and 3 through
PhishGuard even when it targets the abstention rule (§7.0).

The mechanism argued in [§2.6](02-architecture.md) and
[ADR-001](adr/001-tri-modal-fusion.md) is that B1 reads text, the channel the
attacker owns outright — they wrote it, and they can rewrite it for free —
while the fusion also reads headers, URL structure and behavioural context,
where the attacker's control degrades from total, to partial, to almost none.
The member scores under the PG-HARD attack refine that argument rather than
simply confirming it. At 120 queries the attacker drags the `rules` member's
mean score on hard phishing from 0.477 to 0.141 and the `engineered` member's
from 0.691 to 0.376, while the two text members barely move (`charngram` 0.821
to 0.758, `wordtfidf` 0.846 to 0.780). The readers that move least are the
fusion's own text members, which read canonicalised text (D-NORM). What keeps
hard phishing out of the inbox is that at least one reader keeps objecting, so
the members disagree and abstention sends the message to a human. On this run
the evidence supports decorrelated readers plus abstention as the mechanism,
more than it supports the non-text channels on their own.

### Which families work, and what they cost the attacker

Each family run alone against the same 150 messages under the same budget:

| ID | Family | Escapes block | Silent delivery | Mean drop | Max drop | Attacker cost |
|---|---|---|---|---|---|---|
| A-URL | URL obfuscation and redirection | 0.00000 | 0.00000 | 0.00185 | 0.09035 | Low to medium |
| A-BEH | Behavioural and timing mimicry | 0.00000 | 0.00000 | 0.00141 | 0.05101 | High — low-and-slow sending cuts campaign reach |
| A-UNI | Unicode and homoglyph obfuscation | 0.00000 | 0.00000 | 0.00089 | 0.04722 | Low |
| A-LEX | Lexical and semantic perturbation | 0.00000 | 0.00000 | 0.00077 | 0.03536 | Low |
| A-CHANNEL | Out-of-band payload delivery | 0.00000 | 0.00000 | 0.00019 | 0.01097 | High — callback fraud needs live operators |
| A-TRUST | Payload relocation onto reputable infrastructure | 0.00000 | 0.00000 | 0.00012 | 0.00515 | Medium — accounts are cheap, takedowns are fast |
| A-STRUCT | Structural and HTML manipulation | 0.00000 | 0.00000 | 0.00010 | 0.00246 | Low |
| A-HDR | Header and identity shaping | 0.00000 | 0.00000 | 0.00006 | 0.00235 | Medium |

No family, run alone, moves a single message out of auto-quarantine at this
budget, so this table cannot rank the families by success, and there is no
query cost of evasion to report. It can only rank them by how far they move the
score, and those differences sit in the third and fourth decimal place. The
ordering by mean drop — A-URL, A-BEH, A-UNI and A-LEX ahead of the other four —
is indicative at most.

PG-HARD separates the families better. With the adaptive attacker restricted to
one family at a time, at 40 queries against 48 hard phishing records, the only
families that get anything past PhishGuard are A-HDR and A-BEH, one record each
(2.1%), and A-BEH
leaves the smallest share still auto-blocked (16.7%, against 29.2–41.7% for the
other seven). The text-only filter is most exposed to A-UNI (14.6% delivered
unwarned) and A-TRUST (12.5%).

The attacker-cost column is the part a purely numerical table would lose.
A-BEH's transforms send like a legitimate correspondent — business hours,
low-and-slow pacing, reply framing — and the low-and-slow part cuts the
attacker's campaign reach, so what A-BEH achieves on PG-HARD is paid for in
delivered volume. A-HDR is cheap on the attacker's own domain and impossible on
the brand's real one, because that is domain compromise, which is out of scope
(`OOS-1`) and an authentication problem rather than a classification one.
A-CHANNEL removes the link altogether — a phone number or a QR code — which
bypasses every URL feature but needs a staffed phone line or a victim willing
to act by hand.

### What the decision policy does under attack

Macro F1 hides the movement that matters, because a message that slides from
BLOCK into REVIEW is still counted correct. The banded view, with the attacked
messages put through the deployed policy (calibrated score, velocity guard,
then abstention):

| Traffic | ALLOW | REVIEW | BLOCK | Review rate | Phishing allowed | Legitimate blocked |
|---|---|---|---|---|---|---|
| Clean | 928 | 312 | 698 | 0.16099 | 2 | 0 |
| Under attack | 928 | 323 | 687 | 0.16667 | 2 | 0 |

Eleven messages move out of BLOCK, and all eleven stop in REVIEW; none reaches
ALLOW. They are among the 150 attacked messages, and their raw scores stayed at
or above 0.80 — that is what the zero in the two-tier table means — so each
moved because its calibrated score fell below 0.80 or because its members began
to disagree and abstention held it for a human. The review rate rises from
16.10% to 16.67% of traffic, auto-decided recall moves from 0.99714 to 0.99710,
and no legitimate message is blocked in either condition.

### Interpretation: what the attacker gets, and what it costs

The attacker's realistic achievement against this system is **displacement, not
evasion**. Ten queries per message move 11 of the 150 attacked phishing
messages from automatic quarantine into a human decision, and none into an
inbox. On PG-HARD, with 120 queries, the pattern is starker: the share of hard
phishing that PhishGuard auto-blocks falls from 41.7% to 2.1%, and 44 of the 48
records end in REVIEW — but 3 reach the inbox. Where the defence holds, its
failure mode is graceful: the load lands on the analyst queue, where a human is
looking, rather than on the recipient. Where it does not, the cost is a victim.

Two things make that displacement expensive. The budget is spent: at the
120-query budget the adaptive attacker used 112 queries per hard phishing
record on average, against a live scoring endpoint, which is exactly the
pattern rate limiting and the `phishguard_auth_failures_total` alert exist to
make visible. And the families that would move the behavioural block cost the
attacker campaign reach, which is the resource phishing economics actually
depend on.

The honest counter-statement: this is measured against transforms this project
wrote. See §7.12.

### The measurement surface

The composed attack is run against the **raw, pre-calibration fusion score**,
not the calibrated probability the API returns. This is deliberate, and it is
conservative about the attacker's search. The isotonic calibrator saturates: it
maps almost everything to approximately 0 or approximately 1, so an attacker
probing the calibrated output gets almost no gradient to climb and would appear
to fail completely. That would flatter the defence rather than measure it.

Measured against the calibrated surface the API actually exposes, the numbers
are:

| Surface | Escapes auto-block | Macro F1 drop |
|---|---|---|
| Raw fusion score (reported headline) | 0.00000 | 0.00000 |
| Calibrated score (what the API returns) | **0.00000** | **0.00000** |

On this run both surfaces report zero at a budget of 10, so the comparison
cannot say how far the raw surface overstates the attacker. It does show the
limit of calling the raw figure an upper bound. The raw-surface rate counts
only raw scores below 0.80, while the deployed policy acts on the calibrated
score and on member agreement, and the banded view above shows it moving 11
attacked messages out of BLOCK that neither rate counts. The raw surface is the
more generous oracle for the attacker's *search*; the banded outcome, not
either rate, measures what the deployed system does with the result. Both rates
are reported, because reporting only the flattering one would be dishonest, and
reporting only the conservative one would misdescribe the deployed system.

## 7.5 Modality ablation

What each feature family is worth, holding the model fixed: the `engineered`
member is retrained on each family alone, each pair, and all three. If the
three families were redundant, a single-modality model would match the full
one.

| Families | Features | Macro F1 | PR-AUC | Recall | FPR | Δ vs all three |
|---|---|---|---|---|---|---|
| email | 125 | 0.98446 | 0.99952 | 0.99111 | 0.02119 | −0.00205 |
| url | 107 | 0.94080 | 0.98903 | 0.92778 | 0.04721 | −0.04571 |
| behavioural | 33 | 0.93434 | 0.98721 | 0.90000 | 0.03468 | −0.05217 |
| email + url | 232 | 0.98446 | 0.99964 | 0.99222 | 0.02216 | −0.00205 |
| email + behavioural | 158 | 0.98391 | 0.99930 | 0.97889 | 0.01156 | −0.00260 |
| url + behavioural | 140 | 0.98598 | 0.99929 | 0.97556 | 0.00482 | −0.00053 |
| email + url + behavioural | 265 | **0.98651** | 0.99958 | 0.98222 | 0.00963 | 0.00000 |

Three readings.

**No single family is sufficient.** The best solo family, email at 125
features, is only 0.002 macro F1 behind the full set, but it gets there by
over-flagging: it catches 99.1% of phishing at a false-positive rate of 2.1%,
which in operation means blocking one legitimate message in forty-seven. URL
alone has a 4.7% false-positive rate — one legitimate message in twenty-one —
and misses 7.2% of phishing. Behavioural alone misses 10% of phishing and makes
65.0 errors per 1 000 messages, against 13.4 for all three families together.
Every singleton has a failure that would matter in operation; that part of the
ablation's job is cleanly answered.

**The pairs are less tidy.** Only one pair beats every singleton: url +
behavioural, the pair with no email-family features at all, reaches 0.98598,
0.00053 behind the full set. A model that never sees the headers or the wording
of the message comes that close, which is the clearest single-number statement
of how much signal lives outside them. The other two pairs add
nothing to email alone: email + url ties it exactly (0.98446), and email +
behavioural falls just below it (0.98391).

**And the result that reversed.** On 7 September email + url beat all three
families, and this section argued that the behavioural family cost clean
accuracy. On this run all three together are the best combination — by one
message: 26 errors on the 1 938-message test set, against 27 for url +
behavioural and 30 for email + url. Adding the behavioural family to email +
url trades 13 fewer false alarms (23 to 10) for 9 more misses (7 to 16).
Neither the old deficit nor the new advantage is large enough to argue from;
both are a few messages on one test set, and §7.12's warning about differences
below 0.01 applies to both.

The justification for the behavioural family was never clean accuracy. It is
the claim in §7.4 that the family reads what the attacker cannot rewrite —
correspondence history and domain age — and this run tests that claim only
indirectly. On ordinary phishing at a budget of 10 no family, A-BEH included,
moved a message out of auto-quarantine, so the ordinary set cannot rank the
families at all. On PG-HARD, A-BEH — which changes send time, pacing and
framing, not history — got one hard phishing record past PhishGuard at 40
queries and left the fewest still auto-blocked. That is consistent with the
capability boundary in [§4.4](04-threat-model.md), but it means the behavioural
block is not immune to the attacker, only to the part of the attack that would
require forging the victim's history. The defence ablation in §7.6 points the
same way from the other direction: removing D-ENSEMBLE, which combines the
decorrelated readers, is the only single change that lets the attack through at
this budget.

So on this run there is no clean-accuracy price to state for the behavioural
family, and its benefit under attack is argued rather than measured: no
experiment in this dossier removes the family and then attacks.

A caveat that cuts against the ablation itself: this experiment measures the
`engineered` member alone, not the deployed four-member fusion, and it measures
clean accuracy only. A modality ablation run *under attack* would be the
experiment that directly tests the justification just given, and it is not in
this dossier. §7.13 lists it.

## 7.6 Defence ablation

Eight arms. Each retrains a model from scratch with one control disabled, then
attacks it under the same 10-query budget. The harness caps the ablation at 120
attacked messages — the first 120 of the 150 used in §7.4 — so here one message
is 0.00833 of ASR.

| Arm | Clean F1 | Clean FPR | Adv F1 | F1 drop | ASR | Silent delivery | Δ ASR vs full |
|---|---|---|---|---|---|---|---|
| all defences | 0.98805 | 0.00096 | 0.99481 | 0.00000 | 0.00000 | 0.00000 | — |
| without D-NORM | 0.98857 | 0.00096 | 0.99533 | 0.00000 | 0.00000 | 0.00000 | 0.00000 |
| without D-URL | 0.99118 | 0.00289 | 0.99429 | 0.00000 | 0.00000 | 0.00000 | 0.00000 |
| without D-ADVTRAIN | 0.99429 | 0.00385 | 0.99481 | 0.00000 | 0.00000 | 0.00000 | 0.00000 |
| **without D-ENSEMBLE** | 0.97826 | 0.03372 | 0.96890 | 0.00936 | **0.10000** | **0.10000** | **+0.10000** |
| without D-ABSTAIN | 0.98805 | 0.00096 | 0.99481 | 0.00000 | 0.00000 | 0.00000 | 0.00000 |
| without D-VELOCITY | 0.98805 | 0.00096 | 0.99481 | 0.00000 | 0.00000 | 0.00000 | 0.00000 |
| **no defences** | 0.97358 | 0.03372 | 0.96786 | 0.00572 | **0.09167** | **0.06667** | **+0.09167** |

The "all defences" arm reproduces the registered model's clean and adversarial
macro F1 exactly (0.98805 and 0.99481), as do the arms without D-ABSTAIN and
D-VELOCITY, which act only at decision time. The comparison that is valid is
still *between arms*: each arm is graded at its own operating point, on 120
messages rather than §7.4's 150. The adversarial F1 column inherits §7.4's
surface artefact — attacked messages scored on the raw surface, clean ones on
the calibrated surface — so read the ASR and silent-delivery columns, not the
F1 drop.

### One control carries the robustness at this budget

On 7 September two did: removing adversarial training or the ensemble each
multiplied the attack success rate. On this run, at this budget, one does.

**D-ENSEMBLE** is the control whose removal lets the attack through. Without
it, 12 of the 120 attacked messages escape auto-block (ASR 0.10000), and all 12
fall below the review threshold as well, so every escape is a silent delivery.
The arm keeps only the single strongest view, the `engineered` member — its
clean false-positive rate, 0.03372, is the same as that member's in §7.3 — so
this is the decorrelation argument made measurable: a single model presents
one surface to climb, and four members reading different channels do not move
together under the same edit. It is also the worst single-control arm on clean
data: macro F1 0.97826, and 35 legitimate messages flagged at the 0.5 cut-off
against the full system's one.

Removing every control gives the "no defences" arm: 11 escapes (ASR 0.09167),
8 of them silent (0.06667). That is no worse than removing the ensemble alone —
the two arms are one escape apart — so once the ensemble is gone, the other
five controls add nothing measurable at this budget either.

**D-ADVTRAIN**, the control that carried the most on 7 September, registers
nothing here, and neither do four others. The next subsection says why that is
not the same as useless.

### Five controls show no measurable effect, and why that is not the same as useless

On this run the count is five: removing D-NORM, D-URL, D-ADVTRAIN, D-ABSTAIN or
D-VELOCITY leaves the attack success rate at exactly 0.00000. Two of those
nulls are about the measurement, and three are about the test set.

**D-ABSTAIN and D-VELOCITY cannot appear in this metric by construction.** Both
act *downstream* of the raw fusion score. D-ABSTAIN is the banding policy: it
takes a score and the members' agreement and routes the message to ALLOW,
REVIEW or BLOCK. D-VELOCITY is a campaign-burst guard applied after
calibration. The ablation's ASR is measured on the raw score surface, upstream
of both. A control that never touches the number being measured cannot move
that number, and an ablation reporting exactly 0.00000 for both is the
arithmetic working correctly, not evidence about their value.

This is a **measurement limitation, and it is the honest description of it**.
The effect of D-ABSTAIN is visible elsewhere in this dossier and it is
substantial. In §7.4's banded view, the 11 attacked messages that leave BLOCK
all stop in REVIEW; without D-ABSTAIN there is no REVIEW band, and each would
be a binary decision that falls one way or the other. On PG-HARD, 44 of 48
hard phishing records end in REVIEW under the strongest attack. And §7.8 shows
the price in clean operation: 16.1% of ordinary test mail held for a human. A
metric that scores all of that at zero is measuring the wrong surface, and the
fix is an ablation run against the banded outcome rather than the raw score —
§7.13.

D-VELOCITY has the additional problem that its input, campaign burst structure,
is only partially exercised by a single-message attack loop. It defends against
volume, and the ablation attacks one message at a time.

**D-ADVTRAIN, D-URL and D-NORM are nulls of a different kind: the test set is
not hard enough to separate them.** At a budget of 10 the composed search makes
about one edit per message (§7.4), and every arm that keeps the ensemble holds
all 120 attacked messages above its block threshold. An attack that moves
nothing cannot say which control stopped it. The PG-HARD adaptive attack is the
more discriminating test, but it is run against the deployed model only, not
against each arm, so it cannot attribute its result to a control either. Two
further points limit what the D-ADVTRAIN null can mean: the control trains on
the same suite the attacker draws from (§7.12), and the suite itself changed in
1.3.0, when the open-redirect transform was fixed (§7.0), so this arm and its
7 September counterpart were not attacked with identical transforms.

**D-NORM's effect is likely masked rather than absent.** Removing it leaves ASR
at 0.00000 and moves clean and adversarial macro F1 by about 0.0005 — upward,
which is noise. D-NORM's job is to fold away unicode and homoglyph obfuscation.
Against the full model the composed attacker reached for A-UNI more than for any
other family (83 of 150 messages, §7.4) and moved nothing out of
auto-quarantine; the obfuscation deltas are retained as nine features, so heavy
folding raises the score by itself, and with the ensemble also resisting the
family, removing canonicalisation does not show up. That is a claim about
*this* configuration and *this* budget; against heavier obfuscation, or with
the ensemble also removed, the arm would be expected to separate, and that has
not been measured.

### The D-URL arm anomaly

The anomaly of 7 September — removing D-URL *lowered* measured attack success —
does not recur: without D-URL the ASR is 0.00000, the same as the full system.
A different oddity takes its place, and it applies to D-ADVTRAIN as well.
Removing either control *raises* clean macro F1 at the 0.5 cut-off (to 0.99118
without D-URL and 0.99429 without D-ADVTRAIN, against 0.98805) while raising
the clean false-positive rate (to 0.00289 and 0.00385, against 0.00096 — two and
three more legitimate messages flagged). Two observations dispose of the
apparent gain:

1. Clean macro F1 at a 0.5 cut-off is a fragile comparison here. The full
   system loses 16 of its 22 misses to a single calibrator step at 0.40
   (§7.3), and every arm refits its own calibrator, so a difference of
   0.003–0.006 can come from where one step lands rather than from the control
   removed.
2. The false-positive rate moves the other way, and it is the binding
   constraint (gate G3): a filter that blocks legitimate mail gets switched off.
   URL canonicalisation and adversarial training earn their place on that
   column, not on macro F1 — although by two and three messages, which is also
   a small effect.

What a 120-message attack sample can resolve is unchanged: one message is
0.00833 of ASR. Only two arms differ from zero at all — without D-ENSEMBLE (12
escapes, all 12 silent) and no defences (11 escapes, 8 silent) — and they are
not distinguishable from each other.

## 7.7 Calibration and the operating point

| Metric | Value |
|---|---|
| Method | isotonic regression, fitted on the disjoint `cal` pool (n = 1 233) |
| ECE (calibrated) | **0.00771** |
| MCE (calibrated) | 0.00191 |
| ECE (uncalibrated fusion) | 0.00929 |

Gate **G4** allows an ECE up to 0.08; observed 0.00771. Calibration matters
here for a specific reason: the ALLOW/REVIEW/BLOCK thresholds are compared
against a probability, so if 0.80 does not mean "80% likely to be phishing",
the policy is arbitrary.

**The near-zero ECE should not be read as a hard calibration problem solved.**
The reliability curve explains why. Of fifteen bins, two hold 1 907 of the
1 938 messages:

| Score bin | Count | Mean predicted | Observed frequency |
|---|---|---|---|
| 0.000 – 0.067 | 1 029 | 0.00004 | 0.00194 |
| 0.067 – 0.133 | 9 | 0.10862 | 0.33333 |
| 0.200 – 0.267 | 1 | 0.24430 | 1.00000 |
| 0.267 – 0.333 | 1 | 0.32255 | 0.00000 |
| 0.400 – 0.467 | 19 | 0.40000 | 0.84211 |
| 0.467 – 0.533 | 1 | 0.52473 | 1.00000 |
| 0.933 – 1.000 | 878 | 1.00000 | 0.99886 |

Every remaining bin is empty. Isotonic regression fitted to a pool this
separable approaches a step function, and a step function that is right about
which side each message falls on has an excellent ECE almost trivially. Where
the calibrator is not confirming a separation the corpus already provides, it
is visibly wrong: the 19 messages it scores at 0.40 are phishing 16 times out
of 19, and the 9 it scores near 0.11 are phishing a third of the time. They are
too few to move the ECE, and the MCE skips bins that small, so its 0.00191
describes only the two extreme bins — which is exactly why neither summary
should be quoted alone. On real mail, where scores populate the middle of the
range, the ECE would be materially worse and the isotonic fit — which is
non-parametric and can overfit a small calibration pool — would need
re-examining. The confidence profile makes the same point from the other
direction: confidence is defined as |score − 0.5| × 2, and **1 907 of 1 938**
messages fall in its top decile — within 0.05 of certainty in one direction or
the other — with accuracy 0.99843 in that bin.

### The operating point

`at_operating_point` answers an operational question: which threshold delivers
the target false-positive rate of 0.02? On this run:

| Field | Value |
|---|---|
| Target FPR | 0.02 |
| Derived threshold | **0.01190** |
| Achieved FPR | 0.01252 |
| Macro F1 at that threshold | 0.99223 |
| Recall at that threshold | 0.99778 |

The threshold is well below the deployed block threshold of 0.80, which is the
expected shape: on a corpus this separable, almost any cut-off above the noise
floor satisfies a 2% false-positive budget, and the deployed thresholds are set
higher than the budget requires in order to leave the REVIEW band room to do
its job. The model records exactly that: its thresholds are "configured (the
requested false-alarm budget would put the block boundary below 0.5, which
cannot be justified)". At the derived threshold, 2 of 900 phishing messages
are missed and 13 legitimate ones are flagged.

**An implementation note worth recording, because it is a general trap.** An
earlier revision computed this threshold as the (1 − target) quantile of the
negative-class scores. That is wrong whenever the score distribution has a mass
point, which is the normal case for a well-separated calibrated model. On the
7 September corpus every legitimate test message scored at or near 0.0, so the
98th percentile of the negatives *was* 0.0, and a threshold of 0.0 under the
`score >= threshold` comparison used everywhere else classified every test
message as phishing — a reported false-positive rate of 1.0 while nominally
targeting 0.02. The trap is still live on this run: 1 027 of the 1 038
legitimate test messages have a calibrated score below 0.025. The routine now
searches the achieved false-positive rate directly over the distinct negative
scores and steps strictly above the largest negative when the budget is zero.
Two regression tests in `tests/unit/test_metrics.py` pin the behaviour.

The episode is worth keeping in the dossier for two reasons. The failure was
silent — the number looked like a number — and it was caused by exactly the
property §7.12 identifies as this evaluation's central weakness: a synthetic
corpus that the model separates almost perfectly.

## 7.8 Decision bands in operation

The deployed three-way policy applied to the test set, on the calibrated
scores the API returns, with the velocity guard and abstention included:

| Outcome | Count | Share |
|---|---|---|
| ALLOW (deliver) | 928 | 47.88% |
| REVIEW (analyst queue) | 312 | **16.10%** |
| BLOCK (quarantine) | 698 | 36.02% |

| Metric | Value |
|---|---|
| Review rate | 0.16099 |
| Auto-decided | 1 626 of 1 938 |
| Auto-decided macro F1 | 0.99875 |
| Auto-decided FPR | 0.00000 |
| Auto-decided recall | 0.99714 |
| **Phishing auto-allowed (missed)** | **2** |
| **Legitimate auto-blocked** | **0** |
| Phishing held in REVIEW | 200 |
| Legitimate held in REVIEW | 112 |

Auto-decision metrics deliberately exclude the review band: a message a human
has been asked to look at is neither a false positive nor a missed detection
until the human decides. Review volume is reported alongside so the trade is
visible rather than hidden.

The band is doing what [ADR-006](adr/006-abstention-band.md) intends — no
legitimate message is blocked and only two phishing messages are delivered —
and it is not doing it cheaply. It holds 200 phishing and 112 legitimate
messages, so 10.8% of all legitimate test mail waits for an analyst. Most of
the band is not the score: only 20 test messages have a calibrated score
between 0.40 and 0.80, and BLOCK holds 698 messages although 878 score at or
above 0.80. The rest are routed to REVIEW by the controls that act after the
score, almost all of them by abstention on member disagreement (the velocity
guard's increase is bounded, and at most one test message scores close enough
to 0.40 for it to matter). That includes the one legitimate message the model
scores at 1.0 (§7.10), which is held rather than blocked.

A 16.1% review rate is therefore a property of the abstention rule on this
corpus, and it moves with the training seed, from 14.7% to 16.5% (§7.12). Real
traffic may produce more or less. How many analyst-hours that costs cannot be
answered from this corpus, but it is now priced rather than ignored: under the
cost model's illustrative assumptions (2% phishing, a tenth of traffic hard)
the deployed policy sends 182 of every 1 000 messages to a human
(`evaluation.md` §6). The `PhishGuardReviewQueueGrowing` alert fires at a
sustained 35% review rate, because the number that matters is the one observed
in deployment, not the one measured here.

## 7.9 Latency

150 single-message assessments through the full decision path, as served by
`POST /api/v1/scan`:

| Percentile | With explanation | Without explanation |
|---|---|---|
| Mean | 12.451 ms | 7.101 ms |
| p50 | 11.896 ms | 6.846 ms |
| p95 | **17.228 ms** | 10.219 ms |
| p99 | 21.511 ms | 11.377 ms |
| Max | 25.030 ms | 11.512 ms |
| Throughput | 80.3 msg/s | 140.8 msg/s |

Gate **G7** requires p95 under 150 ms on the inline mail path; observed
**17.228 ms**, an 8.7× margin. p95 rather than mean, because it is the tail that
causes queue backlog at a gateway. On this run the single-message tail is short
— p99 21.511 ms, and the slowest of the 150 requests took 25.030 ms — but that
is one request at a time on an idle machine; under concurrent load the margin
shrinks quickly (§7.14).

The interesting number is the difference between the two columns. Evidence
generation — counterfactual occlusion over the engineered model, rule
attribution, token attribution — costs roughly **5 ms** at the mean, a little
over two fifths of the total. Scoring itself is about 7 ms. That is a
deliberate and reversible trade: explanation is what makes the human-oversight
control real, and if a deployment ever needed the headroom, `explain=false`
raises throughput by about three quarters (140.8 against 80.3 messages a
second) without touching the verdict.

**The batch path.** `POST /api/v1/scan/batch` and `phishguard triage` score a
list of messages in one vectorised pass through the members, the fusion and the
calibrator instead of one call per message. Measured once by hand, not by the
pipeline, so no artefact records it: 600 freshly generated messages, the same
configuration, one process:

| Path | Messages/s | Relative |
|---|---|---|
| One call per message, no evidence | 147.0 | 1.0× |
| **One batch, no evidence** | **337.3** | **2.3×** |
| One call per message, with evidence | 85.2 | 0.6× |
| One batch, evidence only for messages sent to review (`triage`) | 182.0 | 1.2× |

Batching changes nothing but speed: all 600 messages received the identical
score and band on both paths (`test_batch_and_single_scoring_agree` checks the
same property on every run).

These are single-process, single-machine numbers on the evaluation host, with
no network, no gateway and no concurrent load. They establish that the model is
not the bottleneck; they do not establish deployment capacity, which §7.14
measures under concurrent load.

## 7.10 Error analysis

**23 errors across 1 938 test messages** (error rate 0.01187) at the 0.5
cut-off: 22 missed phishing messages and one false alarm.

| Failure mode | Count |
|---|---|
| missed: cloned legitimate template, signal is header/URL only | 19 |
| missed: thread hijack inside an existing conversation | 2 |
| missed: business email compromise, no link and no lexical tells | 1 |
| false alarm: unknown but legitimate sender | 1 |

The 0.5 cut-off overstates what reaches anyone. Under the deployed policy 2
phishing messages are delivered with no warning and no legitimate message is
blocked (§7.8): 16 of the 22 misses sit at a calibrated score of exactly 0.40
and go to an analyst, and the false alarm is held for review by abstention
rather than blocked.

The most confident mistakes:

| Lure type | True label | Score | Sender domain | Subject |
|---|---|---|---|---|
| `legit_rebrand` | legitimate | **1.0000** | `bluestudio.biz` | `Bluestudio is now part of a new group` |
| `clone` | phishing | **0.0000** | `ttk-legal.nl` | `Shipment AMJ-759873 is out for delivery` |
| `thread_hijack` | phishing | **0.0000** | `harbourline-freight.example` | `Re: Re: next week's sprint planning` |
| `clone` | phishing | 0.1111 | `id-ww6ifb.icu` | `New sign-in to your Microsoft 365 account` |
| `clone` | phishing | 0.1111 | `ttk-legal.nl` | `Your parcel 28X9DDEUAM arrives today` |

Three mistakes are maximally confident, and each is a precise instance of a
hard case in the threat model.

The false alarm is a genuine supplier announcing a rebrand, scored 1.0. It is
the same pattern as PG-HARD's `HN-REBRAND`, the benchmark's one honest failure:
a real company that has moved to a new domain looks, to the model, like an
unknown sender on new infrastructure. §7.16 (RAI-1) takes it up.

The two phishing messages scored 0.0 are a cloned delivery notice and a reply
injected into a live thread. A cloned template carries no lexical signal at
all: the body is a legitimate notification, so every text member reads it as
benign and is correct to do so, and the only evidence is the sending domain
and the URL structure. A hijacked thread is harder still, because the
conversation it joins is real. The model did not merely get these wrong — it
scored them at **0.0**, maximally confident in the wrong direction, which means
the header, URL and behavioural evidence was not merely outweighed but
effectively absent.

Two structural points follow. First, cloned templates are the failure mode the
tri-modal design exists to prevent, and they are 19 of the 22 misses: the clone
slice is where the argument in [§2.6](02-architecture.md) is weakest, not
strongest. Second, 23 errors are enough to see structure but not to measure it.
One lure type dominates, and three of the four categories have one or two
members; they identify what to watch, not how often it happens. On 7 September
there was one error and no error analysis to speak of; there is one now, with
the caveat that its categories are the generator's own.

## 7.11 Subgroup slices

### A metric artefact to dispose of first

The `lure_type` slice table reports macro F1 near 0.5 for almost every slice.
This is **not** a performance finding. Each lure type is single-class by
construction — every `bank` message is phishing, every `newsletter` message is
legitimate — and macro F1 averages per-class F1 over both classes, so a slice
containing only one class scores 0 for the absent class and roughly 1 for the
present one. For single-class slices, read **recall, FPR and error count**;
ignore macro F1 entirely.

### Where the weakness is

Every error here is at the 0.5 cut-off on the calibrated score, as in §7.10.
The slices that contain both classes:

| Slice | Value | n | Recall | FPR | Errors |
|---|---|---|---|---|---|
| Body length | short (<250) | 889 | **0.91414** | 0.00000 | 17 |
| | medium (250–800) | 1 049 | 0.99288 | 0.00288 | 6 |
| HTML | text only | 1 584 | **0.96524** | 0.00105 | 23 |
| | html part | 354 | 1.00000 | 0.00000 | 0 |
| Attachments | no attachment | 1 767 | 0.97174 | 0.00098 | 22 |
| | with attachment | 171 | 0.99363 | 0.00000 | 1 |
| Links | with links | 1 845 | 0.97572 | 0.00102 | 22 |
| | no links | 93 | 0.97143 | 0.00000 | 1 |
| Authentication | auth imperfect | 823 | 0.97639 | 0.00000 | 14 |
| | auth all pass | 1 115 | 0.97394 | 0.00124 | 9 |

By lure type, `clone` (209 messages) holds 19 of the 22 misses, a recall of
0.90909, and `legit_rebrand` (14 messages) holds the one false alarm, an FPR of
0.07143; every other lure type large enough to get its own row has no errors.
The thread-hijack and business-email-compromise misses come from lure types too
small to get a row.

On 7 September one message appeared in six slices and identified nothing. Now
the errors concentrate: every one of the 23 is in a text-only message, and 17
are in short bodies. The attributes are coherent. Short bodies give the text
members less to read, and a text-only clone of a legitimate notification has
almost nothing in it but the sender and the link. The `clone` slice is the
largest phishing lure type in the test set at 209 messages and, by design, the
one whose text carries no signal.

Authentication no longer separates the slices: recall is 0.97639 where it is
imperfect and 0.97394 where it passes. On this corpus a failed SPF or DMARC
check is not decisive, as it would not be on real mail, where forwarding and
list rewriting break authentication for legitimate senders
([§6.3](06-data-dictionary.md#artefacts-caught-during-development)).

**Behavioural context is supplied for all 1 938 test messages**, so the
"behavioural context" slice has only one value and the comparison that would be
most informative — with context against without — is not measured here at all.
Deployments where the gateway supplies no sender history are exactly the case
the `PhishGuardBehaviouralContextMissing` alert watches for, and §7.5's
`email + url` row (0.98446) is the closest available proxy for what that
degradation costs.

The slices are also, unavoidably, slices of the generator's own categories. A
real-world slicing — by industry, by recipient seniority, by language, by mail
client — is not possible on this corpus and would be the more informative
analysis.

## 7.12 Threats to validity

This section is the one to read before quoting any number from this dossier.

### The corpus is synthetic, and the model can learn the generator

Every figure here is measured on messages produced by
`src/phishguard/data/synthetic.py`. That generator is campaign-structured,
difficulty-balanced, leakage-audited, and constructed so that no single feature
separates the classes by more than about 0.84 AUC — but it is a *model* of
phishing, not a *sample* of it. A learner that finds regularities in the
generator's construction is rewarded exactly as if it had found regularities in
phishing.

**A clean macro F1 of 0.98805 is an upper bound and must not be read as a
real-world detection rate.** The same applies to the 0.00096 false-positive
rate, the 2 phishing messages delivered unwarned, the 16.1% review rate and the
0.00771 ECE. On real mail the error rates would be substantially worse and the
review rate could be very different; the honest position is that this dossier
does not know by how much.

What transfers far better is everything **comparative**: fusion against B0 and
B1, PG-HARD, the modality ablation, the defence ablation, and the robustness
comparison in §7.4. Those are measured under identical conditions on identical
data, so the generator's peculiarities largely cancel. The claim "the fusion,
with abstention, is far harder to get hard phishing past than a text-only
model" is well supported by this evidence (3 of 48 against 43 of 48 at 120
queries). The claim "this system detects 97.6% of phishing" is not supported by
it at all.

### Robustness is measured against attacks this project designed

The transforms in eight families, composed under a query budget, are a serious
test. They are also a test whose contents were chosen by the same people who
built the defence, which makes it structurally incapable of finding the attack
nobody thought of. A genuinely novel family is by construction untested, and
the residual-risk register records that rather than pretending otherwise. The
suite is also only as good as its code: until 1.3.0 one transform, A-URL-02,
silently ran another transform's code, and only static analysis noticed
(§7.0).

The point is sharper than it sounds: D-ADVTRAIN *trains on these same
transforms*. Part of the measured robustness is therefore a defence trained on
its own examination paper. The generalisation question — does training on
these transforms produce resistance to one outside the suite — is not answered
here, and the leave-one-family-out training experiment that would begin to
answer it is in §7.13.

### The attack surface is more generous than the API

The headline attack success rate is measured against the raw pre-calibration
score, which gives the attacker a finer-grained oracle than any real client can
observe. This is deliberate and conservative about the attacker's search — a
saturated calibrator would report near-zero attack success and flatter the
defence — and the calibrated figure is reported alongside it (on this run both
are 0.00000). But it does mean the headline robustness number describes a
*stronger* searcher than the deployed system faces, and the defence ablation
inherits the same surface. It does not make the raw-surface rate an upper bound
on everything the attack does: the deployed policy moved 11 attacked messages
out of BLOCK whose raw scores stayed above 0.80 (§7.4).

### The hard cases are not hard enough

On 7 September the hard subset scored within 0.001 of the full test set, with
the same single error, and this section concluded that the generator could not
produce the ambiguity that makes real cases hard. The harder generator and
PG-HARD answer that in part. The hard subset — 489 messages of cloned
templates, BEC, thread hijacking and legitimate mail with a phishing-shaped
surface — now scores macro F1 **0.95475** against 0.98805 for the whole test
set, and it holds all 22 missed phishing messages. PG-HARD is harder again:
every case was written to invert a named detection cue, and the deployed policy
sends 70.8% of its records to a human.

What remains true is the limit on what a generator can manufacture: a real BEC
message from a genuinely compromised colleague's account is hard because there
is almost nothing to find, and a generator that has to label its own output
cannot easily produce that. Treat the hard-subset and PG-HARD figures as
evidence that the difficulty controls work directionally, not as a measurement
of the system's ceiling on real mail.

### Single run, no confidence intervals

Since 1.2.0 this is only partly true. Every evaluation now retrains with two
further training seeds on the same data and reports the range:

| Run | PG-HARD phish delivered unwarned | PG-HARD legitimate blocked | PG-HARD sent to a human | Ordinary phish delivered unwarned | Ordinary mail sent to a human |
|---|---|---|---|---|---|
| evaluated model (`pg-0e0dffa24f`) | 0 of 96 | 8 of 96 (HN-REBRAND) | 70.8% | 0.22% | 16.1% |
| retrained, seed 101 | 1 of 96 (HP-HIJACK) | 0 of 96 | 71.4% | 0.44% | 14.7% |
| retrained, seed 202 | 0 of 96 | 0 of 96 | 80.2% | 0.44% | 16.5% |

On PG-HARD a single borderline case tips with the seed — HP-HIJACK on the
phishing side, HN-REBRAND on the legitimate side — so those results are quoted
as ranges (0–1 and 0–8), not as the evaluated model's single value.

The rest is still one run. The corpus seed (20260907), split seed (11) and
attack seed (7) are fixed; the seed runs repeat neither the attack suite nor
the ablations; and a range over three runs is not a confidence interval, of
which there are none in this document. This matters most where the differences
are smallest:

- The modality ablation's ordering at the top — all three families ahead of
  url + behavioural — is one message, and on 7 September email + url came out
  ahead of all three. That is what a difference below 0.01 looks like when it
  is measured twice.
- Defence-ablation ASR differences below about 0.01 are single messages out of
  120. On this run only two arms differ from zero at all, and they are one
  escape apart.
- The error analysis in §7.10 and the slice analysis in §7.11 rest on 23
  errors, 19 of them from one lure type.

The large effects — the 0.29333 ASR advantage over B1, D-ENSEMBLE's +0.10000,
the 0.09265 delta over B0, and PG-HARD's 3 of 48 against 43 of 48 under attack
— are large enough that seed variance is unlikely to explain them, although
only the unattacked PG-HARD outcomes have actually been re-measured across
seeds. Everything below roughly 0.01 in this dossier should be treated as
unresolved.

### Behavioural features are simulated by the generator that produced the labels

This is the most serious threat to the project's central claim, and it deserves
to be stated plainly. The behavioural block — correspondence history, domain
age, burst counts, display-name reuse — is not observed from a mail
environment. It is synthesised by the same generator that assigns the labels.
The generator decides both that a message is phishing and that its sender has
no correspondence history, so the correlation between those two facts is a
design choice, not an empirical finding.

This does not invalidate the robustness argument, because that argument is
about *what an attacker can rewrite*, and the asymmetry — an attacker can
change a sentence for free and cannot change a two-year correspondence history
at all — is a real property of the deployment environment rather than of the
corpus. But it does mean the behavioural family's measured contribution
(§7.5) and its measured resistance (A-BEH, §7.4) are both quantified on
simulated data, and neither number should be expected to hold at that magnitude
against a real gateway's telemetry.

### Also worth stating

- **Domain compromise is out of scope** (`OOS-1`). Mail genuinely originating
  from a compromised brand or partner domain passes every header and reputation
  check by construction. It is an authentication problem.
- **No URL is resolved and no attachment is opened** (`OOS-4`), deliberately —
  fetching attacker-controlled content from a gateway creates an SSRF surface
  and leaks victim telemetry. A benign-looking URL serving a malicious page is
  invisible to this layer.
- **Calibration is measured on the training distribution.** Under genuine
  distribution shift the probabilities drift, which is why `/api/v1/stats`
  tracks the score distribution rather than assuming calibration holds.
- **The ordinary-set attack is short.** At a budget of 10 the composed search
  makes about one edit per message (§7.4). The zeros it reports bound a cheap
  attacker; PG-HARD's 40- and 120-query attacks are the longer searches.
- **Latency in §7.9 is single-process and unloaded,** and §7.14 measures
  concurrency on one two-core host. Together they show the model is not the
  bottleneck; they do not size a deployment.

## 7.13 What would make this stronger

In descending order of how much each would change the confidence in the
conclusions.

**1. Multi-seed runs with confidence intervals.** The seed-sensitivity table
(§7.12) varies only the training seed, over three runs, and only for the
unattacked outcomes. Ten seeds across corpus generation, splitting, training and
attack, reporting mean and interval for every headline figure, would be the
full version. It is still the cheapest improvement available — a loop around
`phishguard evaluate` — and it would settle whether the modality ablation's
ordering in §7.5, which reversed between 7 September and this run, is anything
more than noise. No claim below 0.01 in this dossier should be defended
without it.

**2. Evaluation on real public corpora.** The loader interface already accepts
external sources (`--data-source data/nazario.mbox#phish,data/enron#ham`), so
the email and URL families can be evaluated on real mail today. The behavioural
family cannot — public corpora carry no correspondence history — so the honest
experiment is: train and evaluate the `email + url` configuration on real data,
compare its absolute numbers with the synthetic ones, and report the gap. That
gap is the best available estimate of how much §7.12's first limitation is
worth, and it would convert "the absolute numbers are an upper bound" from an
assertion into a measurement.

**3. An independent red-team exercise.** The robustness result is measured
against attacks written by this project's own authors, which is its most
serious methodological weakness. Handing the deployed API to someone with no
knowledge of the transform list, a query budget and a target — get a working
credential-phishing message to ALLOW — would test what the ablation cannot. A
partial substitute available immediately: leave-one-family-out adversarial
training, where D-ADVTRAIN is trained on seven families and evaluated on the
eighth, which tests generalisation to unseen transforms without needing an
external team.

**4. A longitudinal temporal study.** The `temporal` split strategy already
exists (`--split temporal`) but is unused in this dossier. Training on earlier
campaigns and testing on later ones measures concept drift — the thing that
actually degrades deployed phishing filters — and would let the retraining
guidance in [§9](09-admin-user-guide.md) be based on a measured decay rate
rather than on a drift signal with no calibrated trigger point.

**5. A human-analyst agreement study.** Every claim about explanation quality
in this project is an assertion. Give a panel of analysts a set of messages
with and without the evidence list, measure decision accuracy and time to
decision, and the human-oversight control becomes measured rather than
designed. It would also replace the assumed unit in the cost model with a
measured one: §7.8's 16.1% review rate is priced in analyst reviews, and nobody
has measured what a review costs or how accurate it is — the model assumes
analysts miss 5% of the phishing they review.

**6. Ablations on the right surface.** Two specific fixes to §7.5 and §7.6.
Run the modality ablation *under attack* rather than on clean data only, which
is the experiment that directly tests the justification given for keeping the
behavioural family. And run the defence ablation against the **banded outcome**
rather than the raw score, so that D-ABSTAIN and D-VELOCITY can register an
effect at all instead of being scored at zero by construction — and on PG-HARD
with the adaptive attacker, the one test on this run hard enough to separate
controls: at a budget of 10 on ordinary phishing, five of the six
single-control arms are indistinguishable from the full system.

**7. Calibration under shift.** The 0.00771 ECE is measured on the training
distribution. Deliberately shifting the test distribution — a different lure
mix, a different phishing ratio, messages from a later time period — and
re-measuring ECE would show whether the isotonic fit survives contact with
anything it has not seen, which is the question §7.7 raises and cannot answer.
The drift monitor (§7.0) detects such a shift; it does not say what the shift
does to calibration.

## 7.14 Load and resource measurements

§7.9 measures one request on an idle machine. A mail gateway is never idle, so
this section measures the service under concurrent load: throughput, the
latency distribution, errors and memory, at increasing concurrency. The whole
decision path is exercised — validation, assessment, evidence, the audit write
and the review queue.

```bash
phishguard loadtest --concurrency 1,2,4,8 --requests 150     # threads, one process
phishguard loadtest --processes 1,2 --requests 150           # server processes
phishguard loadtest --url http://localhost:8000 --api-key <analyst key>   # a running service
```

Results are written to `artifacts/reports/loadtest.json` and
`loadtest-processes.json`; `phishguard evaluate` also runs the threaded test
and puts it in the dossier. Machine: 2 CPU cores, 8 GB RAM. The run inside
`phishguard evaluate` (100 requests each at 1, 4 and 8 concurrent requests)
gives 67.1 to 70.3 messages/s and reports a higher peak memory, 254.0 MB,
because it is the peak of the evaluation process as a whole; its latency at
eight concurrent requests differs from the CLI run's, and is discussed below
the table.

### What the load test found, and what was changed

The first run found three defects, each invisible to the single-message
latency gate. Each was diagnosed with the request traces (§2.12), fixed, and
re-measured.

| # | Finding | Cause | Fix | Before → after |
|---|---|---|---|---|
| 1 | Scoring in a server worker thread was ~3× slower than on the main thread | Each worker thread got its own team of OpenMP threads, which busy-waited for work on a one-row prediction | Limit OpenMP to one thread per serving thread (`runtime.py`) | single-thread p50 36.6 → 11.7 ms; 27 → 84 messages/s |
| 2 | Adding threads *reduced* throughput: 72.8 messages/s with one request at a time, 43–45 with two or more | Scoring holds the interpreter lock; concurrent requests took turns and paid for every switch, and an I/O step (the audit write) waited behind CPU-bound scoring each time | Serve requests one at a time per process, in arrival order: a first-come, first-served scoring slot (`FairSlots`, `PG_SCORING_CONCURRENCY=1`) | see table below |
| 3 | A plain semaphore fixed throughput but not the tail: p50 15 ms, p99 2.2 s at 8 concurrent requests | `threading.Semaphore` is not fair; the thread that released it usually won again, starving the rest | Hand the slot directly to the oldest waiter | p99 at 8 concurrent: 2 207 → 137.2 ms |

Row 1's figures, and row 3's "before", were measured when those fixes were
made. Row 3's "after" and the tables below are the final measurements, with all
three fixes in place.

A fourth issue appeared only in the multi-process harness: running the scoring
loop on a process's *main* thread, where the OpenMP limit deliberately does not
apply, put two processes' spinning OpenMP threads on two cores and the p95 went
to 6.9 seconds. The API never scores on the main thread, but `phishguard serve`
now also sets `OMP_NUM_THREADS=1` for its worker processes as a second line of
defence.

### One process under concurrent load

"Before" is the measurement taken before the scoring slot was introduced;
"after" is the final measurement in `loadtest.json`, 150 requests at each
level.

| Concurrent requests | Before: messages/s | Before: p95 ms | **After: messages/s** | **After: p95 ms** | After: p99 ms | Errors |
|---|---|---|---|---|---|---|
| 1 | 72.8 | 18.0 | **78.6** | **17.4** | 18.8 | 0 |
| 2 | 45.4 | 63.8 | **68.7** | **38.4** | 40.6 | 0 |
| 4 | 43.7 | 137.0 | **70.8** | **70.0** | 73.6 | 0 |
| 8 | 42.9 | 284.8 | **70.0** | **133.7** | 137.2 | 0 |

Throughput under load now falls by 10–13% from the single-request rate (68.7
to 70.8 messages/s against 78.6) instead of by about 40%, and the p95 at eight
concurrent requests more than halves, from 284.8 ms to 133.7 ms — inside the
150 ms budget of gate G7 in this run, where before only four concurrent
requests were. Latency now grows linearly with the queue, which is what a
capacity planner can reason about: at *c* requests in flight, expect about
*c* × 14 ms (the median at eight is 111.6 ms). Peak memory for the process:
213.6 MB.

The evaluation's own load run does not agree at the highest level. With 100
requests per level it measured a p95 of 150.7 ms at eight requests in flight in
this run, against the CLI load test's 133.7 ms — just over the budget rather
than inside it. Eight in flight therefore sits right at the 150 ms budget, and
the margin there should not be quoted as comfortable; four in flight is well
inside it, at a p95 of 70.0 ms in the CLI run and 70.6 ms in the evaluation's.

### More processes

| Server processes | Messages/s | Speed-up | p50 ms | p95 ms | Errors |
|---|---|---|---|---|---|
| 1 | 74.4 | 1.00× | 13.0 | 18.5 | 0 |
| 2 | 151.6 | **2.04×** | 12.4 | 18.6 | 0 |

Two processes sharing one SQLite audit database in WAL mode double the
throughput with no change in latency: the audit write is not a bottleneck at
this rate, and scoring scales with cores. `phishguard serve --workers N` (or
`PG_API_WORKERS`) is the setting; each process holds its own copy of the model.

### Sizing a deployment from these numbers

One process handles about 70 messages a second — roughly 250 000 an hour — on
one core. An organisation of 1 200 people receiving, say, 100 external messages
each per working day needs about 120 000 assessments a day; even if half of
them arrive in the busiest hour, that is 17 a second, a quarter of one
process's capacity. Two processes give headroom for bursts and for one process
restarting. The binding constraint is the p95 budget, not throughput: keep the
number of requests waiting per process below eight — at eight the p95 sits at
the budget, at four it is well inside it.

Caveats. These are in-process measurements without the web framework or the
network; `--url` measures a running service end to end and should be repeated
on the deployment host. With several processes, `/metrics` and
`/api/v1/traces/recent` describe the process that answered and the rate limiter
is per process; in a container platform, prefer one process per container and
scale containers, so each one is scraped separately.

## 7.15 Security and privacy checks

Each check is an automated test unless stated otherwise, and runs on every
push in CI. "Pass" means passing in the run that produced this dossier.

| Area | Check | Evidence | Result |
|---|---|---|---|
| Authentication | Missing or wrong key → 401; keys compared in constant time against stored SHA-256 digests; the key id reveals nothing about the key | `test_missing_and_wrong_keys_are_rejected`, `test_only_digests_are_retained_never_the_key`, `test_key_id_does_not_reveal_the_key` | Pass |
| Function-level authorisation | Analyst cannot reach admin functions; reporters cannot work the queue; admin inherits analyst | `test_analyst_cannot_reach_admin_functions`, `test_reporters_never_work_the_queue`, `test_admin_inherits_analyst_permissions` | Pass |
| Object-level authorisation (OWASP API1) | Only the assignee or an admin may act on a claimed case; concurrent claims resolve to exactly one winner | `test_an_analyst_cannot_work_a_case_another_analyst_owns`, `test_a_second_analyst_cannot_steal_a_claimed_case`, `test_the_store_refuses_a_stale_transition` | Pass |
| High-risk actions | Releasing a message at or above the block threshold needs an admin and a reason; reopening needs an admin | `test_releasing_a_message_the_model_would_block_needs_an_administrator`, `test_only_an_administrator_reopens_and_must_say_why` | Pass |
| Scoring oracle | Reporter responses never contain a score or band | `test_reporter_status_never_mentions_a_score`, `test_a_user_report_is_queued_without_revealing_the_score` | Pass |
| Input validation | Oversized fields and batches rejected; unknown fields rejected | `test_oversized_input_is_rejected_by_the_contract`, `test_batch_size_is_bounded`, `test_unknown_fields_are_rejected` | Pass |
| Hostile input | SQL, template and JNDI injection strings, path traversal, null bytes, 500 emoji, format strings, right-to-left overrides, an XML external entity and a 100 000-character body neither crash nor hang the scanner; scores stay in [0, 1] | `test_hostile_payloads_do_not_crash_the_scanner`, `test_scores_stay_bounded_under_adversarial_input` | Pass |
| Injection | SQL metacharacters in filter parameters do not affect the store | `test_sql_injection_through_a_filter_does_not_affect_the_store` | Pass |
| Abuse | Token-bucket rate limiting per key, with bursts and refill | `test_rate_limiter_allows_a_burst_then_throttles`, `test_rate_limiter_refills_over_time`, `test_rate_limits_are_per_caller` | Pass |
| SSRF / egress | The model never opens a network connection while scoring | `test_the_model_never_fetches_anything_from_the_network` | Pass |
| Identifiers | Decision and case ids are unguessable | `test_a_decision_id_is_unguessable` | Pass |
| Secrets | Production refuses to start without configured keys; development keys are flagged; no credential-looking value committed | `test_production_refuses_to_start_without_configured_keys`, `test_development_keys_are_flagged_loudly`; CI secret scan | Pass |
| Privacy at rest | The audit trail holds no message content; pseudonyms are stable and not reversible; the redaction projection drops content | `test_audit_trail_stores_no_message_content`, `test_pseudonymisation_is_stable_and_not_reversible`, `test_redaction_projection_drops_content` | Pass |
| Privacy in telemetry | Logs and traces never carry message content | `test_logs_never_carry_message_content`, `test_recent_traces_are_bounded_and_carry_no_message_content` | Pass |
| Untrusted archives | Downloaded corpora: path traversal, links and device nodes refused; HTTPS only | `tests/unit/test_fetch.py` | Pass |
| Static analysis | Ruff with the flake8-bandit (`S`) rule set over `src/`, zero findings | CI job "lint" | Pass |
| Dependencies | Known-vulnerability audit of the installed dependency set | `pip-audit --strict` in CI job "security"; Dependabot weekly | Runs in CI — not run in the environment that produced this dossier, whose package index is blocked by policy |
| Container | Non-root user, `cap_drop: ALL`, `no-new-privileges`, memory limit, health check | `docker/api.Dockerfile`, `docker-compose.yml` (review) | Pass (review) |
| Browser | CSP without external sources, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` on every response | `service/app.py` (review) | Pass (review) |

**Privacy impact, in one paragraph.** PhishGuard processes message content in
memory for the duration of one assessment and stores none of it. What persists
is a salted digest of the subject, a pseudonym for the sender, the sender's
domain, sizes, the verdict, the member scores and the *titles* of the evidence
items (for example "Primary link resolves to payroll-hr-portal.co" — which
names a domain but quotes no content). Reporter identities are stored only as
salted digests. Retention is bounded (`PG_AUDIT_RETENTION_DAYS`) and swept at
start-up, except for decisions attached to an active case. Public corpora,
which do contain real people's mail, are never committed (`data/` is
git-ignored) and are fetched only after their terms are acknowledged.

## 7.16 Responsible-AI review

Structured by the trustworthiness characteristics of the NIST AI Risk
Management Framework (AI RMF 1.0), applied to this system.

| Characteristic | What could go wrong here | What the system does | Residual concern |
|---|---|---|---|
| **Valid and reliable** | Numbers flattered by a synthetic corpus | Leakage audit that can fail the build; campaign-grouped splits; PG-HARD; three-seed sensitivity; comparative claims preferred to absolute ones | Absolute accuracy on real mail is unmeasured for the full model (§7.12) |
| **Safe** | A silent miss delivers a working lure; a false block stops business mail | Three-way decision; REVIEW band with an owned queue and SLAs; thresholds priced by a cost model | An attack that reaches ALLOW is still silent (residual-risk register) |
| **Secure and resilient** | Evasion, probing, poisoning | Threat-informed attack suite, six defences measured by ablation, rate limits, admin-only probe, no automatic retraining (§4) | Attacks were written by the defenders (§7.12) |
| **Accountable and transparent** | Nobody can say why a message was blocked or who released it | Model card, versioned models with dataset fingerprints, per-decision evidence, trace ids, a full case history per decision | — |
| **Explainable and interpretable** | Evidence that is technically true and useless to an analyst | Evidence written as sentences, counterfactual attributions ("the score would change by …") and member scores | Explanation quality has not been measured with real analysts (§7.13 item 5) |
| **Privacy-enhanced** | A detection system becomes an archive of employees' mail | No content at rest, pseudonymisation, bounded retention (§7.15) | Evidence titles can name a link's domain |
| **Fair, with harmful bias managed** | Legitimate senders who look unusual are penalised more often | See findings below | Real-world subgroup error rates are unmeasured |

### Findings

**RAI-1 — New and rebranded small businesses are the group most likely to be
blocked in error.** On PG-HARD, every legitimate message the deployed model
blocked came from one case, `HN-REBRAND`: a genuine supplier mailing about a
billing change from a 22-day-old domain — textually identical to invoice fraud,
and new domains are among the strongest phishing signals. Across three training
seeds, 0 to 8 of its 8 variants were blocked. The one false alarm on the
ordinary test set is the same pattern — a supplier announcing a rebrand, scored
1.0 — and there the abstention rule held it for review rather than blocking it
(§7.10). The harm falls on legitimate new businesses and on the recipients
waiting for their mail, not on the attacker.
*Mitigations in place:* the case is in the benchmark so every retrain measures
it; blocked mail can be reported and released through the queue; the evidence
names domain age explicitly, so an analyst sees the reason. *Recommended before
production:* seed the behavioural context with the organisation's supplier
register, so a known supplier's new domain is recognised as a relationship
rather than a stranger.

**RAI-2 — Writing style is a feature, and so is not writing like a native
English speaker.** Several email features reward fluent, conventional English
and penalise unusual phrasing, which phishing often has — and so does mail from
people writing in a second language. The synthetic corpus is English-only and
cannot measure this. *Action:* before deployment in a multilingual
organisation, evaluate false-positive rates on real legitimate mail by
language, and keep the REVIEW band rather than lowering the block threshold if
they differ.

**RAI-3 — Human oversight has to be staffed to be real.** The REVIEW band routed
16.1% of ordinary test mail to a person at the default thresholds (14.7% to
16.5% across three training seeds), including 10.8% of all legitimate mail. A
queue nobody clears is not oversight. *In place:* queue depth and overdue
gauges with alert rules, SLAs by priority, and the cost model that prices
review time.

**RAI-4 — Dual use.** The adversarial probe and the attack suite tell the
caller which edits lower a score, and the synthetic generator writes phishing
text. *In place:* the probe is admin-only, audited and alerted on; generated
phishing is assembled from generic templates with invented look-alike domains,
and nothing in the project sends mail, registers a domain or resolves a URL.
The published tooling helps defenders test their own filters more than it
helps an attacker, who can already test against any public scanner.

**RAI-5 — Reporters are people, not labels.** Employees who report a message
are told what happened in plain words and are never shown a score, so the
reporting channel cannot become a scoring oracle and nobody is made to feel
foolish for a false alarm. User-report precision is tracked as an operational
metric; a falling value means users need guidance, not the model.

**Environmental cost.** Training this model took 28.95 seconds on a CPU, and
serving needs one core per 70 messages a second; the optional transformer member,
which would need a GPU, is off by default and the ablation shows what it would
have to beat.

## 7.17 Go / no-go recommendation

| Decision | Recommendation | Conditions |
|---|---|---|
| Release of this version as a **demonstrable prototype** (the capstone deliverable) | **GO** | 10 of 10 acceptance gates pass; tests, security checks and load test pass; documentation runs on a clean machine |
| **Supervised pilot** on a real mailbox, in *tag-only* mode (verdicts shown to analysts, nothing quarantined) | **GO, with conditions** | Run the `email + url` configuration evaluated on public corpora (§11) alongside; measure the false-positive rate by sender language and for new domains (RAI-1, RAI-2); staff the review queue; keep default thresholds |
| **Autonomous quarantine** in production | **NO-GO for now** | Requires: evaluation on the organisation's own labelled mail with the false-positive rate inside the G3 budget; an independent red-team exercise (§7.13 item 3); supplier-register integration (RAI-1); a signed risk acceptance for the residual-risk register |

The distinction is deliberate. The evidence here supports the *design* — that
fusing three families with abstention is harder to evade than a text model, and
that the ensemble and the abstention band do measurable work — far better than
it supports any absolute accuracy figure on real traffic, or the contribution
of each remaining control, which this run's ablation cannot separate (§7.6). A pilot in tag-only mode is how the second kind
of evidence is gathered without putting business mail at risk.

---

**Next:** [§8 Deployment guide →](08-deployment-guide.md)
