# 7. Evaluation dossier

What was measured, what the numbers mean, and — the part that matters more —
what they do not show.

The machine-generated tables live in
[`artifacts/reports/evaluation.md`](../artifacts/reports/evaluation.md), and
every figure in both documents comes from
[`artifacts/reports/evaluation.json`](../artifacts/reports/evaluation.json).
This document does not restate those tables for their own sake. It interprets
them: which result carries the project's claim, which result is an artefact of
the corpus, and which of the six defensive controls the evidence actually
supports.

All figures below are from the run generated at **2026-09-07T20:59:17Z**
against model **`pg-0bcb098e45`** (trained 2026-09-07T20:31:41Z, 35.53 s).

---

## 7.1 How to reproduce

Three commands from a clean checkout. `evaluate` writes both report files and
exits non-zero if any blocking acceptance gate fails, which is what makes it
usable in CI rather than only in a viva.

```bash
phishguard data     --n 9000                                   # build + audit the corpus
phishguard train    --n 9000 --save                            # train and register
phishguard evaluate --n 9000 --budget 12 --max-attacked 120 \
                    --defense-ablation                         # the dossier
```

The defaults in force for this run, all of them CLI defaults rather than
values passed on the command line:

| Setting | Value | Where it comes from |
|---|---|---|
| Corpus | `synthetic(n=9000, seed=20260907)` | `--n`, `--seed` |
| Phishing ratio | 0.42 | `--phish-ratio` |
| Split | grouped, `--test-size 0.25`, `--split-seed 11` | `--split grouped` |
| Attack seed | 7 | `PG_ATTACK_SEED` |
| Review / block thresholds | 0.40 / 0.80 | `PG_REVIEW_THRESHOLD`, `PG_BLOCK_THRESHOLD` |
| Random seed | 20260907 | `PG_RANDOM_SEED` |

Equivalent `make` targets: `make ablation N=9000 BUDGET=12`, or
`make deliverables` for the tests, the dossier, the ablation, the model card
and the OpenAPI document in one run. The adversarial suite can also be run on
its own against whatever model is currently registered:

```bash
phishguard attack --budget 12 --sweep
```

Two caveats about reproduction. The defence ablation retrains eight models and
attacks each one, so the full run takes roughly twenty to forty minutes rather
than the five to ten of a plain `evaluate`. And the numbers reproduce exactly
only with the same seeds: change `--seed`, `--split-seed` or `PG_ATTACK_SEED`
and the third decimal place will move. That is a property of the measurement,
not a defect, but it is also why §7.12 lists the absence of multi-seed
confidence intervals as a limitation.

## 7.2 Experimental design

### The corpus

9 000 generated messages, of which 8 683 survive near-duplicate scrubbing:
**6 746 train** (44.38% phishing) and **1 937 test** (51.58% phishing). The
generator produces campaign-structured mail across 35 lure types — 17 phishing
(`clone`, `bank`, `crypto`, `invoice_fraud`, `sextortion`, `vendor_swap`,
`calendar_lure` and others) and 18 legitimate (`receipt`, `newsletter`,
`code_review`, `real_password_reset`, `suspicious_ham` and others), of which 31
are represented in this test split. The
rationale for a synthetic corpus, and its cost, is [ADR-002](adr/002-synthetic-corpus.md);
the honest reading of what it can and cannot support is §7.12.

### Campaign-grouped splitting

Messages are grouped by campaign — 1 349 groups, 347 of them held out — and the
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
tell that would make every other number in this report meaningless. No feature
in the 265 exceeds roughly 0.84 AUC on its own, which is what licenses the
claim that the fusion is doing work rather than reading a giveaway.

Gate **G10** encodes this: leakage failing is a build failure, not a footnote.

### Three disjoint training pools

The 6 746 training messages are split again, and nothing sees the same rows
twice:

| Pool | Size | Share | Fits |
|---|---|---|---|
| `fit` | 4 048 | 60% | the four ensemble members |
| `stack` | 1 484 | 22% | the logistic fusion over member scores |
| `cal` | 1 214 | 18% | the isotonic calibrator over fusion output |

D-ADVTRAIN augments the `fit` pool only, adding **1 796** adversarially
perturbed copies of phishing messages.

Each boundary guards against a specific and well-known failure. Fitting the
fusion on member scores produced *in sample* gives a stacker excellent
apparent weights for a regime it will never encounter again — the members are
near-perfect on their own training rows, so the fusion learns from a
distribution that does not exist at inference time. The calibrator needs a
third pool for the same reason one step later: it must see fusion outputs it
did not itself shape. The learned fusion weights (`engineered` 4.87,
`charngram` 3.39, `wordtfidf` 3.28, `rules` 1.90, intercept −6.15) are only
meaningful because they were fitted out of sample.

## 7.3 Headline results

The deployed fusion on the held-out test set, at a 0.5 cut-off, n = 1 937:

| Metric | Value |
|---|---|
| Macro F1 | **0.99948** |
| PR-AUC | 0.99969 |
| ROC-AUC | 0.99950 |
| Recall (phishing) | 0.99900 |
| Precision (phishing) | 1.00000 |
| False-positive rate | 0.00000 |
| False-negative rate | 0.00100 |
| Accuracy | 0.99948 |

Confusion matrix:

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **Actually legitimate** | TN 938 | FP 0 |
| **Actually phishing** | FN 1 | TP 998 |

One error in 1 937 messages. That number is discussed properly in §7.12; read
it there before quoting it anywhere.

On the **hard subset** — 677 messages of cloned brand templates, business email
compromise, thread hijacking and legitimate mail with a phishing-shaped
surface — macro F1 is **0.99846**, recall 0.99754, FPR 0.00000, PR-AUC 0.99931,
with the same single false negative (TN 271, FP 0, FN 1, TP 405).

### Baselines and members

| System | Macro F1 | PR-AUC | Recall | FPR | Δ macro F1 vs fusion |
|---|---|---|---|---|---|
| B0 — rule checklist | 0.91109 | 0.98126 | 0.84885 | 0.02239 | **−0.08839** |
| B1 — TF-IDF + logistic regression | 0.98812 | 0.99974 | 0.97898 | 0.00213 | **−0.01136** |
| member: `rules` | 0.91109 | 0.98126 | 0.84885 | 0.02239 | −0.08839 |
| member: `engineered` | 0.99897 | 0.99999 | 0.99800 | 0.00000 | −0.00051 |
| member: `charngram` | 0.98760 | 0.99977 | 0.97798 | 0.00213 | −0.01188 |
| member: `wordtfidf` | 0.98451 | 0.99967 | 0.97197 | 0.00213 | −0.01497 |
| **fusion (deployed)** | **0.99948** | 0.99969 | 0.99900 | 0.00000 | — |

B0 is the analyst checklist the system replaces, and it is the same code as the
`rules` member; the delta over it (0.08839) is gate **G8**. B0's real cost is
visible in the confusion matrix rather than the F1: it misses 151 of 999
phishing messages and blocks 21 of 938 legitimate ones, and it is the false
positives that get a filter switched off.

B1 is the conventional strong baseline: word and character TF-IDF into a
logistic regression, i.e. the text-only model that a competent
final-year project would build. On clean data it is **0.01136** behind the
fusion. That gap is small, and it should be small — on a corpus this separable
almost anything reasonable scores well. On clean accuracy alone, the tri-modal
design is not obviously worth its complexity.

That is the correct place to be sceptical, and §7.4 is the answer.

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

Second, the clean score distribution is close to degenerate: **938 of 1 937**
test messages score below 0.067 and **994** score above 0.933, leaving five
anywhere in between. Against that distribution, a 0.5-anchored ASR asks whether
an attacker can cross a chasm, when the operationally interesting question is
whether they can take one step.

So success is defined against the deployed policy, in two tiers:

| Definition | Meaning | Rate | Count |
|---|---|---|---|
| **Escapes auto-block** (score < 0.80) | no longer quarantined; lands in the analyst queue | **0.06667** | 8 of 120 |
| **Silent delivery** (score < 0.40) | reaches the inbox with no human ever seeing it | **0.00833** | 1 of 120 |

Both are reported because they cost different things. The first costs analyst
time; the second costs a victim.

Attack conditions: 120 phishing messages, a black-box decision-based attacker
with a **12-query budget** and restarts, composing across all six families and
30 transforms. Mean queries spent per message 21.14; median queries to a
successful evasion 24.0; mean 0.88 transforms applied in a successful evasion.
Mean final score after attack **0.96497**, mean score drop **0.02795**, median
drop **0.00052**, maximum drop **0.63492**.

The median tells the real story: for half the attacked messages the entire
12-query budget moved the score by less than 0.0006. The mean is dragged up by
a small number of messages where the attacker found real purchase.

Aggregate quality under attack:

| Metric | Clean | Under attack | Change |
|---|---|---|---|
| Macro F1 | 0.99948 | 0.99897 | **−0.00051** |
| Recall (phishing) | 0.99900 | 0.99800 | −0.00100 |
| FP / FN | 0 / 1 | 0 / 2 | +1 missed |

Gate **G5** requires the macro F1 drop to stay under 0.15; observed 0.00051.
Gate **G6** requires the escape-block rate to stay under 0.35; observed 0.06667.

### Fusion versus the text-only baseline — the central claim

The same attacker, the same budget, the same 120 messages, against B1:

| System | Clean F1 | Adversarial F1 | Drop | Escapes auto-block | Silent delivery |
|---|---|---|---|---|---|
| B1 — TF-IDF + logreg | 0.98812 | 0.96851 | 0.01961 | **0.55000** | **0.16667** |
| Fusion (this project) | 0.99948 | 0.99897 | **0.00051** | **0.06667** | **0.00833** |

This is the project's result. On clean data the fusion beats B1 by 0.011 macro
F1, which is not an argument for anything. Under attack, B1 loses **55%** of
its phishing to the attacker — more than half of all attacked messages escape
auto-quarantine — and **16.7%** are delivered silently to the inbox. The fusion
loses 6.7% and 0.8%. The ASR advantage of **0.48333** is gate **G9**, and it is
the number the title of this project has to earn.

The mechanism is the one argued in [§2.6](02-architecture.md) and
[ADR-001](adr/001-tri-modal-fusion.md). B1 reads text. Text is the channel the
attacker owns outright: they wrote it, and they can rewrite it for free. The
fusion also reads headers, URL structure and behavioural context, and the
attacker's control over those degrades from total, to partial, to almost none.
The 20× gap in silent-delivery rate is what that asymmetry is worth.

### Which families work, and what they cost the attacker

Each family run alone against the same 120 messages under the same budget:

| ID | Family | Escapes block | Silent delivery | Mean drop | Max drop | Median queries to evade | Attacker cost |
|---|---|---|---|---|---|---|---|
| A-UNI | Unicode and homoglyph obfuscation | 0.03333 | 0.00000 | 0.01066 | 0.33122 | 5.0 | Low |
| A-URL | URL obfuscation and redirection | 0.03333 | 0.00000 | 0.01091 | 0.38973 | 10.5 | Low to medium |
| A-LEX | Lexical and semantic perturbation | 0.01667 | 0.00000 | 0.00243 | 0.20786 | 4.5 | Low |
| A-HDR | Header and identity shaping | 0.01667 | 0.00000 | 0.00514 | 0.23527 | 7.0 | Medium |
| A-STRUCT | Structural and HTML manipulation | 0.00833 | 0.00000 | 0.00031 | 0.01791 | 5.0 | Low |
| A-BEH | Behavioural and timing mimicry | 0.00833 | 0.00000 | 0.00067 | 0.01126 | 2.0 | High — low-and-slow sending cuts campaign reach |

Read this table with 1/120 = 0.00833 in mind. The bottom two rows are *one
message each*, and the gap between A-LEX at 0.01667 and A-STRUCT at 0.00833 is
a single message. Differences of one or two escapes are not significant at this
sample size; the ordering is indicative, not established.

What survives that caveat is the shape. The two families the composed attacker
actually reaches for — A-URL (used on 54 of 120 messages, 45%) and A-UNI (46
messages, 38%) — are the two with the largest single-message drops (0.389 and
0.331) and the cheapest execution. A-LEX is used on 14 messages and A-HDR on
one; A-STRUCT and A-BEH are never selected by the composed attacker at all,
which is consistent with their near-zero solo effect. The most-used individual
transforms are `A-URL-01` (36 uses) and `A-UNI-01` (36 uses).

No family run alone achieves a single silent delivery. The one silent delivery
in the whole suite comes from composition.

The right-hand column is the part a purely numerical table would lose. A-BEH's
0.00833 is not merely a small number: the transform that produces it requires
low-and-slow sending, which cuts the attacker's campaign reach — they pay for
the evasion in delivered volume. A-HDR is cheap on the attacker's own domain
and impossible on the brand's real one, because that is domain compromise,
which is out of scope (`OOS-1`) and an authentication problem rather than a
classification one.

### What the decision policy does under attack

Macro F1 hides the movement that matters, because a message that slides from
BLOCK into REVIEW is still counted correct. The banded view, measured on the
raw score surface:

| Traffic | ALLOW | REVIEW | BLOCK | Review rate | Phishing allowed | Legitimate blocked |
|---|---|---|---|---|---|---|
| Clean | 939 | 5 | 993 | 0.00258 | 1 | 0 |
| Under attack | 940 | 11 | 986 | 0.00568 | 2 | 0 |

Seven messages move out of BLOCK. Six of them stop in REVIEW; one reaches
ALLOW. The review rate roughly doubles, from 0.26% to 0.57% of traffic, and
auto-decided recall falls from 0.99899 to 0.99798. No legitimate message is
blocked in either condition.

### Interpretation: what the attacker gets, and what it costs

The attacker's realistic achievement against this system is **displacement, not
evasion**. Twelve queries per message, composed across six families, converts
roughly seven in a thousand test messages from an automatic quarantine into a
human decision, and one message in 120 into an inbox delivery. The defence's
failure mode is graceful: the load lands on the analyst queue, where a human
is looking, rather than on the recipient.

Three things make that displacement expensive. The budget is spent — a median
of 24 queries against a live scoring endpoint for the messages that do evade,
which is exactly the pattern rate limiting and the `phishguard_auth_failures_total`
alert exist to make visible. The transforms that work best are the ones the
defence has already partly folded away, so the marginal query buys less than
the first. And the families that would move the behavioural block cost the
attacker campaign reach, which is the resource phishing economics actually
depend on.

The honest counter-statement: this is measured against transforms this project
wrote. See §7.12.

### The measurement surface

The composed attack is run against the **raw, pre-calibration fusion score**,
not the calibrated probability the API returns. This is deliberate and it is
conservative. The isotonic calibrator saturates: it maps almost everything to
approximately 0 or approximately 1, so an attacker probing the calibrated
output gets almost no gradient to climb and would appear to fail completely.
That would flatter the defence rather than measure it.

Measured against the calibrated surface the API actually exposes, the numbers
are:

| Surface | Escapes auto-block | Macro F1 drop |
|---|---|---|
| Raw fusion score (reported headline) | 0.06667 | 0.00051 |
| Calibrated score (what the API returns) | **0.01667** | **0.00000** |

The headline figure is therefore an upper bound on what a real attacker
against the deployed API achieves, by a factor of four. Both are reported
because reporting only the flattering one would be dishonest, and reporting
only the conservative one would misdescribe the deployed system.

## 7.5 Modality ablation

What each feature family is worth, holding the model fixed: the `engineered`
member is retrained on each family alone, each pair, and all three. If the
three families were redundant, a single-modality model would match the full
one.

| Families | Features | Macro F1 | PR-AUC | Recall | FPR | Δ vs all three |
|---|---|---|---|---|---|---|
| email | 125 | 0.98502 | 0.99952 | 0.97497 | 0.00426 | −0.01291 |
| url | 107 | 0.93802 | 0.99125 | 0.93193 | 0.05544 | −0.05991 |
| behavioural | 33 | 0.92617 | 0.98745 | 0.88989 | 0.03518 | −0.07176 |
| email + url | 232 | **0.99897** | 0.99996 | 0.99800 | 0.00000 | **+0.00104** |
| email + behavioural | 158 | 0.99173 | 0.99983 | 0.98699 | 0.00320 | −0.00620 |
| url + behavioural | 140 | 0.98657 | 0.99929 | 0.98298 | 0.00959 | −0.01136 |
| email + url + behavioural | 265 | 0.99793 | 0.99996 | 0.99600 | 0.00000 | 0.00000 |

Three readings, in order of how comfortable they are.

**No single family is sufficient.** The best solo family, email at 125
features, is 0.013 macro F1 behind the full set and misses 2.5% of phishing.
URL alone has a 5.5% false-positive rate, which in operation means blocking
one legitimate message in eighteen — unusable. Behavioural alone misses 11% of
phishing. Every pair beats every singleton. The families are complementary,
which is the ablation's first job and it is cleanly answered.

**Pairs behave as the design predicts.** email + url is the strongest pair; the
two families that combine a message's own content with its destinations.
url + behavioural, the pair with no email content at all, still reaches 0.98657
— a model that never reads the body text is within 0.011 of the full set,
which is the clearest single-number statement of how much signal lives outside
the text channel.

**And the uncomfortable one: email + url slightly beats all three.**
0.99897 against 0.99793 — the behavioural family costs **0.00104 macro F1** and
0.002 recall on clean data. This is not a rounding artefact; it is two
additional false negatives on the test set. Adding 33 behavioural features
makes clean accuracy marginally worse.

That result is not hidden and it is not explained away. It is what the
measurement says, and there is a straightforward reason for it: the behavioural
block adds 33 dimensions whose clean-data discriminative power is the weakest of
the three families (0.92617 solo), so on a corpus where email + url already
achieves a 0.0 false-positive rate and 0.998 recall, the extra dimensions can
only add variance. There is no headroom left to buy.

The justification for keeping the family is that it was never bought for clean
accuracy. It was bought for the property in §7.4: it is the family the attacker
cannot rewrite. A-BEH — the only attack family that targets it — has the lowest
attack success rate in the suite (0.00833), the smallest mean score drop
(0.00067), and the only "High" attacker cost in the taxonomy, because forging
"we have exchanged forty emails over two years" requires actually having done
so. The defence ablation in §7.6 shows the same asymmetry from the other
direction: D-ENSEMBLE, which is what makes the decorrelated legs matter,
carries 0.042 of measured ASR.

So the trade is explicit: **0.00104 of clean macro F1, on a synthetic corpus
where clean accuracy is an upper bound anyway, in exchange for the modality
that the project's central robustness claim rests on.** Stated in operational
terms rather than in F1: two extra false negatives on a 1 937-message test set,
against a 20× reduction in silent-delivery rate under attack. If the
behavioural family were dropped, §7.4's table would be the one that changed,
and it is the one that matters.

A caveat that cuts against the ablation itself: this experiment measures the
`engineered` member alone, not the deployed four-member fusion, and it measures
clean accuracy only. A modality ablation run *under attack* would be the
experiment that directly tests the justification just given, and it is not in
this dossier. §7.13 lists it.

## 7.6 Defence ablation

Eight arms. Each retrains a model from scratch with one control disabled, then
attacks it under the same 12-query budget on 120 messages.

| Arm | Clean F1 | Clean FPR | Adv F1 | F1 drop | ASR | Silent delivery | Δ ASR vs full |
|---|---|---|---|---|---|---|---|
| all defences | 0.99948 | 0.00000 | 0.99948 | 0.00000 | 0.03333 | 0.00000 | — |
| without D-NORM | 0.99948 | 0.00000 | 0.99897 | 0.00051 | 0.03333 | 0.00000 | 0.00000 |
| without D-URL | 0.99690 | 0.00533 | 0.99897 | 0.00000 | 0.02500 | 0.00833 | −0.00833 |
| **without D-ADVTRAIN** | 0.99897 | 0.00000 | 0.99483 | 0.00414 | **0.10833** | **0.05833** | **+0.07500** |
| **without D-ENSEMBLE** | 0.99845 | 0.00107 | 0.99535 | 0.00310 | **0.07500** | **0.05000** | **+0.04167** |
| without D-ABSTAIN | 0.99948 | 0.00000 | 0.99948 | 0.00000 | 0.03333 | 0.00000 | 0.00000 |
| without D-VELOCITY | 0.99948 | 0.00000 | 0.99948 | 0.00000 | 0.03333 | 0.00000 | 0.00000 |
| **no defences** | 0.99793 | 0.00107 | 0.99019 | 0.00774 | **0.12500** | **0.10000** | **+0.09167** |

Note that the "all defences" arm scores ASR 0.03333, not the headline 0.06667.
The arms are freshly trained models, not the registered `pg-0bcb098e45`, so the
comparison that is valid here is *between arms*, not between an arm and the
headline.

### Two controls carry the robustness

**D-ADVTRAIN** is the single most valuable control. Removing it triples the
attack success rate (0.03333 → 0.10833) and takes silent delivery from zero to
0.05833 — seven messages reaching inboxes that otherwise reached none — at a
clean-accuracy cost of 0.00051. Training on perturbed copies of the phishing
class is what teaches the members that the perturbations are not the signal.

**D-ENSEMBLE** is second. Removing it more than doubles ASR (0.03333 → 0.07500)
and produces six silent deliveries. This is the decorrelation argument made
measurable: a single model presents one surface to climb, and four members
reading different channels do not move together under the same edit.

Removing both, along with everything else, gives the "no defences" arm: ASR
0.12500 and a silent-delivery rate of 0.10000, which is twelve times the full
system's. The two controls do not simply add — 0.075 + 0.042 = 0.117 against a
measured 0.092 — which is expected, since both are defending against overlapping
parts of the same attack surface.

### Three controls show no measurable effect, and why that is not the same as useless

**D-ABSTAIN and D-VELOCITY cannot appear in this metric by construction.** Both
act *downstream* of the raw fusion score. D-ABSTAIN is the banding policy: it
takes a score and routes it to ALLOW, REVIEW or BLOCK. D-VELOCITY is a
campaign-burst guard applied after calibration. The ablation's ASR is measured
on the raw score surface, upstream of both. A control that never touches the
number being measured cannot move that number, and an ablation reporting
exactly 0.00000 for both is the arithmetic working correctly, not evidence
about their value.

This is a **measurement limitation, and it is the honest description of it**.
The effect of D-ABSTAIN is visible elsewhere in this dossier and it is
substantial: the banded table in §7.4 shows six of the seven messages that
escape BLOCK under attack stopping in REVIEW rather than reaching an inbox.
That *is* D-ABSTAIN, and without it those six are binary decisions that fall
one way or the other. Section 7.8 puts the same control in clean operation:
two phishing messages held for a human at a 0.1% review rate. A metric that
scores that at zero is measuring the wrong surface, and the fix is an ablation
run against the banded outcome rather than the raw score — §7.13.

D-VELOCITY has the additional problem that its input, campaign burst structure,
is only partially exercised by a single-message attack loop. It defends against
volume, and the ablation attacks one message at a time.

**D-NORM's effect is likely masked rather than absent.** Removing it leaves ASR
unchanged at 0.03333, but it does move adversarial F1 (0.99948 → 0.99897).
The most probable explanation is redundancy: D-NORM's job is to fold away
unicode and homoglyph obfuscation, and the ensemble already resists the A-UNI
family well (solo ASR 0.03333, mean drop 0.01066) because D-ADVTRAIN trained
the members on obfuscated copies and because the obfuscation deltas are
retained as nine features, so heavy folding raises the score by itself. With
two other controls already covering that family, removing the third does not
show up. That is a claim about *this* configuration and *this* attack suite;
against a corpus with heavier obfuscation, or with D-ADVTRAIN also disabled,
the arm would very likely separate.

### The D-URL arm anomaly

Removing D-URL *reduces* measured ASR, from 0.03333 to 0.02500. Taken at face
value this says a defensive control makes the system less robust, which is not
credible. Three observations dispose of it:

1. The difference is **one message**. 0.03333 is 4 of 120, 0.02500 is 3 of 120.
   At this sample size that is noise.
2. The same arm is the only low-ASR arm with a **non-zero silent-delivery rate**
   (0.00833 against 0.00000 for the full system). By the definition that
   actually matters operationally, this arm is worse, not better.
3. It is also the worst arm for clean accuracy: macro F1 0.99690 against
   0.99948, and a clean false-positive rate of **0.00533** against 0.00000 —
   five legitimate messages blocked that the full system delivers. URL
   canonicalisation earns its place on clean data alone.

The anomaly is best read as a reminder of what a 120-message attack sample can
and cannot resolve: ±1 message is ±0.0083 of ASR, so any arm within about one
percentage point of another is indistinguishable. Only the D-ADVTRAIN
(+0.075), D-ENSEMBLE (+0.042) and no-defences (+0.092) deltas are large
enough — nine, five and eleven messages respectively — to be worth interpreting
at all.

## 7.7 Calibration and the operating point

| Metric | Value |
|---|---|
| Method | isotonic regression, fitted on the disjoint `cal` pool (n = 1 214) |
| ECE (calibrated) | **0.00099** |
| MCE (calibrated) | 0.00103 |
| ECE (uncalibrated fusion) | 0.00472 |

Gate **G4** allows an ECE up to 0.08; observed 0.00099. Calibration matters
here for a specific reason: the ALLOW/REVIEW/BLOCK thresholds are compared
against a probability, so if 0.80 does not mean "80% likely to be phishing",
the policy is arbitrary.

**The near-zero ECE should not be read as a hard calibration problem solved.**
The reliability curve explains why. Of fifteen bins, two hold essentially all
the mass:

| Score bin | Count | Mean predicted | Observed frequency |
|---|---|---|---|
| 0.000 – 0.067 | 938 | 0.00003 | 0.00107 |
| 0.133 – 0.200 | 1 | 0.15152 | 0.00000 |
| 0.667 – 0.733 | 1 | 0.71288 | 1.00000 |
| 0.733 – 0.800 | 1 | 0.79968 | 1.00000 |
| 0.800 – 0.867 | 1 | 0.85719 | 1.00000 |
| 0.867 – 0.933 | 1 | 0.89415 | 1.00000 |
| 0.933 – 1.000 | 994 | 0.99994 | 1.00000 |

Every remaining bin is empty. Isotonic regression fitted to a pool this
separable approaches a step function, and a step function that is right about
which side each message falls on has an excellent ECE almost trivially. The
calibrator here is confirming a separation the corpus already provides, not
resolving genuine uncertainty. On real mail, where scores populate the middle
of the range, this number would be materially worse and the isotonic fit —
which is non-parametric and can overfit a small calibration pool — would need
re-examining. The confidence profile makes the same point from the other
direction: confidence is defined as |score − 0.5| × 2, and **1 931 of 1 937**
messages fall in its top decile — within 0.05 of certainty in one direction or
the other — with accuracy 0.99948 in that bin.

### The operating point

`at_operating_point` answers an operational question: which threshold delivers
the target false-positive rate of 0.02? On this run:

| Field | Value |
|---|---|
| Target FPR | 0.02 |
| Derived threshold | **0.03215** |
| Achieved FPR | 0.00213 |
| Macro F1 at that threshold | 0.99845 |
| Recall at that threshold | 0.99900 |

The threshold is well below the deployed block threshold of 0.80, which is the
expected shape: on a corpus this separable, almost any cut-off above the noise
floor satisfies a 2% false-positive budget, and the deployed thresholds are set
higher than the budget requires in order to leave the REVIEW band room to do
its job.

**An implementation note worth recording, because it is a general trap.** An
earlier revision computed this threshold as the (1 − target) quantile of the
negative-class scores. That is wrong whenever the score distribution has a mass
point, which is the normal case for a well-separated calibrated model: 938 of
938 legitimate messages here score at or near 0.0, so the 98th percentile of
the negatives *was* 0.0, and a threshold of 0.0 under the `score >= threshold`
comparison used everywhere else classified all 1 937 messages as phishing — a
reported false-positive rate of 1.0 while nominally targeting 0.02. The routine
now searches the achieved false-positive rate directly over the distinct
negative scores and steps strictly above the largest negative when the budget is
zero. Two regression tests in `tests/unit/test_metrics.py` pin the behaviour.

The episode is worth keeping in the dossier for two reasons. The failure was
silent — the number looked like a number — and it was caused by exactly the
property §7.12 identifies as this evaluation's central weakness: a synthetic
corpus that the model separates almost perfectly.

## 7.8 Decision bands in operation

The deployed three-way policy applied to the test set, on the calibrated
scores the API returns:

| Outcome | Count | Share |
|---|---|---|
| ALLOW (deliver) | 939 | 48.48% |
| REVIEW (analyst queue) | 2 | **0.10%** |
| BLOCK (quarantine) | 996 | 51.42% |

| Metric | Value |
|---|---|
| Review rate | 0.00103 |
| Auto-decided | 1 935 of 1 937 |
| Auto-decided macro F1 | 0.99948 |
| Auto-decided FPR | 0.00000 |
| Auto-decided recall | 0.99900 |
| **Phishing auto-allowed (missed)** | **1** |
| **Legitimate auto-blocked** | **0** |
| Phishing held in REVIEW | 2 |
| Legitimate held in REVIEW | 0 |

Auto-decision metrics deliberately exclude the review band: a message a human
has been asked to look at is neither a false positive nor a missed detection
until the human decides. Review volume is reported alongside so the trade is
visible rather than hidden.

Both messages routed to REVIEW are phishing, and no legitimate message is
routed there at all — so on this corpus the band is doing exactly what
[ADR-006](adr/006-abstention-band.md) intends: it catches genuinely uncertain
phishing rather than generating analyst work from ordinary mail.

A 0.1% review rate is, however, an artefact of the same separability discussed
throughout. Real traffic will produce far more mass between 0.40 and 0.80, and
the operationally relevant question — how many analyst-hours per thousand
messages — cannot be answered from this corpus. The `PhishGuardReviewQueueGrowing`
alert fires at a sustained 35% review rate for exactly that reason: the number
that matters is the one observed in deployment, not the one measured here.

## 7.9 Latency

150 single-message assessments through the full decision path, as served by
`POST /api/v1/scan`:

| Percentile | With explanation | Without explanation |
|---|---|---|
| Mean | 38.045 ms | 8.143 ms |
| p50 | 37.299 ms | 7.855 ms |
| p95 | **44.816 ms** | 11.522 ms |
| p99 | 46.820 ms | 12.482 ms |
| Max | 49.560 ms | 12.742 ms |
| Throughput | 26.3 msg/s | 122.8 msg/s |

Gate **G7** requires p95 under 150 ms on the inline mail path; observed
**44.816 ms**, a 3.3× margin. p95 rather than mean, because it is the tail that
causes queue backlog at a gateway.

The interesting number is the difference between the two columns. Evidence
generation — counterfactual occlusion over the engineered model, rule
attribution, token attribution — costs roughly **30 ms**, about four fifths of
the total. Scoring itself is 8 ms. That is a deliberate and reversible trade:
explanation is what makes the human-oversight control real, and if a deployment
ever needed the headroom, `explain=false` recovers a 4.7× throughput
improvement without touching the verdict. Batch throughput is materially higher
than the single-message figure, since the fixed costs amortise.

These are single-process, single-machine numbers on the evaluation host, with
no network, no gateway and no concurrent load. They establish that the model is
not the bottleneck; they do not establish deployment capacity.

## 7.10 Error analysis

**One error across 1 937 test messages** (error rate 0.00052), and it is a
false negative:

| Failure mode | Count |
|---|---|
| missed: cloned legitimate template, signal is header/URL only | 1 |

The single most confident mistake:

| Field | Value |
|---|---|
| Lure type | `clone` |
| True label | phishing |
| Assigned score | **0.0000** |
| Sender domain | `park-field.in` |
| Subject | `Your verification code is 925765` |
| Severity | 0.5 |

This one message is worth more attention than its count suggests, because it
is a precise instance of the hardest case in the threat model. A cloned
template carries no lexical signal at all: the body is a legitimate
verification-code email, so every text member reads it as benign and is
correct to do so. The only evidence available is the sending domain and the
URL structure. The model did not merely get it wrong — it scored the message at
**0.0**, maximally confident in the wrong direction, which means the header and
URL evidence was not merely outweighed but effectively absent.

Two structural points follow. First, this is the failure mode the tri-modal
design exists to prevent, and here it prevented nothing; the clone slice is
where the argument in [§2.6](02-architecture.md) is weakest, not strongest.
Second, a single error is not a basis for any statistical claim about error
structure. One data point identifies a category worth watching; it cannot
support a statement about that category's frequency, and a corpus that
generates one error in two thousand messages cannot support error analysis in
the usual sense at all. The categories exist so that the analysis is ready to
run on a corpus that produces enough errors to analyse.

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

Every slice with more than one class scores at or above 0.99833 macro F1, and
**the false-positive rate is 0.00000 in every slice without exception**. All
variation is in recall, and the single test-set error propagates into every
slice that contains it:

| Slice group | Weakest value | n | Recall | Errors | Strongest value | n | Recall |
|---|---|---|---|---|---|---|---|
| Lure type | `clone` | 335 | **0.99701** | 1 | the other 14 phishing lures | — | 1.00000 |
| Body length | short (<250) | 861 | **0.99485** | 1 | medium (250–800) | 1 076 | 1.00000 |
| Authentication | auth all pass | 1 160 | **0.99696** | 1 | auth imperfect | 777 | 1.00000 |
| HTML | text only | 1 566 | 0.99866 | 1 | html part | 371 | 1.00000 |
| Links | with links | 1 828 | 0.99898 | 1 | no links | 109 | 1.00000 |
| Attachments | no attachment | 1 800 | 0.99887 | 1 | with attachment | 137 | 1.00000 |

Read down the "weakest" column: `clone` lure, short body, authentication fully
passing, text-only, has links, no attachment. That is one message — the
`park-field.in` verification-code clone from §7.10 — appearing six times.
Nothing here identifies six weaknesses; it identifies one message with six
attributes.

The attributes are nonetheless the right ones to worry about, and they are
coherent. `auth imperfect` (n = 777, 86% phishing) achieves perfect recall
because a failed SPF or DMARC check is close to decisive. `auth all pass`
(n = 1 160, only 28% phishing) is where phishing has to be caught on content,
behaviour and URL structure alone, and it is where the error lives. Short
bodies give the text members less to read. The `clone` slice is the largest
single lure type in the test set at 335 messages and, by design, the one whose
text carries no signal.

**Behavioural context is supplied for all 1 937 test messages**, so the
"behavioural context" slice has only one value and the comparison that would be
most informative — with context against without — is not measured here at all.
Deployments where the gateway supplies no sender history are exactly the case
the `PhishGuardBehaviouralContextMissing` alert watches for, and §7.5's
`email + url` row (0.99897) is the closest available proxy for what that
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

**A clean macro F1 of 0.99948 is an upper bound and must not be read as a
real-world detection rate.** The same applies to the 0.0 false-positive rate,
the single test-set error, the 0.1% review rate and the 0.00099 ECE. On real
mail, all of these would be substantially worse; the honest position is that
this dossier does not know by how much.

What transfers far better is everything **comparative**: fusion against B0 and
B1, the modality ablation, the defence ablation, and the robustness comparison
in §7.4. Those are measured under identical conditions on identical data, so
the generator's peculiarities largely cancel. The claim "the tri-modal fusion
degrades far less under attack than a text-only model" is well supported by
this evidence. The claim "this system detects 99.9% of phishing" is not
supported by it at all.

### Robustness is measured against attacks this project designed

Thirty transforms across six families, composed under a query budget, is a
serious test. It is also a test whose contents were chosen by the same people
who built the defence, which makes it structurally incapable of finding the
attack nobody thought of. A genuinely novel family is by construction untested,
and the residual-risk register records that rather than pretending otherwise.

The point is sharper than it sounds: D-ADVTRAIN *trains on these same
transforms*. Part of the measured robustness is therefore a defence trained on
its own examination paper. The generalisation question — does training on
these thirty transforms produce resistance to a thirty-first — is not answered
here, and the leave-one-family-out training experiment that would begin to
answer it is in §7.13.

### The attack surface is more generous than the API

The headline attack success rate is measured against the raw pre-calibration
score, which gives the attacker a finer-grained oracle than any real client can
observe. This is deliberate and conservative — a saturated calibrator would
report near-zero attack success and flatter the defence — and the calibrated
figure is reported alongside it (0.01667 against 0.06667). But it does mean the
headline robustness number describes a *stronger* adversary than the deployed
system faces, while the modality and defence ablations inherit the same
generous surface.

### The hard cases are not hard enough

The hard subset was assembled to be the honest read of the system's ceiling:
cloned templates, BEC, thread hijacking, legitimate mail with a phishing-shaped
surface. It scores macro F1 **0.99846** — 0.001 below the full test set, with
the *same single error*. A subset that was genuinely hard would separate from
the whole by considerably more than that. The most likely explanation is that
the generator cannot produce the ambiguity that makes real cases hard: a real
BEC message from a genuinely compromised colleague's account is hard because
there is almost nothing to find, and a generator that has to label its own
output cannot easily manufacture that.

Treat the hard-subset figures as evidence that the difficulty controls worked
directionally, not as a measurement of the system's ceiling.

### Single run, no confidence intervals

Every number is from one run, with one corpus seed (20260907), one split seed
(11) and one attack seed (7). There are no error bars anywhere in this
document. This matters most where the differences are smallest:

- The modality ablation's central finding, email + url exceeding all three
  families, is a gap of **0.00104 macro F1** — two messages. A second seed
  could plausibly reverse its sign.
- Defence-ablation ASR differences below about 0.01 are single messages out of
  120; the D-URL anomaly in §7.6 is one message.
- The single test-set error means the error analysis in §7.10 and the slice
  analysis in §7.11 rest on one data point.

The large effects — the 0.48333 ASR advantage over B1, D-ADVTRAIN's +0.075,
D-ENSEMBLE's +0.042, the 0.08839 delta over B0 — are large enough that seed
variance is unlikely to explain them. Everything below roughly 0.01 in this
dossier should be treated as unresolved.

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
- **Latency is single-process and unloaded.** It shows the model is not the
  bottleneck; it does not size a deployment.

## 7.13 What would make this stronger

In descending order of how much each would change the confidence in the
conclusions.

**1. Multi-seed runs with confidence intervals.** Ten seeds across corpus
generation, splitting and attack, reporting mean and interval for every headline
figure. This is the cheapest improvement available — it is a loop around
`phishguard evaluate` — and it would resolve, one way or the other, whether the
behavioural family's clean-accuracy cost in §7.5 and the D-URL anomaly in §7.6
are real. No claim below 0.01 in this dossier should be defended without it.

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
training, where D-ADVTRAIN is trained on five families and evaluated on the
sixth, which tests generalisation to unseen transforms without needing an
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
designed. This would also give the REVIEW band a real cost model, which §7.8
currently lacks: the 0.1% review rate means nothing without knowing what a
review costs.

**6. Ablations on the right surface.** Two specific fixes to §7.5 and §7.6.
Run the modality ablation *under attack* rather than on clean data only, which
is the experiment that directly tests the justification given for keeping the
behavioural family. And run the defence ablation against the **banded outcome**
rather than the raw score, so that D-ABSTAIN and D-VELOCITY can register an
effect at all instead of being scored at zero by construction.

**7. Calibration under shift.** The 0.00099 ECE is measured on the training
distribution. Deliberately shifting the test distribution — a different lure
mix, a different phishing ratio, messages from a later time period — and
re-measuring ECE would show whether the isotonic fit survives contact with
anything it has not seen, which is the question §7.7 raises and cannot answer.

---

**Next:** [§8 Deployment guide →](08-deployment-guide.md)
