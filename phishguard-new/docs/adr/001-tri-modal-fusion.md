# ADR-001: Fuse three independent feature families rather than train one strong text model

- **Status**: Accepted
- **Date**: 2026-09-07
- **Deciders**: Capstone team (BAI-17)

## Context

The problem brief says detectors do well on a fixed dataset and fail when
attackers alter spelling, domains or style. That failure has a location: the
channel the sender authors. Four of the six families in the original taxonomy in
`src/phishguard/adversarial/taxonomy.py` (A-LEX, A-UNI, A-STRUCT and most of
A-HDR) operate there and cost the attacker nothing. (The taxonomy has since
grown to eight families; see [§4.5](../04-threat-model.md).)

Clean accuracy does not decide the question. Baseline B1, a word TF-IDF logistic
regression, reaches macro F1 0.98812 with a 0.21% false-positive rate; the full
system reaches 0.99948. Eleven thousandths of macro F1 is not a design argument,
and anyone choosing on that number alone should build B1 and stop.

The generator makes the real problem explicit. `_clone_campaign` in
`src/phishguard/data/synthetic.py` produces phishing that copies a brand's
genuine transactional email verbatim, changing only the link and the sending
domain, because that is what a real credential-phishing kit does. On those
messages the body carries no discriminating signal at all: the words are the
brand's own. The question is not which model is most accurate, but where the
discriminating signal sits relative to what the attacker controls.

## Decision

The detector fuses four members reading different views: `rules` (a 37-rule
checklist, no learning), `engineered` (a `HistGradientBoostingClassifier` over
265 features in a fixed, contract-verified order: 125 email, 107 URL, 33
behavioural), `charngram` (char_wb 3-5 TF-IDF with logistic regression) and
`wordtfidf` (word 1-2 TF-IDF with logistic regression). A logistic fusion
combines their scores and isotonic calibration follows. The arrangement is
registered as control D-ENSEMBLE; a transformer member exists behind
`use_transformer` and is off by default.

The behavioural family carries the argument. Text and URL features live in a
space the attacker controls directly. Behavioural features do not: forging "we
have exchanged forty emails over two years" requires having done so, and a
domain cannot be aged retroactively.

## Alternatives considered

### A single fine-tuned transformer over message text

Best clean accuracy per unit of engineering effort, no feature extractors to
keep in sync with a frozen contract, real handling of paraphrase and semantics,
and transfer to languages no hand-built lexicon covers. Most recent literature
does this.

Rejected because it reads one channel, and it is the one the attacker authors
for free. It cannot see a link-text-versus-href mismatch, a Reply-To divergence,
a domain three edits from the brand's, or that this sender has never written to
this recipient. On the clone slice it reads the brand's own prose and has
nothing to work with. The CPU latency gate (G7, p95 under 150 ms) is a secondary
objection.

### TF-IDF plus logistic regression (baseline B1)

Genuinely strong: 0.98812 macro F1, two false positives on 938 legitimate
messages, trains in seconds, and every decision decomposes exactly into token
contributions. It is the kind of baseline that embarrasses over-engineered
systems, which is why it stays in the dossier.

Rejected on what happens under attack. Against the same budgeted black-box
attacker, B1's attack success rate is 0.55 and its silent delivery rate 0.16667;
the fusion's are 0.06667 and 0.00833. Roughly one attacked message in six
reaches a B1-protected inbox unexamined.

### The engineered model alone, without the ensemble

Cheaper, and the modality ablation shows email plus URL reaching 0.99897,
slightly above the full tri-modal 0.99793, so on clean data the ensemble buys no
accuracy.

Rejected because a single view is a single point of failure: a perturbation that
moves it moves the whole decision. Disagreement across members is itself
meaningful, since a message that moves some views and not others is the
signature of evasion rather than of an ordinary borderline case. This design is
kept as the D-ENSEMBLE=off ablation arm.

## Consequences

**Positive**

- Attack success 0.06667 against 0.55 for the text-only baseline, on 120 attacked
  messages at a 12-query budget; gate G9 records the 0.48333 advantage.
- Macro F1 under the composed attack drops by 0.00051, and no single attack
  family exceeds 0.03333 success on its own.
- Evidence can cite a header or URL reason when the text is clean, which is the
  clone case an analyst most needs explained.
- Every member and family ablates independently, so each contribution is
  measured rather than asserted.

**Negative**

- Roughly four times single-model inference cost: p95 44.816 ms with evidence
  generation, 11.522 ms without.
- 265 feature extractors are a real maintenance surface. The contract is frozen
  into the model and verified on load as a hard failure, because a model served
  against a shifted layout produces plausible numbers that are wrong.
- The behavioural family is absent from every public corpus and from any gateway
  supplying no sender history. There, 33 of 265 features sit at neutral defaults
  and the robustness case weakens to what email and URL carry alone.
- Adding the behavioural family costs clean accuracy: 0.99793 against 0.99897 for
  email plus URL. It is bought for robustness and paid for in accuracy.

**Neutral / accepted trade-offs**

- Fusion weights are published (engineered 4.86895, charngram 3.38557,
  wordtfidf 3.27974, rules 1.89621), so where the decision comes from is
  inspectable.
- The transformer member is implemented but disabled, keeping the option open
  without putting it on the critical path.
- `rules` contributes little accuracy alone (0.91109) and is kept because it is
  the baseline to beat and its evidence is the most readable.

## Evidence at release 1.3.0 (22 September 2026)

The figures above are from the 7 September decision run; this section gives
the current ones, for model `pg-0e0dffa24f`, as reported in the
[evaluation dossier](../07-evaluation-dossier.md).

- Clean macro F1: fusion 0.98805, B1 0.97709, `rules` 0.89540. The gap to B1
  is 0.01096, and at a 0.5 cut-off B1 now makes no false positive on 1038
  legitimate messages, where the fusion makes one.
- Ordinary attack (150 phishing messages, a 10-query budget, the attack suite
  as corrected in 1.3.0): attack success 0.00000 for the fusion against
  0.29333 for B1, which is the G9 advantage. Silent delivery is 0.00000 for
  both, so B1 no longer delivers anything unexamined on this set. The reported
  macro F1 drop is 0.00000, and no family run alone moves a message out of
  auto-quarantine.
- The silent-delivery gap now shows only on PG-HARD: an adaptive attacker with
  120 queries gets 3 of 48 hard phishing records past PhishGuard unwarned
  (6.2%) and 43 of 48 past the text-only filter (89.6%).
- The D-ENSEMBLE=off arm, the `engineered` member alone, lets 12 of 120
  attacked messages escape auto-block, all of them silently (attack success
  0.10000 against 0.00000 for the full system), and scores clean macro F1
  0.97826 with a false-positive rate of 0.03372.
- The modality ablation has reversed: all three families reach 0.98651 and
  email plus URL 0.98446, so the behavioural family no longer costs clean
  accuracy. The lead over url plus behavioural (0.98598) is one message, and
  the dossier treats neither the old deficit nor the new gain as large enough
  to argue from.
- Cloned brand templates, the Context's motivating case, are now the main
  failure: 19 of the 22 phishing messages missed at a 0.5 cut-off are clones
  whose only signal is the header and the URL, and the dossier calls the clone
  slice the place where this argument is weakest, not strongest.
- Latency for a single message: p95 17.228 ms with evidence generation,
  10.219 ms without.
- Fusion weights: `charngram` 5.04403, `wordtfidf` 4.37399, `engineered`
  4.06316, `rules` 2.21593.

The decision holds, but on the ground given against the third alternative
(members that disagree under attack, which abstention then sends to a human)
more than on the one in the Decision section: under the 120-query PG-HARD
attack the `engineered` member's mean score fell from 0.691 to 0.376 and
`rules` from 0.477 to 0.141, while `charngram` and `wordtfidf` barely moved
(0.821 to 0.758, 0.846 to 0.780), and the behavioural family's benefit under
attack is argued rather than measured, because no experiment removes it and
then attacks.

The third trigger below has fired: `engineered` (4.06316) sits below
`charngram` (5.04403) in this model, and the registry manifests of the retrains
immediately before it on 22 September show the same ordering; the dossier lists
the new weights but does not discuss the reversal. The fourth has not fired for
a single message (p95 17.228 ms), but under concurrent load the p95 with
evidence reached 150.7 ms at eight requests in flight in the evaluation's load
run (133.7 ms in the CLI load test, 70.6 ms at four); 1.3.0 scores one request
at a time per process, and the dossier's sizing guidance is to keep fewer than
eight requests waiting per process and add processes for throughput. The first
two have not fired: no live traffic has been measured, and the advantage over
B1 is 0.29333.

## Revisit when

- Behavioural context is unavailable for more than 20% of live traffic, making
  the family dead weight for a fifth of the mail.
- The attack-success advantage over B1 falls below 0.15, or any text-only model
  measures below 0.10 attack success at the same budget.
- The `engineered` member's fusion weight falls below `charngram`'s across two
  consecutive retrains.
- Inference p95 with evidence exceeds 100 ms, leaving no headroom under the
  150 ms gate.
