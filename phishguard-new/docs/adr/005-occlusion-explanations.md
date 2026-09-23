# ADR-005: Use counterfactual occlusion for tree-model attributions instead of SHAP

- **Status**: Accepted
- **Date**: 2026-09-07
- **Deciders**: Capstone team (BAI-17)

## Context

Every verdict carries an evidence list, because a blocked message an analyst
cannot interrogate is a decision nobody can oversee. Two of the three
attribution paths are exact by construction. The fusion is logistic regression
over member scores, so a member's contribution to the log-odds is `coef * score`
by definition. The text members are linear over TF-IDF, so a token's
contribution is `coef * tfidf`.

The third path is the problem. The `engineered` member is a
`HistGradientBoostingClassifier` over 265 features and carries the largest
fusion weight (4.86895), so it is both the member that decides the most and the
only one with no linear decomposition. Whatever method is chosen supplies most
of the feature-level evidence an analyst reads.

Mixing an exact quantity and an approximate one in one ordered list, unmarked,
is a specific hazard for an audit trail: the analyst sees "contribution 0.31"
next to "contribution 0.28" with no way to know that one is a definition and the
other an estimate with an unstated error bar. There is also a cost constraint:
the service explains every decision rather than only the ones an analyst opens,
under a p95 latency gate of 150 ms.

## Decision

`engineered_attributions` in `src/phishguard/explain/attributions.py` computes
counterfactual occlusion. Each candidate feature is replaced by a neutral
reference value and the model re-scored; the drop is that feature's
contribution, in probability units. The reference is zero for the count and flag
features that dominate the vector, with 22 explicit overrides in
`_NEUTRAL_OVERRIDES` where zero would mean the opposite of neutral: a lookalike
edit distance of zero means an exact brand match, a domain age of zero means a
domain registered today.

Only features that actually deviate from the reference are occluded, capped at
24 by largest deviation, and the whole set is evaluated as one batched
prediction of K+1 rows. This answers the question the analyst is asking: what
would the score have been if this signal had been normal.

## Alternatives considered

### TreeSHAP

The strongest case is a good one. TreeSHAP computes exact Shapley values for
tree ensembles in polynomial time, so it is not an approximation in the way
sampling methods are. It has an axiomatic grounding occlusion lacks: efficiency
means contributions sum to the prediction, and symmetry and dummy give it
properties an ad hoc method must argue for case by case. It handles interactions
correctly, which occlusion does not, and the notation is one reviewers recognise
on sight.

Rejected because Shapley values answer a different question. A Shapley value is a
feature's fair share of the deviation from a base value, averaged over all
orderings of the others. The analyst is asking whether the message would still
have been blocked if the sending domain had been ordinary. That is a single
counterfactual, it has an exact answer here, and it costs one batched prediction
over 25 rows. The loss of interaction attribution is real and is recorded below
rather than argued away.

### Permutation or global feature importance

Cheap, stable, model-agnostic, and it needs no reference vector curated by hand.
It is already the right tool for the model card's account of what the model
relies on in general.

Rejected for per-decision evidence because it is global by construction. It can
say `hdr_display_brand_domain_mismatch` matters across the corpus; it cannot say
why this message scored 0.97, which is the only question a reviewer has.

### LIME

Model-agnostic, per-instance, widely understood, and it would apply uniformly
across every member rather than needing a different method per model type.

Rejected because it fits a surrogate on sampled perturbations, so the
explanation is a local approximation of a local approximation, and it is
stochastic: two identical requests can produce different evidence. In an audit
trail meant to be defensible months later, an explanation that does not
reproduce is worse than none.

## Consequences

**Positive**

- Contributions are real counterfactuals in probability units, so the evidence
  card can state that the score falls by a given amount if the signal is normal,
  and that sentence is literally true of the model.
- Deterministic, so the stored evidence titles in the audit trail can be
  reproduced on demand.
- No extra dependency, and nothing to keep in version lockstep with
  scikit-learn's tree internals.
- One vectorised call over at most 25 rows, which is why every decision is
  explained rather than only the ones somebody opens.

**Negative**

- Occlusion is single-feature and attributes nothing to interactions. This cuts
  against the reason a gradient-boosting model was chosen at all: the signal is
  genuinely interactive, and a new domain making a credential request at 03:00 is
  exactly the case whose joint effect the attributions cannot show.
- Correlated features share credit badly. `url_is_https`, `url_is_https__max`
  and `url_is_https__mean` move together and each is occluded as though the
  others were fixed. Contributions therefore do not sum to the score and must
  never be presented as though they did.
- The neutral reference is a hand-curated table of 22 overrides plus an implicit
  zero for the other 243 features. It encodes a judgement about what normal
  means, is not derived from the training distribution, and a wrong entry
  produces a confidently wrong explanation rather than a visibly broken one.
- Capping candidates at 24 by absolute deviation can miss a feature with a small
  deviation and a large effect, because deviation size is a proxy for influence
  rather than a measure of it.

**Neutral / accepted trade-offs**

- Explanation cost is visible in the latency profile: p95 44.816 ms with evidence
  generation against 11.522 ms without, well inside the gate but not free.
  Occlusion is one component; rule evaluation, token attribution and phrase
  rendering are the rest.
- Three methods for three model types makes the evidence list heterogeneous by
  design, which is why each item carries an explicit `kind`.
- Member disagreement is reported alongside the attributions as its own signal,
  since a message that moves some views and not others is the signature of an
  evasion attempt.

## Evidence at release 1.3.0 (22 September 2026)

The figures above are from the 7 September decision run; this section gives
the current ones, for model `pg-0e0dffa24f`, as reported in the
[evaluation dossier](../07-evaluation-dossier.md).

- `engineered` no longer carries the largest fusion weight: it is 4.06316,
  third of four behind `charngram` (5.04403) and `wordtfidf` (4.37399), with
  `rules` at 2.21593, so the Context's premise that it is the member that
  decides the most does not hold on the weights.
- Latency for a single message: p95 17.228 ms with evidence generation,
  10.219 ms without.
- Evidence generation as a whole (occlusion, rule attribution and token
  attribution) costs roughly 5 ms at the mean, 12.451 ms against 7.101 ms, a
  little over two fifths of the total; `explain=false` raises single-message
  throughput from 80.3 to 140.8 messages a second without changing the
  verdict.

The decision holds: it rested on the question occlusion answers (one exact
counterfactual per signal), on determinism and on cost, and the current figures
weaken none of them.

The last trigger below has not fired for a single message (p95 17.228 ms) but
is passed under concurrent load: with explanations on, one process reached a
p95 of 150.7 ms at eight requests in flight in the evaluation's load run
(70.6 ms at four), where extra concurrency lengthens the wait, not the work;
the dossier's answer is to keep fewer than eight requests waiting per process
and, if a deployment needs the headroom, to turn explanations off. None of the
others has fired, and the first has not been tested: no analyst study of the
evidence has been run.

## Revisit when

- Analyst review finds cards regularly citing a feature whose counterfactual
  contribution points the opposite way from the verdict, indicating the reference
  table has drifted from what normal looks like.
- The `engineered` member is replaced by a model with an exact decomposition, in
  which case use the decomposition and delete this code.
- An investigation genuinely needs interaction attribution. The answer then is
  TreeSHAP as a second, offline method available on demand, not as the inline
  one.
- `_NEUTRAL_OVERRIDES` grows past roughly 40 entries, meaning normal has stopped
  being a simple idea and should be estimated from the training set rather than
  declared.
- The explained path's p95 approaches 100 ms.
