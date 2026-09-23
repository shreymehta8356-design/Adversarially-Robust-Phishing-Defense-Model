# ADR-006: Use a three-way ALLOW / REVIEW / BLOCK decision instead of a binary one

- **Status**: Accepted
- **Date**: 2026-09-07
- **Deciders**: Capstone team (BAI-17)

## Context

The two errors this system can make have sharply asymmetric costs and both are
expensive. A false positive quarantines the invoice the finance team is waiting
for, and one high-profile case gets the filter switched off, after which its
recall is zero. The rule baseline it replaces already sits at a 2.2%
false-positive rate, at the edge of what a business tolerates, and gate G3 caps
the system at 0.02. A false negative delivers a working credential lure to
somebody who was told the filter would catch it.

A binary threshold forces every uncertain message into one of those two errors,
silently. The design question is whether uncertainty should be resolved by the
model or surfaced.

The adversary sharpens this. The attacker in
`src/phishguard/adversarial/attacker.py` does not try to make a message look
legitimate in general; it hill-climbs to push the score under a threshold. Under
a binary policy every unit of score clawed back below the line converts directly
into a delivered message, so the region just below the threshold is where the
contest is decided.

## Decision

The decision is three-way. Below 0.40 the message is ALLOWed and delivered. At
or above 0.80 it is BLOCKed and quarantined. Between them it is REVIEW: queued
for an analyst rather than auto-decided, with `Verdict.abstained` set and the
evidence needed to resolve it.

The band is registered as control D-ABSTAIN and can be ablated. `band_of`
collapses to a two-way split on the block threshold when the control is off, so
the value attributable to abstention is measured rather than assumed. Both
thresholds are configuration, published in the model card and returned in every
verdict's `signals` block.

## Alternatives considered

### A single threshold tuned to the false-positive budget

The simpler system, and the case is stronger than it first looks. One number is
easier to explain, tune and audit than two, the operating point can be read off
the precision-recall curve to hit the false-positive gate exactly, nobody has to
be hired to read a queue, and an inline mail path is better served by a policy
that always answers. If the model is well calibrated and the costs are known,
the optimal decision rule genuinely is a single threshold.

Rejected on what the attack data shows about the region below that threshold.
Under the composed attack, 8 of 120 phishing messages were dragged below 0.80.
With a single threshold all 8 would have been delivered; with the band, 7 land
in REVIEW and 1 falls below 0.40 and is delivered silently. Same model, same
attacker, an eightfold difference in what reaches an inbox with no human having
looked. Baseline B1 shows the same effect at a different scale: 66 of 120 escape
the block threshold and 20 are delivered silently.

### A learned reject option with an explicit abstention cost

Theoretically better founded. The cost of an analyst's attention is a real
quantity, the cost of a delivered phish is a real quantity, and learning the
abstention boundary jointly with the classifier under those costs is principled
in a way that picking two constants is not. There is a literature with
guarantees attached.

Rejected because it requires a defensible number for the ratio of those costs,
and this project has measured neither. A boundary resting on an invented cost
ratio looks more rigorous than two published constants while being less honest,
and it hides the policy choice inside the model where an administrator cannot
move it. Two constants the model card publishes, that change without retraining,
and that a calibration gate makes meaningful (ECE at most 0.08 required, 0.00099
observed) are the more defensible arrangement now.

### Return the probability and let the mail gateway band it

Policy belongs at the policy layer, different tenants could choose different
thresholds, and the detector stays a pure scoring function. Several commercial
scanners work this way.

Rejected because the verdict, the evidence and the audit record all have to
agree on what was decided. If the band lives in the gateway, the trail records a
score while the actual decision goes unrecorded, and the after-the-fact question
that justifies the audit store cannot be answered. The calibrated score is
returned alongside the band anyway, so a gateway that wants to override can.

## Consequences

**Positive**

- The band absorbs the attacker's most effective outcome. Dragging a message from
  0.99 to 0.6 buys review, not delivery, so the attacker must travel more than
  twice as far for the same result.
- On clean traffic the band is nearly free: 2 of 1937 test messages land in
  REVIEW (0.1%), both phishing, no legitimate mail queued, while the 1935
  auto-decided messages hold macro F1 0.99948 at a zero false-positive rate.
- D-ABSTAIN is the only control in the catalogue that counters all six attack
  families, because it does not depend on recognising the attack.
- Thresholds are an operational dial: tightening the band during a live campaign
  is a configuration change, not a retrain.

**Negative**

- The band's usefulness is entirely a function of calibration, and the isotonic
  calibrator on this well-separated corpus is close to a step function: 1931 of
  1937 test messages score above 0.9. The band is therefore nearly empty on clean
  data, and its measured value rests on a handful of attacked messages rather
  than a broad distribution of genuinely uncertain ones.
- The analyst queue is a cost the project has not measured against real volume. A
  0.1% review rate is negligible in a dossier and a full-time post at ten million
  messages a day, and no staffing model says which regime a deployment is in.
- Abstention does not remove evasion, it converts some of it into review load. A
  message pushed below 0.40 still evades silently, and 1 of 120 did.
- The two thresholds are chosen rather than derived. 0.40 and 0.80 are defensible
  and are not optimal in any demonstrated sense.

**Neutral / accepted trade-offs**

- The review band is where the analyst feedback loop gets most of its data, which
  is what makes the `analyst_disagreements` drift signal possible at all.
- D-VELOCITY can push a message up into REVIEW but is bounded at +0.15 and capped
  at 0.99, so it can add review load and cannot on its own manufacture a block
  from a clean message.
- Three outcomes means the API contract, the console and the gateway integration
  each carry a case a binary system would not have.

## Revisit when

- The live review rate exceeds what the SOC actually reads: as a working rule,
  more than 1% of volume, or a queue not emptied within a shift.
- Silent delivery rate under the adversarial suite exceeds 0.02, meaning attacks
  reach past the review band rather than being caught by it.
- Measured ECE rises above 0.05. The band boundaries are probability statements,
  and once the probabilities stop meaning what they say the thresholds should be
  re-derived rather than kept.
- Analyst feedback disagrees with the model on more than roughly 20% of REVIEW
  decisions, meaning the band is queuing the wrong messages.
- A defensible measurement of analyst time against phishing loss becomes
  available, making the learned reject option viable.
