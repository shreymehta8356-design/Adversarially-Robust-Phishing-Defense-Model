# ADR-003: Model a decision-based black-box adversary, not a white-box gradient attacker

- **Status**: Accepted
- **Date**: 2026-09-07
- **Deciders**: Capstone team (BAI-17)

## Context

A robustness number is meaningless without a capability model, and both easy
mistakes produce numbers that look rigorous. Grant the attacker everything and
nothing survives, so the measurement says only that the problem is hard. Grant
them typos and everything survives, so it says only that the evaluation was
easy. The value of an adversarial evaluation sits entirely in that boundary.

The realistic boundary is observable. Phishing kits are routinely tested against
public scanners before launch: the operator sends a candidate, sees whether it is
caught, edits, retries. They have complete knowledge of the message they author
and a feedback channel returning a verdict. They do not have the model.

The decision core also constrains what is meaningful. The fusion combines a
37-rule checklist with no learning, a histogram gradient-boosting model and two
linear text models, so there is no differentiable path from message to score.

The last constraint is honesty about the attacked surface. Isotonic calibration
on a well-separated pool approaches a step function: a perturbation moving the
fusion score from 0.995 to 0.93 still maps to 1.0. Attacking the calibrated
output reports zero attack success, not because the model is robust but because
the attacker has been handed a signal with no gradient in it.

## Decision

The adversary is a competent phishing operator with full knowledge of the
message they send and black-box, decision-based query access to the score,
bounded by a query budget (12 in the recorded run). They can rewrite any field
they author, choose their own infrastructure, choose when and how fast to send,
and iterate against observed scores. They cannot change the recipient's history
with them, age their domain retroactively, make the brand's genuine domain send
the mail, or see weights or gradients.

Those boundaries are enforced mechanically: the transforms in
`src/phishguard/adversarial/transforms.py` mutate only attacker-controlled
fields, and `payload_preserved` rejects candidates that have stopped being
working phishing. Six families (A-LEX, A-UNI, A-URL, A-STRUCT, A-HDR, A-BEH)
each map to distinct controls so they score independently. White-box evasion is
recorded as OOS-2 rather than quietly dropped. The suite attacks the raw fusion
score, granting a finer oracle than the deployed API exposes, so the measured
figure upper-bounds real attacker success.

## Alternatives considered

### White-box gradient attacks (PGD, HotFlip, TextFooler with gradients)

The literature standard, and the strongest argument for it is a security one
rather than an academic one: the conservative assumption is that the attacker
knows everything, and a defence that holds only under ignorance is not a
defence. It also produces numbers directly comparable with published work.

Rejected because it assumes the attacker holds the weights, which is a different
problem with a different remedy. If weights leak, the response is artefact
access control, registry auditing, rotation and retraining, not a robustness
claim about the leaked model. OOS-2 records the exclusion and its mitigation.

### Transfer attacks from a surrogate model

No query access needed, which is realistic against a gateway returning nothing
to the sender, and transfer is a real phenomenon that has defeated real filters.

Rejected because the surrogate's fidelity becomes the quantity measured. A
poorly matched surrogate reports high robustness for free, and there is no
principled way to argue one is well matched without the access the threat model
denies. Direct query access is both stronger for the attacker and less dependent
on the evaluator's choices.

### Unbounded query access

Simplest to justify as a worst case, with no budget parameter to defend.

Rejected because it makes the result uninformative. Any threshold-based detector
falls to enough queries; the interesting quantity is how many. Under the
composed attack the mean is 21.14 queries and the median to a successful evasion
is 24, and that is a usable attacker-cost metric only because the budget is
finite and every scored candidate counts as one query.

## Consequences

**Positive**

- The headline numbers describe something an operator can act on: composed
  attack success 0.06667 (8 of 120 messages dragged below the 0.80 block
  threshold) and silent delivery 0.00833 (1 of 120 below 0.40).
- Each family maps to named controls, so the residual-risk register is
  per-family and per-control rather than one aggregate.
- The raw-score surface makes the reported figure a stated upper bound rather
  than an unstated best case; both numbers appear in the dossier.
- Composition and restarts are allowed, so the attacker can stack homoglyphs,
  redirect chaining and business-hours delivery. Testing transforms in isolation
  would badly understate risk.

**Negative**

- A-BEH is simultaneously the family the design is structurally strongest against
  and the one the synthetic corpus makes easiest to model. The measured
  resistance there is the least trustworthy number in the suite.
- The taxonomy is a closed set of six families over a fixed transform library, so
  a genuinely novel technique scores zero by construction. D-ADVTRAIN's residual
  note says this of the control; it applies to the evaluation as a whole.
- The assumption that an attacker cannot fabricate correspondence history fails
  against a compromised legitimate mailbox. OOS-1 puts domain and account
  compromise out of scope, so the defence's strongest leg is absent in exactly
  the highest-impact real incident.
- A budget of 12 queries is a judgement, not a measurement. Nobody has observed
  how many probes a real operator spends against a filter of this kind.

**Neutral / accepted trade-offs**

- The search is greedy hill-climbing with restarts, not an optimal attack, so the
  reported success rate is a lower bound on what an optimal attacker within the
  same capability model would achieve.
- OOS-3 (poisoning through the feedback loop) is excluded because feedback never
  retrains automatically, and OOS-4 (payload detonation) because fetching
  attacker-controlled content would create an SSRF surface and leak victim
  telemetry. Both are design decisions, not omissions.

## Revisit when

- The audit trail shows one API key issuing more than roughly a thousand scans
  against a single model version with no corresponding mail volume, the
  observable signature of budget-unbounded probing.
- Analyst feedback is wired to automatic retraining, at which point OOS-3 stops
  being true and poisoning enters scope.
- Model artefacts or the registry are exposed outside the deployment boundary,
  making OOS-2 live.
- A published technique cannot be expressed by the transform library, or
  per-family attack success for any family exceeds 0.10.
