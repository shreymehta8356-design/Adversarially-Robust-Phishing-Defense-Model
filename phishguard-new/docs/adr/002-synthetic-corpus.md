# ADR-002: Use a synthetic, campaign-structured corpus as the primary training data

- **Status**: Accepted
- **Date**: 2026-09-07
- **Deciders**: Capstone team (BAI-17)

## Context

[ADR-001](001-tri-modal-fusion.md) commits the system to three feature
families, one of them behavioural: prior correspondence volume, reply ratio,
domain age, burst shape, display-name reuse. No public corpus records any of it.
Nazario, Enron, SpamAssassin, PhishTank and the UCI URL sets are message and URL
archives; none knows whether this sender has ever written to this recipient. A
tri-modal system cannot be trained on data missing a modality, and the ablation
that justifies the design cannot be run at all.

The second constraint is legal and ethical. Real phishing corpora contain real
victims' mailbox addresses, the acceptance criteria forbid committing personal
data, and several corpora forbid redistribution. The third is reproducibility:
every number in the dossier should be regenerable in one command on a machine
with no network and no dataset licences.

A subtler problem surfaced during development. Mail is campaign-structured: one
kit emits hundreds of near-identical messages. A random row-level split puts
siblings of a test message into training and reports an accuracy that evaporates
in production. Preventing that needs a corpus that knows which messages belong
to the same campaign, which real archives do not label.

## Decision

`src/phishguard/data/synthetic.py` is the primary corpus: deterministic under a
fixed seed, campaign-structured (every message carries a `group_key` so
`src/phishguard/data/splits.py` can keep whole campaigns on one side of the
split), and composed slot-by-slot from sentence banks rather than emitted from
fixed templates, so two campaigns of the same lure type are genuinely different
text.

`src/phishguard/data/loaders.py` maps the five public corpora onto the same
`EmailMessage` schema so `phishguard train --data-source <path>` works
unchanged. Those loaders download nothing and set
`BehavioralContext.available = False` rather than inventing context.

## Alternatives considered

### Public corpora only (Enron ham with Nazario phishing)

The default choice, and the one an examiner is most inclined to trust. The text
is real, written by real people and real attackers; no generator's assumptions
can leak in, and the numbers sit alongside published work.

Rejected for three compounding reasons. The behavioural modality does not exist,
so 33 features would be constant and the tri-modal claim untestable. The corpora
differ by far more than the label (Enron is 2001 US corporate mail, Nazario is
phishing from 2005-2015), so a classifier learns era and register as much as
phishing. And the licences plus the personal data make the corpus uncommittable,
breaking reproducibility directly.

### Hybrid: real message text with synthesised behavioural context

Keeps real prose while filling the missing modality, and a fair amount of
published work does exactly this when a corpus lacks a feature.

Rejected because the synthesised block would have to be conditioned on the
label. There is nothing else to condition it on: the corpus does not record who
knew whom. That manufactures precisely the artefact the leakage audit exists to
catch, in the one family the whole design argument rests on. A behavioural
feature that is a re-encoding of the label is worse than none.

### An LLM-generated corpus

Fluent, varied, cheap, and it models the genuinely hard modern case of
LLM-written phishing with no lexical tells. The prose would be better than a
sentence bank's.

Rejected on determinism and inspectability. Generation is not repeatable
offline, so the dossier stops being regenerable in one command; the generating
model's safety training skews which phishing it will write in ways nobody can
characterise; and the assumptions become opaque, where this generator is
readable Python whose every distributional choice can be argued with.

## Consequences

**Positive**

- The behavioural modality exists, so the tri-modal design can be ablated rather
  than asserted.
- `group_key` makes grouped splitting possible by construction: the recorded run
  has 1349 groups, 347 in test, zero group overlap and zero near-duplicate pairs.
- Difficulty is deliberate: roughly 18% of legitimate mail is hard (real password
  resets, real invoices), roughly 22% of phishing is hard (business email
  compromise, thread hijacking), clone campaigns are 20% of phishing, and
  `_suspicious_ham_campaign` produces legitimate marketing using shorteners,
  deadlines and fresh campaign subdomains.
- Several distributions exist because earlier revisions leaked and the audit
  caught them: SPF/DKIM/DMARC outcomes now overlap between classes (an earlier
  version had `hdr_auth_score` separating at AUC 0.997), both classes draw URL
  paths from one vocabulary, HTTPS rates are 0.92 and 0.99, and legitimate mail
  sometimes routes through an ESP sending domain so display-name mismatch is
  evidence rather than proof.

**Negative**

- Clean metrics are an upper bound and the generator's assumptions are baked into
  every one of them. Macro F1 0.99948 with zero false positives on 938 legitimate
  messages is a statement about the generator, not about a mailbox.
- Every discriminating signal is present because a person put it there. Any
  real-world signal nobody thought of is absent, and no audit can find a feature
  that was never generated.
- The leakage audit constrains the artefact without manufacturing realism. It
  proves no single feature separates the classes above AUC 0.985; it cannot prove
  the joint distribution resembles real traffic. The hard subset (0.99846) is the
  honest ceiling read and is still generator-bounded.
- Robustness numbers inherit the caveat twice: the corpus and the attack
  transform library were written by the same team, so the attacks come from the
  same imagination as the data.

**Neutral / accepted trade-offs**

- Cross-checking against real data is a flag, not a rewrite, but running it needs
  licensed corpora the repository cannot ship.
- Public-corpus runs necessarily lose the behavioural family, so they measure a
  different system than the dossier describes.

## Evidence at release 1.3.0 (22 September 2026)

The figures above are from the 7 September decision run; this section gives
the current ones, for model `pg-0e0dffa24f`, as reported in the
[evaluation dossier](../07-evaluation-dossier.md).

- The split has 1256 campaign groups, 284 of them held out, with 6750 training
  and 1938 test messages; zero group overlap, zero exact-duplicate and zero
  near-duplicate pairs.
- The generator has been made harder, because the 7 September corpus gave one
  error in 1937, which the dossier says is not a measurement. The difficulty
  shares listed under Positive describe that earlier generator: it now draws
  34% of legitimate campaigns and 40% of phishing campaigns as hard (the
  `hard_ham_ratio` and `hard_phish_ratio` defaults in `data/synthetic.py`),
  and clones stay at 20% of phishing campaigns. The message-level shares
  depend on campaign sizes and are not recorded.
- The leakage audit still passes after the change (gate G10): the generator is
  built so that no single feature separates the classes by more than about
  0.84 AUC, and the audit flags none of the 265.
- Clean macro F1 is 0.98805 with one false positive on 1038 legitimate
  messages (false-positive rate 0.00096); there are 23 errors in 1938, 19 of
  them cloned brand templates whose only signal is the header and the URL.
- The hard subset (489 messages) scores macro F1 0.95475 against 0.98805 for
  the whole test set and holds all 22 missed phishing messages. PG-HARD, 192
  records from 24 hand-written cases that each invert a named detection cue,
  is now the primary hard-case result, and the dossier reads both as evidence
  that the difficulty controls work directionally, not as a ceiling on real
  mail.

The decision holds: the behavioural modality still exists only in the
synthetic corpus, so the tri-modal design can still be trained and ablated only
there, and the harder generator applies the Negative consequences above (clean
metrics describe the generator) rather than departing from them; the dossier
still quotes comparative results as the ones that transfer.

None of the triggers below has fired: the generator changed and the audit
flagged no feature, clean macro F1 fell rather than rose, and no real traffic
has been evaluated.

## Revisit when

- A public corpus appears carrying sender-relationship context, making synthetic
  data an augmentation rather than the primary.
- Any volume of labelled real traffic becomes available.
- The leakage audit flags a suspicious feature after a generator change, or clean
  macro F1 rises above 0.999 while the hard subset does not move, meaning
  difficulty has been engineered out rather than solved.
- Real-traffic false-positive rate exceeds the 0.02 gate by more than a factor of
  two, indicating the `suspicious_ham` distribution is too narrow.
