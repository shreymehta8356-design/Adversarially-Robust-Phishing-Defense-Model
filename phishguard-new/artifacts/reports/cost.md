## Operating point — an expected-cost justification

Costs are in units of **one analyst review**. Assumed, illustratively — an organisation substitutes its own: a phish delivered with no warning costs **200** reviews, a wrongly quarantined legitimate message **10**; analysts miss 5% of the phishing they review. Traffic: 2.0% of inbound mail is phishing; 10% of phishing and 10% of legitimate mail behaves like PG-HARD. Class behaviour is measured on the test data and re-weighted to that prevalence.

| Policy | Review ≥ | Block ≥ | Abstain at spread ≥ | Cost / 1,000 | Sent to a human / 1,000 |
|---|---|---|---|---|---|
| **Deployed** | 0.40 | 0.80 | 0.45 (symmetric) | **341.0** | 182.0 |
| Cost-optimal under these assumptions | 0.15 | 0.45 | 0.55 (symmetric) | **307.5** | 138.6 |
| Cost-optimal, abstention disabled | 0.25 | 0.45 | off | **485.5** | 22.3 |
| Text-only filter, cost-optimal | 0.25 | 0.95 | off | **206.2** | 111.5 |

**What the two policies trade.** The deployed policy is the safety-first end of the frontier: 0.040 silently delivered phish per 1,000 messages, at the price of sending 182 in every 1,000 to a human. The cost-optimal policy cuts that review load to 139 per 1,000 and accepts 0.164 silent deliveries per 1,000 in exchange. Neither is 'correct': the choice depends on what a missed phish costs *this* organisation, which is why the next table exists.

### Candidate defaults, priced and attacked

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

### Which policy for which organisation

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

Under these assumptions the text-only filter, at its own cost-optimal policy, is **cheaper** on benign traffic, by 101.3 cost units per 1,000 messages. That price leaves out the attacker.

### Sensitivity

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
