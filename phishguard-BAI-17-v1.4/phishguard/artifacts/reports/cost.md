## Operating point — an expected-cost justification

Costs are in units of **one analyst review**. Assumed, illustratively — an organisation substitutes its own: a phish delivered with no warning costs **200** reviews, a wrongly quarantined legitimate message **10**; analysts miss 5% of the phishing they review. Traffic: 2.0% of inbound mail is phishing; 10% of phishing and 10% of legitimate mail behaves like PG-HARD. Class behaviour is measured on the test data and re-weighted to that prevalence.

| Policy | Review ≥ | Block ≥ | Abstain at spread ≥ | Cost / 1,000 | Sent to a human / 1,000 |
|---|---|---|---|---|---|
| **Deployed** | 0.40 | 0.80 | 0.45 (symmetric) | **262.2** | 120.5 |
| Cost-optimal under these assumptions | 0.45 | 0.95 | 0.25 (symmetric) | **191.4** | 116.1 |
| Cost-optimal, abstention disabled | 0.25 | 0.45 | off | **485.5** | 22.3 |
| Text-only filter, cost-optimal | 0.25 | 0.95 | off | **206.2** | 111.5 |

**What the two policies trade.** The deployed policy is the safety-first end of the frontier: 0.040 silently delivered phish per 1,000 messages, at the price of sending 121 in every 1,000 to a human. The cost-optimal policy cuts that review load to 116 per 1,000 and accepts 0.100 silent deliveries per 1,000 in exchange. Neither is 'correct': the choice depends on what a missed phish costs *this* organisation, which is why the next table exists.

### Candidate defaults, priced and attacked

Three candidate defaults, priced on benign traffic and then attacked. *Worst-case regret* is how much more a policy costs than the best possible policy, for whichever of four organisation profiles it fares worst on. *Under attack* is the share of hard phishing the adaptive attacker gets delivered with no warning.

| Candidate | Review / block / abstain | Cost / 1,000 | Worst-case regret / 1,000 | Delivered under attack (worst budget) |
|---|---|---|---|---|
| Deployed default | 0.40 / 0.80 / 0.45 (symmetric) | 262.2 | 3719.8 | **6.2%** (3 of 48) |
| Minimax-regret choice | 0.45 / 0.95 / 0.25 (symmetric) | 191.4 | 2.3 | **12.5%** (6 of 48) |
| Cost-optimal at the stated assumptions | 0.45 / 0.95 / 0.25 (symmetric) | 191.4 | — | **12.5%** (6 of 48) |

**The finding.** The cost-optimal policy is cheaper on benign traffic partly because it leaves an attacker room: it delivers 12% of hard phishing under the adaptive attack (6 of 48 against 3 for the deployed default). The minimax-regret choice is cheaper on benign traffic partly because it leaves an attacker room: it delivers 12% of hard phishing under the adaptive attack (6 of 48 against 3 for the deployed default). Most of the gap in worst-case regret is false blocks: at the stated share of hard traffic the deployed default quarantines 8.2 legitimate messages per 1,000 against 0.0 for the minimax-regret choice, and the Regulated, zero tolerance profile prices each at 500 reviews. Because every PG-HARD case stands for a slice of real traffic, one case that is blocked in all its variants moves this figure on its own (section 4 names it). The default is **not** re-tuned from this table: the candidates are chosen on the same test mail and PG-HARD records they are scored on, so adopting one here would tune the policy to the benchmark. The way to move it is `phishguard cost --attack` on an organisation's own traffic. The deployed default's price on benign traffic is stated either way: a worst-case regret of 3720 cost units per 1,000 messages across the four profiles below.

Profiles used for the regret calculation (illustrative):

- **Lean IT team** — missed phish 200, false block 10 reviews
- **Finance / legal - invoices matter** — missed phish 500, false block 200 reviews
- **Staffed SOC, high stakes** — missed phish 2000, false block 100 reviews
- **Regulated, zero tolerance** — missed phish 5000, false block 500 reviews

### Which policy for which organisation

| If a missed phish costs … reviews | Review ≥ | Block ≥ | Abstain | Cost / 1,000 | Sent to a human / 1,000 |
|---|---|---|---|---|---|
| 20 | 0.50 | 0.95 | 0.25 (symmetric) | 131.0 | 109.3 |
| 50 | 0.45 | 0.95 | 0.25 (symmetric) | 143.3 | 116.1 |
| 100 | 0.45 | 0.95 | 0.25 (symmetric) | 159.3 | 116.1 |
| 200 | 0.45 | 0.95 | 0.25 (symmetric) | 191.4 | 116.1 |
| 500 | 0.45 | 0.95 | 0.25 (symmetric) | 287.4 | 116.1 |
| 1000 | 0.15 | 0.95 | 0.40 (symmetric) | 394.8 | 148.8 |
| 5000 | 0.30 | 0.95 | 0.30 (escalate) | 725.2 | 109.0 |

**Where abstention earns its place.** On ordinary mail alone the cost-optimal policy disables abstention — on easy mail, escalation is mostly cost. It pays for itself once **1.8%** of traffic (in both classes) is hard.

Against the best the text-only filter can do under the same assumptions, PhishGuard at its cost-optimal policy saves **14.8** cost units per 1,000 messages.

### Sensitivity

| Miss cost | Hard share | Optimal review / block / abstain | Optimal cost | Deployed cost | Abstention pays? |
|---|---|---|---|---|---|
| 20 | 0% | 0.50 / 0.95 / 0.25 | 126.5 | 217.5 | yes |
| 20 | 2% | 0.50 / 0.95 / 0.25 | 127.4 | 217.8 | yes |
| 20 | 5% | 0.50 / 0.95 / 0.25 | 128.7 | 218.1 | yes |
| 20 | 10% | 0.50 / 0.95 / 0.25 | 131.0 | 218.7 | yes |
| 20 | 25% | 0.45 / 0.95 / 0.25 | 135.7 | 220.4 | yes |
| 50 | 0% | 0.50 / 0.95 / 0.25 | 137.7 | 224.0 | yes |
| 50 | 2% | 0.50 / 0.95 / 0.25 | 139.7 | 224.4 | yes |
| 50 | 5% | 0.45 / 0.95 / 0.25 | 142.3 | 225.0 | yes |
| 50 | 10% | 0.45 / 0.95 / 0.25 | 143.3 | 225.9 | yes |
| 50 | 25% | 0.45 / 0.95 / 0.25 | 146.5 | 228.8 | yes |
| 100 | 0% | 0.45 / 0.95 / 0.25 | 155.9 | 234.8 | yes |
| 100 | 2% | 0.45 / 0.95 / 0.25 | 156.6 | 235.4 | yes |
| 100 | 5% | 0.45 / 0.95 / 0.25 | 157.6 | 236.4 | yes |
| 100 | 10% | 0.45 / 0.95 / 0.25 | 159.3 | 238.0 | yes |
| 100 | 25% | 0.45 / 0.95 / 0.25 | 164.5 | 242.9 | yes |
| 200 | 0% | 0.45 / 0.95 / 0.25 | 185.2 | 256.3 | yes |
| 200 | 2% | 0.45 / 0.95 / 0.25 | 186.5 | 257.5 | yes |
| 200 | 5% | 0.45 / 0.95 / 0.25 | 188.3 | 259.3 | yes |
| 200 | 10% | 0.45 / 0.95 / 0.25 | 191.4 | 262.2 | yes |
| 200 | 25% | 0.45 / 0.95 / 0.25 | 200.6 | 271.1 | yes |
| 500 | 0% | 0.45 / 0.95 / 0.25 | 273.2 | 321.0 | yes |
| 500 | 2% | 0.45 / 0.95 / 0.25 | 276.1 | 323.8 | yes |
| 500 | 5% | 0.45 / 0.95 / 0.25 | 280.3 | 327.9 | yes |
| 500 | 10% | 0.45 / 0.95 / 0.25 | 287.4 | 334.8 | yes |
| 500 | 25% | 0.45 / 0.95 / 0.25 | 308.8 | 355.5 | yes |
| 1000 | 0% | 0.10 / 0.95 / 0.55 | 350.4 | 428.8 | yes |
| 1000 | 2% | 0.15 / 0.95 / 0.30 | 368.6 | 434.2 | yes |
| 1000 | 5% | 0.15 / 0.95 / 0.30 | 378.7 | 442.3 | yes |
| 1000 | 10% | 0.15 / 0.95 / 0.40 | 394.8 | 455.8 | yes |
| 1000 | 25% | 0.15 / 0.95 / 0.40 | 442.1 | 496.2 | yes |
