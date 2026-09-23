## PG-HARD-1 — curated hard-case benchmark

24 hand-designed cases (12 hard negatives, 12 hard positives), 8 deterministic variants each = **192 records**. Every case inverts a named detection cue; none of this set is easy.

All three systems are tuned to the same false-alarm budget on the ordinary held-out test set (review 0.0039 FPR, block 0.0010 FPR) before being measured here, so the columns are comparable.

### Headline — the two failures that cost money

| System | Silent delivery | False block | Acceptable outcome | Sent to a human |
|---|---|---|---|---|
| PhishGuard (full tri-modal ensemble) | **0.0%** (0) | **8.3%** (8) | 95.8% | 70.8% |
| Text-only filter (TF-IDF + logistic regression) | **0.0%** (0) | **51.0%** (49) | 74.5% | 4.2% |
| Hand-written rule checklist | **77.1%** (74) | **0.0%** (0) | 61.5% | 4.2% |

On **ordinary** mail the same policy sends 16.1% of messages to a human, blocks 0.00% of legitimate mail and lets 0.22% of phishing through silently (n=1938). The hard-case result above is bought with that review queue; without this line it would be an overclaim, because a system that escalates everything scores perfectly on PG-HARD and is useless in production.

*Silent delivery* = a hard phish the user received with no warning. *False block* = legitimate mail the user never saw. Routing a hard case to human review counts as an acceptable outcome for both labels, because that is what the middle band is for.

### Where the system is weakest

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

### Case-by-case

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

### Honest failures

These cases are not fully handled. They are reported rather than removed, and each names the cue the system is still leaning on.

- **HN-REBRAND** — Legitimate supplier on a three-week-old domain (pass 0%, worst score 1.000); defeats *domain age*.
