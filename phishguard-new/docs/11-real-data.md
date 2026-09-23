# 11 · Running on real public phishing data

The system trains on its synthetic corpus by default (see §6 for why). This
guide is how to cross-check the results on real, public mail — and, more
importantly, how to avoid the traps that make most published results on these
corpora mean less than they appear to.

> **Nothing here downloads anything automatically.** Each corpus has its own
> terms, several contain real people's email, and none may be committed to the
> repository. Download them yourself into a `data/` folder, which `.gitignore`
> already excludes.

---

## 1. The corpora

| Corpus | Class | Format | Era | Where |
|---|---|---|---|---|
| **Nazario phishing corpus** | phishing | Unix mbox (one file per period) | 2005–2025 | [monkey.org/~jose/phishing](https://monkey.org/~jose/phishing/) |
| **SpamAssassin public corpus** | legitimate (`easy_ham`, `hard_ham`) · spam | directories of RFC-822 files, in `.tar.bz2` | 2002–2003 | [spamassassin.apache.org/old/publiccorpus](https://spamassassin.apache.org/old/publiccorpus/) |
| **Enron email dataset** | legitimate | maildir tree | to Dec 2001 | [cs.cmu.edu/~enron](https://www.cs.cmu.edu/~enron/) |

Read before you use them:

- **Nazario** ships a `README.txt` and a `LICENSE.txt` in the same directory.
  Read the licence; it sets the terms of research use.
- **SpamAssassin**'s readme asks that the messages are never sent into a live
  mail system. Its `spam` folders are **spam, not phishing** — PhishGuard
  refuses to treat spam as phishing unless you say so (`--spam-as`).
- **Enron** entered the public domain through the FERC investigation, but it is
  still the real correspondence of real people. Treat it as personal data.

---

## 2. Download and lay out the files

### The one-command way

```
phishguard fetch-public --list
phishguard fetch-public nazario-2005 spamassassin-easy-ham
```

The second command prints each corpus's terms and stops. Read them; if you
accept them, run it again with `--accept-terms`. It then downloads over HTTPS
into `data\`, unpacks the SpamAssassin archive safely (an archive member that
would escape the folder, or is a link, is refused), records the source URL,
size and SHA-256 of every file in `data\PROVENANCE.json`, and prints the exact
`phishguard data --verify` command to run next.

`nazario-2005` with `spamassassin-easy-ham` is the closest-in-time pairing the
free corpora allow (2005 phishing, 2002–2003 legitimate mail) — still not
era-matched, which is exactly what the audit in section 3 will tell you.

### By hand (Windows)

Nazario files are plain mbox — download one, e.g. `phishing-2024`, straight
into `data\`. The SpamAssassin archives are `.tar.bz2`; Windows 10 and 11 have
`tar` built in:

```
mkdir data
cd data
tar -xjf 20030228_easy_ham.tar.bz2
tar -xjf 20030228_hard_ham.tar.bz2
cd ..
```

You should end up with:

```
data\
  phishing-2024          <- Nazario mbox (no extension is fine)
  easy_ham\              <- SpamAssassin: numbered files + a 'cmds' file
  hard_ham\
```

The loader skips SpamAssassin's `cmds` file and archive leftovers
automatically. Mark each source with `#phish` or `#ham`, because single-class
corpora carry no label of their own.

---

## 3. Audit the corpus **before** training

```
phishguard data --verify --data-source "data\phishing-2024#phish,data\easy_ham#ham"
```

The audit loads everything, then runs four families of checks. It exits
non-zero when the corpus is not usable, so it can gate a CI job.

| Check | What it catches |
|---|---|
| **Load report** | Rows skipped and why: unknown label spellings (refused, never guessed), spam, unparseable records, mis-decoded charsets, HTML-only mail converted to text, encoded subjects |
| **Label noise** | The same message appearing under *both* labels |
| **Duplicates** | Exact duplicates, and near-copies across the label boundary |
| **Confound audit** | Metadata with no phishing meaning — receipt year, whether any auth verdict exists, whether a DMARC verdict exists, hop count, HTML presence — that nevertheless predicts the label |

### The confound you will almost certainly hit

The three free corpora were collected in **different decades**. Pair recent
Nazario phishing with Enron or SpamAssassin legitimate mail and the audit
reports something like:

```
confound audit (metadata that should NOT predict the label):
  !! receipt year           AUC 1.000
  !! has any auth verdict   AUC 1.000
  !! has a DMARC verdict    AUC 1.000

[FAIL] era mismatch: phishing spans 2023-2023, legitimate mail 2001-2001
```

A classifier trained on that corpus can score near-perfectly by learning *when*
each message was sent, not whether it is phishing. The authentication features
are the sharpest example. DMARC was only published in 2012 and the
`Authentication-Results` header only standardised in 2009, so pre-2012
legitimate mail *cannot* carry a DMARC verdict. On that merge, "has a DMARC
verdict" predicts **phishing** perfectly, which is the opposite of what it means
in a real mailbox.

**No pairing of the free corpora is era-matched.** The closest is Nazario's
earliest files (`phishing0.mbox` to `phishing3.mbox`, 2005–2007) with
SpamAssassin's legitimate mail (2002–2003), which is still years apart. So:

1. **Run the audit and keep its output** with any result you report.
2. **Use a temporal split** (`--split temporal`), which trains on the past and
   tests on the future and cannot be flattered by mixing eras across the split.
3. **Treat the numbers as an upper bound**, not as deployment performance.
4. For a genuinely era-matched evaluation, the legitimate side has to come from
   the same period as the phishing — in practice, an organisation's own mail,
   used with consent.

---

## 4. Train and evaluate

```
phishguard train    --data-source "data\phishing-2024#phish,data\easy_ham#ham" --split temporal --save
phishguard evaluate --data-source "data\phishing-2024#phish,data\easy_ham#ham" --split temporal
```

`--limit 5000` caps how many messages are read from each source, which keeps a
first run fast.

**Keep the real-data results separate from the synthetic ones.** Both write to
`artifacts\`, so point this run at its own folder first — in PowerShell:

```
$env:PG_ARTIFACTS_DIR = "artifacts-real"
```

Models, reports and figures for the real-data run then go to `artifacts-real\`,
and the synthetic dossier in `artifacts\` is left untouched. Every report
records the dataset's content version (a SHA-256 over the messages and
labels), so the two runs can never be confused.

### What changes on public data, and how to report it

- **No behavioural context.** Public corpora never include the gateway's view
  of the sender relationship, domain age or campaign burst. PhishGuard runs on
  **email and URL evidence only** and records that it did, so quote the results
  as *email + URL*, not tri-modal. The synthetic results are the tri-modal
  ones.
- **Auth features may be confounded** (above). If the audit flags them, say so
  next to any number that depends on them.
- **PG-HARD still applies.** `phishguard hard` works with a model trained on
  real data, and it is still the fairest single number to quote.

---

## 5. CSV corpora (Kaggle, UCI)

CSVs load directly. Column names are matched case- and
separator-insensitively (`Email Text`, `email-text` and `email_text` are the
same column). The label convention is **inferred from the column's full set of
values** before any row is labelled, because the conventions conflict:

| Values in the label column | Read as |
|---|---|
| `-1` and `1` only | **UCI convention:** −1 = phishing, 1 = legitimate |
| `0` and `1` only | 1 = phishing, 0 = legitimate |
| names | `phishing`, `phishing email`, `malicious` … = phishing; `ham`, `safe email`, `legitimate` … = legitimate |
| `spam` | skipped unless you pass `--spam-as phish` or `--spam-as ham` |
| anything unrecognised | **refused and counted**, never defaulted to legitimate |

```
phishguard data --verify --data-source "data\Phishing_Email.csv"
```
