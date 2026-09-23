# Quick start — read this one

> **Prefer to follow pictures?** Open `docs/run-it.html` in your browser. It is
> the same six steps with a Windows/Mac switch and a screenshot of what each
> command should print. Nothing to install to read it — just double-click it.

**Goal: PhishGuard running in your browser in about five minutes.**

You do not need Docker. You do not need to understand the project first. You
need Python and an internet connection for the first run.

---

## The whole thing

**1. Open a terminal in the project folder.**

The folder is the one containing `pyproject.toml`. If you unzipped the project:

```
cd phishguard
```

> **Windows:** press Start, type `PowerShell`, open it, then `cd` to the folder.
> Right-clicking the folder while holding Shift gives you "Open PowerShell here".
>
> **Mac:** right-click the folder in Finder → Services → New Terminal at Folder.

**2. Run one command.**

```
python start.py
```

> If that says `python: command not found`, try `python3 start.py` instead.

**3. Wait.**

The script prints five steps as it goes. Step 4 trains the model and takes
**one to three minutes**. That happens once — the next run skips it.

**4. Your browser opens at `http://localhost:8000`.**

If it does not open by itself, type that address in yourself.

**5. Paste this key into the box at the top right and press Connect:**

```
dev-admin-key-change-me
```

**6. Pick an example from the dropdown, press "Assess message".**

That's it. You're running.

---

## What you just started

The terminal is now running the server. Leave that window open.

- **Stop it:** press `Ctrl+C` in the terminal.
- **Start it again later:** `python start.py` — it will be quick this time,
  because the model is already trained.

---

## What to click first

| Do this | You'll see |
|---|---|
| Load **Credential phishing (obvious)** → Assess | A red **BLOCK** verdict and a list of reasons in plain English |
| Load **Legitimate internal mail** → Assess | A green **ALLOW** |
| Load **Cloned brand template (hard)** → Assess | A red **BLOCK** — the interesting one, see below |
| Press **Compare with a text-only filter** | The same message read two ways, side by side |
| Go to the **Hard-case benchmark** tab | PG-HARD: 24 cases that each defeat a named detection cue |
| Go to the **Adversarial probe** tab → Run probe | The system attacking its own decision to see if it holds |
| Go to **Model & monitoring** → **Check drift** | Whether recent mail still looks like what the model was trained on (needs 30+ assessed messages) |
| Open **http://localhost:8000/report** in a new tab, key `dev-reporter-key-change-me`, report a message | What an employee sees: a case number and a plain-language status, never a score |
| Back in the console → **Review queue** tab → click the new case → **Claim** → **Confirm phishing** | The analyst's side: the case, its evidence and its history. Refresh the report page to see the outcome |

### The one worth understanding

**Cloned brand template** is the case this whole project is about.

Its text is PayPal's real password-reset wording, copied word for word — which
is exactly what real phishing kits do. Only the link and the sending domain
were changed.

Assess it, then press **Compare with a text-only filter**:

| Reader | Score | Verdict |
|---|---|---|
| Text-only filter (reads the words) | ~0.52 | REVIEW — it cannot tell. The words are PayPal's own. |
| **PhishGuard** | **~1.00** | **BLOCK** |

The evidence list says why, in plain English: the link goes to
`paypal-secure-mail.com`, which impersonates a brand it does not belong to;
the domain is 41 days old; the sender has never written before and is sending
in a burst. None of that is in the words, which is the argument for the whole
design — on one screen.

Then load **Compromised internal account (hard)**. The rule checklist scores it
~0.01 (the sender really is a colleague), the other three readers score it
near 1.0 — so PhishGuard sends it to a human (**REVIEW**) instead of guessing.

### The number to quote in your viva

Not the 99% accuracy. That is measured on a representative corpus, which is
mostly easy mail, and an examiner is right to push on it.

Quote **PG-HARD** instead — 24 hand-designed cases, each of which defeats a
named detection cue, with 8 variants each:

```
.venv/bin/phishguard hard
```

| System | Missed phishing | Blocked good mail | Acceptable |
|---|---|---|---|
| **PhishGuard** | **0%** | **8%** | **96%** |
| Text-only filter | 0% | 51% | 74% |
| Rule checklist | 77% | 0% | 61% |

All three are tuned to the same false-alarm budget first, so the columns are
comparable. PhishGuard's 8% is one case (a real supplier on a brand-new
domain) in all eight variants. Retrained with other random seeds it ranged
from **0 to 1** missed and **7 to 8** blocked out of 96 each — quote that range.
The cost is honest and stated: about **11% of ordinary mail goes to a human**,
because the system escalates when its readers disagree instead of guessing.

---

## Extras for your written report

Run these from the project folder once the model is trained. On Windows use
`.venv\Scripts\` in place of `.venv/bin/`.

| Command | What you get |
|---|---|
| `.venv/bin/phishguard figures` | Nine figures and their captions in `artifacts/reports/figures/` |
| `.venv/bin/phishguard cost` | Why the thresholds are where they are, in analyst-hours |
| `.venv/bin/phishguard drift --simulate` | The drift monitor staying quiet for five weeks, then catching a shift |

`start.py` installs what `figures` needs. If it printed "report figures
unavailable", run `.venv/bin/pip install -e ".[report]"` once when you are
online.

Using a real public phishing corpus instead of the synthetic one is covered in
[docs/11-real-data.md](docs/11-real-data.md) — read its section 3 first.

---

## Try it on your own emails

Real mail is the best demo. Three ways, easiest first:

1. **One email.** In Gmail open a message (your Spam folder is a good source),
   click **⋮ → Download message**, then in the console go to **Review queue →
   Import real mail**, pick the file and press **Import and assess**.
2. **Many emails.** Save several that way into one folder, then:
   ```
   .venv\Scripts\phishguard import "C:\Users\you\Downloads\saved-mail"
   ```
3. **Your live inbox.** Make a Gmail *app password* (Google Account →
   Security → App passwords), then:
   ```
   .venv\Scripts\phishguard inbox --user you@gmail.com
   ```
   It watches for new mail, read-only, and sends anything doubtful to the
   review queue. Stop it with `Ctrl+C`.

Real mail has no sender history, so the verdict says so and the system leans
on the words and the links. Don't upload real mail to GitHub: it contains real
names.

## Put it online

`deploy/README.md` has the steps. The shortest: push the project to GitHub,
then on [render.com](https://render.com) choose **New → Blueprint** and pick
the repository. Ten minutes later you have an `https://…onrender.com` address
you can send to your examiner.

## Optional: the deep-learning reader (needs your GPU)

```
.venv\Scripts\pip install torch --index-url https://download.pytorch.org/whl/cu121
.venv\Scripts\pip install -e ".[transformer]"
.venv\Scripts\phishguard train --with-transformer --save
.venv\Scripts\phishguard evaluate
```

The first `train` downloads DistilBERT (about 260 MB) once. On an RTX 3050 it
adds a few minutes; the dossier then shows whether the fifth reader helped
under attack, not only on clean mail.

---

## If something goes wrong

The script stops with a plain-English reason and the command that fixes it.
Beyond that:

| What you see | What to do |
|---|---|
| `python: command not found` | Try `python3 start.py` |
| "needs Python 3.10 or newer" | Install Python from [python.org/downloads](https://www.python.org/downloads/), then run `python3.12 start.py` |
| Install step fails | You are probably offline. Connect and run `python start.py` again |
| "could not create the environment" | On Ubuntu/Debian: `sudo apt install python3-venv`, then try again |
| Training gets killed | Low memory. Run `.venv/bin/phishguard train --n 4000 --save` then `python start.py` |
| Browser shows nothing at localhost:8000 | Check the terminal is still running. If it exited, scroll up for the reason |
| `401` in the console | The key is wrong. It is `dev-admin-key-change-me`, pasted exactly |

Still stuck? Run this — it checks everything and tells you what is broken:

```
.venv/bin/phishguard doctor --self-test
```

On Windows that is `.venv\Scripts\phishguard doctor --self-test`.

---

## If you would rather use Docker

Only if you already have Docker Desktop installed and running. It is not
simpler than the above — it is just a different route.

```
docker compose up --build -d
docker compose logs -f api
```

Wait for `model loaded`, then open `http://localhost:8000`. Stop it with
`docker compose down`.

---

## What to read next

You do not need any of this to run the project.

| If you want to | Read |
|---|---|
| Prepare for the viva | [§8 Deployment guide](docs/08-deployment-guide.md), the demo script at the end |
| Understand how it works | [§2 Architecture](docs/02-architecture.md) |
| Quote the results | [§7 Evaluation dossier](docs/07-evaluation-dossier.md) |
| Change thresholds or keys | [§9 Admin guide](docs/09-admin-user-guide.md) |
| See everything | [docs/README.md](docs/README.md) |
