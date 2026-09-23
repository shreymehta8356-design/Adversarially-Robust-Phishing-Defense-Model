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
| Load **Cloned brand template (hard)** → Assess | An amber **REVIEW** — the interesting one, see below |
| Go to the **Adversarial probe** tab → Run probe | The system attacking its own decision to see if it holds |

### The one worth understanding

**Cloned brand template** is the case this whole project is about.

Its text is PayPal's real password-reset email, copied word for word — which is
exactly what real phishing kits do. Only the link and the sending domain were
changed.

Look at the four member scores after you assess it:

| Reader | Score | Why |
|---|---|---|
| `charngram` | ~0.03 | It reads the words. The words are PayPal's own. It sees nothing wrong. |
| `wordtfidf` | ~0.03 | Same. |
| `rules` | ~0.83 | `paypal-secure-mail.com` is not PayPal's domain. |
| `engineered` | ~0.76 | Brand squat, domain registered 41 days ago, sender never seen before. |
| **Overall** | **~0.41 → REVIEW** | The readers disagree, so a human decides. |

A normal text-based phishing filter is not just weaker here — it is
**confidently wrong**, at 0.03. That is the argument for the whole design, and
it is visible on one screen.

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
