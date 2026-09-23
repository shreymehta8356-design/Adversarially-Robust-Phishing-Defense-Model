# Putting PhishGuard online

Three hosts, all giving an HTTPS address anyone can open. Render is the
easiest; the Hugging Face Space has the most memory for free; Fly keeps the
model and audit trail on a disk.

| Host | Cost | Memory | Keeps data between restarts | Setup |
|---|---|---|---|---|
| **Render** | free | 512 MB | no (retrains on deploy) | `render.yaml`, one click |
| **Hugging Face Space** | free | 16 GB | no | `deploy/huggingface-space/` |
| **Fly.io** | small | 1 GB | yes (volume) | `fly.toml` |

All three run the same container as `docker compose up`, so what the examiner
sees online is exactly what runs on your laptop.

## Render (recommended)

1. Push the project to a GitHub repository.
2. On [render.com](https://render.com), choose **New → Blueprint**, pick the
   repository and click **Apply**. `render.yaml` does the rest.
3. Wait for the first deploy: the build takes a few minutes and the service
   then trains a model (about three more minutes). The log ends with
   `starting API`.
4. Open the service's **Environment** tab and copy `PG_ADMIN_KEY`. That is the
   key you paste into the console at `https://<your-service>.onrender.com`.
   `PG_REPORTER_KEY` is for the employee page at `/report`.

The free plan sleeps after 15 minutes without traffic and takes about a
minute to wake, then retrains if the instance was replaced. Open the address a
few minutes before a demonstration.

## Hugging Face Space

1. Create a new Space, SDK **Docker**, hardware **CPU basic** (free).
2. Upload the whole project, and copy `deploy/huggingface-space/Dockerfile` and
   `deploy/huggingface-space/README.md` to the Space's root (replacing the
   README).
3. In **Settings → Variables and secrets**, add the secrets `PG_ADMIN_KEY`,
   `PG_ANALYST_KEY`, `PG_REPORTER_KEY` and `PG_PSEUDONYMIZATION_SALT` — any long
   random strings (`python -c "import secrets;print(secrets.token_urlsafe(32))"`).
4. The Space builds, trains and serves at `https://<user>-phishguard.hf.space`.

## Fly.io

```
fly launch --copy-config --no-deploy
fly volumes create pgdata --size 1
fly secrets set PG_ADMIN_KEY=... PG_ANALYST_KEY=... PG_REPORTER_KEY=... PG_PSEUDONYMIZATION_SALT=...
fly deploy
```

## What changes in production

- `PG_ENVIRONMENT=prod` refuses to start without real keys; the development
  keys never work online.
- Keys can be given one per role (`PG_ADMIN_KEY`, `PG_ANALYST_KEY`,
  `PG_REPORTER_KEY`) or together (`PG_API_KEYS=admin:...,analyst:...`).
- The container listens on whatever `PORT` the host assigns.
- `PG_BOOTSTRAP_N` sets how big the first training corpus is; lower it if the
  host runs out of memory during the first start.
- Nothing in the audit trail contains message content, so hosting it on a
  shared platform does not leak mail. Real mailboxes you import do stay on
  the host's disk for as long as the instance lives.
