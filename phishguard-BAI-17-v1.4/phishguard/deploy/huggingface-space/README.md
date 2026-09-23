---
title: PhishGuard
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# PhishGuard — adversarially robust phishing defense

Capstone BAI-17. The Space trains a model on first start (about two minutes),
then serves the analyst console at `/`, the employee report page at `/report`
and the API at `/api/v1/*` (`/openapi.json` for the contract).

Set these **secrets** in the Space settings before the first start:
`PG_ADMIN_KEY`, `PG_ANALYST_KEY`, `PG_REPORTER_KEY`, `PG_PSEUDONYMIZATION_SALT`
(any long random strings). The admin key is what you paste into the console.
