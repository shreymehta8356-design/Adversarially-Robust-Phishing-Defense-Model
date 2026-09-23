# Security policy

PhishGuard is security software: it decides which mail reaches people, and its
own weaknesses are an attacker's route past it. Reports are welcome and taken
seriously.

## Supported versions

| Version | Supported |
|---|---|
| 1.3.x | Yes |
| < 1.3 | No — upgrade; 1.3.0 fixes an attack-suite defect that affected robustness measurements |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's
private vulnerability reporting ("Report a vulnerability" on the repository's
Security tab), or contact the maintainers listed in `.github/CODEOWNERS`.

Include what you found, how to reproduce it, and what an attacker gains. For an
**evasion** — a phishing message that the deployed model delivers — include the
message (with any real victim's details removed), the model version from the
response, and the score and band you observed. Evasions are expected at some
rate and are recorded in the residual-risk register; a report is still useful
because it becomes a test case.

We aim to acknowledge a report within three working days and to agree a
disclosure date with you.

## Scope

In scope: the API and its authentication and authorisation, the analyst
console and report page, the audit store, the container image, the CI
pipeline, and evasions of the detector that fall inside the threat model
([docs/04](docs/04-threat-model.md)).

Out of scope, by design (see docs/04 §4.9): mail sent from a genuinely
compromised brand domain, attacks that require the model weights, attachment
detonation and URL fetching (the system never does either), and denial of
service through volume beyond the configured rate limits.

## What the system does to protect itself

| Control | Where |
|---|---|
| Role-based API keys (`reporter`, `analyst`, `admin`), stored as SHA-256 digests and compared in constant time | `service/security.py` |
| Object-level authorisation on review cases; high-risk release reserved to admins | `service/workflow.py` |
| Per-key token-bucket rate limiting; bounded input sizes; unknown fields rejected | `service/security.py`, `service/contracts.py` |
| No message content in the database, logs or traces; salted digests and pseudonyms only | `service/store.py`, `schemas.py` |
| The detector never opens a network connection (no SSRF, no victim telemetry) | tested in `tests/security/` |
| Refuses to start in production without configured keys | `service/security.py` |
| Non-root container, all capabilities dropped, `no-new-privileges` | `docker/`, `docker-compose.yml` |
| Dependency audit (`pip-audit`), CodeQL, Dependabot, secret scan, ruff security rules in CI | `.github/` |

The full analysis is the threat model (STRIDE, misuse cases, residual risk) in
[docs/04](docs/04-threat-model.md), and the checks with their test evidence are
in [docs/07 §7.15](docs/07-evaluation-dossier.md).

## Handling secrets

- Generate keys with `python -c "import secrets; print(secrets.token_urlsafe(32))"`
  and pass them in `PG_API_KEYS`; never commit them. `.env` is git-ignored.
- Change `PG_PSEUDONYMIZATION_SALT` from its default before real mail is
  processed, and keep it stable: changing it breaks pseudonym continuity.
- Rotate keys by overlapping old and new (docs/09 §9.8). Rotate immediately if
  an admin key may have leaked: it grants the adversarial probe.
