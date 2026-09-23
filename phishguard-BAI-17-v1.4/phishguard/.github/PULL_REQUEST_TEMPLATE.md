## What and why

<!-- What changed, and the reason. Link the issue: "Closes #42". -->

Closes #

## How it was tested

<!-- New or changed tests, and anything checked by hand (console, API, load test). -->

- [ ] `ruff check src tests scripts` and `ruff format --check src tests scripts` pass
- [ ] `pytest` passes

## Did a measured result move?

<!-- If the model, features, defences or attack suite changed, run
     `phishguard evaluate --n 9000 --budget 10 --max-attacked 150` and paste the
     before/after of anything that moved. "No" is a fine answer for other changes. -->

| Metric | Before | After |
|---|---|---|
| | | |

## Security and privacy

- [ ] No message content in logs, traces, the database or test fixtures
- [ ] No secrets, keys, corpora or models in the diff
- [ ] Every new endpoint requires a role; object-level checks where a resource has an owner
- [ ] Inputs are bounded (length, count) and unknown fields rejected

## Docs

- [ ] Docs updated where behaviour, configuration or a number changed
- [ ] `CHANGELOG.md` entry added
