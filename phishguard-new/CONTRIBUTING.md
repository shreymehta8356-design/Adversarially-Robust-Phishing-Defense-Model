# Contributing to PhishGuard

How work gets from an idea to `main`. Short on purpose: every rule here exists
because the evaluation, the audit trail or the examiner depends on it.

## 1. Start from an issue

Every change starts as an issue on the board, using one of the templates:

| Template | Use it for |
|---|---|
| **User story** | New behaviour. Written as "As a … I want … so that …", with acceptance criteria an examiner could check |
| **Bug report** | Something that does not do what the docs say |
| **Experiment** | A measurement: what is being compared, on what data, with which seeds, and what result would change a decision |

The prioritised backlog is in [`docs/backlog.csv`](docs/backlog.csv);
`scripts/bootstrap_github.py` creates the labels, milestones and issues from it
on a new repository.

## 2. Branch

`main` is always releasable: tests pass, the acceptance gates pass, the docs
match the code. Work happens on short-lived branches named for the issue:

```
feat/42-review-queue        a user story
fix/57-shadowed-transform   a bug
exp/61-seed-sensitivity     an experiment
docs/64-traceability        documentation only
```

## 3. Commit

One logical change per commit, message in the imperative, with the issue
number:

```
Hold the scoring slot for the whole request (#58)

Concurrent requests took turns on the interpreter lock; at 8 in flight
throughput fell to 43 messages/s. Serving them in arrival order keeps it
at 66 and halves the p95. Measured with `phishguard loadtest`.
```

The body says *why*, and quotes the measurement when a number moved.

## 4. Check locally before pushing

```bash
ruff check src tests scripts          # lint, including the security rules
ruff format --check src tests scripts # formatting
pytest                                # 281 tests, about a minute
phishguard doctor                     # environment preflight
```

If the change touches the model, the features, the defences or the attack
suite, also run the gates — a robustness regression must not merge:

```bash
phishguard train --n 9000 --save
phishguard evaluate --n 9000 --budget 10 --max-attacked 150
```

No pytest? `python scripts/run_tests.py` runs the same suite with no
dependencies beyond the project's own.

## 5. Open a pull request

The template asks for: what changed and why, the linked issue, how it was
tested, any change to a measured result (with before and after), and the
security and privacy checklist. CI must be green: lint, tests on Python 3.10,
3.11 and 3.12, the dependency and secret scan, the acceptance gates, and the
container smoke test.

## 6. Review

Every pull request into `main` is reviewed — by a teammate, or on a team of
one, by the author the next day with the diff read top to bottom and the review
written as comments. Reviewers check, in this order:

1. **Correctness** — does it do what the issue says, and is there a test that
   would fail without it?
2. **Security and privacy** — no message content in logs, traces or the
   database; no new unauthenticated endpoint; no secret in the diff; inputs
   bounded; authorisation checked on the object, not just the role.
3. **Measurement** — if a number in the dossier moves, is the new number
   explained, and is it better for the right reason?
4. **Operability** — can an administrator see it working (metric, log line,
   trace span) and turn it off or roll it back?
5. **Readability** — would the next person understand why, not just what?

`CODEOWNERS` routes each area to the role that owns it (data, model, systems;
see [docs/10](docs/10-work-log.md) §10.2).

## 7. Definition of done

- [ ] Acceptance criteria of the issue are met and demonstrated.
- [ ] Tests added or updated; the full suite passes.
- [ ] Lint and format pass.
- [ ] Docs updated where behaviour, configuration or a number changed.
- [ ] `CHANGELOG.md` has an entry under the next version.
- [ ] If the model or attack suite changed: evaluation re-run, gates pass,
      dossier and model card regenerated.

## 8. Releasing

1. Move the `CHANGELOG.md` entries under a new version heading with the date.
2. Bump `version` in `pyproject.toml` and `__version__` in
   `src/phishguard/__init__.py`.
3. Tag: `git tag -a v1.3.0 -m "PhishGuard 1.3.0"` and push the tag. The
   release workflow builds the container image, runs the smoke test and
   publishes a release with the changelog section as its notes.

## Data and secrets

Never commit message corpora, trained models, audit databases, API keys or
salts. `data/`, `artifacts/models/` and `*.db` are git-ignored, and CI fails on
anything that looks like a committed credential. See [SECURITY.md](SECURITY.md).
