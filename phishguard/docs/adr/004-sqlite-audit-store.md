# ADR-004: Use SQLite in WAL mode for the audit trail, behind a repository interface

- **Status**: Accepted
- **Date**: 2026-09-07
- **Deciders**: Capstone team (BAI-17)

## Context

Human oversight is a requirement with a concrete test: an analyst must be able
to answer *why did this message get blocked last Tuesday* after the fact. That
means every decision is recorded, every analyst judgement is attached to the
decision it concerns, and the record survives a restart.

The workload has a specific shape. One row per scan, appended by a single
process, never updated. Reads are the console paging and filtering by band,
sender domain, score and time, plus two aggregations: `stats()` over a rolling
window (band counts, mean score and latency, top sender domains, analyst
disagreements) and `score_distribution()`, which is the drift monitor's raw
input. Volume is modest and retention defaults to 90 days.

The deployment is one application container with a `/data` volume, and an
acceptance criterion is that the system runs on a clean machine from documented
instructions. Every additional service in `docker compose` is another way for
that claim to become aspirational. A second decision is embedded here: the trail
is a log of decisions about people's mail, so what it stores is a privacy
question before it is a storage question.

## Decision

`src/phishguard/service/store.py` implements `DecisionStore` over SQLite in WAL
mode, with `synchronous=NORMAL`, `foreign_keys=ON` and a five-second busy
timeout, using thread-local connections and plain SQL rather than an ORM. Three
tables: `decisions`, `feedback` (foreign-keyed to a decision) and `probes`.
Retention is enforced in-process by `purge_older_than`, called by
`retention_sweep` at startup and daily.

No message content is stored. A row carries a truncated SHA-256 digest of the
subject, a salted pseudonym of the sender address, the sender domain, recipient
count, body length, attachment count, the score, band and label, member scores,
and the titles of the top six evidence items. Enough to investigate an incident,
not enough to reconstruct anybody's mail.

## Alternatives considered

### PostgreSQL

The right answer at scale and the boring production choice, which counts in its
favour. It handles concurrent writers, has real migration tooling, supports
partitioning and retention policies that need not be hand-written, and decouples
the audit trail's lifetime from the container's volume, so losing the container
does not lose the record. Every SQLite limit listed below is an argument for
PostgreSQL the day that limit binds.

Rejected because it adds a service, a connection pool, a migration story and a
failure mode to a system with exactly one writer. In a single-node deployment a
database outage is indistinguishable from an API outage to the caller, so the
extra component buys availability that cannot be realised. The interface is five
methods wide and the schema is plain SQL, so the migration stays available.

### Append-only JSONL files

The simplest thing that could work: no schema, no locking, trivially greppable,
naturally rotatable, readable with tools every operator already has. For a pure
append-only log it would be entirely adequate.

Rejected because the reads are not appends. `stats()` groups by band and by
sender domain over a window and joins feedback to decisions; `list_decisions`
filters on four dimensions and pages; `get_decision` is a point lookup. Serving
those over JSONL means building indexes, a query path and a windowing scheme,
which is writing a worse database to avoid using the one that ships with Python.

### Structured logs to the existing telemetry pipeline

The service already emits JSON logs and Prometheus metrics. Sending decisions
there means no store at all, with retention, access control and querying becoming
the log platform's problem, which is where many organisations prefer them.

Rejected because analyst feedback is a write against a specific existing record
with a foreign key to it, and the disagreement query that produces the drift
signal is a join. A log pipeline is a poor place for a mutable, referentially
constrained record, and retention enforcement would stop being a tested method
here and become a configuration item in somebody else's system.

## Consequences

**Positive**

- The container is self-contained: `docker compose up` on a clean machine gives a
  working audit trail with no external dependency.
- WAL means the console's reads never block a scan write, which is what makes a
  single-file store viable on the inline mail path.
- Data minimisation is structural rather than procedural. There is no column that
  could hold a body or a subject line, so it cannot be logged by accident.
- Retention is enforced by code with tests, not by a runbook.

**Negative**

- Single-node by construction. Two API replicas over a shared volume is not
  supported and would present as lock contention rather than a clean failure.
- `synchronous=NORMAL` trades a narrow durability window for write throughput, so
  the most recent decisions can be lost on an unclean shutdown. Acceptable for a
  trail whose purpose is investigation; not acceptable for a system of record.
- The subject digest is an unsalted SHA-256 truncated to 16 hex characters. The
  sender pseudonym is salted; the subject digest is not, so common subject lines
  such as "Invoice attached" are recoverable by dictionary from a stolen
  database. The fix is to salt it with the same `pseudonymization_salt`, at the
  cost of breaking correlation with existing rows.
- `SCHEMA_VERSION` exists with no migration runner behind it, so a schema change
  is a manual operation on the volume.
- A `database_url` setting exists in configuration and is not read by this store,
  which is a loose end that could mislead an operator.

**Neutral / accepted trade-offs**

- No ORM: queries are hand-written strings, checkable by eye, not composable, and
  not portable to another dialect without editing.
- The store is a process-wide singleton with a test reset hook, which is
  convenient and makes multi-tenant use in one process impossible.
- Sender domain is stored in the clear on purpose. Domain-level correlation is
  the most useful thing the trail does, and a domain is not personal data in the
  way a mailbox address is.

## Revisit when

- Sustained write rate exceeds roughly 50 decisions per second, or the API needs
  more than one replica.
- Retained rows exceed a few tens of millions, at which point the windowed
  aggregations stop being fast enough to serve the console synchronously.
- A compliance requirement demands write-ahead durability. `synchronous=FULL` is
  the cheap answer and costs throughput; PostgreSQL is the better one.
- The trail must outlive the container's volume, or be joined against an external
  identity, SIEM or ticketing system.
