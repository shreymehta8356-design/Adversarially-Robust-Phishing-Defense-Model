"""The audit trail.

Every decision the system makes is recorded, because "expose operational
evidence such as logs, metrics and traces" and "human oversight" both require
that an analyst can answer *why did this message get blocked last Tuesday*
after the fact.

Two design decisions worth defending.

**SQLite, in WAL mode, behind a repository interface.** The audit trail is an
append-mostly single-writer log with modest volume, which is precisely SQLite's
strength; it needs no server, starts instantly, makes the container
self-contained and keeps the "runs on a clean machine" gate honest. The
interface is narrow enough that swapping in PostgreSQL means implementing five
methods, and the schema is plain SQL rather than an ORM's projection of it.

**No message content is stored.** Not the subject, not the body, not the
sender's address. Rows carry a salted digest of the subject, a pseudonymised
sender, the sender's domain, sizes, the score and the top evidence *titles*.
That is enough to investigate an incident and not enough to reconstruct
anybody's mail, which is what data minimisation means in practice.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

#: 1 - decisions, feedback, probes. 2 - the review queue (cases, case_events)
#: and a trace id on every decision. Upgrades happen in place on open.
SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id         TEXT PRIMARY KEY,
    request_id          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    created_ts          REAL NOT NULL,
    score               REAL NOT NULL,
    band                TEXT NOT NULL,
    label               INTEGER NOT NULL,
    model_version       TEXT NOT NULL,
    subject_hash        TEXT NOT NULL DEFAULT '',
    sender_px           TEXT NOT NULL DEFAULT '',
    sender_domain       TEXT NOT NULL DEFAULT '',
    recipient_count     INTEGER NOT NULL DEFAULT 0,
    body_length         INTEGER NOT NULL DEFAULT 0,
    attachment_count    INTEGER NOT NULL DEFAULT 0,
    behavioral_available INTEGER NOT NULL DEFAULT 0,
    latency_ms          REAL NOT NULL DEFAULT 0,
    member_scores       TEXT NOT NULL DEFAULT '{}',
    top_evidence        TEXT NOT NULL DEFAULT '[]',
    key_id              TEXT NOT NULL DEFAULT '',
    client_reference    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_decisions_created  ON decisions(created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_band     ON decisions(band, created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_domain   ON decisions(sender_domain);
CREATE INDEX IF NOT EXISTS idx_decisions_request  ON decisions(request_id);

CREATE TABLE IF NOT EXISTS feedback (
    feedback_id   TEXT PRIMARY KEY,
    decision_id   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    created_ts    REAL NOT NULL,
    analyst_label TEXT NOT NULL,
    rationale     TEXT NOT NULL DEFAULT '',
    action_taken  TEXT NOT NULL DEFAULT '',
    key_id        TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (decision_id) REFERENCES decisions(decision_id)
);

CREATE INDEX IF NOT EXISTS idx_feedback_decision ON feedback(decision_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created  ON feedback(created_ts DESC);

CREATE TABLE IF NOT EXISTS cases (
    case_id       TEXT PRIMARY KEY,
    decision_id   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    created_ts    REAL NOT NULL,
    updated_ts    REAL NOT NULL,
    state         TEXT NOT NULL,
    origin        TEXT NOT NULL,
    priority      INTEGER NOT NULL,
    sla_due_ts    REAL NOT NULL,
    assignee      TEXT,
    claimed_ts    REAL,
    resolved_ts   REAL,
    resolution    TEXT,
    reporter_key  TEXT NOT NULL DEFAULT '',
    reporter_px   TEXT NOT NULL DEFAULT '',
    report_category TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (decision_id) REFERENCES decisions(decision_id)
);

CREATE INDEX IF NOT EXISTS idx_cases_state    ON cases(state, priority, created_ts);
CREATE INDEX IF NOT EXISTS idx_cases_reporter ON cases(reporter_key, reporter_px);
CREATE INDEX IF NOT EXISTS idx_cases_decision ON cases(decision_id);

CREATE TABLE IF NOT EXISTS case_events (
    event_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    created_ts    REAL NOT NULL,
    actor         TEXT NOT NULL,
    actor_role    TEXT NOT NULL,
    action        TEXT NOT NULL,
    from_state    TEXT,
    to_state      TEXT,
    note          TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events(case_id, event_id);

CREATE TABLE IF NOT EXISTS probes (
    probe_id      TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    created_ts    REAL NOT NULL,
    model_version TEXT NOT NULL,
    original_score REAL NOT NULL,
    final_score   REAL NOT NULL,
    evaded        INTEGER NOT NULL,
    queries       INTEGER NOT NULL,
    steps         TEXT NOT NULL DEFAULT '[]',
    key_id        TEXT NOT NULL DEFAULT ''
);
"""


def _now() -> tuple[str, float]:
    now = datetime.now(timezone.utc)
    return now.isoformat(timespec="milliseconds"), now.timestamp()


class DecisionStore:
    """SQLite-backed audit trail."""

    def __init__(self, path: str | Path, *, timeout: float = 10.0) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._initialise()

    # ------------------------------------------------------------ plumbing
    def _connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.path), timeout=self._timeout, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # WAL lets readers proceed while a write is in flight, which is what
            # makes a single-file store viable under concurrent scan traffic.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _initialise(self) -> None:
        with self._init_lock, self._tx() as conn:
            conn.executescript(_SCHEMA)
            # In-place upgrade of a version-1 store: the new tables above are
            # created idempotently; a column added to an existing table needs
            # an explicit ALTER, guarded so it runs once.
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(decisions)")}
            if "trace_id" not in columns:
                conn.execute("ALTER TABLE decisions ADD COLUMN trace_id TEXT NOT NULL DEFAULT ''")
            row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
            elif int(row["version"]) < SCHEMA_VERSION:
                conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))

    def schema_version(self) -> int:
        row = self._connect().execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        return int(row["version"]) if row else 0

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ------------------------------------------------------------- writes
    def record_decision(
        self,
        *,
        decision_id: str,
        request_id: str,
        verdict: dict[str, Any],
        redacted: dict[str, Any],
        key_id: str = "",
        client_reference: str = "",
        trace_id: str = "",
    ) -> dict[str, Any]:
        """Append one decision. ``redacted`` must already be content-free."""
        created_at, created_ts = _now()
        evidence_titles = [str(e.get("title", ""))[:200] for e in verdict.get("evidence", [])[:6]]
        row = {
            "decision_id": decision_id,
            "request_id": request_id,
            "created_at": created_at,
            "created_ts": created_ts,
            "score": float(verdict.get("score", 0.0)),
            "band": str(verdict.get("band", "")),
            "label": int(verdict.get("label", 0)),
            "model_version": str(verdict.get("model_version", "")),
            "subject_hash": str(redacted.get("subject_hash", "")),
            "sender_px": str(redacted.get("sender_px", "")),
            "sender_domain": str(redacted.get("sender_domain", "")),
            "recipient_count": int(redacted.get("recipient_count", 0)),
            "body_length": int(redacted.get("body_length", 0)),
            "attachment_count": int(redacted.get("attachment_count", 0)),
            "behavioral_available": int(bool(verdict.get("behavioral_available"))),
            "latency_ms": float(verdict.get("latency_ms", 0.0)),
            "member_scores": json.dumps(verdict.get("member_scores", {})),
            "top_evidence": json.dumps(evidence_titles),
            "key_id": key_id,
            "client_reference": client_reference[:128],
            "trace_id": trace_id[:64],
        }
        with self._tx() as conn:
            conn.execute(
                f"INSERT INTO decisions ({','.join(row)}) "  # noqa: S608 - column names are fixed literals above
                f"VALUES ({','.join(':' + k for k in row)})",
                row,
            )
        return row

    def record_feedback(
        self,
        *,
        feedback_id: str,
        decision_id: str,
        analyst_label: str,
        rationale: str = "",
        action_taken: str = "",
        key_id: str = "",
    ) -> dict[str, Any]:
        created_at, created_ts = _now()
        with self._tx() as conn:
            exists = conn.execute(
                "SELECT 1 FROM decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(decision_id)
            conn.execute(
                "INSERT INTO feedback (feedback_id, decision_id, created_at, created_ts, "
                "analyst_label, rationale, action_taken, key_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    feedback_id,
                    decision_id,
                    created_at,
                    created_ts,
                    analyst_label,
                    rationale[:2000],
                    action_taken[:64],
                    key_id,
                ),
            )
        return {
            "feedback_id": feedback_id,
            "decision_id": decision_id,
            "recorded_at": created_at,
            "analyst_label": analyst_label,
        }

    def record_probe(
        self,
        *,
        probe_id: str,
        model_version: str,
        original_score: float,
        final_score: float,
        evaded: bool,
        queries: int,
        steps: list[str],
        key_id: str = "",
    ) -> None:
        created_at, created_ts = _now()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO probes (probe_id, created_at, created_ts, model_version, "
                "original_score, final_score, evaded, queries, steps, key_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    probe_id,
                    created_at,
                    created_ts,
                    model_version,
                    float(original_score),
                    float(final_score),
                    int(evaded),
                    int(queries),
                    json.dumps(steps),
                    key_id,
                ),
            )

    # -------------------------------------------------------------- reads
    def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        row = conn.execute(
            "SELECT d.*, f.analyst_label AS feedback_label "
            "FROM decisions d LEFT JOIN feedback f ON f.decision_id = d.decision_id "
            "WHERE d.decision_id = ?",
            (decision_id,),
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_decisions(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        band: str | None = None,
        sender_domain: str | None = None,
        min_score: float | None = None,
        since_ts: float | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        conn = self._connect()
        clauses: list[str] = []
        params: list[Any] = []
        if band:
            clauses.append("d.band = ?")
            params.append(band)
        if sender_domain:
            clauses.append("d.sender_domain = ?")
            params.append(sender_domain.lower())
        if min_score is not None:
            clauses.append("d.score >= ?")
            params.append(float(min_score))
        if since_ts is not None:
            clauses.append("d.created_ts >= ?")
            params.append(float(since_ts))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        total = int(
            conn.execute(f"SELECT COUNT(*) AS n FROM decisions d {where}", params).fetchone()["n"]  # noqa: S608 - fixed fragments; every value is a ? parameter
        )
        rows = conn.execute(
            "SELECT d.*, f.analyst_label AS feedback_label FROM decisions d "  # noqa: S608 - fixed fragments; every value is a ? parameter
            "LEFT JOIN feedback f ON f.decision_id = d.decision_id "
            f"{where} ORDER BY d.created_ts DESC LIMIT ? OFFSET ?",
            [*params, int(max(1, min(limit, 500))), int(max(0, offset))],
        ).fetchall()
        return [self._row_to_dict(r) for r in rows], total

    def stats(self, *, window_hours: int = 24) -> dict[str, Any]:
        """Operational summary for the console and the monitoring endpoint."""
        conn = self._connect()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).timestamp()
        totals = conn.execute(
            "SELECT COUNT(*) AS n, AVG(score) AS avg_score, AVG(latency_ms) AS avg_latency "
            "FROM decisions WHERE created_ts >= ?",
            (cutoff,),
        ).fetchone()
        bands = conn.execute(
            "SELECT band, COUNT(*) AS n FROM decisions WHERE created_ts >= ? GROUP BY band",
            (cutoff,),
        ).fetchall()
        top_domains = conn.execute(
            "SELECT sender_domain, COUNT(*) AS n, AVG(score) AS avg_score "
            "FROM decisions WHERE created_ts >= ? AND sender_domain != '' "
            "GROUP BY sender_domain ORDER BY n DESC LIMIT 10",
            (cutoff,),
        ).fetchall()
        feedback = conn.execute(
            "SELECT analyst_label, COUNT(*) AS n FROM feedback WHERE created_ts >= ? "
            "GROUP BY analyst_label",
            (cutoff,),
        ).fetchall()
        # Disagreement between the model and the analysts who reviewed it: the
        # single most useful drift signal this service can produce on its own.
        disagreements = conn.execute(
            "SELECT COUNT(*) AS n FROM feedback f JOIN decisions d "
            "ON d.decision_id = f.decision_id WHERE f.created_ts >= ? AND ("
            "  (f.analyst_label = 'phishing'   AND d.band = 'ALLOW') OR "
            "  (f.analyst_label = 'legitimate' AND d.band = 'BLOCK'))",
            (cutoff,),
        ).fetchone()
        return {
            "window_hours": window_hours,
            "decisions": int(totals["n"] or 0),
            "mean_score": round(float(totals["avg_score"] or 0.0), 5),
            "mean_latency_ms": round(float(totals["avg_latency"] or 0.0), 3),
            "bands": {r["band"]: int(r["n"]) for r in bands},
            "top_sender_domains": [
                {
                    "domain": r["sender_domain"],
                    "count": int(r["n"]),
                    "mean_score": round(float(r["avg_score"] or 0.0), 4),
                }
                for r in top_domains
            ],
            "feedback": {r["analyst_label"]: int(r["n"]) for r in feedback},
            "analyst_disagreements": int(disagreements["n"] or 0),
        }

    def score_distribution(self, *, bins: int = 10, window_hours: int = 24) -> list[dict[str, Any]]:
        """Score histogram over a window - the drift monitor's raw input."""
        conn = self._connect()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).timestamp()
        rows = conn.execute(
            "SELECT score FROM decisions WHERE created_ts >= ?", (cutoff,)
        ).fetchall()
        counts = [0] * bins
        for r in rows:
            idx = min(int(float(r["score"]) * bins), bins - 1)
            counts[max(idx, 0)] += 1
        return [
            {"lower": round(i / bins, 3), "upper": round((i + 1) / bins, 3), "count": c}
            for i, c in enumerate(counts)
        ]

    def purge_older_than(self, days: int) -> int:
        """Retention enforcement. Returns the number of decisions removed.

        A case still being worked keeps its decision past retention: deleting
        the evidence under an analyst mid-review would be worse than keeping
        one row a little longer. Resolved cases go with their decisions.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
        with self._tx() as conn:
            expired = (
                "SELECT d.decision_id FROM decisions d WHERE d.created_ts < ? AND NOT EXISTS "
                "(SELECT 1 FROM cases c WHERE c.decision_id = d.decision_id "
                " AND c.state IN ('open', 'in_review', 'escalated'))"
            )
            conn.execute(
                "DELETE FROM case_events WHERE case_id IN "  # noqa: S608 - fixed fragments; every value is a ? parameter
                f"(SELECT case_id FROM cases WHERE decision_id IN ({expired}))",
                (cutoff,),
            )
            conn.execute(f"DELETE FROM cases WHERE decision_id IN ({expired})", (cutoff,))  # noqa: S608
            conn.execute(
                f"DELETE FROM feedback WHERE decision_id IN ({expired})",  # noqa: S608 - fixed SQL
                (cutoff,),
            )
            cursor = conn.execute(
                f"DELETE FROM decisions WHERE decision_id IN ({expired})",  # noqa: S608 - fixed SQL
                (cutoff,),
            )
            conn.execute("DELETE FROM probes WHERE created_ts < ?", (cutoff,))
            return int(cursor.rowcount or 0)

    def count(self) -> int:
        return int(self._connect().execute("SELECT COUNT(*) AS n FROM decisions").fetchone()["n"])

    # ------------------------------------------------------ review queue
    _CASE_COLUMNS = (
        "c.case_id, c.decision_id, c.created_at, c.created_ts, c.updated_ts, c.state, "
        "c.origin, c.priority, c.sla_due_ts, c.assignee, c.claimed_ts, c.resolved_ts, "
        "c.resolution, c.reporter_key, c.reporter_px, c.report_category, "
        "d.score, d.band, d.sender_domain, d.top_evidence, d.member_scores, "
        "d.model_version, d.trace_id"
    )

    def open_case(
        self,
        *,
        case_id: str,
        decision_id: str,
        origin: str,
        priority: int,
        sla_due_ts: float,
        actor: str,
        actor_role: str,
        reporter_key: str = "",
        reporter_px: str = "",
        report_category: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        """Create a case and its first event in one transaction."""
        created_at, created_ts = _now()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO cases (case_id, decision_id, created_at, created_ts, updated_ts, "
                "state, origin, priority, sla_due_ts, reporter_key, reporter_px, report_category) "
                "VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    decision_id,
                    created_at,
                    created_ts,
                    created_ts,
                    origin,
                    int(priority),
                    float(sla_due_ts),
                    reporter_key,
                    reporter_px,
                    report_category[:32],
                ),
            )
            conn.execute(
                "INSERT INTO case_events (case_id, created_at, created_ts, actor, actor_role, "
                "action, from_state, to_state, note) VALUES (?, ?, ?, ?, ?, 'opened', NULL, "
                "'open', ?)",
                (case_id, created_at, created_ts, actor, actor_role, note[:1000]),
            )
        return {"case_id": case_id, "created_at": created_at, "created_ts": created_ts}

    def case_for_decision(self, decision_id: str) -> str | None:
        row = (
            self._connect()
            .execute(
                "SELECT case_id FROM cases WHERE decision_id = ? ORDER BY created_ts LIMIT 1",
                (decision_id,),
            )
            .fetchone()
        )
        return row["case_id"] if row else None

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        row = conn.execute(
            f"SELECT {self._CASE_COLUMNS} FROM cases c "  # noqa: S608 - fixed column list
            "JOIN decisions d ON d.decision_id = c.decision_id WHERE c.case_id = ?",
            (case_id,),
        ).fetchone()
        if row is None:
            return None
        out = self._row_to_dict(row)
        out["events"] = [
            dict(e)
            for e in conn.execute(
                "SELECT event_id, created_at, created_ts, actor, actor_role, action, "
                "from_state, to_state, note FROM case_events WHERE case_id = ? "
                "ORDER BY event_id",
                (case_id,),
            ).fetchall()
        ]
        return out

    def list_cases(
        self,
        *,
        states: tuple[str, ...] | None = None,
        priority: int | None = None,
        reporter_key: str | None = None,
        reporter_px: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if states:
            clauses.append(f"c.state IN ({','.join('?' for _ in states)})")
            params.extend(states)
        if priority is not None:
            clauses.append("c.priority = ?")
            params.append(int(priority))
        if reporter_key is not None:
            clauses.append("c.reporter_key = ?")
            params.append(reporter_key)
        if reporter_px:
            clauses.append("c.reporter_px = ?")
            params.append(reporter_px)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        conn = self._connect()
        total = int(
            conn.execute(
                f"SELECT COUNT(*) AS n FROM cases c {where}",  # noqa: S608 - fixed fragments; every value is a ? parameter
                params,
            ).fetchone()["n"]
        )
        # Active work first by priority then age; resolved work newest first.
        rows = conn.execute(
            f"SELECT {self._CASE_COLUMNS} FROM cases c "  # noqa: S608 - placeholders only
            f"JOIN decisions d ON d.decision_id = c.decision_id {where} "
            "ORDER BY CASE WHEN c.state = 'resolved' THEN 1 ELSE 0 END, "
            "CASE WHEN c.state = 'resolved' THEN -c.updated_ts ELSE c.priority END, "
            "c.created_ts LIMIT ? OFFSET ?",
            [*params, int(max(1, min(limit, 500))), int(max(0, offset))],
        ).fetchall()
        return [self._row_to_dict(r) for r in rows], total

    def apply_transition(
        self,
        *,
        case_id: str,
        expected_state: str,
        to_state: str,
        assignee: str | None,
        resolution: str | None,
        action: str,
        actor: str,
        actor_role: str,
        note: str = "",
    ) -> bool:
        """Persist a validated transition.

        The UPDATE matches on the state the caller validated against, so two
        analysts claiming the same case at once cannot both succeed: the second
        update matches no row and ``False`` is returned.
        """
        created_at, now = _now()
        with self._tx() as conn:
            if to_state != expected_state or action != "comment":
                cursor = conn.execute(
                    "UPDATE cases SET state = ?, assignee = ?, resolution = ?, updated_ts = ?, "
                    "claimed_ts = CASE WHEN ? = 'claim' THEN ? ELSE claimed_ts END, "
                    "resolved_ts = CASE WHEN ? = 'resolved' THEN ? "
                    "                   WHEN ? = 'open' THEN NULL ELSE resolved_ts END "
                    "WHERE case_id = ? AND state = ?",
                    (
                        to_state,
                        assignee,
                        resolution if to_state == "resolved" else None,
                        now,
                        action,
                        now,
                        to_state,
                        now,
                        to_state,
                        case_id,
                        expected_state,
                    ),
                )
                if cursor.rowcount != 1:
                    return False
            conn.execute(
                "INSERT INTO case_events (case_id, created_at, created_ts, actor, actor_role, "
                "action, from_state, to_state, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    created_at,
                    now,
                    actor,
                    actor_role,
                    action,
                    expected_state,
                    to_state,
                    note[:1000],
                ),
            )
        return True

    def queue_depth(self, *, now: float | None = None) -> tuple[dict[str, int], int]:
        """Cases per state, and active cases past their service level. Cheap."""
        now = time.time() if now is None else now
        conn = self._connect()
        by_state = {
            r["state"]: int(r["n"])
            for r in conn.execute("SELECT state, COUNT(*) AS n FROM cases GROUP BY state")
        }
        overdue = int(
            conn.execute(
                "SELECT COUNT(*) AS n FROM cases WHERE state IN ('open', 'in_review', 'escalated') "
                "AND sla_due_ts < ?",
                (now,),
            ).fetchone()["n"]
        )
        return by_state, overdue

    def queue_stats(self, *, now: float | None = None, window_days: int = 30) -> dict[str, Any]:
        """Queue health: depth, overdue work, time to claim and to resolve."""
        now = time.time() if now is None else now
        cutoff = now - window_days * 86400
        conn = self._connect()
        by_state, overdue = self.queue_depth(now=now)
        active_by_priority = {
            int(r["priority"]): int(r["n"])
            for r in conn.execute(
                "SELECT priority, COUNT(*) AS n FROM cases "
                "WHERE state IN ('open', 'in_review', 'escalated') GROUP BY priority"
            )
        }
        resolved = conn.execute(
            "SELECT origin, resolution, created_ts, claimed_ts, resolved_ts, sla_due_ts "
            "FROM cases WHERE state = 'resolved' AND resolved_ts >= ?",
            (cutoff,),
        ).fetchall()

        def median(values: list[float]) -> float | None:
            if not values:
                return None
            v = sorted(values)
            mid = len(v) // 2
            return round(v[mid] if len(v) % 2 else (v[mid - 1] + v[mid]) / 2, 1)

        to_claim = [r["claimed_ts"] - r["created_ts"] for r in resolved if r["claimed_ts"]]
        to_resolve = [r["resolved_ts"] - r["created_ts"] for r in resolved]
        reports = [r for r in resolved if r["origin"] == "user_report"]
        confirmed = sum(1 for r in reports if r["resolution"] == "confirmed_phishing")
        return {
            "by_state": {
                s: by_state.get(s, 0) for s in ("open", "in_review", "escalated", "resolved")
            },
            "active_by_priority": {f"P{p}": active_by_priority.get(p, 0) for p in (1, 2, 3)},
            "overdue": overdue,
            "window_days": window_days,
            "resolved_in_window": len(resolved),
            "resolutions": {
                "confirmed_phishing": sum(
                    1 for r in resolved if r["resolution"] == "confirmed_phishing"
                ),
                "released": sum(1 for r in resolved if r["resolution"] == "released"),
            },
            "median_seconds_to_claim": median(to_claim),
            "median_seconds_to_resolve": median(to_resolve),
            "resolved_within_sla": (
                round(
                    sum(1 for r in resolved if r["resolved_ts"] <= r["sla_due_ts"]) / len(resolved),
                    4,
                )
                if resolved
                else None
            ),
            "user_reports_resolved": len(reports),
            "user_report_precision": round(confirmed / len(reports), 4) if reports else None,
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        out = dict(row)
        for key in ("member_scores", "top_evidence"):
            if key in out and isinstance(out[key], str):
                try:
                    out[key] = json.loads(out[key])
                except json.JSONDecodeError:
                    out[key] = {} if key == "member_scores" else []
        out["behavioral_available"] = bool(out.get("behavioral_available", 0))
        return out

    def monitoring_rows(
        self, *, window_hours: int = 24, limit: int = 20000
    ) -> list[dict[str, Any]]:
        """The content-free columns the drift monitor needs, for one window."""
        cutoff = time.time() - window_hours * 3600
        with self._tx() as conn:
            rows = conn.execute(
                """
                SELECT band, member_scores, body_length, recipient_count,
                       attachment_count, behavioral_available
                  FROM decisions
                 WHERE created_ts >= ?
                 ORDER BY created_ts DESC
                 LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------ oversight report
    def feedback_report(self, *, window_days: int = 30) -> dict[str, Any]:
        """How often analysts overrule the model, and in which direction.

        This is the closest thing to a supervised signal the deployment can
        produce, and it is deliberately *not* a training set. The audit store
        holds salted digests and structural counts, never message text or
        addresses in the clear, so there is nothing here to refit a model on
        even in principle. That is the privacy design working as intended, and
        it means the feedback loop is an operational one -- it tells an
        operator that the thresholds or the model have drifted and a fresh
        labelled corpus is needed -- rather than an automatic retrain, which
        would also be an obvious poisoning surface.
        """
        cutoff = time.time() - window_days * 86400
        with self._tx() as conn:
            rows = conn.execute(
                """
                SELECT f.analyst_label AS analyst_label,
                       f.action_taken  AS action_taken,
                       d.band          AS band,
                       d.score         AS score,
                       d.model_version AS model_version,
                       d.sender_domain AS sender_domain
                  FROM feedback f
                  JOIN decisions d ON d.decision_id = f.decision_id
                 WHERE f.created_ts >= ?
                """,
                (cutoff,),
            ).fetchall()

        total = len(rows)
        out: dict[str, Any] = {
            "window_days": window_days,
            "n_feedback": total,
            "by_analyst_label": {},
            "by_band": {},
            "disagreements": 0,
            "false_block_reports": 0,
            "missed_phish_reports": 0,
            "domains_most_reported": [],
            "note": (
                "Analyst feedback is an operational drift signal, not training "
                "data: the audit store holds no message text by design, so "
                "there is nothing here to refit on. A rising disagreement rate "
                "is the trigger to collect a fresh labelled corpus and retrain "
                "deliberately."
            ),
        }
        if not total:
            return out

        domains: dict[str, int] = {}
        for r in rows:
            label = (r["analyst_label"] or "unsure").lower()
            band = r["band"]
            out["by_analyst_label"][label] = out["by_analyst_label"].get(label, 0) + 1
            out["by_band"][band] = out["by_band"].get(band, 0) + 1
            model_says_phish = band == "BLOCK"
            if label == "legitimate" and model_says_phish:
                out["disagreements"] += 1
                out["false_block_reports"] += 1
                domains[r["sender_domain"]] = domains.get(r["sender_domain"], 0) + 1
            elif label == "phishing" and band == "ALLOW":
                out["disagreements"] += 1
                out["missed_phish_reports"] += 1
                domains[r["sender_domain"]] = domains.get(r["sender_domain"], 0) + 1

        out["disagreement_rate"] = round(out["disagreements"] / total, 4)
        out["domains_most_reported"] = [
            {"domain": d, "reports": n}
            for d, n in sorted(domains.items(), key=lambda kv: -kv[1])[:10]
            if d
        ]
        return out


_store: DecisionStore | None = None
_store_lock = threading.Lock()


def get_store(path: str | Path | None = None) -> DecisionStore:
    """Process-wide store singleton."""
    global _store
    with _store_lock:
        if _store is None or path is not None:
            from phishguard.config import get_settings

            target = Path(path) if path is not None else get_settings().db_path
            _store = DecisionStore(target)
        return _store


def reset_store() -> None:
    """Test helper: drop the singleton so the next call rebuilds it."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.close()
        _store = None


def retention_sweep(store: DecisionStore, days: int) -> dict[str, Any]:
    """Run once at startup and daily thereafter."""
    started = time.perf_counter()
    removed = store.purge_older_than(days)
    return {
        "removed": removed,
        "retention_days": days,
        "seconds": round(time.perf_counter() - started, 3),
    }
