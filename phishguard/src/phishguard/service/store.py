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
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 1

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
            conn = sqlite3.connect(
                str(self.path), timeout=self._timeout, check_same_thread=False
            )
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
            row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version(version) VALUES (?)",
                             (SCHEMA_VERSION,))

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
    ) -> dict[str, Any]:
        """Append one decision. ``redacted`` must already be content-free."""
        created_at, created_ts = _now()
        evidence_titles = [
            str(e.get("title", ""))[:200] for e in verdict.get("evidence", [])[:6]
        ]
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
        }
        with self._tx() as conn:
            conn.execute(
                f"INSERT INTO decisions ({','.join(row)}) "
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
                (feedback_id, decision_id, created_at, created_ts, analyst_label,
                 rationale[:2000], action_taken[:64], key_id),
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
                (probe_id, created_at, created_ts, model_version, float(original_score),
                 float(final_score), int(evaded), int(queries), json.dumps(steps), key_id),
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
            conn.execute(
                f"SELECT COUNT(*) AS n FROM decisions d {where}", params
            ).fetchone()["n"]
        )
        rows = conn.execute(
            "SELECT d.*, f.analyst_label AS feedback_label FROM decisions d "
            "LEFT JOIN feedback f ON f.decision_id = d.decision_id "
            f"{where} ORDER BY d.created_ts DESC LIMIT ? OFFSET ?",
            [*params, int(max(1, min(limit, 500))), int(max(0, offset))],
        ).fetchall()
        return [self._row_to_dict(r) for r in rows], total

    def stats(self, *, window_hours: int = 24) -> dict[str, Any]:
        """Operational summary for the console and the monitoring endpoint."""
        conn = self._connect()
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=window_hours)
        ).timestamp()
        totals = conn.execute(
            "SELECT COUNT(*) AS n, AVG(score) AS avg_score, AVG(latency_ms) AS avg_latency "
            "FROM decisions WHERE created_ts >= ?", (cutoff,)
        ).fetchone()
        bands = conn.execute(
            "SELECT band, COUNT(*) AS n FROM decisions WHERE created_ts >= ? "
            "GROUP BY band", (cutoff,)
        ).fetchall()
        top_domains = conn.execute(
            "SELECT sender_domain, COUNT(*) AS n, AVG(score) AS avg_score "
            "FROM decisions WHERE created_ts >= ? AND sender_domain != '' "
            "GROUP BY sender_domain ORDER BY n DESC LIMIT 10", (cutoff,)
        ).fetchall()
        feedback = conn.execute(
            "SELECT analyst_label, COUNT(*) AS n FROM feedback WHERE created_ts >= ? "
            "GROUP BY analyst_label", (cutoff,)
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
                {"domain": r["sender_domain"], "count": int(r["n"]),
                 "mean_score": round(float(r["avg_score"] or 0.0), 4)}
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
        """Retention enforcement. Returns the number of decisions removed."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
        with self._tx() as conn:
            conn.execute(
                "DELETE FROM feedback WHERE decision_id IN "
                "(SELECT decision_id FROM decisions WHERE created_ts < ?)",
                (cutoff,),
            )
            cursor = conn.execute("DELETE FROM decisions WHERE created_ts < ?", (cutoff,))
            conn.execute("DELETE FROM probes WHERE created_ts < ?", (cutoff,))
            return int(cursor.rowcount or 0)

    def count(self) -> int:
        return int(
            self._connect().execute("SELECT COUNT(*) AS n FROM decisions").fetchone()["n"]
        )

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
