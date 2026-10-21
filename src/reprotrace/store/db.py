"""SQLite index of runs, comparisons and divergences (Architecture.md 4.3).

The database holds metadata only. Raw traces, events and reports stay on disk; run folders
remain the source of truth for runs, and ``sync_runs`` indexes any folder the database does
not know yet (for example a run folder downloaded from CI).
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from reprotrace import config
from reprotrace.errors import ReproTraceError, SchemaVersionError, StoreError
from reprotrace.models import Divergence, Run
from reprotrace.store.run_files import all_run_ids, load_run

DB_SCHEMA_VERSION = 1

# Architecture.md 4.3, plus: schema_version on comparisons and divergences (Rules.md 6),
# and comparisons.details_json for labels, run ids and counts needed to rebuild a report.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, label TEXT, group_id TEXT, command_json TEXT,
  exit_code INTEGER, timed_out INTEGER, duration_ms INTEGER,
  started_at TEXT, git_commit TEXT, trace_path TEXT, events_path TEXT,
  env_json TEXT, schema_version INTEGER
);
CREATE TABLE IF NOT EXISTS comparisons (
  id TEXT PRIMARY KEY, group_a TEXT, group_b TEXT,
  created_at TEXT, config_json TEXT, report_path TEXT,
  details_json TEXT, schema_version INTEGER
);
CREATE TABLE IF NOT EXISTS divergences (
  id TEXT PRIMARY KEY, comparison_id TEXT REFERENCES comparisons(id),
  kind TEXT, summary TEXT, score REAL, reasons_json TEXT,
  a_events_json TEXT, b_events_json TEXT, schema_version INTEGER
);
CREATE INDEX IF NOT EXISTS idx_runs_group ON runs(group_id);
CREATE INDEX IF NOT EXISTS idx_div_cmp ON divergences(comparison_id, score DESC);
"""


@contextmanager
def connect(base_dir: Path) -> Iterator[sqlite3.Connection]:
    """Open (and create if needed) the project database; commit on success."""
    path = config.db_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(path)
    except sqlite3.Error as exc:
        raise StoreError(f"Cannot open database {path}: {exc}") from exc
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _ensure_schema(conn, path)
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        raise StoreError(f"Database error in {path}: {exc}") from exc
    finally:
        conn.close()


def _ensure_schema(conn: sqlite3.Connection, path: Path) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        # One locked transaction: executescript would otherwise commit (and flush to disk)
        # after every statement, which made creating a database slow on some disks. Also
        # safe if two reprotrace commands create the database at the same time.
        conn.executescript(
            f"BEGIN IMMEDIATE;{_SCHEMA}PRAGMA user_version = {DB_SCHEMA_VERSION};COMMIT;"
        )
    elif version != DB_SCHEMA_VERSION:
        raise SchemaVersionError(
            f"Unsupported database schema version {version} in {path}",
            hint=f"This version of reprotrace reads schema version {DB_SCHEMA_VERSION}.",
        )


def upsert_run(conn: sqlite3.Connection, run: Run) -> None:
    """Insert or replace one run's metadata."""
    conn.execute(
        "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            run.id, run.label, run.group_id, json.dumps(run.command), run.exit_code,
            int(run.timed_out), run.duration_ms, run.started_at.isoformat(), run.git_commit,
            run.trace_path, f"{config.RUNS_DIR_NAME}/{run.id}/{config.EVENTS_FILE}",
            json.dumps(run.env_redacted), run.schema_version,
        ),
    )  # fmt: skip


@dataclass
class SyncResult:
    """Outcome of indexing run folders: how many were added, which were skipped and why."""

    added: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)


def sync_runs(conn: sqlite3.Connection, base_dir: Path) -> SyncResult:
    """Index run folders that are not in the database yet.

    Folders whose metadata cannot be loaded (corrupt, partial copy, unknown schema version)
    are skipped and reported, so one bad folder does not hide every other run.
    """
    known = {row[0] for row in conn.execute("SELECT id FROM runs")}
    result = SyncResult()
    for run_id in all_run_ids(base_dir):
        if run_id in known:
            continue
        try:
            run = load_run(base_dir, run_id)
        except ReproTraceError as error:
            result.skipped.append((run_id, error.message))
            continue
        upsert_run(conn, run)
        result.added += 1
    return result


@dataclass(frozen=True)
class RunRow:
    """One run as listed by ``reprotrace runs``."""

    id: str
    label: str
    group_id: str
    command: list[str]
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    started_at: datetime


def list_runs(conn: sqlite3.Connection) -> list[RunRow]:
    """All indexed runs, newest first."""
    rows = conn.execute(
        "SELECT id, label, group_id, command_json, exit_code, timed_out, duration_ms, "
        "started_at FROM runs ORDER BY started_at DESC, id"
    )
    return [
        RunRow(
            id=row["id"],
            label=row["label"],
            group_id=row["group_id"],
            command=json.loads(row["command_json"]),
            exit_code=row["exit_code"],
            timed_out=bool(row["timed_out"]),
            duration_ms=row["duration_ms"],
            started_at=datetime.fromisoformat(row["started_at"]),
        )
        for row in rows
    ]


@dataclass(frozen=True)
class StoredComparison:
    """A comparison read back from the database, divergences best first."""

    id: str
    ref_a: str
    ref_b: str
    created_at: datetime
    config: dict[str, Any]
    details: dict[str, Any]
    report_path: str | None
    divergences: list[Divergence]


def save_comparison(
    conn: sqlite3.Connection,
    comparison_id: str,
    ref_a: str,
    ref_b: str,
    created_at: datetime,
    config_data: dict[str, Any],
    details: dict[str, Any],
    ranked: list[Divergence],
) -> None:
    """Store a comparison and its ranked divergences.

    Divergence rows use the id ``<comparison_id>:<divergence id>`` so ids stay unique
    across comparisons.
    """
    conn.execute(
        "INSERT INTO comparisons VALUES (?,?,?,?,?,?,?,?)",
        (
            comparison_id, ref_a, ref_b, created_at.isoformat(), json.dumps(config_data),
            None, json.dumps(details), DB_SCHEMA_VERSION,
        ),
    )  # fmt: skip
    conn.executemany(
        "INSERT INTO divergences VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (
                f"{comparison_id}:{d.id}", comparison_id, d.kind, d.summary, d.score,
                json.dumps(d.reasons), json.dumps(d.a_event_ids), json.dumps(d.b_event_ids),
                d.schema_version,
            )
            for d in ranked
        ],
    )  # fmt: skip


def load_comparison(conn: sqlite3.Connection, comparison_id: str) -> StoredComparison:
    """Read a comparison and its divergences (highest score first)."""
    row = conn.execute("SELECT * FROM comparisons WHERE id = ?", (comparison_id,)).fetchone()
    if row is None:
        raise StoreError(
            f"Comparison not found: {comparison_id}",
            hint="Comparison ids are printed by 'reprotrace diff'.",
        )
    if row["schema_version"] != DB_SCHEMA_VERSION:
        raise SchemaVersionError(
            f"Unsupported schema_version {row['schema_version']} for {comparison_id}"
        )
    prefix = f"{comparison_id}:"
    divergences = [
        Divergence(
            id=d["id"].removeprefix(prefix),
            kind=d["kind"],
            summary=d["summary"],
            a_event_ids=json.loads(d["a_events_json"]),
            b_event_ids=json.loads(d["b_events_json"]),
            score=d["score"],
            reasons=json.loads(d["reasons_json"]),
        )
        for d in conn.execute(
            "SELECT * FROM divergences WHERE comparison_id = ? ORDER BY score DESC, rowid",
            (comparison_id,),
        )
    ]
    return StoredComparison(
        id=row["id"],
        ref_a=row["group_a"],
        ref_b=row["group_b"],
        created_at=datetime.fromisoformat(row["created_at"]),
        config=json.loads(row["config_json"]),
        details=json.loads(row["details_json"]),
        report_path=row["report_path"],
        divergences=divergences,
    )


def set_report_path(conn: sqlite3.Connection, comparison_id: str, path: str) -> None:
    """Record where the Markdown report of a comparison was written."""
    conn.execute("UPDATE comparisons SET report_path = ? WHERE id = ?", (path, comparison_id))
