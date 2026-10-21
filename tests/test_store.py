"""Phase 6: SQLite store (runs, comparisons, divergences)."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conftest import fixture_run, install_fixture_run
from reprotrace import config
from reprotrace.diff.compare import compare_saved
from reprotrace.diff.rank import rank_divergences
from reprotrace.diff.record import record_comparison
from reprotrace.errors import SchemaVersionError, StoreError
from reprotrace.models import DiffConfig, Divergence, NormalizationConfig, RankConfig
from reprotrace.store.db import (
    DB_SCHEMA_VERSION,
    connect,
    list_runs,
    load_comparison,
    save_comparison,
    set_report_path,
    sync_runs,
)
from reprotrace.store.run_files import resolve_runs


def test_database_is_created_with_schema(tmp_path: Path) -> None:
    with connect(tmp_path) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert {"runs", "comparisons", "divergences"} <= tables
    assert version == DB_SCHEMA_VERSION
    assert config.db_path(tmp_path).is_file()
    with connect(tmp_path):  # reopening an existing database works
        pass


def test_unknown_database_version_is_rejected(tmp_path: Path) -> None:
    with connect(tmp_path):
        pass
    raw = sqlite3.connect(config.db_path(tmp_path))
    raw.execute("PRAGMA user_version = 99")
    raw.close()
    with pytest.raises(SchemaVersionError), connect(tmp_path):
        pass


def test_sync_indexes_run_folders_once(tmp_path: Path) -> None:
    ids = [
        install_fixture_run(tmp_path, n) for n in ("pair_good_1", "pair_good_2", "local_timeout")
    ]
    with connect(tmp_path) as conn:
        assert sync_runs(conn, tmp_path).added == 3
        assert sync_runs(conn, tmp_path).added == 0
        rows = list_runs(conn)
    assert sorted(r.id for r in rows) == sorted(ids)
    assert [r.started_at for r in rows] == sorted((r.started_at for r in rows), reverse=True)
    good = [r for r in rows if r.label == "good"]
    assert len({r.group_id for r in good}) == 1


def _divergence(div_id: str, score: float) -> Divergence:
    return Divergence(
        id=div_id, kind="file_only_in_a", summary=f"s{div_id}", a_event_ids=["r:1"],
        b_event_ids=[], score=score, reasons=["because"],
    )  # fmt: skip


def test_comparison_round_trip(tmp_path: Path) -> None:
    created = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
    ranked = [_divergence("d2", 0.9), _divergence("d1", 0.4)]
    with connect(tmp_path) as conn:
        save_comparison(
            conn, "cmp_x", "grp_a", "grp_b", created, {"k": 1}, {"a_label": "a"}, ranked
        )
        set_report_path(conn, "cmp_x", "r.md")
    with connect(tmp_path) as conn:
        stored = load_comparison(conn, "cmp_x")
    assert stored.divergences == ranked
    assert (stored.ref_a, stored.ref_b, stored.created_at) == ("grp_a", "grp_b", created)
    assert stored.config == {"k": 1} and stored.details == {"a_label": "a"}
    assert stored.report_path == "r.md"


def test_divergence_ids_are_unique_per_comparison(tmp_path: Path) -> None:
    now = datetime(2026, 10, 21, tzinfo=UTC)
    with connect(tmp_path) as conn:
        for cid in ("cmp_1", "cmp_2"):
            save_comparison(conn, cid, "a", "b", now, {}, {}, [_divergence("d1", 0.5)])
        rows = [r[0] for r in conn.execute("SELECT id FROM divergences ORDER BY id")]
    assert rows == ["cmp_1:d1", "cmp_2:d1"]


def test_unknown_comparison(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="Comparison not found"), connect(tmp_path) as conn:
        load_comparison(conn, "cmp_000000000000")


def test_record_comparison_of_saved_groups(tmp_path: Path) -> None:
    for name in ("pair_good_1", "pair_good_2", "pair_bad_1", "pair_bad_2"):
        install_fixture_run(tmp_path, name)
    with connect(tmp_path) as conn:
        sync_runs(conn, tmp_path)
        groups = {r.label: r.group_id for r in list_runs(conn)}
    saved = compare_saved(tmp_path, groups["good"], groups["bad"])
    ranked = rank_divergences(saved.comparison)
    cid = record_comparison(
        tmp_path, saved, ranked, NormalizationConfig(), DiffConfig(), RankConfig()
    )
    with connect(tmp_path) as conn:
        stored = load_comparison(conn, cid)
    assert cid.startswith("cmp_")
    assert [d.id for d in stored.divergences] == [d.id for d in ranked]
    assert stored.details["a_label"] == "good" and stored.details["failing_side"] == "b"
    assert len(stored.details["a_run_ids"]) == 2
    assert ["TZ", "UTC", "Asia/Kolkata"] in stored.details["env_rows"]
    assert RankConfig.model_validate(stored.config["rank"]) == RankConfig()


def test_broken_run_folders_are_skipped_and_reported(tmp_path: Path) -> None:
    good = install_fixture_run(tmp_path, "pair_good_1")
    corrupt = config.run_dir(tmp_path, "run_corrupt00000")
    corrupt.mkdir(parents=True)
    (corrupt / config.META_FILE).write_text("{not json")
    future = config.run_dir(tmp_path, "run_future000000")
    future.mkdir(parents=True)
    (future / config.META_FILE).write_text('{"schema_version": 99}')
    with connect(tmp_path) as conn:
        result = sync_runs(conn, tmp_path)
        ids = [r.id for r in list_runs(conn)]
    assert result.added == 1 and ids == [good]
    reasons = dict(result.skipped)
    assert "Corrupt run metadata" in reasons["run_corrupt00000"]
    assert "Unsupported schema_version 99" in reasons["run_future000000"]


def test_group_lookup_ignores_unrelated_broken_folders(tmp_path: Path) -> None:
    install_fixture_run(tmp_path, "pair_good_1")
    install_fixture_run(tmp_path, "pair_good_2")
    broken = config.run_dir(tmp_path, "run_broken000000")
    broken.mkdir(parents=True)
    (broken / config.META_FILE).write_text("{truncated")
    group = fixture_run("pair_good_1").group_id
    assert len(resolve_runs(tmp_path, group)) == 2


def test_schema_creation_is_idempotent(tmp_path: Path) -> None:
    # Another process may have created the tables just before this one sets the version.
    with connect(tmp_path):
        pass
    raw = sqlite3.connect(config.db_path(tmp_path))
    raw.execute("PRAGMA user_version = 0")
    raw.close()
    with connect(tmp_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA_VERSION
