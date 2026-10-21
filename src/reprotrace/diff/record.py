"""Save a ranked comparison in the project database."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reprotrace.diff.compare import SavedComparison
from reprotrace.models import DiffConfig, Divergence, NormalizationConfig, RankConfig
from reprotrace.store.db import connect, save_comparison, sync_runs


def comparison_details(saved: SavedComparison) -> dict[str, Any]:
    """Facts a report needs that are not in the divergences themselves."""
    cmp = saved.comparison
    return {
        "a_label": cmp.a_label,
        "b_label": cmp.b_label,
        "a_run_ids": [r.id for r in saved.a_runs],
        "b_run_ids": [r.id for r in saved.b_runs],
        "matched_processes": cmp.matched_processes,
        "unmatched_processes": cmp.unmatched_processes,
        "ignored_unstable": cmp.ignored_unstable,
        "failing_side": cmp.failing_side,
        "env_rows": [list(row) for row in cmp.env_rows],
        "notes": list(cmp.notes),
    }


def record_comparison(
    base_dir: Path,
    saved: SavedComparison,
    ranked: list[Divergence],
    norm_config: NormalizationConfig,
    diff_config: DiffConfig,
    rank_config: RankConfig,
) -> str:
    """Store ``ranked`` divergences of ``saved`` and return the new comparison id."""
    comparison_id = f"cmp_{uuid.uuid4().hex[:12]}"
    config_data = {
        "normalization": norm_config.model_dump(),
        "diff": diff_config.model_dump(),
        "rank": rank_config.model_dump(),
    }
    with connect(base_dir) as conn:
        sync_runs(conn, base_dir)
        save_comparison(
            conn,
            comparison_id,
            saved.ref_a,
            saved.ref_b,
            datetime.now(UTC),
            config_data,
            comparison_details(saved),
            ranked,
        )
    return comparison_id
