"""Read and write the per-run files under ``.reprotrace/runs/<run_id>/``."""

import json
import re
from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from reprotrace import config
from reprotrace.errors import SchemaVersionError, StoreError
from reprotrace.models import Event, Run
from reprotrace.models.event import RUN_SCHEMA_VERSION

_RUN_ID = re.compile(r"^[A-Za-z0-9_\-]+$")


def run_folder(base_dir: Path, run_id: str) -> Path:
    """Return an existing run folder or raise StoreError."""
    if not _RUN_ID.match(run_id):
        raise StoreError(f"Invalid run id: {run_id}")
    folder = config.run_dir(base_dir, run_id)
    if not (folder / config.META_FILE).is_file():
        runs_dir = config.data_dir(base_dir) / config.RUNS_DIR_NAME
        raise StoreError(f"Run not found: {run_id}", hint=f"Saved runs are in {runs_dir}")
    return folder


def load_run(base_dir: Path, run_id: str) -> Run:
    """Load ``meta.json`` for a run, checking its schema version."""
    meta_path = run_folder(base_dir, run_id) / config.META_FILE
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StoreError(f"Corrupt run metadata: {meta_path} ({exc})") from exc
    version = data.get("schema_version") if isinstance(data, dict) else None
    if version != RUN_SCHEMA_VERSION:
        raise SchemaVersionError(
            f"Unsupported schema_version {version!r} in {meta_path}",
            hint=f"This version of reprotrace reads schema_version {RUN_SCHEMA_VERSION}.",
        )
    try:
        return Run.model_validate(data)
    except ValidationError as exc:
        raise StoreError(f"Invalid run metadata: {meta_path}") from exc


def raw_trace_path(base_dir: Path, run: Run) -> Path:
    """Return the absolute path of a run's raw trace."""
    return config.data_dir(base_dir) / run.trace_path


def write_events(path: Path, events: Iterable[Event]) -> None:
    """Write events as JSON Lines, replacing any previous file atomically."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(event.model_dump_json())
            handle.write("\n")
    tmp.replace(path)
