"""AI explanations on disk: one JSON file per comparison in .reprotrace/explanations/."""

import json
from pathlib import Path

from pydantic import ValidationError

from reprotrace import config
from reprotrace.errors import SchemaVersionError, StoreError
from reprotrace.models import EXPLANATION_SCHEMA_VERSION, Explanation


def save_explanation(base_dir: Path, explanation: Explanation) -> Path:
    """Write ``explanation`` (replacing an earlier one for the same comparison)."""
    path = config.explanation_path(base_dir, explanation.comparison_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(explanation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def load_explanation(base_dir: Path, comparison_id: str) -> Explanation | None:
    """The stored explanation of a comparison, or None if there is none."""
    path = config.explanation_path(base_dir, comparison_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StoreError(f"Cannot read {path}: {error}") from error
    if not isinstance(data, dict) or data.get("schema_version") != EXPLANATION_SCHEMA_VERSION:
        version = data.get("schema_version") if isinstance(data, dict) else None
        raise SchemaVersionError(f"Unsupported schema_version {version} in {path}")
    try:
        return Explanation.model_validate(data)
    except ValidationError as error:
        raise StoreError(f"Invalid explanation in {path}: {error.errors()[0]['msg']}") from error
