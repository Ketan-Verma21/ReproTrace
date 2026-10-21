import json
import shutil
from pathlib import Path

import pytest

from reprotrace import config
from reprotrace.models import Run

TRACES = Path(__file__).resolve().parent.parent / "testdata" / "traces"


def fixture_lines(name: str) -> list[str]:
    """Lines of a real strace fixture in testdata/traces/."""
    return (TRACES / f"{name}.strace").read_text(encoding="utf-8").splitlines()


def fixture_run(name: str) -> Run:
    """The Run saved alongside a fixture (local fixtures only)."""
    return Run.model_validate(json.loads((TRACES / f"{name}.meta.json").read_text()))


@pytest.fixture
def traces_dir() -> Path:
    return TRACES


def install_fixture_run(base: Path, name: str) -> str:
    """Copy a fixture (trace + meta) into ``base/.reprotrace/runs/<run_id>/``; return the id."""
    run = fixture_run(name)
    folder = config.run_dir(base, run.id)
    folder.mkdir(parents=True)
    shutil.copy(TRACES / f"{name}.strace", folder / config.RAW_TRACE_FILE)
    (folder / config.META_FILE).write_text(run.model_dump_json())
    return run.id
