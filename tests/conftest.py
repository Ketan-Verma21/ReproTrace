import json
from pathlib import Path

import pytest

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
