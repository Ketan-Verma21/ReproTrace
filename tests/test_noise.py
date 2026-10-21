"""Noise filter on repeated real captures of one command in one environment."""

import pytest

from conftest import TRACES, fixture_lines
from reprotrace.models import Event
from reprotrace.normalize.noise import build_noise_profile, signature_set
from reprotrace.normalize.rules import normalize_events
from reprotrace.parse.strace_parser import parse_lines

REPEAT_GROUPS = ["repeat_python_tempfile", "repeat_multiprocess"]
# Exit check of Phase 3: repeated runs normalize to (nearly) identical signature sets.
MAX_UNSTABLE_FRACTION = 0.02


def normalized_run(name: str) -> list[Event]:
    events, _ = parse_lines(fixture_lines(name), name)
    return normalize_events(events)


def group_runs(group: str) -> list[list[Event]]:
    names = sorted(p.stem for p in TRACES.glob(f"{group}_*.strace"))
    assert len(names) >= 2, f"capture {group} with: bash testdata/capture_fixtures.sh repeat_"
    return [normalized_run(name) for name in names]


@pytest.mark.parametrize("group", REPEAT_GROUPS)
def test_repeated_runs_are_nearly_identical(group: str) -> None:
    profile = build_noise_profile(group_runs(group))
    total = profile.stable_count + len(profile.unstable)
    assert total > 0
    assert len(profile.unstable) / total <= MAX_UNSTABLE_FRACTION, profile.unstable


@pytest.mark.parametrize("group", REPEAT_GROUPS)
def test_raw_text_differs_between_repeats(group: str) -> None:
    # Guards against a vacuous pass: the raw traces really differ (PIDs, timestamps, temp
    # names) and only normalization makes them match.
    names = sorted(p.stem for p in TRACES.glob(f"{group}_*.strace"))
    parsed = [parse_lines(fixture_lines(name), name)[0] for name in names[:2]]
    assert {e.raw for e in parsed[0]} != {e.raw for e in parsed[1]}
    if group == "repeat_python_tempfile":
        targets = [{e.target for e in run if e.kind == "file" and e.target} for run in parsed]
        assert targets[0] != targets[1]


def test_different_commands_produce_unstable_signatures() -> None:
    runs = [normalized_run("local_python_missing_file"), normalized_run("local_long_path")]
    profile = build_noise_profile(runs)
    assert "openat|/nonexistent/config.toml|O_RDONLY|ENOENT" in profile.unstable
    assert any(s.startswith("openat|/nonexistent/xxx") for s in profile.unstable)
    assert profile.run_ids == ["local_python_missing_file", "local_long_path"]


def test_single_run_marks_nothing_unstable() -> None:
    run = normalized_run("local_timeout")
    profile = build_noise_profile([run])
    assert profile.unstable == []
    assert profile.stable_count == len(signature_set(run))


def test_empty_input_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_noise_profile([])
