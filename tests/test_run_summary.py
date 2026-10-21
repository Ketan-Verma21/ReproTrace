import json
import shutil
from pathlib import Path

import pytest

from conftest import TRACES, fixture_lines, fixture_run
from reprotrace import config
from reprotrace.errors import SchemaVersionError, StoreError
from reprotrace.models import Event
from reprotrace.parse.run import parse_run
from reprotrace.parse.strace_parser import parse_lines
from reprotrace.report.run_summary import build_run_summary, render_run_summary
from reprotrace.store.run_files import load_group, load_run, resolve_runs


def plain(lines) -> str:
    return "\n".join(line.plain for line in lines)


def summary_of(name: str):
    run = fixture_run(name)
    events, stats = parse_lines(fixture_lines(name), run.id)
    return build_run_summary(run, events, stats)


def test_failed_opens_include_missing_file_with_evidence() -> None:
    summary = summary_of("local_python_missing_file")
    item = next(i for i in summary.failed_opens if i.target == "/nonexistent/config.toml")
    assert item.outcome == "ENOENT"
    assert item.first_event_id.startswith(summary.run.id + ":")


def test_programs_executed_in_order() -> None:
    summary = summary_of("local_multiprocess")
    assert [i.target for i in summary.programs] == ["/usr/bin/sh", "/usr/bin/ls", "/usr/bin/cat"]


def test_connections() -> None:
    summary = summary_of("local_connect_refused")
    assert [(i.target, i.outcome) for i in summary.connections] == [("127.0.0.1:9", "EINPROGRESS")]


def test_render_mentions_counts_and_limits() -> None:
    summary = summary_of("local_python_missing_file")
    text = plain(render_run_summary(summary, limit=1))
    assert "0 unparsed" in text
    assert f"Files that failed to open ({len(summary.failed_opens)})" in text
    assert "more hidden (use --all)" in text
    full = plain(render_run_summary(summary, limit=None))
    assert "/nonexistent/config.toml" in full


def test_render_timeout_and_signal_outcomes() -> None:
    assert "Outcome: timed out" in plain(render_run_summary(summary_of("local_timeout")))
    killed = plain(render_run_summary(summary_of("local_killed_by_signal")))
    assert "Outcome: killed by signal 15" in killed


def _install_fixture_run(base: Path, name: str) -> str:
    run = fixture_run(name)
    folder = config.run_dir(base, run.id)
    folder.mkdir(parents=True)
    shutil.copy(TRACES / f"{name}.strace", folder / config.RAW_TRACE_FILE)
    (folder / config.META_FILE).write_text(run.model_dump_json())
    return run.id


def test_parse_run_writes_events_jsonl(tmp_path: Path, traces_dir: Path) -> None:
    run_id = _install_fixture_run(tmp_path, "local_multiprocess")
    parsed = parse_run(tmp_path, run_id)
    lines = (config.run_dir(tmp_path, run_id) / config.EVENTS_FILE).read_text().splitlines()
    assert len(lines) == len(parsed.events)
    assert Event.model_validate_json(lines[0]) == parsed.events[0]
    assert json.loads(lines[0])["schema_version"] == 1


def test_load_run_rejects_unknown_schema_version(tmp_path: Path) -> None:
    run_id = _install_fixture_run(tmp_path, "local_timeout")
    meta = config.run_dir(tmp_path, run_id) / config.META_FILE
    data = json.loads(meta.read_text())
    data["schema_version"] = 99
    meta.write_text(json.dumps(data))
    with pytest.raises(SchemaVersionError):
        load_run(tmp_path, run_id)


def test_load_run_missing_and_invalid_ids(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="Run not found"):
        load_run(tmp_path, "run_000000000000")
    with pytest.raises(StoreError, match="Invalid run id"):
        load_run(tmp_path, "../etc")


def test_resolve_runs_by_group_and_run(tmp_path: Path) -> None:
    first = _install_fixture_run(tmp_path, "pair_good_1")
    second = _install_fixture_run(tmp_path, "pair_good_2")
    group_id = fixture_run("pair_good_1").group_id
    runs = resolve_runs(tmp_path, group_id)
    assert [r.id for r in runs] == [first, second]
    assert [r.id for r in resolve_runs(tmp_path, first)] == [first]


def test_unknown_group_raises(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="Group not found"):
        load_group(tmp_path, "grp_000000000000")
