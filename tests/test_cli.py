import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reprotrace import __version__
from reprotrace.capture import runner as capture_runner
from reprotrace.cli import app

runner = CliRunner()


def test_help_runs() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ReproTrace" in result.output


def test_version_prints_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"reprotrace {__version__}"


needs_strace = pytest.mark.skipif(shutil.which("strace") is None, reason="strace not installed")


@needs_strace
def test_capture_command_saves_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app, ["capture", "--label", "local", "--runs", "2", "--", "sh", "-c", "exit 4"]
    )
    assert result.exit_code == 0, result.output
    assert "Captured 2 run(s), label local" in result.output
    assert result.output.count("exit 4") == 2
    metas = list((tmp_path / ".reprotrace" / "runs").glob("*/meta.json"))
    assert len(metas) == 2


def test_capture_unknown_command_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["capture", "--label", "x", "--", "no_such_program_reprotrace"])
    assert result.exit_code == 1
    assert "Error: Command not found" in result.output
    assert "Traceback" not in result.output


def test_capture_without_strace_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(capture_runner.shutil, "which", lambda *_a, **_k: None)
    result = runner.invoke(app, ["capture", "--label", "x", "--", "true"])
    assert result.exit_code == 2
    assert "strace is not installed" in result.output


@needs_strace
def test_show_summarizes_captured_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    capture_result = runner.invoke(
        app, ["capture", "--label", "local", "--", "sh", "-c", "cat /nonexistent_reprotrace"]
    )
    assert capture_result.exit_code == 0, capture_result.output
    (run_folder,) = (tmp_path / ".reprotrace" / "runs").iterdir()
    run_id = run_folder.name
    result = runner.invoke(app, ["show", run_id])
    assert result.exit_code == 0, result.output
    assert "/nonexistent_reprotrace  ENOENT" in result.output
    assert "0 unparsed" in result.output
    assert (tmp_path / ".reprotrace" / "runs" / run_id / "events.jsonl").is_file()


def test_show_unknown_run_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["show", "run_000000000000"])
    assert result.exit_code == 1
    assert "Error: Run not found" in result.output


@needs_strace
def test_diff_of_two_groups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    command = ["--", "sh", "-c", "cat marker.txt"]
    (tmp_path / "marker.txt").write_text("x")
    good = runner.invoke(app, ["capture", "--label", "good", "--runs", "2", *command])
    (tmp_path / "marker.txt").unlink()
    bad = runner.invoke(app, ["capture", "--label", "bad", "--runs", "2", *command])
    assert good.exit_code == bad.exit_code == 0
    groups = [line.split()[-1] for line in good.output.splitlines() + bad.output.splitlines()
              if line.startswith("Captured")]  # fmt: skip
    result = runner.invoke(app, ["diff", groups[0], groups[1]])
    assert result.exit_code == 0, result.output
    assert "good (2 run(s)) vs bad (2 run(s))" in result.output
    assert "Exit codes: good exit 0, bad exit 1" in result.output
    assert "Top divergences (ranked, heuristic)" in result.output
    first = result.output.split("  1  [", 1)[1].split("\n  2  [", 1)[0]
    assert "openat <cwd>/marker.txt: OK on good, ENOENT on bad" in first
    assert "Why ranked here: failed on bad (ENOENT) but succeeded on good" in first
    assert "Note: ranking is a heuristic, not proof of cause." in result.output


def test_diff_unknown_group_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["diff", "grp_000000000000", "grp_000000000001"])
    assert result.exit_code == 1
    assert "Error: Group not found" in result.output


@needs_strace
def test_full_flow_capture_diff_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 6 exit check: capture twice, diff, report; the report reads clearly."""
    monkeypatch.chdir(tmp_path)
    command = ["--", "sh", "-c", "cat marker.txt"]
    (tmp_path / "marker.txt").write_text("x")
    assert (
        runner.invoke(app, ["capture", "--label", "good", "--runs", "2", *command]).exit_code == 0
    )
    (tmp_path / "marker.txt").unlink()
    assert runner.invoke(app, ["capture", "--label", "bad", "--runs", "2", *command]).exit_code == 0

    listing = runner.invoke(app, ["runs"])
    assert listing.exit_code == 0
    assert "4 run(s) in 2 group(s)" in listing.output
    groups = [w for w in listing.output.split() if w.startswith("grp_")]
    bad, good = groups[0], groups[1]  # newest first

    compared = runner.invoke(app, ["--no-color", "diff", good, bad])
    assert compared.exit_code == 0, compared.output
    cid = next(w.rstrip(".") for w in compared.output.split() if w.startswith("cmp_"))
    assert f"reprotrace report {cid}" in compared.output

    written = runner.invoke(app, ["report", cid])
    assert written.exit_code == 0, written.output
    text = (tmp_path / ".reprotrace" / "reports" / f"{cid}.md").read_text()
    assert "- **Likely cause:** openat &lt;cwd&gt;/marker.txt: OK on good, ENOENT on bad" in text
    assert "## Limitations" in text


def test_runs_with_nothing_saved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["runs"])
    assert result.exit_code == 0
    assert "No saved runs yet." in result.output


def test_report_of_unknown_comparison_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", "cmp_000000000000"])
    assert result.exit_code == 1
    assert "Error: Comparison not found: cmp_000000000000" in result.output
    assert "Traceback" not in result.output


def test_runs_reports_broken_folders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    broken = tmp_path / ".reprotrace" / "runs" / "run_broken000000"
    broken.mkdir(parents=True)
    (broken / "meta.json").write_text("{truncated")
    result = runner.invoke(app, ["runs"])
    assert result.exit_code == 0
    assert "Skipped run folder run_broken000000: Corrupt run metadata" in result.output
    assert "No saved runs yet." in result.output
