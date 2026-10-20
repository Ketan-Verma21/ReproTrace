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
