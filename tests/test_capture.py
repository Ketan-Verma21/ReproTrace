import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from reprotrace import config
from reprotrace.capture import runner
from reprotrace.capture.redact import REDACTED
from reprotrace.errors import EXIT_ENVIRONMENT_ERROR, CaptureError
from reprotrace.models import Run

needs_strace = pytest.mark.skipif(shutil.which("strace") is None, reason="strace not installed")

ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "TZ": "UTC", "API_TOKEN": "abc"}


def test_new_id_has_prefix_and_no_colon() -> None:
    run_id = runner.new_id("run")
    assert run_id.startswith("run_")
    assert ":" not in run_id
    assert runner.new_id("run") != run_id


def test_build_strace_args_is_a_list_with_command_after_separator() -> None:
    args = runner.build_strace_args(Path("/usr/bin/strace"), Path("out.trace"), ["pytest", "-x"])
    assert args == [
        "/usr/bin/strace",
        "-f",
        "-ttt",
        "-y",
        "-s",
        "200",
        "-v",
        "-o",
        "out.trace",
        "--",
        "pytest",
        "-x",
    ]


def test_find_strace_missing_raises_environment_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner.shutil, "which", lambda _name: None)
    with pytest.raises(CaptureError) as info:
        runner.find_strace()
    assert info.value.exit_code == EXIT_ENVIRONMENT_ERROR
    assert "apt install strace" in (info.value.hint or "")


def test_check_command_exists_rejects_unknown_program() -> None:
    with pytest.raises(CaptureError, match="Command not found"):
        runner.check_command_exists(["no_such_program_reprotrace"], ENV)


def test_check_command_exists_rejects_empty_command() -> None:
    with pytest.raises(CaptureError, match="No command"):
        runner.check_command_exists([], ENV)


def test_empty_trace_raises_environment_error(tmp_path: Path) -> None:
    trace = tmp_path / "raw.strace"
    trace.write_text("")
    result = runner.ProcessResult(exit_code=1, timed_out=False, duration_ms=5)
    with pytest.raises(CaptureError) as info:
        runner.check_trace_produced(trace, result)
    assert info.value.exit_code == EXIT_ENVIRONMENT_ERROR
    assert "SYS_PTRACE" in (info.value.hint or "")


def test_empty_trace_after_timeout_is_not_an_error(tmp_path: Path) -> None:
    result = runner.ProcessResult(exit_code=None, timed_out=True, duration_ms=5)
    runner.check_trace_produced(tmp_path / "missing.strace", result)


def test_run_with_timeout_records_exit_code(tmp_path: Path) -> None:
    result = runner.run_with_timeout(
        [sys.executable, "-c", "raise SystemExit(3)"], 30, ENV, cwd=tmp_path
    )
    assert result.exit_code == 3
    assert not result.timed_out


def _process_alive(pid: int) -> bool:
    status = Path(f"/proc/{pid}/status")
    if not status.exists():
        return False
    state_line = next(line for line in status.read_text().splitlines() if line.startswith("State:"))
    state = state_line.split()[1]
    return state not in ("Z", "X")  # zombie or dead: the process has already exited


def test_timeout_kills_whole_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    script = f"sleep 60 & echo $! > {pid_file}; wait"
    result = runner.run_with_timeout(["sh", "-c", script], 1.0, ENV, cwd=tmp_path, grace_s=2.0)
    assert result.timed_out
    assert result.exit_code is None
    child_pid = int(pid_file.read_text())
    assert not _process_alive(child_pid)


def test_read_git_commit_outside_repo_is_none(tmp_path: Path) -> None:
    assert runner.read_git_commit(tmp_path) is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_read_git_commit_inside_repo(tmp_path: Path) -> None:
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run([*git, "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "init"], cwd=tmp_path, check=True)
    commit = runner.read_git_commit(tmp_path)
    assert commit is not None
    assert len(commit) == 40


@needs_strace
def test_capture_run_writes_trace_and_meta(tmp_path: Path) -> None:
    run = runner.capture_run(
        [sys.executable, "-c", "raise SystemExit(3)"],
        label="local",
        group_id="grp_test",
        base_dir=tmp_path,
        timeout_s=60,
        env=ENV,
    )
    folder = config.run_dir(tmp_path, run.id)
    trace = folder / config.RAW_TRACE_FILE
    assert trace.stat().st_size > 0
    assert "execve(" in trace.read_text()

    meta = json.loads((folder / config.META_FILE).read_text())
    assert meta["schema_version"] == 1
    assert meta["exit_code"] == 3
    assert meta["timed_out"] is False
    assert meta["label"] == "local"
    assert meta["group_id"] == "grp_test"
    assert meta["trace_path"] == f"runs/{run.id}/raw.strace"
    assert meta["env_redacted"]["API_TOKEN"] == REDACTED
    assert meta["env_redacted"]["TZ"] == "UTC"
    assert Run.model_validate(meta) == run


@needs_strace
def test_capture_run_records_timeout(tmp_path: Path) -> None:
    run = runner.capture_run(["sleep", "30"], "local", "grp_test", tmp_path, timeout_s=1.0, env=ENV)
    assert run.timed_out
    assert run.exit_code is None
    assert (config.run_dir(tmp_path, run.id) / config.META_FILE).exists()


@needs_strace
def test_capture_group_shares_group_id(tmp_path: Path) -> None:
    runs = runner.capture_group(["true"], "ci", 2, tmp_path, timeout_s=30, env=ENV)
    assert len(runs) == 2
    assert runs[0].group_id == runs[1].group_id
    assert runs[0].id != runs[1].id


def test_capture_group_rejects_bad_settings(tmp_path: Path) -> None:
    with pytest.raises(CaptureError, match="--runs"):
        runner.capture_group(["true"], "ci", 0, tmp_path, timeout_s=30, env=ENV)
    with pytest.raises(CaptureError, match="--timeout"):
        runner.capture_group(["true"], "ci", 1, tmp_path, timeout_s=0, env=ENV)
