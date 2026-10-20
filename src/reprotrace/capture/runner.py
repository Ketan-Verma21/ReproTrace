"""Run a user-supplied command under strace and save the raw trace and run metadata."""

import logging
import os
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from reprotrace import config
from reprotrace.capture.redact import redact_env
from reprotrace.errors import EXIT_ENVIRONMENT_ERROR, CaptureError
from reprotrace.models import Run

log = logging.getLogger(__name__)

GIT_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class ProcessResult:
    """Outcome of one traced process. A timeout or non-zero exit is data, not an error."""

    exit_code: int | None
    timed_out: bool
    duration_ms: int


def new_id(prefix: str) -> str:
    """Return a short unique id such as ``run_1a2b3c4d5e6f``. Contains no ':'."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def find_strace() -> Path:
    """Return the path to the strace binary or raise CaptureError if it is missing."""
    found = shutil.which("strace")
    if found is None:
        raise CaptureError(
            "strace is not installed.",
            hint="Install it with: sudo apt install strace",
            exit_code=EXIT_ENVIRONMENT_ERROR,
        )
    return Path(found)


def check_command_exists(command: list[str], env: dict[str, str]) -> None:
    """Raise CaptureError if the program to trace cannot be found on PATH."""
    if not command:
        raise CaptureError("No command given.", hint="Usage: reprotrace capture -- <command>")
    program = command[0]
    if shutil.which(program, path=env.get("PATH")) is None:
        raise CaptureError(
            f"Command not found: {program}",
            hint="Check the spelling, or pass the full path to the program.",
        )


def build_strace_args(strace: Path, trace_path: Path, command: list[str]) -> list[str]:
    """Build the strace argument list. Never a shell string."""
    return [str(strace), *config.STRACE_FLAGS, "-o", str(trace_path), "--", *command]


def _kill_group(process: subprocess.Popen[bytes], grace_s: float) -> None:
    """Terminate the whole process group, escalating to SIGKILL after ``grace_s``."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        log.debug("process group %s already exited before SIGTERM", process.pid)
        return
    try:
        process.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        log.debug("process group %s ignored SIGTERM; sending SIGKILL", process.pid)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            log.debug("process group %s exited before SIGKILL", process.pid)
        process.wait()


def run_with_timeout(
    args: list[str],
    timeout_s: float,
    env: dict[str, str],
    cwd: Path,
    grace_s: float = config.KILL_GRACE_S,
) -> ProcessResult:
    """Run ``args`` in a new process group, killing the group if it exceeds ``timeout_s``.

    Output is not captured so the user sees their command's output as usual. A negative
    exit code means the process was ended by that signal number (Python convention).
    """
    started = time.monotonic()
    # start_new_session puts strace and every traced child in one process group, so a
    # timeout can stop all of them instead of leaving orphans.
    process = subprocess.Popen(args, env=env, cwd=cwd, start_new_session=True)
    try:
        exit_code: int | None = process.wait(timeout=timeout_s)
        timed_out = False
    except subprocess.TimeoutExpired:
        _kill_group(process, grace_s)
        exit_code = None
        timed_out = True
    duration_ms = int((time.monotonic() - started) * 1000)
    return ProcessResult(exit_code=exit_code, timed_out=timed_out, duration_ms=duration_ms)


def check_trace_produced(trace_path: Path, result: ProcessResult) -> None:
    """Raise CaptureError if strace wrote nothing, which means it could not trace at all."""
    if result.timed_out:
        return
    if trace_path.exists() and trace_path.stat().st_size > 0:
        return
    raise CaptureError(
        "strace produced no trace. It is probably not allowed to use ptrace here.",
        hint=(
            "In Docker, run the container with --cap-add=SYS_PTRACE. On a host, check "
            "/proc/sys/kernel/yama/ptrace_scope."
        ),
        exit_code=EXIT_ENVIRONMENT_ERROR,
    )


def read_git_commit(cwd: Path) -> str | None:
    """Return the current git commit of ``cwd``, or None when it is not available."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.debug("git commit not available: %s", exc)
        return None
    if completed.returncode != 0:
        log.debug("git rev-parse failed: %s", completed.stderr.strip())
        return None
    return completed.stdout.strip() or None


def write_meta(run: Run, path: Path) -> None:
    """Write run metadata as JSON."""
    path.write_text(run.model_dump_json(indent=2) + "\n", encoding="utf-8")


def capture_run(
    command: list[str],
    label: str,
    group_id: str,
    base_dir: Path,
    timeout_s: float,
    env: dict[str, str],
) -> Run:
    """Trace ``command`` once and save ``raw.strace`` and ``meta.json`` under ``base_dir``."""
    strace = find_strace()
    check_command_exists(command, env)
    run_id = new_id("run")
    folder = config.run_dir(base_dir, run_id)
    folder.mkdir(parents=True)
    trace_path = folder / config.RAW_TRACE_FILE

    started_at = datetime.now(UTC)
    result = run_with_timeout(
        build_strace_args(strace, trace_path, command), timeout_s, env, cwd=base_dir
    )
    check_trace_produced(trace_path, result)

    run = Run(
        id=run_id,
        label=label,
        group_id=group_id,
        command=list(command),
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        duration_ms=result.duration_ms,
        started_at=started_at,
        git_commit=read_git_commit(base_dir),
        # Relative to the data dir so a run folder copied from CI still resolves.
        trace_path=trace_path.relative_to(config.data_dir(base_dir)).as_posix(),
        env_redacted=redact_env(env),
    )
    write_meta(run, folder / config.META_FILE)
    return run


def capture_group(
    command: list[str],
    label: str,
    runs: int,
    base_dir: Path,
    timeout_s: float,
    env: dict[str, str],
) -> list[Run]:
    """Trace ``command`` ``runs`` times; all runs share one group id."""
    if runs < 1:
        raise CaptureError(f"--runs must be at least 1, got {runs}.")
    if timeout_s <= 0:
        raise CaptureError(f"--timeout must be positive, got {timeout_s}.")
    group_id = new_id("grp")
    return [capture_run(command, label, group_id, base_dir, timeout_s, env) for _ in range(runs)]
