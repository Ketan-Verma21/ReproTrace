"""Paths and default settings."""

from pathlib import Path

DATA_DIR_NAME = ".reprotrace"
RUNS_DIR_NAME = "runs"
RAW_TRACE_FILE = "raw.strace"
META_FILE = "meta.json"
EVENTS_FILE = "events.jsonl"

DEFAULT_TIMEOUT_S = 300.0
DEFAULT_RUNS = 1
# Grace period between SIGTERM and SIGKILL when a traced command times out.
KILL_GRACE_S = 5.0

# Flags fixed by Architecture.md 3.2. -s 200 keeps strings long enough for paths while
# bounding trace size; -v keeps full execve environments for environment diffs.
STRACE_FLAGS: tuple[str, ...] = ("-f", "-ttt", "-y", "-s", "200", "-v")


def data_dir(base: Path) -> Path:
    """Return the ReproTrace data directory for a project rooted at ``base``."""
    return base / DATA_DIR_NAME


def run_dir(base: Path, run_id: str) -> Path:
    """Return the folder that holds one run's files."""
    return data_dir(base) / RUNS_DIR_NAME / run_id
