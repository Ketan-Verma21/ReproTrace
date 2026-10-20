"""Pydantic models for captured data (see Architecture.md section 4)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

RUN_SCHEMA_VERSION = 1


class Run(BaseModel):
    """Metadata for one traced execution of a command."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = RUN_SCHEMA_VERSION
    id: str
    label: str
    group_id: str
    command: list[str]
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    started_at: datetime
    git_commit: str | None
    trace_path: str
    env_redacted: dict[str, str]


EVENT_SCHEMA_VERSION = 1
PARSE_STATS_SCHEMA_VERSION = 1

EventKind = Literal["file", "exec", "net", "proc", "env", "other"]


class Event(BaseModel):
    """One syscall, process exit, or signal from a trace (Architecture.md 4.1)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = EVENT_SCHEMA_VERSION
    id: str
    run_id: str
    proc: str
    seq: int
    kind: EventKind
    syscall: str
    target: str | None
    args: list[str]
    result: str | None
    errno: str | None
    signature: str | None = None
    raw: str


class UnparsedLine(BaseModel):
    """A trace line the parser could not interpret, kept verbatim."""

    model_config = ConfigDict(extra="forbid")

    line_number: int
    raw: str


class ParseStats(BaseModel):
    """Counts describing how completely a trace was parsed."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = PARSE_STATS_SCHEMA_VERSION
    total_lines: int = 0
    blank_lines: int = 0
    event_count: int = 0
    merged_pairs: int = 0
    unmatched_unfinished: int = 0
    unmatched_resumed: int = 0
    unparsed: list[UnparsedLine] = []

    @property
    def unparsed_count(self) -> int:
        """Number of lines that could not be interpreted."""
        return len(self.unparsed)


NORMALIZATION_SCHEMA_VERSION = 1
NOISE_SCHEMA_VERSION = 1

RuleName = Literal["cwd", "home", "user", "temp_paths", "pids", "inodes", "timestamps", "addresses"]

DEFAULT_RULES: tuple[RuleName, ...] = (
    "cwd",
    "home",
    "user",
    "temp_paths",
    "pids",
    "inodes",
    "timestamps",
    "addresses",
)

# Syscalls that carry no evidence about environment differences (memory management,
# signal setup, plain I/O on already-open descriptors). Their events stay in events.jsonl
# but get no signature, so alignment and the noise filter skip them.
DEFAULT_IGNORED_SYSCALLS: tuple[str, ...] = (
    "arch_prctl", "brk", "clock_gettime", "clock_nanosleep", "close", "close_range", "dup",
    "dup2", "dup3", "epoll_create1", "epoll_ctl", "epoll_wait", "fcntl", "futex",
    "getegid", "geteuid", "getgid", "getpgrp", "getpid", "getppid", "getrandom", "getrusage",
    "gettid", "getuid", "lseek", "madvise", "mmap", "mprotect", "mremap", "munmap",
    "nanosleep", "pipe2", "poll", "pread64", "prlimit64", "pwrite64", "read", "readv",
    "rseq", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend",
    "sched_getaffinity", "sched_yield", "select", "set_robust_list", "set_tid_address",
    "sigaltstack", "sysinfo", "umask", "uname", "write", "writev",
)  # fmt: skip


class NormalizationConfig(BaseModel):
    """Which normalization rules run, in order, and what is ignored."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = NORMALIZATION_SCHEMA_VERSION
    rules: list[RuleName] = list(DEFAULT_RULES)
    ignored_syscalls: list[str] = list(DEFAULT_IGNORED_SYSCALLS)
    ignored_path_prefixes: list[str] = []


class NoiseProfile(BaseModel):
    """Signatures that are not present in every run of one environment."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = NOISE_SCHEMA_VERSION
    run_ids: list[str]
    stable_count: int
    unstable: list[str]
