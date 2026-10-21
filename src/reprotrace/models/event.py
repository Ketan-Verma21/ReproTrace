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


DIVERGENCE_SCHEMA_VERSION = 1
DIFF_CONFIG_SCHEMA_VERSION = 1

# Environment variables that differ between any two shells or runs without changing
# program behavior.
DEFAULT_IGNORED_ENV_VARS: tuple[str, ...] = ("_", "OLDPWD", "PWD", "SHLVL", "TERM_SESSION_ID")


class DiffConfig(BaseModel):
    """Settings for comparing two environments."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = DIFF_CONFIG_SCHEMA_VERSION
    ignored_env_vars: list[str] = list(DEFAULT_IGNORED_ENV_VARS)


class Divergence(BaseModel):
    """One behavioral difference between two environments (Architecture.md 4.2).

    ``score`` and ``reasons`` are filled by the ranker (Phase 5); until then they are
    0.0 and empty.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = DIVERGENCE_SCHEMA_VERSION
    id: str
    kind: str
    summary: str
    a_event_ids: list[str]
    b_event_ids: list[str]
    score: float = 0.0
    reasons: list[str] = []


RANK_CONFIG_SCHEMA_VERSION = 1

SignalName = Literal[
    "failed_one_side",
    "category",
    "earliest_in_process",
    "stability",
    "proximity_to_failing_exit",
    "not_failure_consequence",
]


class RankConfig(BaseModel):
    """All ranking weights in one place (Phases.md task 5.3). Ranking is a heuristic.

    ``weights``: how much each signal (0..1) counts in the score.
    ``category_weights``: the 0..1 value of the ``category`` signal per divergence kind;
    ``*_only_in_a`` / ``*_only_in_b`` kinds are looked up without the side suffix.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = RANK_CONFIG_SCHEMA_VERSION
    weights: dict[SignalName, float] = {
        "failed_one_side": 3.0,
        "category": 2.0,
        "earliest_in_process": 2.0,
        "stability": 1.0,
        "proximity_to_failing_exit": 1.0,
        "not_failure_consequence": 3.0,
    }
    category_weights: dict[str, float] = {
        "result_mismatch": 1.0,
        "env_diff": 0.8,
        "executable_mismatch": 0.8,
        "library_mismatch": 0.7,
        "exec_only": 0.6,
        "net_only": 0.6,
        "process_only": 0.6,
        "file_only": 0.5,
        "proc_only": 0.3,
        "other_only": 0.2,
        "exit_status_mismatch": 0.2,
    }
    default_category_weight: float = 0.3
    # A failing call seen on one side only (no counterpart) is weaker evidence than the
    # same call succeeding on one side and failing on the other.
    one_sided_failure_value: float = 0.4
    # Error codes that report a normal condition rather than a failure: "not a terminal",
    # "would block", "connection in progress", "no child", interrupted-and-restarted calls.
    benign_errnos: list[str] = [
        "ENOTTY", "EAGAIN", "EINPROGRESS", "EINTR", "ECHILD", "ERESTARTSYS",
        "ERESTARTNOHAND", "ERESTARTNOINTR", "ERESTART_RESTARTBLOCK",
    ]  # fmt: skip
    # Environment differences: a variable missing on the failing side or set to different
    # values is strong evidence (category env_diff). A variable set only on the failing side
    # rarely causes a failure, and CI platform bookkeeping variables almost never do.
    env_only_on_failing_side_value: float = 0.3
    env_platform_value: float = 0.1
    env_platform_prefixes: list[str] = [
        "GITHUB_", "RUNNER_", "ACTIONS_", "GITLAB_", "CI_", "BUILDKITE_", "CIRCLE",
        "TRAVIS_", "JENKINS_", "BUILD_", "AGENT_",
    ]  # fmt: skip
    env_platform_names: list[str] = [
        "CI", "ImageOS", "ImageVersion", "INVOCATION_ID", "JOURNAL_STREAM",
        "SYSTEMD_EXEC_PID", "ENABLE_RUNNER_TRACING",
    ]  # fmt: skip
    # Interactive terminal/desktop session variables: present on a developer machine, absent
    # in CI, and practically never the cause. Locale (LANG, LC_*), VIRTUAL_ENV and the like
    # are deliberately not listed.
    env_session_prefixes: list[str] = [
        "XDG_", "GNOME_", "KDE_", "DBUS_", "GTK_", "QT_", "VTE_", "TERM_", "SSH_",
        "WAYLAND_", "P9K_", "_P9K_", "POWERLEVEL9K_", "GPG_", "VSCODE_", "TMUX",
    ]  # fmt: skip
    env_session_names: list[str] = [
        "COLORTERM", "DESKTOP_SESSION", "DISPLAY", "GDMSESSION", "LESS", "LSCOLORS",
        "LS_COLORS", "PAGER", "PS1", "SESSION_MANAGER", "TERM", "XAUTHORITY", "XMODIFIERS",
        "ZSH", "EDITOR", "VISUAL", "HISTFILE", "HISTSIZE", "MAIL", "MOTD_SHOWN",
        "USERNAME", "WINDOWID", "SHELL",
    ]  # fmt: skip
    critical_threshold: float = 0.7
    warning_threshold: float = 0.5
