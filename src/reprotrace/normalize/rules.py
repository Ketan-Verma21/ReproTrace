"""Named, ordered normalization rules and event signatures.

Each rule rewrites volatile text (PIDs, timestamps, temp names, ...) into a placeholder so
that the same behavior on two runs produces the same signature. Rules apply to an event's
target and result and to the arguments its signature uses; ``args`` and ``raw`` stay
verbatim so evidence always shows what strace printed.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from reprotrace.models import Event, NormalizationConfig, RuleName
from reprotrace.parse.syntax import fd_path
from reprotrace.parse.syscalls import (
    EXIT_SYSCALL,
    KILLED_SYSCALL,
    SIGNAL_SYSCALL,
    SPAWN_SYSCALLS,
    execve_env,
)

_OPEN_SYSCALLS = frozenset({"open", "openat", "openat2", "creat"})
_OPEN_FLAG_INDEX = {"open": 1, "openat": 2, "openat2": 2}
# Open flags that change what a call means; others (O_CLOEXEC, O_NONBLOCK, ...) do not.
_MEANINGFUL_OPEN_FLAGS = (
    "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL", "O_TRUNC", "O_APPEND",
    "O_DIRECTORY",
)  # fmt: skip
_CWD_ANNOTATION = re.compile(r"AT_FDCWD<([^>]*)>")
# A path prefix ends at a separator, quote, annotation end, comma, space, or end of text.
_PATH_END = r"(?=[/\"'>:,\s\]\)]|$)"

Rewrite = Callable[[str], str]


@dataclass(frozen=True)
class NormalizationContext:
    """Facts about one run that some rules need."""

    cwd: str | None = None
    home: str | None = None
    user: str | None = None


def derive_context(events: list[Event]) -> NormalizationContext:
    """Read cwd, HOME, and user name from a run's own events.

    HOME and USER/LOGNAME come from the first successful execve environment; cwd from the
    first ``AT_FDCWD<...>`` annotation (strace -y).
    """
    home = user = cwd = None
    for event in events:
        if home is None and event.kind == "exec" and event.result == "0":
            env = execve_env(event.args)
            home = env.get("HOME")
            user = env.get("USER") or env.get("LOGNAME")
        if cwd is None:
            for arg in event.args[:1]:
                if match := _CWD_ANNOTATION.match(arg):
                    cwd = match.group(1)
        if home is not None and cwd is not None:
            break
    if user is None and home and home.rstrip("/").count("/") >= 2:
        user = home.rstrip("/").rsplit("/", 1)[-1]
    return NormalizationContext(cwd=cwd, home=home, user=user)


def _sub(pattern: str, replacement: str, flags: int = 0) -> Rewrite:
    compiled = re.compile(pattern, flags)
    return lambda text: compiled.sub(replacement, text)


def _prefix_rule(prefix: str | None, placeholder: str) -> list[Rewrite]:
    if not prefix or prefix == "/":
        return []
    return [_sub(re.escape(prefix.rstrip("/")) + _PATH_END, placeholder)]


def _build_rule(name: RuleName, ctx: NormalizationContext) -> list[Rewrite]:
    if name == "cwd":
        return _prefix_rule(ctx.cwd, "<cwd>")
    if name == "home":
        return _prefix_rule(ctx.home, "~")
    if name == "user":
        # Short names would match ordinary words, so they are left alone.
        if not ctx.user or len(ctx.user) < 3:
            return []
        return [_sub(rf"(?<![A-Za-z0-9_]){re.escape(ctx.user)}(?![A-Za-z0-9_])", "<user>")]
    if name == "temp_paths":
        return [
            _sub(r"(?<![\w.])(/tmp|/var/tmp|/dev/shm)/[^/\"'>:,\s\]\)]+", r"\1/<tmp>"),
            _sub(r"\bpytest-\d+\b", "pytest-<n>"),
        ]
    if name == "pids":
        return [
            _sub(r"/proc/\d+" + _PATH_END, "/proc/<pid>"),
            _sub(r"\bsi_pid=\d+", "si_pid=<pid>"),
        ]
    if name == "inodes":
        return [
            _sub(r"\b(socket|pipe|net|anon_inode:[^\]\s]*):\[\d+\]", r"\1:[<inode>]"),
            _sub(r"\bst_ino=\d+", "st_ino=<inode>"),
            _sub(r"\bmakedev\([^)]*\)", "makedev(<dev>)"),
        ]
    if name == "timestamps":
        return [
            _sub(r"/\* \d{4}-\d{2}-\d{2}T[^*]*\*/", "/* <ts> */"),
            _sub(r"(?<![\w.])1\d{9}(?:\.\d+)?(?![\w.])", "<ts>"),
            _sub(r"\b(tv_sec|tv_nsec|st_[amc]time_nsec)=\d+", r"\1=<n>"),
        ]
    if name == "addresses":
        return [_sub(r"\b0x[0-9a-fA-F]{5,}\b", "<addr>")]
    raise ValueError(f"unknown normalization rule: {name}")


class Normalizer:
    """Applies the configured rules, in order, for one run."""

    def __init__(self, config: NormalizationConfig, ctx: NormalizationContext) -> None:
        self.config = config
        self.rewrites: list[Rewrite] = [
            rewrite for name in config.rules for rewrite in _build_rule(name, ctx)
        ]
        self._ignored_syscalls = frozenset(config.ignored_syscalls)

    def text(self, value: str) -> str:
        """Apply every enabled rule to ``value``."""
        for rewrite in self.rewrites:
            value = rewrite(value)
        return value

    def _optional(self, value: str | None) -> str | None:
        return None if value is None else self.text(value)

    def is_ignored(self, syscall: str, target: str | None) -> bool:
        """True if an event is on the ignore-list (by syscall or by normalized target)."""
        if syscall in self._ignored_syscalls:
            return True
        prefixes = self.config.ignored_path_prefixes
        return target is not None and any(target.startswith(p) for p in prefixes)

    def event(self, event: Event) -> Event:
        """Return a copy of ``event`` with normalized target/result and its signature.

        ``args`` and ``raw`` stay verbatim; only the arguments a signature uses are
        normalized, inside ``signature``. Ignored events are returned unchanged.
        """
        if event.syscall in self._ignored_syscalls:
            return event
        target = self._optional(event.target)
        if target is None and event.kind == "other" and event.args:
            target = self._optional(fd_path(event.args[0]))
        result = self._optional(event.result)
        if self.is_ignored(event.syscall, target):
            return event.model_copy(update={"target": target, "result": result})
        sig = self.signature(event, target)
        return event.model_copy(update={"target": target, "result": result, "signature": sig})

    def _arg(self, event: Event, index: int) -> str:
        if -len(event.args) <= index < len(event.args):
            return self.text(event.args[index])
        return ""

    def signature(self, event: Event, target: str | None) -> str:
        """Return a stable description of what ``event`` did, without volatile values.

        ``target`` must already be normalized. PIDs, fds, sizes and other results are left
        out; only the outcome (``ok``, an errno, or ``unfinished``) is kept.
        """
        syscall = event.syscall
        outcome = _outcome(event)
        if syscall in _OPEN_SYSCALLS:
            return f"{syscall}|{target or ''}|{_open_flags(event)}|{outcome}"
        if event.kind == "exec":
            return f"{syscall}|{target or ''}|{self._arg(event, 1)}|{outcome}"
        if syscall in (EXIT_SYSCALL, KILLED_SYSCALL):
            return f"{syscall}|{event.result}"
        if syscall == SIGNAL_SYSCALL:
            return f"{syscall}|{event.target}"
        if syscall in ("exit", "exit_group"):
            return f"{syscall}|{self._arg(event, 0)}"
        if syscall in SPAWN_SYSCALLS:
            return f"{syscall}|{outcome}"
        if syscall in ("kill", "tgkill", "tkill"):
            return f"{syscall}|{self._arg(event, -1)}|{outcome}"
        if syscall == "socket":
            sock_type = self._arg(event, 1).split("|")[0]
            return f"socket|{self._arg(event, 0)}|{sock_type}|{outcome}"
        return f"{syscall}|{target or ''}|{outcome}"


def _outcome(event: Event) -> str:
    if event.errno:
        return event.errno
    return "ok" if event.result is not None else "unfinished"


def _open_flags(event: Event) -> str:
    index = _OPEN_FLAG_INDEX.get(event.syscall)
    if index is None or index >= len(event.args):
        return ""
    flags = event.args[index].split("|")
    return "|".join(flag for flag in _MEANINGFUL_OPEN_FLAGS if flag in flags)


def normalize_events(
    events: list[Event],
    config: NormalizationConfig | None = None,
    ctx: NormalizationContext | None = None,
) -> list[Event]:
    """Return normalized copies of ``events``. Pure: the input list is not modified."""
    config = config or NormalizationConfig()
    normalizer = Normalizer(config, ctx if ctx is not None else derive_context(events))
    return [normalizer.event(event) for event in events]
