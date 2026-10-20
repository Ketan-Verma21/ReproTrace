"""Per-syscall knowledge: which kind an event is and what its target is."""

import re
from pathlib import PurePosixPath

from reprotrace.models import EventKind
from reprotrace.parse.syntax import fd_path, split_args, unquote

EXIT_SYSCALL = "<exited>"
KILLED_SYSCALL = "<killed>"
SIGNAL_SYSCALL = "<signal>"

_EXEC = frozenset({"execve", "execveat"})
_NET = frozenset(
    {"socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom",
     "sendmsg", "recvmsg", "getsockname", "getpeername", "setsockopt", "getsockopt",
     "shutdown", "socketpair"}
)  # fmt: skip
_PROC = frozenset(
    {"clone", "clone3", "fork", "vfork", "exit", "exit_group", "wait4", "waitid", "kill",
     "tgkill", "tkill", EXIT_SYSCALL, KILLED_SYSCALL, SIGNAL_SYSCALL}
)  # fmt: skip
SPAWN_SYSCALLS = frozenset({"clone", "clone3", "fork", "vfork"})

# Syscalls whose first argument is a path.
_PATH_ARG0 = frozenset(
    {"open", "creat", "stat", "lstat", "stat64", "lstat64", "access", "readlink", "chdir",
     "mkdir", "rmdir", "unlink", "truncate", "chmod", "chown", "lchown", "statfs", "rename",
     "link", "symlink", "execve", "utime", "utimes"}
)  # fmt: skip
# Syscalls of the form f(dirfd, path, ...).
_PATH_ARG1 = frozenset(
    {"openat", "openat2", "newfstatat", "fstatat64", "statx", "faccessat", "faccessat2",
     "readlinkat", "unlinkat", "mkdirat", "execveat", "fchmodat", "fchownat", "renameat",
     "renameat2", "utimensat", "linkat", "mknodat"}
)  # fmt: skip
# Syscalls on an open file descriptor; the target comes from the -y annotation.
_FD_ARG0 = frozenset({"fstat", "fstat64", "fstatfs", "fchdir", "getdents", "getdents64"})

_FILE = _PATH_ARG0.union(_PATH_ARG1, _FD_ARG0) - _EXEC

_INET = re.compile(r'sin_port=htons\((?P<port>\d+)\).*?inet_addr\("(?P<addr>[^"]*)"\)')
_INET6 = re.compile(r'sin6_port=htons\((?P<port>\d+)\).*?inet_pton\(AF_INET6, "(?P<addr>[^"]*)"')
_UNIX = re.compile(r'sun_path=(?P<abstract>@?)"(?P<path>[^"]*)"')


def classify(syscall: str) -> EventKind:
    """Return the event kind for a syscall name."""
    if syscall in _EXEC:
        return "exec"
    if syscall in _FILE:
        return "file"
    if syscall in _NET:
        return "net"
    if syscall in _PROC:
        return "proc"
    return "other"


def _string_arg(args: list[str], index: int) -> str | None:
    if index >= len(args):
        return None
    decoded = unquote(args[index])
    if decoded is None:
        return None
    value, truncated = decoded
    return value + "..." if truncated else value


def _path_relative_to_dirfd(dirfd_arg: str, path: str | None) -> str | None:
    if path is None:
        return fd_path(dirfd_arg)
    if path == "":
        # f(fd, "", ..., AT_EMPTY_PATH) operates on the fd itself.
        return fd_path(dirfd_arg)
    if path.startswith("/"):
        return path
    directory = fd_path(dirfd_arg)
    if directory is None:
        return path
    return str(PurePosixPath(directory) / path)


def socket_address(sockaddr: str) -> str:
    """Return ``ip:port``, ``[ip6]:port`` or ``unix:path`` for a sockaddr argument."""
    if match := _INET.search(sockaddr):
        return f"{match['addr']}:{match['port']}"
    if match := _INET6.search(sockaddr):
        return f"[{match['addr']}]:{match['port']}"
    if match := _UNIX.search(sockaddr):
        return f"unix:{match['abstract']}{match['path']}"
    return sockaddr


def target_of(syscall: str, args: list[str]) -> str | None:
    """Return the path, program, or address an event acts on, if it has one."""
    if syscall in _PATH_ARG0:
        return _string_arg(args, 0)
    if syscall in _PATH_ARG1 and args:
        return _path_relative_to_dirfd(args[0], _string_arg(args, 1))
    if syscall in _FD_ARG0 and args:
        return fd_path(args[0])
    if syscall in {"connect", "bind"} and len(args) > 1:
        return socket_address(args[1])
    return None


def execve_env(args: list[str]) -> dict[str, str]:
    """Return the environment array of an execve call (third argument) as a dict.

    Values longer than strace's -s limit end in ``...``.
    """
    if len(args) < 3 or not args[2].startswith("["):
        return {}
    env: dict[str, str] = {}
    for item in split_args(args[2][1:-1]):
        decoded = unquote(item)
        if decoded is None:
            continue
        value, truncated = decoded
        name, sep, rest = value.partition("=")
        if sep:
            env[name] = rest + "..." if truncated else rest
    return env
