"""Normalization rules: before/after examples taken from the real fixtures."""

import pytest
from pydantic import ValidationError

from conftest import fixture_lines
from reprotrace.models import Event, NormalizationConfig
from reprotrace.normalize.rules import (
    NormalizationContext,
    Normalizer,
    derive_context,
    normalize_events,
)
from reprotrace.parse.strace_parser import parse_lines


def events_of(name: str) -> list[Event]:
    events, _ = parse_lines(fixture_lines(name), "run_t")
    return events


def first(events: list[Event], **fields: object) -> Event:
    return next(e for e in events if all(getattr(e, k) == v for k, v in fields.items()))


def normalizer(rules: list[str], ctx: NormalizationContext) -> Normalizer:
    return Normalizer(NormalizationConfig(rules=rules), ctx)


@pytest.fixture
def local_events() -> list[Event]:
    return events_of("local_python_missing_file")


@pytest.fixture
def local_ctx(local_events: list[Event]) -> NormalizationContext:
    return derive_context(local_events)


# --- context ---------------------------------------------------------------------------


def test_context_comes_from_execve_env_and_cwd_annotation(
    local_events: list[Event], local_ctx: NormalizationContext
) -> None:
    exe = first(local_events, kind="exec")
    assert exe.target is not None
    assert local_ctx.home is not None and exe.target.startswith(local_ctx.home + "/")
    assert local_ctx.user == local_ctx.home.rsplit("/", 1)[-1]
    assert local_ctx.cwd is not None and local_ctx.cwd.startswith("/tmp/tmp.")


# --- one test per rule: real text before -> after ------------------------------------


def test_cwd_rule(local_events: list[Event], local_ctx: NormalizationContext) -> None:
    before = next(a for e in local_events for a in e.args[:1] if a.startswith("AT_FDCWD<"))
    assert normalizer(["cwd"], local_ctx).text(before) == "AT_FDCWD<<cwd>>"


def test_home_rule(local_events: list[Event], local_ctx: NormalizationContext) -> None:
    before = first(local_events, kind="exec").target
    after = normalizer(["home"], local_ctx).text(before)
    assert after == "~" + before[len(local_ctx.home) :]
    assert after.startswith("~/")


def test_user_rule(local_events: list[Event], local_ctx: NormalizationContext) -> None:
    before = first(local_events, kind="exec").target
    after = normalizer(["user"], local_ctx).text(before)
    assert local_ctx.user not in after
    assert after.startswith("/home/<user>/")


def test_temp_paths_rule_on_cwd_and_mkdtemp() -> None:
    events = events_of("repeat_python_tempfile_1")
    ctx = derive_context(events)
    rule = normalizer(["temp_paths"], ctx)
    assert rule.text(ctx.cwd) == "/tmp/<tmp>"
    created = first(events, syscall="openat", target=next(
        e.target for e in events if e.target and e.target.endswith("/f.txt")
    ))  # fmt: skip
    assert rule.text(created.target) == "/tmp/<tmp>/f.txt"


def test_pids_rule() -> None:
    events = events_of("repeat_python_tempfile_1")
    before = next(e.target for e in events if e.target and e.target.endswith("/status"))
    assert before.split("/")[2].isdigit()
    assert normalizer(["pids"], NormalizationContext()).text(before) == "/proc/<pid>/status"


def test_inodes_rule() -> None:
    socket = first(events_of("local_connect_refused"), syscall="socket")
    assert socket.result.startswith("3<socket:[")
    rule = normalizer(["inodes"], NormalizationContext())
    assert rule.text(socket.result) == "3<socket:[<inode>]>"
    stat = first(events_of("local_python_missing_file"), syscall="newfstatat")
    after = rule.text(stat.args[2])
    assert "st_ino=<inode>" in after and "makedev(<dev>)" in after
    assert "st_ino=" in stat.args[2] and "st_ino=<inode>" not in stat.args[2]


def test_timestamps_rule() -> None:
    stat = first(events_of("local_python_missing_file"), syscall="newfstatat")
    before = stat.args[2]
    after = normalizer(["timestamps"], NormalizationContext()).text(before)
    assert "/* 20" in before and "/* <ts> */" in after
    assert "st_atime=<ts>" in after
    assert "st_atime_nsec=<n>" in after


def test_addresses_rule() -> None:
    mmap = next(e for e in events_of("local_python_missing_file") if e.args[0].startswith("0x7"))
    after = normalizer(["addresses"], NormalizationContext()).text(mmap.args[0])
    assert after == "<addr>"


def test_rule_order_cwd_before_temp_paths(local_ctx: NormalizationContext) -> None:
    cwd_first = normalizer(["cwd", "temp_paths"], local_ctx).text(local_ctx.cwd)
    temp_first = normalizer(["temp_paths", "cwd"], local_ctx).text(local_ctx.cwd)
    assert cwd_first == "<cwd>"
    assert temp_first == "/tmp/<tmp>"


# --- ignore-list and config ------------------------------------------------------------


def test_ignored_syscalls_keep_no_signature(local_events: list[Event]) -> None:
    normalized = normalize_events(local_events)
    mmaps = [e for e in normalized if e.syscall == "mmap"]
    assert mmaps and all(e.signature is None for e in mmaps)
    original = first(local_events, syscall="mmap")
    assert first(normalized, id=original.id) == original  # unchanged, not even copied


def test_ignored_path_prefixes(local_events: list[Event]) -> None:
    config = NormalizationConfig(ignored_path_prefixes=["/nonexistent"])
    normalized = normalize_events(local_events, config)
    missing = first(normalized, syscall="openat", target="/nonexistent/config.toml")
    assert missing.signature is None


def test_default_config_has_every_rule_in_order() -> None:
    config = NormalizationConfig()
    assert config.rules == [
        "cwd",
        "home",
        "user",
        "temp_paths",
        "pids",
        "inodes",
        "timestamps",
        "addresses",
    ]
    assert "mmap" in config.ignored_syscalls
    assert "openat" not in config.ignored_syscalls


def test_unknown_rule_is_rejected() -> None:
    with pytest.raises(ValidationError):
        NormalizationConfig(rules=["no_such_rule"])


def test_disabling_a_rule_keeps_the_original_text(local_events: list[Event]) -> None:
    config = NormalizationConfig(rules=[r for r in NormalizationConfig().rules if r != "home"])
    exe = first(normalize_events(local_events, config), kind="exec")
    assert "~" not in exe.target


# --- signatures -------------------------------------------------------------------------


def test_signatures_on_real_events(local_events: list[Event]) -> None:
    normalized = normalize_events(local_events)
    missing = first(normalized, syscall="openat", target="/nonexistent/config.toml")
    assert missing.signature == "openat|/nonexistent/config.toml|O_RDONLY|ENOENT"
    assert first(normalized, syscall="<exited>").signature == "<exited>|1"
    assert first(normalized, syscall="exit_group").signature == "exit_group|1"
    exe = first(normalized, kind="exec")
    assert exe.signature.startswith("execve|~/Code/")
    assert exe.signature.endswith("|ok")


def test_spawn_signature_drops_child_pid() -> None:
    normalized = normalize_events(events_of("local_multiprocess"))
    assert first(normalized, syscall="vfork").signature == "vfork|ok"
    assert first(normalized, syscall="clone").signature == "clone|ok"


def test_socket_and_connect_signatures() -> None:
    normalized = normalize_events(events_of("local_connect_refused"))
    assert first(normalized, syscall="socket").signature == "socket|AF_INET|SOCK_STREAM|ok"
    assert first(normalized, syscall="connect").signature == "connect|127.0.0.1:9|EINPROGRESS"


def test_fd_calls_take_target_from_annotation() -> None:
    normalized = normalize_events(events_of("local_python_missing_file"))
    ioctl = next(e for e in normalized if e.syscall == "ioctl" and e.signature)
    assert ioctl.target is not None
    assert ioctl.signature == f"ioctl|{ioctl.target}|{ioctl.errno or 'ok'}"


def test_normalize_is_pure_and_deterministic(local_events: list[Event]) -> None:
    snapshot = [e.model_copy() for e in local_events]
    first_pass = normalize_events(local_events)
    assert local_events == snapshot
    assert normalize_events(local_events) == first_pass
    changed = [e for e in first_pass if e.signature is not None]
    assert all(
        e.raw == o.raw and e.args == o.args for e, o in zip(first_pass, local_events, strict=True)
    )
    assert changed


@pytest.mark.parametrize(
    "name",
    [
        "local_python_missing_file",
        "local_multiprocess",
        "local_connect_refused",
        "local_long_path",
        "local_killed_by_signal",
        "local_timeout",
        "docker_python_missing_file",
    ],
)
def test_every_fixture_normalizes(name: str) -> None:
    normalized = normalize_events(events_of(name))
    assert any(e.signature for e in normalized)
