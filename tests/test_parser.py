"""Parser tests. Trace input comes from the real captures in testdata/traces/."""

from pathlib import Path

import pytest

from conftest import TRACES, fixture_lines
from reprotrace.models import Event
from reprotrace.parse.strace_parser import parse_lines, parse_trace_file
from reprotrace.parse.syntax import fd_path, split_args, unquote
from reprotrace.parse.syscalls import classify, socket_address, target_of

ALL_FIXTURES = sorted(p.stem for p in TRACES.glob("*.strace"))


def events_of(name: str) -> list[Event]:
    events, _ = parse_lines(fixture_lines(name), "run_t")
    return events


def find(events: list[Event], **fields: object) -> list[Event]:
    return [e for e in events if all(getattr(e, k) == v for k, v in fields.items())]


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_fixture_parses_without_unparsed_lines(name: str) -> None:
    events, stats = parse_trace_file(TRACES / f"{name}.strace", "run_t")
    assert stats.unparsed_count == 0
    assert stats.unmatched_resumed == 0
    assert stats.event_count == len(events) > 0
    # Each merged pair turns two lines into one event.
    assert stats.event_count == stats.total_lines - stats.blank_lines - stats.merged_pairs


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_ids_are_stable_and_sequential(name: str) -> None:
    events = events_of(name)
    assert [e.seq for e in events] == list(range(len(events)))
    assert all(e.id == f"run_t:{e.seq}" for e in events)
    assert events_of(name) == events  # deterministic


def test_fixture_list_is_complete() -> None:
    assert len(ALL_FIXTURES) == 23


# --- merge of <unfinished ...> / <... resumed> ---------------------------------------


def test_unfinished_resumed_pairs_are_merged() -> None:
    _, stats = parse_lines(fixture_lines("local_multiprocess"), "run_t")
    assert stats.merged_pairs == 6
    assert stats.unmatched_unfinished == 0


def test_merged_vfork_has_result_and_both_raw_lines() -> None:
    (vfork,) = find(events_of("local_multiprocess"), syscall="vfork")
    assert vfork.result == "26967"
    assert vfork.raw.count("\n") == 1
    assert "<unfinished ...>" in vfork.raw
    assert "<... vfork resumed>" in vfork.raw


def test_merged_event_takes_position_of_first_line() -> None:
    events = events_of("local_multiprocess")
    (vfork,) = find(events, syscall="vfork")
    child_exec = find(events, syscall="execve", target="/usr/bin/ls")[0]
    # The child's execve was logged between the vfork start and its resume line.
    assert vfork.seq < child_exec.seq


def test_merged_wait4_combines_arguments() -> None:
    wait = find(events_of("local_multiprocess"), syscall="wait4", result="26967")[0]
    assert wait.args[0] == "-1"
    assert wait.args[1] == "[{WIFEXITED(s) && WEXITSTATUS(s) == 2}]"
    assert len(wait.args) == 4


def test_unfinished_without_resume_becomes_event_without_result() -> None:
    lines = fixture_lines("local_multiprocess")
    cut = next(i for i, line in enumerate(lines) if "vfork( <unfinished" in line)
    events, stats = parse_lines(lines[: cut + 1], "run_t")
    assert stats.unmatched_unfinished == 1
    assert events[-1].syscall == "vfork"
    assert events[-1].result is None


def test_resumed_without_start_is_counted_and_kept() -> None:
    lines = fixture_lines("local_multiprocess")
    start = next(i for i, line in enumerate(lines) if "vfork( <unfinished" in line)
    resume = next(i for i, line in enumerate(lines) if "<... vfork resumed>" in line)
    events, stats = parse_lines(lines[:start] + lines[start + 1 :], "run_t")
    assert stats.unmatched_resumed == 1
    assert stats.unparsed[0].raw == lines[resume]
    assert not find(events, syscall="vfork")


def test_garbage_lines_never_crash_and_are_kept() -> None:
    lines = ["not a trace line", "", "123 1.5 openat(unterminated", *fixture_lines("local_timeout")]
    events, stats = parse_lines(lines, "run_t")
    assert stats.blank_lines == 1
    assert [u.line_number for u in stats.unparsed] == [1, 3]
    assert stats.unparsed[0].raw == "not a trace line"
    assert len(events) == len(fixture_lines("local_timeout"))


# --- supported syscalls ---------------------------------------------------------------


def test_openat_failure() -> None:
    (event,) = find(events_of("local_python_missing_file"), target="/nonexistent/config.toml")
    assert (event.syscall, event.kind, event.result, event.errno) == (
        "openat",
        "file",
        "-1",
        "ENOENT",
    )


def test_openat_success_keeps_fd_annotation_in_result() -> None:
    event = find(events_of("local_multiprocess"), syscall="openat", target="/etc/hostname")[0]
    assert event.result == "3</etc/hostname>"
    assert event.errno is None


def test_newfstatat_with_empty_path_uses_fd_annotation() -> None:
    event = find(events_of("local_multiprocess"), syscall="newfstatat")[0]
    assert event.args[1] == '""'
    assert event.target == "/etc/ld.so.cache"


def test_newfstatat_with_path() -> None:
    events = events_of("local_python_missing_file")
    event = find(events, syscall="newfstatat", target="/usr/lib/python311.zip")[0]
    assert event.errno == "ENOENT"


def test_statx_target() -> None:
    events = find(events_of("local_multiprocess"), syscall="statx", target="/nonexistent")
    assert events and all(e.errno == "ENOENT" for e in events)


def test_execve() -> None:
    (event,) = find(events_of("local_python_missing_file"), syscall="execve")
    assert event.kind == "exec"
    assert event.target.endswith("/.venv/bin/python3")
    assert event.args[1] == '["python3", "-c", "open(\'/nonexistent/config.toml\')"]'
    assert event.args[2].startswith('["PATH=')
    assert event.result == "0"


def test_execve_in_docker_trace() -> None:
    (event,) = find(events_of("docker_python_missing_file"), syscall="execve")
    assert event.target == "/usr/local/bin/python3"


def test_connect_target_and_errno() -> None:
    (event,) = find(events_of("local_connect_refused"), syscall="connect")
    assert event.kind == "net"
    assert event.target == "127.0.0.1:9"
    assert event.errno == "EINPROGRESS"


def test_clone_and_vfork_create_child_labels() -> None:
    events = events_of("local_multiprocess")
    labels = {e.target: e.proc for e in find(events, syscall="execve")}
    assert labels == {"/usr/bin/sh": "p0", "/usr/bin/ls": "p0.1", "/usr/bin/cat": "p0.2"}
    (clone,) = find(events, syscall="clone")
    assert clone.kind == "proc"
    assert clone.result == "26968"


def test_exit_group_and_exit_lines() -> None:
    events = events_of("local_multiprocess")
    exits = {e.proc: e.result for e in find(events, syscall="<exited>")}
    assert exits == {"p0": "0", "p0.1": "2", "p0.2": "0"}
    assert find(events, syscall="exit_group", proc="p0.1")[0].args == ["2"]


def test_killed_by_signal() -> None:
    events = events_of("local_killed_by_signal")
    assert events[-1].syscall == "<killed>"
    assert events[-1].result == "SIGTERM"
    assert events[-2].syscall == "<signal>"
    assert events[-2].target == "SIGTERM"


def test_sigchld_lines_become_signal_events() -> None:
    signals = find(events_of("local_multiprocess"), syscall="<signal>")
    assert [e.target for e in signals] == ["SIGCHLD", "SIGCHLD"]
    assert all(e.proc == "p0" for e in signals)


def test_interrupted_call_at_timeout() -> None:
    events = events_of("local_timeout")
    (sleep,) = find(events, syscall="clock_nanosleep")
    assert sleep.result == "?"
    assert sleep.errno == "ERESTART_RESTARTBLOCK"
    assert events[-1].syscall == "<killed>"


def test_long_path_is_kept_whole() -> None:
    (event,) = find(events_of("local_long_path"), syscall="openat", errno="ENOENT", proc="p0")[-1:]
    assert event.target == "/nonexistent/" + "x" * 300


def test_truncated_string_argument_is_kept() -> None:
    reads = [e for e in events_of("local_python_missing_file") if e.syscall == "read"]
    truncated = [e for e in reads if e.args[1].endswith('"...')]
    assert truncated
    assert unquote(truncated[0].args[1])[1] is True


def test_kinds() -> None:
    kinds = {e.syscall: e.kind for e in events_of("local_connect_refused")}
    assert kinds["openat"] == "file"
    assert kinds["execve"] == "exec"
    assert kinds["socket"] == "net"
    assert kinds["exit_group"] == "proc"
    assert kinds["mmap"] == "other"


# --- helpers (stat and fork do not occur in x86_64 glibc traces; see Memory.md) -------


def test_stat_and_fork_are_classified() -> None:
    assert classify("stat") == "file"
    assert classify("lstat") == "file"
    assert classify("fork") == "proc"
    assert target_of("stat", ['"/etc/hosts"', "0x7ffd0000"]) == "/etc/hosts"


def test_relative_path_is_joined_to_dirfd() -> None:
    assert target_of("openat", ["AT_FDCWD</tmp/w>", '"conf/a.toml"', "O_RDONLY"]) == (
        "/tmp/w/conf/a.toml"
    )


def test_split_args_respects_fd_annotations_strings_and_brackets() -> None:
    text = '3</tmp/a,b>, "x, y", [1, 2], {a=1, b=2}, f(1, 2)'
    assert split_args(text) == ["3</tmp/a,b>", '"x, y"', "[1, 2]", "{a=1, b=2}", "f(1, 2)"]
    assert split_args("") == []


def test_unquote_decodes_escapes() -> None:
    assert unquote('"a\\nb\\"c\\x41\\101"') == ('a\nb"cAA', False)
    assert unquote('"abc"...') == ("abc", True)
    assert unquote("0x10") is None


def test_fd_path_and_socket_address() -> None:
    assert fd_path("AT_FDCWD</home/u>") == "/home/u"
    assert fd_path("3") is None
    assert socket_address('{sa_family=AF_UNIX, sun_path="/run/x.sock"}') == "unix:/run/x.sock"


def test_parse_trace_file_tolerates_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.strace"
    path.write_bytes(b"\xff\xfe garbage\n")
    events, stats = parse_trace_file(path, "run_t")
    assert events == []
    assert stats.unparsed_count == 1
