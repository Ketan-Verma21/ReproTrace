"""Parse strace output (``strace -f -ttt -y -s 200 -v``) into Event objects.

The parser never raises on input: lines it cannot interpret are counted and kept in
ParseStats. Calls split across ``<unfinished ...>`` / ``<... resumed>`` lines are merged
per PID into one event placed at the position of the first line.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from reprotrace.models import Event, ParseStats, UnparsedLine
from reprotrace.parse.syntax import scan_call_args, split_args
from reprotrace.parse.syscalls import (
    EXIT_SYSCALL,
    KILLED_SYSCALL,
    SIGNAL_SYSCALL,
    SPAWN_SYSCALLS,
    classify,
    target_of,
)

_LINE = re.compile(r"^(?:(?P<pid>\d+)\s+)?(?P<ts>\d+\.\d+)\s+(?P<body>.*)$", re.DOTALL)
_UNFINISHED = "<unfinished ...>"
_RESUMED = re.compile(r"^<\.\.\. (?P<name>[a-z_][a-z0-9_]*) resumed>(?P<rest>.*)$", re.DOTALL)
_CALL_START = re.compile(r"^(?P<name>[a-z_][a-z0-9_]*)\(")
_RESULT = re.compile(
    r"\s*=\s*(?P<result>\?|-?(?:0x[0-9a-fA-F]+|\d+)(?:<[^>]*>)?)"
    r"(?:\s+(?P<errno>E[A-Z0-9_]+))?(?:\s+.*)?$",
    re.DOTALL,
)
_EXITED = re.compile(r"^\+\+\+ exited with (?P<code>-?\d+) \+\+\+$")
_KILLED = re.compile(r"^\+\+\+ killed by (?P<sig>SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$")
_SIGNAL = re.compile(r"^--- (?P<sig>SIG[A-Z0-9]+)\b.*---$", re.DOTALL)


@dataclass(frozen=True)
class _Call:
    syscall: str
    args: list[str]
    result: str | None
    errno: str | None


@dataclass(frozen=True)
class _Draft:
    """An event before its process label and id are known."""

    order: int  # line number of the event's first line
    pid: str
    call: _Call
    target: str | None
    raw: str


@dataclass(frozen=True)
class _Pending:
    line_number: int
    name: str
    text: str
    raw: str


def parse_call(text: str) -> _Call | None:
    """Parse ``name(args) = result [ERRNO (message)]``; None if it does not fit."""
    start = _CALL_START.match(text)
    if start is None:
        return None
    scanned = scan_call_args(text, start.end())
    if scanned is None:
        return None
    args, end = scanned
    outcome = _RESULT.match(text, end + 1)
    if outcome is None:
        return None
    result = outcome["result"]
    errno = outcome["errno"] if result in ("-1", "?") else None
    return _Call(start["name"], args, result, errno)


def _parse_partial(pending: _Pending) -> _Call:
    """Build a call from an unfinished line that was never resumed."""
    args_text = pending.text[len(pending.name) + 1 :]
    return _Call(pending.name, split_args(args_text), None, None)


def _draft(order: int, pid: str, call: _Call, raw: str) -> _Draft:
    return _Draft(order, pid, call, target_of(call.syscall, call.args), raw)


class _TraceParser:
    """Single-use state machine over the lines of one trace."""

    def __init__(self) -> None:
        self.stats = ParseStats()
        self.drafts: list[_Draft] = []
        self.pending: dict[str, _Pending] = {}

    def _unparsed(self, line_number: int, raw: str) -> None:
        self.stats.unparsed.append(UnparsedLine(line_number=line_number, raw=raw))

    def _flush_pending(self, pid: str) -> None:
        pending = self.pending.pop(pid, None)
        if pending is not None:
            self.stats.unmatched_unfinished += 1
            self.drafts.append(
                _draft(pending.line_number, pid, _parse_partial(pending), pending.raw)
            )

    def feed(self, line_number: int, line: str) -> None:
        self.stats.total_lines += 1
        if not line.strip():
            self.stats.blank_lines += 1
            return
        match = _LINE.match(line)
        if match is None:
            self._unparsed(line_number, line)
            return
        pid = match["pid"] or "0"
        body = match["body"]
        if body.endswith(_UNFINISHED):
            self._start_unfinished(line_number, pid, body, line)
        elif resumed := _RESUMED.match(body):
            self._resume(line_number, pid, resumed, line)
        else:
            self._complete_line(line_number, pid, body, line)

    def _start_unfinished(self, line_number: int, pid: str, body: str, line: str) -> None:
        text = body[: -len(_UNFINISHED)].rstrip()
        start = _CALL_START.match(text)
        if start is None:
            self._unparsed(line_number, line)
            return
        self._flush_pending(pid)
        self.pending[pid] = _Pending(line_number, start["name"], text, line)

    def _resume(self, line_number: int, pid: str, resumed: re.Match[str], line: str) -> None:
        pending = self.pending.get(pid)
        if pending is None or pending.name != resumed["name"]:
            self.stats.unmatched_resumed += 1
            self._unparsed(line_number, line)
            return
        del self.pending[pid]
        raw = f"{pending.raw}\n{line}"
        call = parse_call(pending.text + resumed["rest"])
        if call is None:
            self._unparsed(pending.line_number, raw)
            return
        self.stats.merged_pairs += 1
        self.drafts.append(_draft(pending.line_number, pid, call, raw))

    def _complete_line(self, line_number: int, pid: str, body: str, line: str) -> None:
        if exited := _EXITED.match(body):
            self._flush_pending(pid)
            call = _Call(EXIT_SYSCALL, [], exited["code"], None)
        elif killed := _KILLED.match(body):
            self._flush_pending(pid)
            call = _Call(KILLED_SYSCALL, [], killed["sig"], None)
        elif signal := _SIGNAL.match(body):
            self.drafts.append(_Draft(line_number, pid, _Call(SIGNAL_SYSCALL, [], None, None),
                                      signal["sig"], line))  # fmt: skip
            return
        else:
            parsed = parse_call(body)
            if parsed is None:
                self._unparsed(line_number, line)
                return
            call = parsed
        self.drafts.append(_draft(line_number, pid, call, line))

    def finish(self) -> list[_Draft]:
        for pid in list(self.pending):
            self._flush_pending(pid)
        return sorted(self.drafts, key=lambda draft: draft.order)


def _process_labels(drafts: list[_Draft]) -> dict[str, str]:
    """Map PIDs to logical labels: root ``p0``, its children ``p0.1``, ``p0.2``, ...

    Children are numbered in the order their parent created them. PIDs whose parent is
    not in the trace get ``u1``, ``u2``, ... in order of first appearance.
    """
    if not drafts:
        return {}
    parent_of: dict[str, str] = {}
    children: dict[str, list[str]] = {}
    first_seen: list[str] = []
    for draft in drafts:
        if draft.pid not in children:
            children[draft.pid] = []
            first_seen.append(draft.pid)
        result = draft.call.result
        if draft.call.syscall in SPAWN_SYSCALLS and result and result.isdigit():
            child = result
            if child != draft.pid and child not in parent_of:
                parent_of[child] = draft.pid
                children[draft.pid].append(child)

    root = first_seen[0]
    labels: dict[str, str] = {root: "p0"}
    orphans = 0
    for pid in first_seen:
        chain: list[str] = []
        current = pid
        while current not in labels and current in parent_of and current not in chain:
            chain.append(current)
            current = parent_of[current]
        if current not in labels:
            orphans += 1
            labels[current] = f"u{orphans}"
        for child in reversed(chain):
            parent = parent_of[child]
            labels[child] = f"{labels[parent]}.{children[parent].index(child) + 1}"
    return labels


def parse_lines(lines: Iterable[str], run_id: str) -> tuple[list[Event], ParseStats]:
    """Parse trace lines into events for ``run_id``. Never raises on malformed input."""
    parser = _TraceParser()
    for line_number, line in enumerate(lines, start=1):
        parser.feed(line_number, line.rstrip("\n"))
    drafts = parser.finish()
    labels = _process_labels(drafts)
    events = [
        Event(
            id=f"{run_id}:{seq}",
            run_id=run_id,
            proc=labels[draft.pid],
            seq=seq,
            kind=classify(draft.call.syscall),
            syscall=draft.call.syscall,
            target=draft.target,
            args=draft.call.args,
            result=draft.call.result,
            errno=draft.call.errno,
            raw=draft.raw,
        )
        for seq, draft in enumerate(drafts)
    ]
    parser.stats.event_count = len(events)
    return events, parser.stats


def parse_trace_file(path: Path, run_id: str) -> tuple[list[Event], ParseStats]:
    """Parse a raw strace file. Undecodable bytes are replaced, never fatal."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle, run_id)
