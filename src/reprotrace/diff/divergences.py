"""Turn one-sided events of aligned processes into Divergence objects.

Pairing order inside a matched process:
1. identical signatures on both sides  -> only reordered, not a divergence
2. process exits                       -> exit_status_mismatch
3. successful execs                    -> executable_mismatch
4. same call, different outcome        -> result_mismatch
5. shared libraries with the same name -> library_mismatch
6. everything left                     -> <kind>_only_in_a / <kind>_only_in_b
Repeated identical findings in one process are grouped into one divergence.
"""

import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from reprotrace.diff.align import ProcessAlignment
from reprotrace.models import Event
from reprotrace.parse.syscalls import EXIT_SYSCALL, KILLED_SYSCALL

_LIBRARY = re.compile(r"/(?P<stem>[^/]+?\.so)(?:\.[0-9][0-9.]*)?$")


@dataclass
class Finding:
    """A divergence before it gets its final id; ``position`` orders the output."""

    kind: str
    summary: str
    position: tuple[int, int, int]
    a_events: list[Event] = field(default_factory=list)
    b_events: list[Event] = field(default_factory=list)


@dataclass(frozen=True)
class Labels:
    """Display names of the two sides, e.g. ``local`` and ``ci``."""

    a: str
    b: str


def outcome(event: Event) -> str:
    """``OK``, an errno name, or ``unfinished``, for display."""
    if event.errno:
        return event.errno
    return "OK" if event.result is not None else "unfinished"


def exit_text(event: Event | None) -> str:
    """Human-readable process end: ``exit 1``, ``killed by SIGTERM`` or ``no exit``."""
    if event is None:
        return "no exit recorded"
    if event.syscall == KILLED_SYSCALL:
        return f"killed by {event.result}"
    return f"exit {event.result}"


def identity(event: Event) -> str:
    """The call without its outcome: what was attempted, not how it ended."""
    signature = event.signature or ""
    return signature.rsplit("|", 1)[0]


def _library_stem(event: Event) -> str | None:
    if event.kind != "file" or event.errno or not event.target:
        return None
    match = _LIBRARY.search(event.target)
    return match.group("stem") if match else None


def _call_text(event: Event) -> str:
    return f"{event.syscall}({event.args[0] if event.args else ''})"


def _times(count: int) -> str:
    return f" (x{count})" if count > 1 else ""


class _Pairing:
    """Consumes one-sided events of a process pair and produces findings."""

    def __init__(self, alignment: ProcessAlignment, pair_index: int, labels: Labels) -> None:
        self.alignment = alignment
        self.pair_index = pair_index
        self.labels = labels
        self.a_left = list(alignment.a_only)
        self.b_left = list(alignment.b_only)
        self.groups: dict[tuple[str, ...], Finding] = {}
        self.reordered = 0

    def _position(self, a_event: Event | None, b_event: Event | None) -> tuple[int, int, int]:
        # Sequence numbers of the two runs are close enough to interleave findings from
        # both sides roughly in trace order.
        if a_event is not None:
            return (self.pair_index, a_event.seq, 0)
        assert b_event is not None
        return (self.pair_index, b_event.seq, 1)

    def _add(self, key: tuple[str, ...], kind: str, summary: Callable[[int], str],
             a_event: Event | None, b_event: Event | None) -> None:  # fmt: skip
        finding = self.groups.get(key)
        if finding is None:
            finding = Finding(kind, "", self._position(a_event, b_event))
            self.groups[key] = finding
        if a_event is not None:
            finding.a_events.append(a_event)
        if b_event is not None:
            finding.b_events.append(b_event)
        finding.summary = summary(max(len(finding.a_events), len(finding.b_events)))

    def _pair(self, a_key: Callable[[Event], str | None],
              b_key: Callable[[Event], str | None]) -> list[tuple[Event, Event]]:  # fmt: skip
        """Pair remaining events whose keys are equal (first come, first paired)."""
        waiting: dict[str, list[Event]] = defaultdict(list)
        for event in self.b_left:
            key = b_key(event)
            if key is not None:
                waiting[key].append(event)
        pairs: list[tuple[Event, Event]] = []
        for event in self.a_left:
            key = a_key(event)
            if key is not None and waiting.get(key):
                pairs.append((event, waiting[key].pop(0)))
        paired_a = {id(a) for a, _ in pairs}
        paired_b = {id(b) for _, b in pairs}
        self.a_left = [e for e in self.a_left if id(e) not in paired_a]
        self.b_left = [e for e in self.b_left if id(e) not in paired_b]
        return pairs

    def run(self) -> list[Finding]:
        labels = self.labels
        self.reordered = len(self._pair(lambda e: e.signature, lambda e: e.signature))

        proc = self.alignment.a_label

        def exit_call_key(event: Event) -> str | None:
            return "exit_call" if event.syscall in ("exit", "exit_group") else None

        for a, b in self._pair(exit_call_key, exit_call_key):
            # exit_group(0) vs exit_group(1): part of the same exit-status difference.
            self._add(("exit", proc), "exit_status_mismatch",
                      lambda n, a=a, b=b: (
                          f"Process {proc} ended differently: {_call_text(a)} on {labels.a}, "
                          f"{_call_text(b)} on {labels.b}"),
                      a, b)  # fmt: skip

        def exit_key(event: Event) -> str | None:
            return "exit" if event.syscall in (EXIT_SYSCALL, KILLED_SYSCALL) else None

        for a, b in self._pair(exit_key, exit_key):
            self._add(("exit", proc), "exit_status_mismatch",
                      lambda n, a=a, b=b: (
                          f"Process {proc} ended differently: {exit_text(a)} on {labels.a}, "
                          f"{exit_text(b)} on {labels.b}"), a, b)  # fmt: skip

        def exec_key(event: Event) -> str | None:
            return "exec" if event.kind == "exec" and event.result == "0" else None

        for a, b in self._pair(exec_key, exec_key):
            self._add(("exec", a.target or "", b.target or ""), "executable_mismatch",
                      lambda n, a=a, b=b: (
                          f"Different program executed: {a.target} on {labels.a}, "
                          f"{b.target} on {labels.b}"), a, b)  # fmt: skip

        for a, b in self._pair(identity, identity):
            key = ("result", identity(a), outcome(a), outcome(b))
            self._add(key, "result_mismatch",
                      lambda n, a=a, b=b: (
                          f"{a.syscall} {a.target or ''}: {outcome(a)} on {labels.a}, "
                          f"{outcome(b)} on {labels.b}{_times(n)}"), a, b)  # fmt: skip

        def library_key(event: Event) -> str | None:
            stem = _library_stem(event)
            return None if stem is None else f"{event.syscall}|{stem}"

        for a, b in self._pair(library_key, library_key):
            key = ("library", a.target or "", b.target or "")
            self._add(key, "library_mismatch",
                      lambda n, a=a, b=b: (
                          f"Library {_library_stem(a)} loaded from {a.target} on {labels.a}, "
                          f"{b.target} on {labels.b}{_times(n)}"), a, b)  # fmt: skip

        for event in self.a_left:
            self._one_sided(event, "a", labels.a)
        for event in self.b_left:
            self._one_sided(event, "b", labels.b)
        return list(self.groups.values())

    def _one_sided(self, event: Event, side: str, label: str) -> None:
        key = (f"only_{side}", event.signature or "")
        a_event = event if side == "a" else None
        b_event = event if side == "b" else None
        target = f" {event.target}" if event.target else ""
        self._add(key, f"{event.kind}_only_in_{side}",
                  lambda n: (f"{event.syscall}{target} ({outcome(event)}) only on "
                             f"{label}{_times(n)}"), a_event, b_event)  # fmt: skip


def divergences_for_process(
    alignment: ProcessAlignment, pair_index: int, labels: Labels
) -> tuple[list[Finding], int]:
    """Findings for one matched process pair, and how many events were only reordered."""
    pairing = _Pairing(alignment, pair_index, labels)
    findings = pairing.run()
    return findings, pairing.reordered


def first_ids(events: Iterable[Event]) -> list[str]:
    """Event ids in trace order."""
    return [event.id for event in sorted(events, key=lambda e: e.seq)]
