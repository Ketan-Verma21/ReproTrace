"""Logical process tree of a run and matching of processes between two runs.

Processes are matched by their position in the exec chain, never by PID: the roots are
matched, then the children of matched processes are paired in creation order among
children that run the same program (basename of their first successful exec).
"""

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from reprotrace.models import Event
from reprotrace.parse.syscalls import EXIT_SYSCALL, KILLED_SYSCALL


@dataclass
class ProcessNode:
    """One logical process (``p0``, ``p0.1``, ...) and its events in order."""

    label: str
    parent: str | None
    children: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)

    @property
    def exec_events(self) -> list[Event]:
        """Successful exec calls of this process, in order."""
        return [e for e in self.events if e.kind == "exec" and e.result == "0"]

    @property
    def program(self) -> str | None:
        """Path of the program the process ran last, if it exec'd at all."""
        execs = self.exec_events
        return execs[-1].target if execs else None

    @property
    def key(self) -> str:
        """Matching key: basename of the first program run, or "" for a plain fork."""
        execs = self.exec_events
        if not execs or not execs[0].target:
            return ""
        return PurePosixPath(execs[0].target).name

    @property
    def exit_event(self) -> Event | None:
        """The ``<exited>`` or ``<killed>`` event, if the process ended in the trace."""
        for event in reversed(self.events):
            if event.syscall in (EXIT_SYSCALL, KILLED_SYSCALL):
                return event
        return None


def _parent_label(label: str) -> str | None:
    return label.rsplit(".", 1)[0] if "." in label else None


def _child_order(label: str) -> tuple[int, ...]:
    parts = label.split(".")[1:]
    return tuple(int(part) for part in parts if part.isdigit())


def build_process_tree(events: list[Event]) -> dict[str, ProcessNode]:
    """Group events by process label and link parents to children.

    Returns nodes in order of first appearance; children are in creation order.
    """
    nodes: dict[str, ProcessNode] = {}
    for event in events:
        node = nodes.get(event.proc)
        if node is None:
            node = nodes[event.proc] = ProcessNode(event.proc, _parent_label(event.proc))
        node.events.append(event)
    for label in list(nodes):
        parent = nodes[label].parent
        while parent is not None and parent not in nodes:
            # A parent with no events of its own still anchors its children.
            nodes[parent] = ProcessNode(parent, _parent_label(parent))
            parent = nodes[parent].parent
    for node in nodes.values():
        if node.parent is not None:
            nodes[node.parent].children.append(node.label)
    for node in nodes.values():
        node.children.sort(key=_child_order)
    return nodes


def roots(tree: dict[str, ProcessNode]) -> list[str]:
    """Labels of processes without a parent in the trace (``p0`` first)."""
    return [label for label, node in tree.items() if node.parent is None]


@dataclass
class ProcessMatch:
    """Result of matching two process trees."""

    pairs: list[tuple[str, str]] = field(default_factory=list)
    only_a: list[str] = field(default_factory=list)
    only_b: list[str] = field(default_factory=list)


def _match_lists(
    a_labels: list[str],
    b_labels: list[str],
    a_tree: dict[str, ProcessNode],
    b_tree: dict[str, ProcessNode],
    result: ProcessMatch,
) -> None:
    b_by_key: dict[str, list[str]] = defaultdict(list)
    for label in b_labels:
        b_by_key[b_tree[label].key].append(label)
    matched_b: set[str] = set()
    for a_label in a_labels:
        candidates = b_by_key.get(a_tree[a_label].key)
        if not candidates:
            result.only_a.append(a_label)
            continue
        b_label = candidates.pop(0)
        matched_b.add(b_label)
        result.pairs.append((a_label, b_label))
        _match_lists(a_tree[a_label].children, b_tree[b_label].children, a_tree, b_tree, result)
    result.only_b.extend(label for label in b_labels if label not in matched_b)


def match_processes(a_tree: dict[str, ProcessNode], b_tree: dict[str, ProcessNode]) -> ProcessMatch:
    """Match processes by exec-chain position. Unmatched subtrees are reported by root only."""
    result = ProcessMatch()
    a_roots, b_roots = roots(a_tree), roots(b_tree)
    if a_roots and b_roots and a_roots[0] == "p0" and b_roots[0] == "p0":
        # The traced command itself is always the same process, whatever it exec'd.
        result.pairs.append(("p0", "p0"))
        _match_lists(a_tree["p0"].children, b_tree["p0"].children, a_tree, b_tree, result)
        a_roots, b_roots = a_roots[1:], b_roots[1:]
    _match_lists(a_roots, b_roots, a_tree, b_tree, result)
    return result


def subtree_size(tree: dict[str, ProcessNode], label: str) -> int:
    """Number of processes in the subtree rooted at ``label`` (including itself)."""
    return 1 + sum(subtree_size(tree, child) for child in tree[label].children)
