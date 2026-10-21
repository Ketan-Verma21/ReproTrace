"""Align the event sequences of two matched processes by signature.

``difflib.SequenceMatcher`` gives good alignments but slows down sharply on long,
repetitive traces. Alignment therefore works in three steps:

1. Trim the common prefix and suffix.
2. Anchor on signatures that occur exactly once on each side (patience diff), keeping the
   longest chain of anchors that is in the same order on both sides.
3. Align each gap between anchors with ``SequenceMatcher`` when it is small enough, and
   otherwise by counting signatures (order inside that gap is then ignored).
"""

from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from reprotrace.models import Event

# Largest gap (len_a * len_b) handed to SequenceMatcher. Above this, gaps are compared as
# multisets, which is linear but ignores order within the gap.
MAX_EXACT_GAP = 1_000_000


@dataclass
class ProcessAlignment:
    """Events of a matched process pair that did not line up."""

    a_label: str
    b_label: str
    matched: int = 0
    a_only: list[Event] = field(default_factory=list)
    b_only: list[Event] = field(default_factory=list)
    approximate_gaps: int = 0


@dataclass
class _Result:
    matched: int = 0
    a_only: list[int] = field(default_factory=list)
    b_only: list[int] = field(default_factory=list)
    approximate_gaps: int = 0


def _longest_increasing(pairs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Longest chain of pairs increasing in both coordinates (pairs sorted by the first)."""
    tails: list[int] = []
    tail_index: list[int] = []
    previous: list[int] = [-1] * len(pairs)
    for i, (_, b) in enumerate(pairs):
        pos = bisect_left(tails, b)
        if pos == len(tails):
            tails.append(b)
            tail_index.append(i)
        else:
            tails[pos] = b
            tail_index[pos] = i
        previous[i] = tail_index[pos - 1] if pos > 0 else -1
    chain: list[tuple[int, int]] = []
    i = tail_index[-1] if tail_index else -1
    while i != -1:
        chain.append(pairs[i])
        i = previous[i]
    chain.reverse()
    return chain


def _unique_anchors(a: list[str], b: list[str], a0: int, a1: int, b0: int, b1: int
                    ) -> list[tuple[int, int]]:  # fmt: skip
    a_counts = Counter(a[a0:a1])
    b_counts = Counter(b[b0:b1])
    b_pos = {b[j]: j for j in range(b0, b1) if b_counts[b[j]] == 1}
    pairs = [(i, b_pos[a[i]]) for i in range(a0, a1) if a_counts[a[i]] == 1 and a[i] in b_pos]
    return _longest_increasing(pairs)


def _align_gap(a: list[str], b: list[str], a0: int, a1: int, b0: int, b1: int,
               out: _Result) -> None:  # fmt: skip
    if a0 == a1 or b0 == b1:
        out.a_only.extend(range(a0, a1))
        out.b_only.extend(range(b0, b1))
        return
    if (a1 - a0) * (b1 - b0) <= MAX_EXACT_GAP:
        # autojunk would treat frequent syscalls as junk and misalign repetitive traces.
        matcher = SequenceMatcher(None, a[a0:a1], b[b0:b1], autojunk=False)
        for tag, i0, i1, j0, j1 in matcher.get_opcodes():
            if tag == "equal":
                out.matched += i1 - i0
            else:
                out.a_only.extend(range(a0 + i0, a0 + i1))
                out.b_only.extend(range(b0 + j0, b0 + j1))
        return
    out.approximate_gaps += 1
    remaining = Counter(b[b0:b1])
    for i in range(a0, a1):
        if remaining[a[i]] > 0:
            remaining[a[i]] -= 1
            out.matched += 1
        else:
            out.a_only.append(i)
    for j in range(b0, b1):
        if remaining[b[j]] > 0:
            remaining[b[j]] -= 1
            out.b_only.append(j)


def align_signatures(a: list[str], b: list[str]) -> _Result:
    """Align two signature lists; return match count and unmatched indices on each side."""
    out = _Result()
    stack = [(0, len(a), 0, len(b))]
    while stack:
        a0, a1, b0, b1 = stack.pop()
        while a0 < a1 and b0 < b1 and a[a0] == b[b0]:
            a0, b0, out.matched = a0 + 1, b0 + 1, out.matched + 1
        while a0 < a1 and b0 < b1 and a[a1 - 1] == b[b1 - 1]:
            a1, b1, out.matched = a1 - 1, b1 - 1, out.matched + 1
        if (a1 - a0) * (b1 - b0) <= MAX_EXACT_GAP:
            _align_gap(a, b, a0, a1, b0, b1, out)
            continue
        anchors = _unique_anchors(a, b, a0, a1, b0, b1)
        if not anchors:
            _align_gap(a, b, a0, a1, b0, b1, out)
            continue
        out.matched += len(anchors)
        prev_a, prev_b = a0, b0
        for i, j in anchors:
            stack.append((prev_a, i, prev_b, j))
            prev_a, prev_b = i + 1, j + 1
        stack.append((prev_a, a1, prev_b, b1))
    out.a_only.sort()
    out.b_only.sort()
    return out


def align_events(
    a_label: str, b_label: str, a_events: list[Event], b_events: list[Event]
) -> ProcessAlignment:
    """Align two signed event sequences of a matched process pair.

    Only events with a signature should be passed in. One-sided events are returned in
    their original order.
    """
    result = align_signatures(
        [e.signature or "" for e in a_events], [e.signature or "" for e in b_events]
    )
    return ProcessAlignment(
        a_label=a_label,
        b_label=b_label,
        matched=result.matched,
        a_only=[a_events[i] for i in result.a_only],
        b_only=[b_events[j] for j in result.b_only],
        approximate_gaps=result.approximate_gaps,
    )
