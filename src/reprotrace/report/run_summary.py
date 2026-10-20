"""Summary of one run for ``reprotrace show``: failed opens, programs, connections."""

from dataclasses import dataclass, field

from reprotrace.models import Event, ParseStats, Run

_OPEN_SYSCALLS = frozenset({"open", "openat", "openat2", "creat"})
_EXEC_SYSCALLS = frozenset({"execve", "execveat"})


@dataclass
class SummaryItem:
    """One line of a summary section, with the first event as evidence."""

    target: str
    outcome: str
    first_event_id: str
    count: int = 1


@dataclass
class RunSummary:
    """Facts about a run that can be read without knowing strace."""

    run: Run
    stats: ParseStats
    failed_opens: list[SummaryItem] = field(default_factory=list)
    programs: list[SummaryItem] = field(default_factory=list)
    connections: list[SummaryItem] = field(default_factory=list)


def _add(items: list[SummaryItem], index: dict[tuple[str, str], SummaryItem], event: Event,
         outcome: str) -> None:  # fmt: skip
    key = (event.target or "?", outcome)
    if key in index:
        index[key].count += 1
        return
    item = SummaryItem(target=key[0], outcome=outcome, first_event_id=event.id)
    index[key] = item
    items.append(item)


def build_run_summary(run: Run, events: list[Event], stats: ParseStats) -> RunSummary:
    """Collect failed file opens, executed programs, and attempted connections."""
    summary = RunSummary(run=run, stats=stats)
    seen_opens: dict[tuple[str, str], SummaryItem] = {}
    seen_programs: dict[tuple[str, str], SummaryItem] = {}
    seen_connections: dict[tuple[str, str], SummaryItem] = {}
    for event in events:
        if event.syscall in _OPEN_SYSCALLS and event.errno:
            _add(summary.failed_opens, seen_opens, event, event.errno)
        elif event.syscall in _EXEC_SYSCALLS and event.result == "0":
            _add(summary.programs, seen_programs, event, "OK")
        elif event.syscall == "connect":
            _add(summary.connections, seen_connections, event, event.errno or "OK")
    return summary


def _outcome_line(run: Run) -> str:
    if run.timed_out:
        return "timed out"
    if run.exit_code is not None and run.exit_code < 0:
        return f"killed by signal {-run.exit_code}"
    return f"exit {run.exit_code}"


def _section(title: str, items: list[SummaryItem], limit: int | None) -> list[str]:
    lines = [f"{title} ({len(items)})"]
    if not items:
        return [*lines, "  none", ""]
    shown = items if limit is None else items[:limit]
    for item in shown:
        repeat = f" x{item.count}" if item.count > 1 else ""
        lines.append(f"  - {item.target}  {item.outcome}{repeat}  [{item.first_event_id}]")
    hidden = len(items) - len(shown)
    if hidden:
        lines.append(f"  {hidden} more hidden (use --all)")
    return [*lines, ""]


def render_run_summary(summary: RunSummary, limit: int | None = 10) -> list[str]:
    """Render a summary as plain text lines; ``limit=None`` shows every item."""
    run, stats = summary.run, summary.stats
    lines = [
        f"Run {run.id}  |  label {run.label}  |  group {run.group_id}",
        f"Command: {' '.join(run.command)}",
        f"Outcome: {_outcome_line(run)}, {run.duration_ms} ms",
        (
            f"Parsed: {stats.event_count} events from {stats.total_lines} lines; "
            f"{stats.unparsed_count} unparsed, {stats.merged_pairs} merged "
            f"unfinished/resumed pairs, {stats.unmatched_unfinished} never resumed"
        ),
        "",
    ]
    lines += _section("Files that failed to open", summary.failed_opens, limit)
    lines += _section("Programs executed", summary.programs, limit)
    lines += _section("Connections attempted", summary.connections, limit)
    lines.append("Evidence ids in [brackets] refer to events.jsonl in the run folder.")
    return lines
