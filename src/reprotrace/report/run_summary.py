"""Summary of one run for ``reprotrace show``: failed opens, programs, connections."""

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from rich.text import Text

from reprotrace.models import Event, ParseStats, Run
from reprotrace.report.terminal import shorten_paths, styled

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
    # Failed opens of a file name that was opened successfully elsewhere: the dynamic loader
    # and Python's import system try several folders before the right one.
    probes: list[SummaryItem] = field(default_factory=list)
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
    found = {
        PurePosixPath(e.target).name
        for e in events
        if e.kind == "file" and e.target and e.errno is None and e.result is not None
    }
    seen_opens: dict[tuple[str, str], SummaryItem] = {}
    seen_probes: dict[tuple[str, str], SummaryItem] = {}
    seen_programs: dict[tuple[str, str], SummaryItem] = {}
    seen_connections: dict[tuple[str, str], SummaryItem] = {}
    for event in events:
        if event.syscall in _OPEN_SYSCALLS and event.errno:
            if event.target and PurePosixPath(event.target).name in found:
                _add(summary.probes, seen_probes, event, event.errno)
            else:
                _add(summary.failed_opens, seen_opens, event, event.errno)
        elif event.syscall in _EXEC_SYSCALLS and event.result == "0":
            _add(summary.programs, seen_programs, event, "OK")
        elif event.syscall == "connect":
            _add(summary.connections, seen_connections, event, event.errno or "OK")
    return summary


def outcome_text(run: Run) -> Text:
    """``exit 0`` (success), ``exit 1`` / ``timed out`` / ``killed by signal N`` (critical)."""
    if run.timed_out:
        return styled("timed out", "critical")
    if run.exit_code is not None and run.exit_code < 0:
        return styled(f"killed by signal {-run.exit_code}", "critical")
    return styled(f"exit {run.exit_code}", "success" if run.exit_code == 0 else "critical")


def _item_line(item: SummaryItem) -> Text:
    repeat = f" x{item.count}" if item.count > 1 else ""
    role = "success" if item.outcome == "OK" else "warning"
    return Text.assemble(
        f"  - {shorten_paths(item.target)}  ",
        styled(f"{item.outcome}{repeat}", role),
        "  ",
        styled(f"[{item.first_event_id}]", "muted"),
    )


def _failed_opens_section(summary: RunSummary, limit: int | None) -> list[Text]:
    """Failed opens, newest kept when the list is long; search-path probes folded."""
    items, probes = summary.failed_opens, summary.probes
    lines = [Text.assemble(styled("Files that failed to open", "accent"), f" ({len(items)})")]
    if not items:
        lines.append(styled("  none", "muted"))
    # The failure that matters usually happens late, right before the program gives up, so a
    # long list keeps its last entries rather than its first.
    shown = items if limit is None or len(items) <= limit else items[-limit:]
    hidden = len(items) - len(shown)
    if hidden:
        lines.append(styled(f"  {hidden} earlier ones hidden (use --all)", "muted"))
    lines += [_item_line(item) for item in shown]
    if probes:
        if limit is None:
            lines.append(
                styled("  Search-path probes (the same file name was found elsewhere):", "muted")
            )
            lines += [_item_line(item) for item in probes]
        else:
            lines.append(
                styled(
                    f"  + {len(probes)} search-path probe(s): the same file name was found "
                    "elsewhere (use --all)",
                    "muted",
                )
            )
    return [*lines, Text()]


def _section(title: str, items: list[SummaryItem], limit: int | None) -> list[Text]:
    lines = [Text.assemble(styled(title, "accent"), f" ({len(items)})")]
    if not items:
        return [*lines, styled("  none", "muted"), Text()]
    shown = items if limit is None else items[:limit]
    for item in shown:
        repeat = f" x{item.count}" if item.count > 1 else ""
        role = "success" if item.outcome == "OK" else "warning"
        lines.append(
            Text.assemble(
                f"  - {shorten_paths(item.target)}  ",
                styled(f"{item.outcome}{repeat}", role),
                "  ",
                styled(f"[{item.first_event_id}]", "muted"),
            )
        )
    hidden = len(items) - len(shown)
    if hidden:
        lines.append(styled(f"  {hidden} more hidden (use --all)", "muted"))
    return [*lines, Text()]


def render_run_summary(summary: RunSummary, limit: int | None = 10) -> list[Text]:
    """Render a summary as lines; ``limit=None`` shows every item."""
    run, stats = summary.run, summary.stats
    unparsed_role = "success" if stats.unparsed_count == 0 else "warning"
    lines = [
        Text.assemble(
            styled(f"Run {run.id}", "accent"),
            "  |  label ",
            styled(run.label, "accent"),
            "  |  group ",
            styled(run.group_id, "muted"),
        ),
        Text(f"Command: {' '.join(run.command)}"),
        Text.assemble("Outcome: ", outcome_text(run), f", {run.duration_ms} ms"),
        Text.assemble(
            f"Parsed: {stats.event_count} events from {stats.total_lines} lines; ",
            styled(f"{stats.unparsed_count} unparsed", unparsed_role),
            f", {stats.merged_pairs} merged unfinished/resumed pairs, "
            f"{stats.unmatched_unfinished} never resumed",
        ),
        Text(),
    ]
    lines += _failed_opens_section(summary, limit)
    lines += _section("Programs executed", summary.programs, limit)
    lines += _section("Connections attempted", summary.connections, limit)
    lines.append(
        styled("Evidence ids in [brackets] refer to events.jsonl in the run folder.", "muted")
    )
    return lines
