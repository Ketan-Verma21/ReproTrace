"""Terminal output of ``reprotrace runs``: capture groups, newest first, with their runs."""

from collections import OrderedDict

from rich.text import Text

from reprotrace.report.terminal import shorten_middle, styled
from reprotrace.store.db import RunRow


def _exit(row: RunRow) -> Text:
    if row.timed_out:
        return styled("timed out", "critical")
    if row.exit_code is not None and row.exit_code < 0:
        return styled(f"signal {-row.exit_code}", "critical")
    return styled(f"exit {row.exit_code}", "success" if row.exit_code == 0 else "critical")


def _skipped_lines(skipped: list[tuple[str, str]]) -> list[Text]:
    lines = [
        styled(f"Skipped run folder {run_id}: {reason}", "warning") for run_id, reason in skipped
    ]
    return [*lines, Text()] if lines else []


def render_runs(rows: list[RunRow], skipped: list[tuple[str, str]] | None = None) -> list[Text]:
    """Group runs by capture group; one header line per group, one line per run.

    ``skipped`` lists run folders that could not be read, with the reason.
    """
    warnings = _skipped_lines(skipped or [])
    if not rows:
        return [
            *warnings,
            Text("No saved runs yet."),
            styled("Capture one with: reprotrace capture --label local -- COMMAND", "muted"),
        ]
    groups: OrderedDict[str, list[RunRow]] = OrderedDict()
    for row in rows:
        groups.setdefault(row.group_id, []).append(row)
    lines = [
        *warnings,
        Text.assemble(
            styled("Saved runs", "accent"),
            f"  |  {len(rows)} run(s) in {len(groups)} group(s), newest first",
        ),
        Text(),
    ]
    for group_id, members in groups.items():
        first = members[-1]
        started = first.started_at.astimezone().strftime("%Y-%m-%d %H:%M")
        lines.append(
            Text.assemble(
                styled(group_id, "accent"),
                f"  {first.label}  {len(members)} run(s)  {started}  ",
                shorten_middle(" ".join(first.command), 50),
            )
        )
        for row in sorted(members, key=lambda r: r.started_at):
            lines.append(
                Text.assemble(
                    "    ", styled(row.id, "muted"), "  ", _exit(row), f"  {row.duration_ms} ms"
                )
            )
    lines += [Text(), styled("Compare two groups with: reprotrace diff GRP_A GRP_B", "muted")]
    return lines
