"""Terminal output of ``reprotrace diff``, ranked (Design.md 4.2)."""

from collections import Counter

from rich.text import Text

from reprotrace.diff.compare import SavedComparison
from reprotrace.diff.rank import severity
from reprotrace.models import Divergence, RankConfig
from reprotrace.report.run_summary import outcome_text
from reprotrace.report.terminal import severity_label, shorten_paths, styled

DEFAULT_LIMIT = 5


def _evidence(divergence: Divergence, a_label: str, b_label: str, max_ids: int = 3) -> Text:
    text = Text("Evidence: ")
    first = True
    for label, ids in ((a_label, divergence.a_event_ids), (b_label, divergence.b_event_ids)):
        if not ids:
            continue
        more = f" +{len(ids) - max_ids} more" if len(ids) > max_ids else ""
        text.append_text(Text("   " if not first else ""))
        text.append(f"{label} ")
        text.append_text(styled(f"{', '.join(ids[:max_ids])}{more}", "muted"))
        first = False
    return text


def render_comparison(
    saved: SavedComparison,
    ranked: list[Divergence],
    limit: int | None = DEFAULT_LIMIT,
    config: RankConfig | None = None,
) -> list[Text]:
    """Render ranked divergences; ``limit=None`` shows every divergence."""
    cmp = saved.comparison
    a_run, b_run = saved.a_runs[0], saved.b_runs[0]
    lines = [
        Text.assemble(
            styled("Comparison", "accent"),
            f"  |  {cmp.a_label} ({cmp.a_run_count} run(s)) vs "
            f"{cmp.b_label} ({cmp.b_run_count} run(s))",
        ),
        Text(f"Command: {' '.join(a_run.command)}"),
        Text.assemble(
            f"Exit codes: {cmp.a_label} ",
            outcome_text(a_run),
            f", {cmp.b_label} ",
            outcome_text(b_run),
        ),
        styled(
            f"Processes matched: {cmp.matched_processes}, unmatched: "
            f"{cmp.unmatched_processes}; unstable signatures ignored: {cmp.ignored_unstable}",
            "muted",
        ),
        Text(),
    ]
    if not ranked:
        lines += [styled("No clear difference found.", "success"), Text()]
    else:
        counts = Counter(severity(d, config) for d in ranked)
        summary = ", ".join(f"{counts[s]} {s.lower()}" for s in ("CRITICAL", "WARNING", "INFO"))
        lines += [
            Text.assemble(
                styled("Top divergences (ranked, heuristic)", "accent"),
                f"  |  {len(ranked)} total: {summary}",
            ),
            Text(),
        ]
        shown = ranked if limit is None else ranked[:limit]
        for rank, d in enumerate(shown, start=1):
            label = severity_label(severity(d, config))
            label.pad_right(10 - len(label.plain))
            lines.append(
                Text.assemble(
                    f"{rank:>3}  ",
                    label,
                    f"  score {d.score:.2f}  ",
                    styled(f"({d.id}, {d.kind})", "muted"),
                )
            )
            lines.append(Text(f"     {shorten_paths(d.summary)}"))
            lines.append(Text.assemble("     ", _evidence(d, cmp.a_label, cmp.b_label)))
            lines.append(
                Text.assemble("     Why ranked here: ", styled("; ".join(d.reasons), "muted"))
            )
            lines.append(Text())
        hidden = len(ranked) - len(shown)
        if hidden:
            lines += [
                styled(f"{hidden} further lower-score divergences hidden (use --all)", "muted"),
                Text(),
            ]
    lines += [styled(f"Note: {note}", "warning") for note in cmp.notes]
    lines.append(styled("Note: ranking is a heuristic, not proof of cause.", "muted"))
    lines.append(
        styled("Evidence ids refer to events.jsonl of the first run on each side.", "muted")
    )
    return lines
