"""Command-line entry point. Argument handling only; logic lives in package modules."""

import os
import traceback
from pathlib import Path
from typing import Annotated

import typer
from rich.text import Text

from reprotrace import __version__, config
from reprotrace.capture.runner import capture_group
from reprotrace.diff.compare import compare_saved
from reprotrace.diff.rank import rank_divergences
from reprotrace.diff.record import record_comparison
from reprotrace.errors import ReproTraceError
from reprotrace.models import DiffConfig, NormalizationConfig, RankConfig, Run
from reprotrace.parse.run import parse_run
from reprotrace.report.diff_text import DEFAULT_LIMIT, render_comparison
from reprotrace.report.markdown import write_report
from reprotrace.report.run_summary import build_run_summary, outcome_text, render_run_summary
from reprotrace.report.runs_text import render_runs
from reprotrace.report.terminal import make_console, print_lines, styled
from reprotrace.store.db import connect, list_runs, sync_runs

app = typer.Typer(
    name="reprotrace",
    help=(
        "ReproTrace compares how a command behaves on two machines and reports "
        "likely causes of the difference."
    ),
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


@app.callback()
def main(
    ctx: typer.Context,
    debug: Annotated[bool, typer.Option("--debug", help="Show stack traces on errors.")] = False,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Plain output without colors.")
    ] = False,
) -> None:
    """Turn a mysterious CI failure into evidence."""
    ctx.obj = {"debug": debug, "no_color": no_color}


def _out(ctx: typer.Context, lines: list[Text]) -> None:
    print_lines(make_console(no_color=bool(ctx.obj and ctx.obj.get("no_color"))), lines)


def _fail(ctx: typer.Context, error: ReproTraceError) -> typer.Exit:
    """Print a short error (and a hint) on stderr; return the exit to raise."""
    no_color = bool(ctx.obj and ctx.obj.get("no_color"))
    console = make_console(no_color=no_color, stderr=True)
    lines: list[Text] = []
    if ctx.obj and ctx.obj.get("debug"):
        lines.append(Text(traceback.format_exc()))
    lines.append(styled(f"Error: {error.message}", "critical"))
    if error.hint:
        lines.append(Text(error.hint))
    print_lines(console, lines)
    return typer.Exit(code=error.exit_code)


@app.command()
def version() -> None:
    """Print the installed ReproTrace version."""
    typer.echo(f"reprotrace {__version__}")


def _describe(run: Run) -> Text:
    trace = Path(config.DATA_DIR_NAME) / run.trace_path
    return Text.assemble(
        "  ",
        styled(run.id, "muted"),
        "  ",
        outcome_text(run),
        f"  {run.duration_ms} ms  ",
        styled(str(trace), "muted"),
    )


@app.command(context_settings={"ignore_unknown_options": True})
def capture(
    ctx: typer.Context,
    command: Annotated[
        list[str], typer.Argument(help="Command to trace. Put it after '--'.", show_default=False)
    ],
    label: Annotated[str, typer.Option(help="Name for this environment, e.g. local or ci.")],
    runs: Annotated[int, typer.Option(min=1, help="How many times to run the command.")] = (
        config.DEFAULT_RUNS
    ),
    timeout: Annotated[
        float, typer.Option(min=0.001, help="Timeout per run, in seconds.")
    ] = config.DEFAULT_TIMEOUT_S,
) -> None:
    """Run a command under strace and save the trace: reprotrace capture --label X -- CMD"""
    try:
        captured = capture_group(
            command=command,
            label=label,
            runs=runs,
            base_dir=Path.cwd(),
            timeout_s=timeout,
            env=dict(os.environ),
        )
    except ReproTraceError as error:
        raise _fail(ctx, error) from error
    header = Text.assemble(
        f"Captured {len(captured)} run(s), label {label}, group ",
        styled(captured[0].group_id, "accent"),
    )
    _out(ctx, [header, *(_describe(run) for run in captured)])


@app.command()
def show(
    ctx: typer.Context,
    run_id: Annotated[str, typer.Argument(help="Run id printed by 'reprotrace capture'.")],
    show_all: Annotated[bool, typer.Option("--all", help="Show every item.")] = False,
) -> None:
    """Parse a run and summarize failed opens, programs, and connections."""
    try:
        parsed = parse_run(Path.cwd(), run_id)
    except ReproTraceError as error:
        raise _fail(ctx, error) from error
    summary = build_run_summary(parsed.run, parsed.events, parsed.stats)
    _out(ctx, render_run_summary(summary, limit=None if show_all else 10))


@app.command("runs")
def list_saved_runs(ctx: typer.Context) -> None:
    """List saved runs, grouped by capture group, newest first."""
    try:
        with connect(Path.cwd()) as conn:
            synced = sync_runs(conn, Path.cwd())
            rows = list_runs(conn)
    except ReproTraceError as error:
        raise _fail(ctx, error) from error
    _out(ctx, render_runs(rows, synced.skipped))


@app.command()
def diff(
    ctx: typer.Context,
    a: Annotated[str, typer.Argument(help="Run id or group id (grp_...) of the first side.")],
    b: Annotated[str, typer.Argument(help="Run id or group id (grp_...) of the second side.")],
    show_all: Annotated[bool, typer.Option("--all", help="Show every divergence.")] = False,
) -> None:
    """Compare two runs or capture groups and rank where their behavior diverges."""
    norm_config, diff_config, rank_config = NormalizationConfig(), DiffConfig(), RankConfig()
    try:
        saved = compare_saved(Path.cwd(), a, b, norm_config, diff_config)
        ranked = rank_divergences(saved.comparison, rank_config)
        comparison_id = record_comparison(
            Path.cwd(), saved, ranked, norm_config, diff_config, rank_config
        )
    except ReproTraceError as error:
        raise _fail(ctx, error) from error
    lines = render_comparison(saved, ranked, None if show_all else DEFAULT_LIMIT, rank_config)
    lines += [
        Text(),
        Text.assemble("Saved as ", styled(comparison_id, "accent"), ". Write a report with:"),
        Text(f"  reprotrace report {comparison_id}"),
    ]
    _out(ctx, lines)


@app.command()
def report(
    ctx: typer.Context,
    comparison_id: Annotated[
        str, typer.Argument(help="Comparison id printed by 'reprotrace diff'.")
    ],
    out: Annotated[
        Path | None, typer.Option("--out", help="Write the report here instead.")
    ] = None,
) -> None:
    """Write a Markdown report of a saved comparison."""
    try:
        path = write_report(Path.cwd(), comparison_id, out)
    except ReproTraceError as error:
        raise _fail(ctx, error) from error
    _out(ctx, [Text.assemble("Report written to ", styled(str(path), "accent"))])
