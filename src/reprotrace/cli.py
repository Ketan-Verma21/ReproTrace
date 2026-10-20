"""Command-line entry point. Argument handling only; logic lives in package modules."""

import os
import traceback
from pathlib import Path
from typing import Annotated

import typer

from reprotrace import __version__, config
from reprotrace.capture.runner import capture_group
from reprotrace.errors import ReproTraceError
from reprotrace.models import Run
from reprotrace.parse.run import parse_run
from reprotrace.report.run_summary import build_run_summary, render_run_summary

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
) -> None:
    """Turn a mysterious CI failure into evidence."""
    ctx.obj = {"debug": debug}


@app.command()
def version() -> None:
    """Print the installed ReproTrace version."""
    typer.echo(f"reprotrace {__version__}")


def _fail(ctx: typer.Context, error: ReproTraceError) -> typer.Exit:
    if ctx.obj and ctx.obj.get("debug"):
        typer.echo(traceback.format_exc(), err=True)
    typer.echo(f"Error: {error.message}", err=True)
    if error.hint:
        typer.echo(error.hint, err=True)
    return typer.Exit(code=error.exit_code)


def _describe(run: Run) -> str:
    outcome = "timed out" if run.timed_out else f"exit {run.exit_code}"
    trace = Path(config.DATA_DIR_NAME) / run.trace_path
    return f"{run.id}  {outcome}  {run.duration_ms} ms  {trace}"


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
    typer.echo(f"Captured {len(captured)} run(s), label {label}, group {captured[0].group_id}")
    for run in captured:
        typer.echo(f"  {_describe(run)}")


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
    for line in render_run_summary(summary, limit=None if show_all else 10):
        typer.echo(line)
