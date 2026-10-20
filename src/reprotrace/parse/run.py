"""Parse a saved run and store its events."""

from dataclasses import dataclass
from pathlib import Path

from reprotrace import config
from reprotrace.errors import StoreError
from reprotrace.models import Event, ParseStats, Run
from reprotrace.parse.strace_parser import parse_trace_file
from reprotrace.store.run_files import load_run, raw_trace_path, run_folder, write_events


@dataclass(frozen=True)
class ParsedRun:
    """A run with its parsed events and parse statistics."""

    run: Run
    events: list[Event]
    stats: ParseStats


def parse_run(base_dir: Path, run_id: str) -> ParsedRun:
    """Parse ``raw.strace`` of a saved run and (re)write its ``events.jsonl``.

    The raw trace is the source of truth and is never modified.
    """
    run = load_run(base_dir, run_id)
    trace = raw_trace_path(base_dir, run)
    if not trace.is_file():
        raise StoreError(f"Raw trace missing for {run_id}: {trace}")
    events, stats = parse_trace_file(trace, run.id)
    write_events(run_folder(base_dir, run_id) / config.EVENTS_FILE, events)
    return ParsedRun(run=run, events=events, stats=stats)
