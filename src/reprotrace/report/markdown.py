"""Markdown report of a saved comparison (Design.md section 5).

Everything shown is traceable to event ids. Evidence excerpts are sanitized: the full
environment in execve lines is replaced by a count, token-like strings are redacted, and
long lines are shortened.
"""

import re
import shlex
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from reprotrace import __version__, config
from reprotrace.capture.redact import REDACTED, looks_like_token, redact_value
from reprotrace.diff.rank import severity
from reprotrace.errors import ReproTraceError
from reprotrace.models import Divergence, Event, Explanation, RankConfig, Run
from reprotrace.parse.run import parse_run
from reprotrace.parse.syscalls import execve_env
from reprotrace.store.db import (
    StoredComparison,
    connect,
    latest_comparison_id,
    load_comparison,
    set_report_path,
)
from reprotrace.store.explanations import load_explanation
from reprotrace.store.run_files import load_run, read_events

TOP_DETAILED = 10
MAX_TABLE_ROWS = 40
MAX_EXCERPT_LINE = 240

KIND_TEXT = {
    "result_mismatch": "The same call had a different result on the two sides.",
    "env_diff": "The environment passed to the command differs.",
    "exit_status_mismatch": "The process ended differently.",
    "executable_mismatch": "A different program was executed.",
    "library_mismatch": "A shared library was loaded from a different path.",
}
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _kind_text(kind: str, a_label: str, b_label: str) -> str:
    if kind in KIND_TEXT:
        return KIND_TEXT[kind]
    if kind.startswith("process_only_in_"):
        side = a_label if kind.endswith("_a") else b_label
        return f"A process ran only on {side}."
    if "_only_in_" in kind:
        category, _, side = kind.partition("_only_in_")
        return f"A {category} call happened only on {a_label if side == 'a' else b_label}."
    return kind


def _redact_strings(line: str) -> str:
    def replace(match: re.Match[str]) -> str:
        content = match.group(1)
        if looks_like_token(content):
            return f'"{REDACTED}"'
        return f'"{redact_value(content)}"'

    return _STRING.sub(replace, line)


def sanitize_raw(event: Event) -> str:
    """Raw trace text of ``event`` that is safe to put in a shareable report."""
    raw = event.raw
    if event.kind == "exec" and len(event.args) > 2 and event.args[2].startswith("["):
        count = len(execve_env(event.args))
        raw = raw.replace(event.args[2], f"[/* {count} variables, see Environment differences */]")
    lines = []
    for line in raw.splitlines():
        line = _redact_strings(line)
        if len(line) > MAX_EXCERPT_LINE:
            line = line[: MAX_EXCERPT_LINE - 4] + " ..."
        lines.append(line)
    return "\n".join(lines)


def _md(text: str) -> str:
    """Escape text for Markdown prose: placeholders like <cwd> would render as HTML tags."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cell(text: str) -> str:
    return _md(text).replace("|", "\\|").replace("\n", " ")


def exit_text(run: Run) -> str:
    """How a run ended, in words."""
    if run.timed_out:
        return "timed out"
    if run.exit_code is not None and run.exit_code < 0:
        return f"killed by signal {-run.exit_code}"
    return f"exit {run.exit_code}"


def _evidence_block(d: Divergence, labels: tuple[str, str], events: dict[str, Event]) -> list[str]:
    block = ["```text"]
    for label, ids in ((labels[0], d.a_event_ids), (labels[1], d.b_event_ids)):
        for event_id in ids[:2]:
            block.append(f"{label}  {event_id}")
            event = events.get(event_id)
            text = sanitize_raw(event) if event else "(event not found in events.jsonl)"
            block += [f"  {line}" for line in text.splitlines()]
        if len(ids) > 2:
            block.append(f"{label}  ... {len(ids) - 2} more: {', '.join(ids[2:6])}")
    block.append("```")
    return block


def ungrounded_citations(explanation: Explanation, ranked: list[Divergence]) -> list[str]:
    """Citations of a stored explanation that do not resolve in this comparison."""
    by_id = {d.id: set(d.a_event_ids) | set(d.b_event_ids) for d in ranked}
    bad: list[str] = []
    for hypothesis in explanation.hypotheses:
        bad += [d for d in hypothesis.divergence_ids if d not in by_id]
        allowed = set().union(*(by_id.get(d, set()) for d in hypothesis.divergence_ids))
        bad += [e for e in hypothesis.event_ids if e not in allowed]
    return bad


def _ai_section(explanation: Explanation, ranked: list[Divergence]) -> list[str]:
    rank_of = {d.id: (rank, d) for rank, d in enumerate(ranked, start=1)}
    stamp = explanation.generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    out = ["## AI explanation", ""]
    out.append(
        f"> **AI-generated hypotheses** ({explanation.provider}, model `{explanation.model}`, "
        f"{stamp}). They were produced from the ranked evidence above only, every citation "
        "was checked to exist, but the reasoning can still be wrong. Treat them as leads to "
        "verify, not as findings."
    )
    out += ["", _md(explanation.summary), ""]
    if explanation.insufficient_evidence:
        out += ["The model judged the evidence insufficient to explain the failure.", ""]
    for number, h in enumerate(explanation.hypotheses, start=1):
        out += [f"### Hypothesis {number}: {_md(h.title)} ({h.confidence} confidence)", ""]
        out += [_md(h.explanation), ""]
        cited = []
        for d_id in h.divergence_ids:
            rank, d = rank_of[d_id]
            cited.append(f"`{d_id}` (rank {rank}: {_md(d.summary)})")
        out.append(f"- **Divergences cited:** {'; '.join(cited)}")
        out.append(f"- **Events cited:** {', '.join(f'`{e}`' for e in h.event_ids)}")
        out.append(f"- **Next experiment:** {_md(h.next_experiment)}")
        out.append("")
    return out


def render_report(
    stored: StoredComparison,
    a_runs: list[Run],
    b_runs: list[Run],
    events: dict[str, Event],
    generated_at: datetime,
    rank_config: RankConfig | None = None,
    explanation: Explanation | None = None,
    ai_note: str | None = None,
) -> str:
    """Render a stored comparison as Markdown. Pure: no file or database access.

    ``explanation`` adds the AI section; it is left out (with a note under Limitations) if
    any of its citations does not resolve in this comparison. ``ai_note`` explains why an
    explanation could not be loaded.
    """
    details = stored.details
    a_label, b_label = details["a_label"], details["b_label"]
    ranked = stored.divergences
    a_run, b_run = a_runs[0], b_runs[0]
    severities = Counter(severity(d, rank_config) for d in ranked)
    any_redacted = any(REDACTED in d.summary for d in ranked) or any(
        REDACTED in value for row in details["env_rows"] for value in row[1:]
    )

    out = [f"# ReproTrace Report: {stored.id}", ""]
    notice = (
        "> **Before sharing:** this report contains paths and command lines from the traced "
        "runs. Raw traces in `.reprotrace/runs/` contain the full, unredacted environment of "
        "the traced command; review them before attaching them anywhere."
    )
    if any_redacted:
        notice += " Values that look like secrets are shown as `<redacted>` in this report."
    out += [notice, ""]

    out += ["## Summary", ""]
    out.append(f"- **Command:** `{shlex.join(a_run.command)}`")
    out.append(
        f"- **Environments compared:** `{a_label}` ({len(a_runs)} run(s), `{stored.ref_a}`) vs "
        f"`{b_label}` ({len(b_runs)} run(s), `{stored.ref_b}`)"
    )
    out.append(f"- **Exit codes:** {a_label} {exit_text(a_run)}, {b_label} {exit_text(b_run)}")
    out.append(
        f"- **Divergences:** {len(ranked)} ({severities['CRITICAL']} critical, "
        f"{severities['WARNING']} warning, {severities['INFO']} info)"
    )
    if ranked:
        top = ranked[0]
        out.append(
            f"- **Likely cause:** {_md(top.summary)} (score {top.score:.2f}). This is the "
            "highest-ranked divergence; the ranking is a heuristic, not proof."
        )
    else:
        out.append("- **Result:** No clear difference found.")
    out.append("")

    if ranked:
        out += ["## Top divergences", ""]
        for rank, d in enumerate(ranked[:TOP_DETAILED], start=1):
            out += [f"### {rank}. {_md(d.summary)}", ""]
            out.append(
                f"**{severity(d, rank_config)}**, score {d.score:.2f}, `{d.kind}`, id `{d.id}`"
            )
            out.append("")
            out.append(f"- **What differed:** {_kind_text(d.kind, a_label, b_label)}")
            evidence_ids = [f"`{a_label}` {', '.join(d.a_event_ids[:3]) or '-'}",
                            f"`{b_label}` {', '.join(d.b_event_ids[:3]) or '-'}"]  # fmt: skip
            out.append(f"- **Evidence:** {'; '.join(evidence_ids)}")
            out.append("")
            out += _evidence_block(d, (a_label, b_label), events)
            out += ["", "- **Why it ranked here:**"]
            out += [f"  - {_md(reason)}" for reason in d.reasons]
            out.append("")

        rest = ranked[TOP_DETAILED:]
        if rest:
            out += ["## Other divergences", ""]
            out += ["| Rank | Score | Severity | Kind | Summary |", "|---|---|---|---|---|"]
            for rank, d in enumerate(rest[:MAX_TABLE_ROWS], start=TOP_DETAILED + 1):
                out.append(
                    f"| {rank} | {d.score:.2f} | {severity(d, rank_config)} | `{d.kind}` | "
                    f"{_cell(d.summary)} |"
                )
            if len(rest) > MAX_TABLE_ROWS:
                out.append("")
                out.append(
                    f"{len(rest) - MAX_TABLE_ROWS} more not shown. List them with "
                    f"`reprotrace diff {stored.ref_a} {stored.ref_b} --all`."
                )
            out.append("")

    out += ["## How to reproduce", ""]
    out.append("Capture each environment again, then compare:")
    out += ["", "```text"]
    for label, runs in ((a_label, a_runs), (b_label, b_runs)):
        command = shlex.join(runs[0].command)
        flag = shlex.quote(runs[0].label)
        out.append(f"# in the {label} environment")
        out.append(f"reprotrace capture --label {flag} --runs {len(runs)} -- {command}")
    out.append("# then, with both run folders in one project")
    out.append("reprotrace diff GRP_A GRP_B")
    out += ["```", ""]
    out.append(f"Original groups: `{stored.ref_a}` and `{stored.ref_b}`.")
    out.append("")

    out += ["## Environment differences", ""]
    if details["env_rows"]:
        out += [f"| Variable | {_cell(a_label)} | {_cell(b_label)} |", "|---|---|---|"]
        out += [f"| `{_cell(k)}` | {_cell(a)} | {_cell(b)} |" for k, a, b in details["env_rows"]]
        out += ["", "Values are normalized (home folder as `~`, working directory as `<cwd>`) "
                "and secrets are redacted."]  # fmt: skip
    else:
        out.append(
            "No differences in the environment passed to the command (shell bookkeeping "
            "variables such as `PWD` and `SHLVL` are ignored)."
        )
    out.append("")

    if explanation is not None:
        bad = ungrounded_citations(explanation, ranked)
        if bad:
            ai_note = (
                "AI explanation left out: it cites ids not in this comparison "
                f"({', '.join(bad[:3])})."
            )
        else:
            out += _ai_section(explanation, ranked)

    out += ["## Limitations", ""]
    out += [
        "- Ranking is a heuristic. A high score means the divergence is consistent with the "
        "failure, not that it is proven to cause it.",
        "- Tracing with strace slows the command down and can hide timing-dependent bugs.",
        "- strace cannot see which environment variables a program reads (`getenv()`); "
        "environment differences compare everything passed to the command.",
        "- Run-to-run noise is filtered only for sides captured with two or more runs.",
        "- Evidence ids refer to the first run of each side; excerpts are shortened and "
        "sanitized. Full lines are in `events.jsonl` and `raw.strace` of those runs.",
    ]
    out += [f"- {_md(note)}" for note in details.get("notes", [])]
    if ai_note:
        out.append(f"- {_md(ai_note)}")
    out += ["", "---", ""]
    out.append(
        f"Generated {generated_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M UTC')} by "
        f"reprotrace {__version__}. Comparison created "
        f"{stored.created_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M UTC')}."
    )
    return "\n".join(out) + "\n"


def run_events(base_dir: Path, run_id: str) -> list[Event]:
    """Events of a saved run (parsed now if events.jsonl is missing)."""
    path = config.run_dir(base_dir, run_id) / config.EVENTS_FILE
    if path.is_file():
        return read_events(path)
    return parse_run(base_dir, run_id).events


def write_report(base_dir: Path, comparison_id: str | None, out: Path | None = None) -> Path:
    """Write the Markdown report of a saved comparison (default: the latest) and return its path."""
    with connect(base_dir) as conn:
        stored = load_comparison(conn, comparison_id or latest_comparison_id(conn))
    comparison_id = stored.id
    details = stored.details
    a_runs = [load_run(base_dir, run_id) for run_id in details["a_run_ids"]]
    b_runs = [load_run(base_dir, run_id) for run_id in details["b_run_ids"]]
    events = {
        event.id: event for run in (a_runs[0], b_runs[0]) for event in run_events(base_dir, run.id)
    }
    rank_config = RankConfig.model_validate(stored.config["rank"])
    explanation, ai_note = None, None
    try:
        explanation = load_explanation(base_dir, comparison_id)
    except ReproTraceError as error:
        # A broken explanation file must never block the deterministic report (Rules.md 4).
        ai_note = f"AI explanation left out: {error.message}"
    text = render_report(
        stored, a_runs, b_runs, events, datetime.now(UTC), rank_config, explanation, ai_note
    )
    target = out if out is not None else config.report_path(base_dir, comparison_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    with connect(base_dir) as conn:
        set_report_path(conn, comparison_id, str(target))
    return target
