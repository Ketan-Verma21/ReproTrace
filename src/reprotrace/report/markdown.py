"""Report of a saved comparison, as Markdown or standalone HTML (Design.md section 5).

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
from reprotrace.report.document import (
    Block,
    Bullets,
    Code,
    CodeBlock,
    Heading,
    Inlines,
    Item,
    Paragraph,
    Quote,
    Rule,
    Severity,
    Strong,
    Table,
    Text,
    t,
    to_html,
    to_markdown,
)
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


def exit_text(run: Run) -> str:
    """How a run ended, in words."""
    if run.timed_out:
        return "timed out"
    if run.exit_code is not None and run.exit_code < 0:
        return f"killed by signal {-run.exit_code}"
    return f"exit {run.exit_code}"


def _evidence_block(d: Divergence, labels: tuple[str, str], events: dict[str, Event]) -> CodeBlock:
    lines = []
    for label, ids in ((labels[0], d.a_event_ids), (labels[1], d.b_event_ids)):
        for event_id in ids[:2]:
            lines.append(f"{label}  {event_id}")
            event = events.get(event_id)
            text = sanitize_raw(event) if event else "(event not found in events.jsonl)"
            lines += [f"  {line}" for line in text.splitlines()]
        if len(ids) > 2:
            lines.append(f"{label}  ... {len(ids) - 2} more: {', '.join(ids[2:6])}")
    return CodeBlock(lines)


def ungrounded_citations(explanation: Explanation, ranked: list[Divergence]) -> list[str]:
    """Citations of a stored explanation that do not resolve in this comparison."""
    by_id = {d.id: set(d.a_event_ids) | set(d.b_event_ids) for d in ranked}
    bad: list[str] = []
    for hypothesis in explanation.hypotheses:
        bad += [d for d in hypothesis.divergence_ids if d not in by_id]
        allowed = set().union(*(by_id.get(d, set()) for d in hypothesis.divergence_ids))
        bad += [e for e in hypothesis.event_ids if e not in allowed]
    return bad


def _ai_section(explanation: Explanation, ranked: list[Divergence]) -> list[Block]:
    rank_of = {d.id: (rank, d) for rank, d in enumerate(ranked, start=1)}
    stamp = explanation.generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    out: list[Block] = [Heading(2, t("AI explanation"))]
    out.append(Quote([
        Strong("AI-generated hypotheses"), Text(f" ({explanation.provider}, model "),
        Code(explanation.model),
        Text(f", {stamp}). They were produced from the ranked evidence above only, every "
             "citation was checked to exist, but the reasoning can still be wrong. Treat them "
             "as leads to verify, not as findings."),
    ]))  # fmt: skip
    out.append(Paragraph(t(explanation.summary)))
    if explanation.insufficient_evidence:
        out.append(
            Paragraph(t("The model judged the evidence insufficient to explain the failure."))
        )
    for number, h in enumerate(explanation.hypotheses, start=1):
        out.append(Heading(3, t(f"Hypothesis {number}: {h.title} ({h.confidence} confidence)")))
        out.append(Paragraph(t(h.explanation)))
        cited: Inlines = [Strong("Divergences cited:"), Text(" ")]
        for index, d_id in enumerate(h.divergence_ids):
            rank, d = rank_of[d_id]
            if index:
                cited.append(Text("; "))
            cited += [Code(d_id), Text(f" (rank {rank}: {d.summary})")]
        events: Inlines = [Strong("Events cited:"), Text(" ")]
        for index, event_id in enumerate(h.event_ids):
            events += [Text(", ")] if index else []
            events.append(Code(event_id))
        out.append(Bullets([
            Item(cited), Item(events),
            Item([Strong("Next experiment:"), Text(f" {h.next_experiment}")]),
        ]))  # fmt: skip
    return out


def build_report(
    stored: StoredComparison,
    a_runs: list[Run],
    b_runs: list[Run],
    events: dict[str, Event],
    generated_at: datetime,
    rank_config: RankConfig | None = None,
    explanation: Explanation | None = None,
    ai_note: str | None = None,
) -> list[Block]:
    """The report as format-neutral blocks. Pure: no file or database access.

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

    out: list[Block] = [Heading(1, t(f"ReproTrace Report: {stored.id}"))]
    notice: Inlines = [
        Strong("Before sharing:"),
        Text(" this report contains paths and command lines from the traced runs. Raw traces in "),
        Code(".reprotrace/runs/"),
        Text(" contain the full, unredacted environment of the traced command; review them "
             "before attaching them anywhere."),
    ]  # fmt: skip
    if any_redacted:
        notice += [Text(" Values that look like secrets are shown as "), Code(REDACTED),
                   Text(" in this report.")]  # fmt: skip
    out.append(Quote(notice))

    summary = [
        Item([Strong("Command:"), Text(" "), Code(shlex.join(a_run.command))]),
        Item([
            Strong("Environments compared:"), Text(" "), Code(a_label),
            Text(f" ({len(a_runs)} run(s), "), Code(stored.ref_a), Text(") vs "), Code(b_label),
            Text(f" ({len(b_runs)} run(s), "), Code(stored.ref_b), Text(")"),
        ]),
        Item([Strong("Exit codes:"),
              Text(f" {a_label} {exit_text(a_run)}, {b_label} {exit_text(b_run)}")]),
        Item([Strong("Divergences:"),
              Text(f" {len(ranked)} ({severities['CRITICAL']} critical, "
                   f"{severities['WARNING']} warning, {severities['INFO']} info)")]),
    ]  # fmt: skip
    if ranked:
        top = ranked[0]
        summary.append(Item([
            Strong("Likely cause:"),
            Text(f" {top.summary} (score {top.score:.2f}). This is the highest-ranked "
                 "divergence; the ranking is a heuristic, not proof."),
        ]))  # fmt: skip
    else:
        summary.append(Item([Strong("Result:"), Text(" No clear difference found.")]))
    out += [Heading(2, t("Summary")), Bullets(summary)]

    if ranked:
        out.append(Heading(2, t("Top divergences")))
        for rank, d in enumerate(ranked[:TOP_DETAILED], start=1):
            out.append(Heading(3, t(f"{rank}. {d.summary}")))
            out.append(Paragraph([
                Severity(severity(d, rank_config)), Text(f", score {d.score:.2f}, "),
                Code(d.kind), Text(", id "), Code(d.id),
            ]))  # fmt: skip
            out.append(Bullets([
                Item([Strong("What differed:"), Text(f" {_kind_text(d.kind, a_label, b_label)}")]),
                Item([
                    Strong("Evidence:"), Text(" "), Code(a_label),
                    Text(f" {', '.join(d.a_event_ids[:3]) or '-'}; "), Code(b_label),
                    Text(f" {', '.join(d.b_event_ids[:3]) or '-'}"),
                ]),
            ]))  # fmt: skip
            out.append(_evidence_block(d, (a_label, b_label), events))
            out.append(Bullets([Item([Strong("Why it ranked here:")], [t(r) for r in d.reasons])]))

        rest = ranked[TOP_DETAILED:]
        if rest:
            out.append(Heading(2, t("Other divergences")))
            rows = [
                [t(str(rank)), t(f"{d.score:.2f}"), [Severity(severity(d, rank_config))],
                 [Code(d.kind)], t(d.summary)]
                for rank, d in enumerate(rest[:MAX_TABLE_ROWS], start=TOP_DETAILED + 1)
            ]  # fmt: skip
            header = [t("Rank"), t("Score"), t("Severity"), t("Kind"), t("Summary")]
            out.append(Table(header, rows))
            if len(rest) > MAX_TABLE_ROWS:
                out.append(Paragraph([
                    Text(f"{len(rest) - MAX_TABLE_ROWS} more not shown. List them with "),
                    Code(f"reprotrace diff {stored.ref_a} {stored.ref_b} --all"), Text("."),
                ]))  # fmt: skip

    out += [Heading(2, t("How to reproduce")),
            Paragraph(t("Capture each environment again, then compare:"))]  # fmt: skip
    commands = []
    for label, runs in ((a_label, a_runs), (b_label, b_runs)):
        command = shlex.join(runs[0].command)
        flag = shlex.quote(runs[0].label)
        commands.append(f"# in the {label} environment")
        commands.append(f"reprotrace capture --label {flag} --runs {len(runs)} -- {command}")
    commands += ["# then, with both run folders in one project", "reprotrace diff GRP_A GRP_B"]
    out.append(CodeBlock(commands))
    out.append(Paragraph([Text("Original groups: "), Code(stored.ref_a), Text(" and "),
                          Code(stored.ref_b), Text(".")]))  # fmt: skip

    out.append(Heading(2, t("Environment differences")))
    if details["env_rows"]:
        header = [t("Variable"), t(a_label), t(b_label)]
        out.append(Table(header, [[[Code(k)], t(a), t(b)] for k, a, b in details["env_rows"]]))
        out.append(Paragraph([
            Text("Values are normalized (home folder as "), Code("~"),
            Text(", working directory as "), Code("<cwd>"), Text(") and secrets are redacted."),
        ]))  # fmt: skip
    else:
        out.append(Paragraph([
            Text("No differences in the environment passed to the command (shell bookkeeping "
                 "variables such as "), Code("PWD"), Text(" and "), Code("SHLVL"),
            Text(" are ignored)."),
        ]))  # fmt: skip

    if explanation is not None:
        bad = ungrounded_citations(explanation, ranked)
        if bad:
            ai_note = (
                "AI explanation left out: it cites ids not in this comparison "
                f"({', '.join(bad[:3])})."
            )
        else:
            out += _ai_section(explanation, ranked)

    limitations = [
        Item(t("Ranking is a heuristic. A high score means the divergence is consistent with "
               "the failure, not that it is proven to cause it.")),
        Item(t("Tracing with strace slows the command down and can hide timing-dependent bugs.")),
        Item([Text("strace cannot see which environment variables a program reads ("),
              Code("getenv()"), Text("); environment differences compare everything passed to "
              "the command.")]),
        Item(t("Run-to-run noise is filtered only for sides captured with two or more runs.")),
        Item([Text("Evidence ids refer to the first run of each side; excerpts are shortened and "
                   "sanitized. Full lines are in "), Code("events.jsonl"), Text(" and "),
              Code("raw.strace"), Text(" of those runs.")]),
    ]  # fmt: skip
    limitations += [Item(t(note)) for note in details.get("notes", [])]
    if ai_note:
        limitations.append(Item(t(ai_note)))
    out += [Heading(2, t("Limitations")), Bullets(limitations), Rule()]
    out.append(Paragraph(t(
        f"Generated {generated_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M UTC')} by "
        f"reprotrace {__version__}. Comparison created "
        f"{stored.created_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M UTC')}."
    ), muted=True))  # fmt: skip
    return out


def render_report(*args, **kwargs) -> str:
    """The report as Markdown (same arguments as ``build_report``)."""
    return to_markdown(build_report(*args, **kwargs))


def render_report_html(*args, **kwargs) -> str:
    """The report as one self-contained HTML page (same arguments as ``build_report``)."""
    blocks = build_report(*args, **kwargs)
    return to_html(blocks, title=f"ReproTrace Report: {args[0].id}")


def run_events(base_dir: Path, run_id: str) -> list[Event]:
    """Events of a saved run (parsed now if events.jsonl is missing)."""
    path = config.run_dir(base_dir, run_id) / config.EVENTS_FILE
    if path.is_file():
        return read_events(path)
    return parse_run(base_dir, run_id).events


def write_report(
    base_dir: Path, comparison_id: str | None, out: Path | None = None, html: bool = False
) -> Path:
    """Write the report of a saved comparison (default: the latest) and return its path.

    Markdown by default; ``html=True`` writes one self-contained HTML page with the same content.
    """
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
    render = render_report_html if html else render_report
    text = render(
        stored, a_runs, b_runs, events, datetime.now(UTC), rank_config, explanation, ai_note
    )
    suffix = ".html" if html else ".md"
    target = out if out is not None else config.report_path(base_dir, comparison_id, suffix)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    with connect(base_dir) as conn:
        set_report_path(conn, comparison_id, str(target))
    return target
