"""Compare two environments, each given as one or more parsed runs of the same command."""

from dataclasses import dataclass, field
from pathlib import Path

from reprotrace.capture.redact import REDACTED, is_secret_key, looks_like_token, redact_value
from reprotrace.diff.align import align_events
from reprotrace.diff.divergences import (
    Finding,
    Labels,
    divergences_for_process,
    exit_text,
    first_ids,
)
from reprotrace.diff.processes import (
    ProcessNode,
    build_process_tree,
    match_processes,
    subtree_size,
)
from reprotrace.models import DiffConfig, Divergence, Event, NormalizationConfig, Run
from reprotrace.normalize.noise import build_noise_profile
from reprotrace.normalize.rules import Normalizer, derive_context
from reprotrace.parse.run import parse_run
from reprotrace.parse.syscalls import EXIT_SYSCALL, execve_env
from reprotrace.store.run_files import resolve_runs

ROOT = "p0"


@dataclass
class Side:
    """One environment: a display label and its parsed runs (first = representative)."""

    label: str
    runs: list[list[Event]]


@dataclass
class _PreparedSide:
    label: str
    run_count: int
    events: list[Event]  # normalized events of the representative run
    normalizer: Normalizer
    env: dict[str, str]  # normalized environment of the root process
    unstable_env: set[str]
    unstable: set[str]


@dataclass
class Evidence:
    """The events behind one divergence, kept for ranking (not stored)."""

    a_events: list[Event]
    b_events: list[Event]
    pair_index: int  # index into the matched process pairs; -1 = environment, >= pairs = process


@dataclass
class Comparison:
    """Result of comparing two sides.

    ``failing_side`` is ``"a"`` or ``"b"`` when exactly one side's command failed (non-zero
    exit, killed, or no recorded exit). ``exit_seq`` is the seq of the root process's last
    event on each side. ``last_matched_seq[(pair_index, side)]`` is the seq of the last event
    that aligned in that process; one-sided events after it form the "failure tail".
    """

    a_label: str
    b_label: str
    a_run_count: int
    b_run_count: int
    divergences: list[Divergence]
    matched_processes: int = 0
    unmatched_processes: int = 0
    reordered_events: int = 0
    ignored_unstable: int = 0
    notes: list[str] = field(default_factory=list)
    evidence: dict[str, Evidence] = field(default_factory=dict)
    process_pairs: list[tuple[str, str]] = field(default_factory=list)
    failing_side: str | None = None
    exit_seq: dict[str, int] = field(default_factory=dict)
    last_matched_seq: dict[tuple[int, str], int] = field(default_factory=dict)
    env_rows: list[tuple[str, str, str]] = field(default_factory=list)


def _root_env_event(events: list[Event]) -> Event | None:
    for event in events:
        if event.proc == ROOT and event.kind == "exec" and event.result == "0":
            return event
    return None


def _normalized_env(events: list[Event], normalizer: Normalizer) -> dict[str, str]:
    event = _root_env_event(events)
    if event is None:
        return {}
    return {key: normalizer.text(value) for key, value in execve_env(event.args).items()}


def _prepare(side: Side, norm_config: NormalizationConfig) -> _PreparedSide:
    if not side.runs:
        raise ValueError(f"side {side.label!r} has no runs")
    normalized_runs: list[list[Event]] = []
    envs: list[dict[str, str]] = []
    normalizer: Normalizer | None = None
    for run in side.runs:
        run_normalizer = Normalizer(norm_config, derive_context(run))
        normalizer = normalizer or run_normalizer
        normalized_runs.append([run_normalizer.event(e) for e in run])
        envs.append(_normalized_env(run, run_normalizer))
    assert normalizer is not None
    keys = set().union(*envs)
    unstable_env = {k for k in keys if len({env.get(k) for env in envs}) > 1}
    profile = build_noise_profile(normalized_runs)
    return _PreparedSide(
        label=side.label,
        run_count=len(side.runs),
        events=normalized_runs[0],
        normalizer=normalizer,
        env=envs[0],
        unstable_env=unstable_env,
        unstable=set(profile.unstable),
    )


def _display_env_value(key: str, value: str | None) -> str:
    if value is None:
        return "(not set)"
    if is_secret_key(key) or looks_like_token(value):
        return REDACTED
    return redact_value(value)


def _env_findings(
    a: _PreparedSide, b: _PreparedSide, config: DiffConfig, labels: Labels
) -> list[Finding]:
    a_event = _root_env_event(a.events)
    b_event = _root_env_event(b.events)
    if a_event is None or b_event is None:
        return []
    ignored = set(config.ignored_env_vars) | a.unstable_env | b.unstable_env
    findings: list[Finding] = []
    for key in sorted(set(a.env) | set(b.env)):
        if key in ignored or a.env.get(key) == b.env.get(key):
            continue
        a_value = _display_env_value(key, a.env.get(key))
        b_value = _display_env_value(key, b.env.get(key))
        if a_value == b_value:
            summary = f"Environment variable {key} differs (values redacted)"
        else:
            summary = (
                f"Environment variable {key}: {a_value} on {labels.a}, {b_value} on {labels.b}"
            )
        findings.append(Finding("env_diff", summary, (-1, 0, len(findings)), [a_event], [b_event]))
    return findings


def _env_rows(
    findings: list[Finding], a: _PreparedSide, b: _PreparedSide
) -> list[tuple[str, str, str]]:
    """(variable, display value on a, display value on b) for each env_diff finding."""
    rows = []
    for finding in findings:
        key = finding.summary.removeprefix("Environment variable ").split(":", 1)[0]
        key = key.removesuffix(" differs (values redacted)")
        rows.append(
            (key, _display_env_value(key, a.env.get(key)), _display_env_value(key, b.env.get(key)))
        )
    return rows


def _describe_process(node: ProcessNode, size: int) -> str:
    program = node.program or "no exec"
    extra = f" and {size - 1} child process(es)" if size > 1 else ""
    return f"process {node.label} ({program}, {exit_text(node.exit_event)}){extra}"


def _process_findings(
    labels_only: list[str], tree: dict[str, ProcessNode], side: str, label: str, start: int
) -> list[Finding]:
    findings = []
    for offset, proc in enumerate(labels_only):
        node = tree[proc]
        first = node.exec_events[:1] or node.events[:1]
        summary = f"Extra {_describe_process(node, subtree_size(tree, proc))} only on {label}"
        a_events = first if side == "a" else []
        b_events = first if side == "b" else []
        position = (start + offset, 0 if side == "a" else 1, first[0].seq if first else 0)
        findings.append(Finding(f"process_only_in_{side}", summary, position, a_events, b_events))
    return findings


def _root_failed(tree: dict[str, ProcessNode]) -> bool:
    root = tree.get(ROOT)
    end = root.exit_event if root else None
    return end is None or end.syscall != EXIT_SYSCALL or end.result != "0"


def _root_exit_seq(tree: dict[str, ProcessNode]) -> int:
    root = tree.get(ROOT)
    return root.events[-1].seq if root and root.events else 0


def compare_sides(
    a: Side,
    b: Side,
    norm_config: NormalizationConfig | None = None,
    diff_config: DiffConfig | None = None,
) -> Comparison:
    """Compare two environments and return unscored divergences in trace order.

    Event ids in the divergences refer to the first run of each side.
    """
    norm_config = norm_config or NormalizationConfig()
    diff_config = diff_config or DiffConfig()
    labels = Labels(a.label, b.label)
    pa, pb = _prepare(a, norm_config), _prepare(b, norm_config)
    unstable = pa.unstable | pb.unstable

    def signed(events: list[Event]) -> list[Event]:
        return [e for e in events if e.signature is not None and e.signature not in unstable]

    a_tree, b_tree = build_process_tree(pa.events), build_process_tree(pb.events)
    match = match_processes(a_tree, b_tree)

    findings = _env_findings(pa, pb, diff_config, labels)
    env_rows = _env_rows(findings, pa, pb)
    reordered = 0
    last_matched: dict[tuple[int, str], int] = {}
    for index, (a_proc, b_proc) in enumerate(match.pairs):
        a_signed, b_signed = signed(a_tree[a_proc].events), signed(b_tree[b_proc].events)
        alignment = align_events(a_proc, b_proc, a_signed, b_signed)
        process_findings, moved = divergences_for_process(alignment, index, labels)
        findings.extend(process_findings)
        reordered += moved
        for side, events, only in (("a", a_signed, alignment.a_only),
                                   ("b", b_signed, alignment.b_only)):  # fmt: skip
            unmatched = {e.seq for e in only}
            matched = [e.seq for e in events if e.seq not in unmatched]
            last_matched[(index, side)] = max(matched, default=-1)
    tail = len(match.pairs)
    findings += _process_findings(match.only_a, a_tree, "a", a.label, tail)
    findings += _process_findings(match.only_b, b_tree, "b", b.label, tail + len(match.only_a))

    findings.sort(key=lambda f: f.position)
    divergences: list[Divergence] = []
    evidence: dict[str, Evidence] = {}
    for number, f in enumerate(findings, start=1):
        divergence = Divergence(
            id=f"d{number}",
            kind=f.kind,
            summary=f.summary,
            a_event_ids=first_ids(f.a_events),
            b_event_ids=first_ids(f.b_events),
        )
        divergences.append(divergence)
        evidence[divergence.id] = Evidence(f.a_events, f.b_events, f.position[0])
    a_failed, b_failed = _root_failed(a_tree), _root_failed(b_tree)
    comparison = Comparison(
        a_label=a.label,
        b_label=b.label,
        a_run_count=pa.run_count,
        b_run_count=pb.run_count,
        divergences=divergences,
        matched_processes=len(match.pairs),
        unmatched_processes=len(match.only_a) + len(match.only_b),
        reordered_events=reordered,
        ignored_unstable=len(unstable),
        evidence=evidence,
        process_pairs=list(match.pairs),
        failing_side="a"
        if a_failed and not b_failed
        else "b"
        if b_failed and not a_failed
        else None,
        exit_seq={"a": _root_exit_seq(a_tree), "b": _root_exit_seq(b_tree)},
        last_matched_seq=last_matched,
        env_rows=env_rows,
    )
    for side in (pa, pb):
        if side.run_count == 1:
            comparison.notes.append(
                f"{side.label} has 1 run, so run-to-run noise could not be filtered there "
                "(capture with --runs 2 or more)."
            )
    return comparison


@dataclass
class SavedComparison:
    """A comparison of saved runs together with the runs it used."""

    comparison: Comparison
    a_runs: list[Run]
    b_runs: list[Run]
    ref_a: str = ""
    ref_b: str = ""


def compare_saved(
    base_dir: Path,
    ref_a: str,
    ref_b: str,
    norm_config: NormalizationConfig | None = None,
    diff_config: DiffConfig | None = None,
) -> SavedComparison:
    """Compare two saved runs or capture groups (ids from ``reprotrace capture``)."""
    a_runs, b_runs = resolve_runs(base_dir, ref_a), resolve_runs(base_dir, ref_b)
    a_side = Side(a_runs[0].label, [parse_run(base_dir, r.id).events for r in a_runs])
    b_side = Side(b_runs[0].label, [parse_run(base_dir, r.id).events for r in b_runs])
    if a_side.label == b_side.label:
        a_side.label, b_side.label = f"{a_side.label} (A)", f"{b_side.label} (B)"
    comparison = compare_sides(a_side, b_side, norm_config, diff_config)
    if a_runs[0].command != b_runs[0].command:
        comparison.notes.append("The two sides ran different commands; expect many differences.")
    return SavedComparison(comparison, a_runs, b_runs, ref_a, ref_b)
