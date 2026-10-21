"""Phase 4: process tree, matching, alignment and divergences on real fixtures."""

import random

import pytest

from conftest import TRACES, fixture_lines
from reprotrace.diff import align
from reprotrace.diff.align import align_signatures
from reprotrace.diff.compare import Side, _display_env_value, compare_sides
from reprotrace.diff.processes import build_process_tree, match_processes
from reprotrace.models import Divergence, Event
from reprotrace.normalize.rules import normalize_events
from reprotrace.parse.strace_parser import parse_lines


def parsed(name: str) -> list[Event]:
    return parse_lines(fixture_lines(name), name)[0]


def group(prefix: str) -> list[str]:
    names = sorted(p.stem for p in TRACES.glob(f"{prefix}_*.strace"))
    assert len(names) >= 2, f"capture with: bash testdata/capture_fixtures.sh {prefix}"
    return names


def side(label: str, names: list[str]) -> Side:
    return Side(label, [parsed(n) for n in names])


def by_id(names: list[str]) -> dict[str, Event]:
    return {e.id: e for n in names for e in parsed(n)}


def find(divergences: list[Divergence], kind: str, text: str = "") -> Divergence:
    return next(d for d in divergences if d.kind == kind and text in d.summary)


# --- process tree and matching ---------------------------------------------------------


def test_process_tree_of_multiprocess_fixture() -> None:
    tree = build_process_tree(normalize_events(parsed("local_multiprocess")))
    assert list(tree) == ["p0", "p0.1", "p0.2"]
    assert tree["p0"].children == ["p0.1", "p0.2"]
    assert [tree[p].key for p in tree] == ["sh", "ls", "cat"]
    assert tree["p0.1"].exit_event.result == "2"
    assert tree["p0.1"].parent == "p0"


def test_processes_match_by_exec_chain_not_pid() -> None:
    a = build_process_tree(normalize_events(parsed("local_multiprocess")))
    b = build_process_tree(normalize_events(parsed("repeat_multiprocess_1")))
    match = match_processes(a, b)
    assert match.pairs == [("p0", "p0"), ("p0.1", "p0.1"), ("p0.2", "p0.2")]
    assert match.only_a == match.only_b == []


def test_unmatched_children_are_reported() -> None:
    a = build_process_tree(normalize_events(parsed("local_multiprocess")))
    b = build_process_tree(normalize_events(parsed("local_python_missing_file")))
    match = match_processes(a, b)
    assert match.pairs == [("p0", "p0")]
    assert match.only_a == ["p0.1", "p0.2"]


# --- alignment ------------------------------------------------------------------------


def test_alignment_accounts_for_every_element() -> None:
    rng = random.Random(7)
    for _ in range(300):
        a = [rng.choice("abcdef") for _ in range(rng.randint(0, 60))]
        b = [rng.choice("abcdef") for _ in range(rng.randint(0, 60))]
        result = align_signatures(a, b)
        assert result.matched + len(result.a_only) == len(a)
        assert result.matched + len(result.b_only) == len(b)
        kept_a = [x for i, x in enumerate(a) if i not in set(result.a_only)]
        kept_b = [x for j, x in enumerate(b) if j not in set(result.b_only)]
        assert kept_a == kept_b  # exact path: matched elements form a common subsequence


def test_alignment_of_identical_runs_is_complete() -> None:
    sigs = [e.signature for e in normalize_events(parsed("local_multiprocess")) if e.signature]
    result = align_signatures(sigs, list(sigs))
    assert result.matched == len(sigs)
    assert result.a_only == result.b_only == []


def test_large_gaps_fall_back_to_counting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(align, "MAX_EXACT_GAP", 4)
    a = list("xaybzc") * 3
    b = list("zcxayb") * 3
    result = align_signatures(a, b)
    assert result.approximate_gaps >= 1
    assert result.matched + len(result.a_only) == len(a)
    assert result.matched + len(result.b_only) == len(b)


# --- exit check: known-difference pair -------------------------------------------------


@pytest.fixture(scope="module")
def pair() -> tuple[list[str], list[str], list[Divergence]]:
    good, bad = group("pair_good"), group("pair_bad")
    comparison = compare_sides(side("good", good), side("bad", bad))
    return good, bad, comparison.divergences


def test_missing_file_divergence_has_correct_event_ids(pair) -> None:
    good, bad, divergences = pair
    d = find(divergences, "result_mismatch", "settings.toml")
    assert d.summary == "openat <cwd>/settings.toml: OK on good, ENOENT on bad"
    a_events, b_events = by_id(good[:1]), by_id(bad[:1])
    (a_id,), (b_id,) = d.a_event_ids, d.b_event_ids
    assert a_id.startswith(f"{good[0]}:") and b_id.startswith(f"{bad[0]}:")
    assert a_events[a_id].syscall == b_events[b_id].syscall == "openat"
    assert '"settings.toml"' in a_events[a_id].raw and a_events[a_id].errno is None
    assert '"settings.toml"' in b_events[b_id].raw and b_events[b_id].errno == "ENOENT"


def test_timezone_env_difference(pair) -> None:
    good, bad, divergences = pair
    d = find(divergences, "env_diff", "TZ")
    assert d.summary == "Environment variable TZ: UTC on good, Asia/Kolkata on bad"
    assert by_id(good[:1])[d.a_event_ids[0]].syscall == "execve"
    assert by_id(bad[:1])[d.b_event_ids[0]].syscall == "execve"
    assert [x.kind for x in divergences].count("env_diff") == 1


def test_timezone_file_differences(pair) -> None:
    _, _, divergences = pair
    assert find(divergences, "file_only_in_a", "/usr/share/zoneinfo/UTC")
    assert find(divergences, "file_only_in_b", "/usr/share/zoneinfo/Asia/Kolkata")


def test_exit_status_difference(pair) -> None:
    good, bad, divergences = pair
    d = find(divergences, "exit_status_mismatch")
    assert d.summary == "Process p0 ended differently: exit 0 on good, exit 1 on bad"
    a_events, b_events = by_id(good[:1]), by_id(bad[:1])
    assert {a_events[i].syscall for i in d.a_event_ids} == {"exit_group", "<exited>"}
    assert {b_events[i].syscall for i in d.b_event_ids} == {"exit_group", "<exited>"}


def test_divergence_ids_and_evidence_are_well_formed(pair) -> None:
    good, bad, divergences = pair
    assert [d.id for d in divergences] == [f"d{i}" for i in range(1, len(divergences) + 1)]
    a_events, b_events = by_id(good[:1]), by_id(bad[:1])
    for d in divergences:
        assert d.a_event_ids or d.b_event_ids
        assert all(i in a_events for i in d.a_event_ids)
        assert all(i in b_events for i in d.b_event_ids)
        assert d.score == 0.0 and d.reasons == []


def test_comparison_is_deterministic() -> None:
    good, bad = group("pair_good"), group("pair_bad")
    first = compare_sides(side("good", good), side("bad", bad)).divergences
    second = compare_sides(side("good", good), side("bad", bad)).divergences
    assert first == second


# --- other comparisons -----------------------------------------------------------------


def test_same_environment_has_no_divergences() -> None:
    runs = group("repeat_multiprocess")
    comparison = compare_sides(side("a", runs[:2]), side("b", runs[2:]))
    assert comparison.divergences == []
    assert comparison.matched_processes == 3


def test_local_vs_docker() -> None:
    comparison = compare_sides(
        side("local", ["local_python_missing_file"]), side("docker", ["docker_python_missing_file"])
    )
    d = find(comparison.divergences, "executable_mismatch")
    assert d.summary.endswith("/usr/local/bin/python3 on docker")
    path = find(comparison.divergences, "env_diff", "PATH")
    assert "/usr/local/bin" in path.summary
    # The missing file is missing on both sides, so it is not a divergence.
    assert not any("/nonexistent/config.toml" in x.summary for x in comparison.divergences)
    assert len(comparison.notes) == 2  # single run on each side


def test_different_commands_report_extra_processes() -> None:
    comparison = compare_sides(
        side("sh", ["local_multiprocess"]), side("py", ["local_python_missing_file"])
    )
    extra = [d for d in comparison.divergences if d.kind == "process_only_in_a"]
    assert [d.summary.split(" (")[0] for d in extra] == [
        "Extra process p0.1",
        "Extra process p0.2",
    ]
    assert find(comparison.divergences, "executable_mismatch")


def test_env_values_are_redacted_for_display() -> None:
    assert _display_env_value("API_TOKEN", "abc") == "<redacted>"
    assert _display_env_value("SOME", "ghp_" + "a1" * 18) == "<redacted>"
    assert _display_env_value("TZ", None) == "(not set)"
    assert _display_env_value("TZ", "UTC") == "UTC"


def test_empty_side_is_rejected() -> None:
    with pytest.raises(ValueError):
        compare_sides(Side("a", []), side("b", ["local_timeout"]))


def test_child_that_never_execs_pairs_with_its_counterpart() -> None:
    """path_binary: on bad every exec of `greet` fails, so the child has no program name."""
    a = build_process_tree(normalize_events(parsed("eval_path_binary_good_1")))
    b = build_process_tree(normalize_events(parsed("eval_path_binary_bad_1")))
    failed = [label for label, node in b.items() if node.parent and node.key == ""]
    assert failed, "the bad side should have a child whose exec never succeeded"
    match = match_processes(a, b)
    assert not match.only_a and not match.only_b
    assert any(b_label in failed and a[a_label].key == "greet" for a_label, b_label in match.pairs)
