"""Phase 5: ranking on the real sample pairs (known causes) and ranking invariants."""

import pytest

from conftest import TRACES, fixture_lines
from reprotrace.diff.compare import Comparison, Side, compare_sides
from reprotrace.diff.rank import category_value, rank_divergences, severity
from reprotrace.models import Divergence, RankConfig
from reprotrace.parse.strace_parser import parse_lines

# (good group, bad group, text identifying the known cause, its expected kind)
SAMPLE_PAIRS = [
    ("pair_good", "pair_bad", "<cwd>/settings.toml", "result_mismatch"),
    ("pair_env_good", "pair_env_bad", "APP_MODE", "env_diff"),
]


def side(label: str, prefix: str) -> Side:
    names = sorted(p.stem for p in TRACES.glob(f"{prefix}_[0-9]*.strace"))
    assert len(names) >= 2, f"capture with: bash testdata/capture_fixtures.sh {prefix}"
    return Side(label, [parse_lines(fixture_lines(n), n)[0] for n in names])


def single(label: str, name: str) -> Side:
    return Side(label, [parse_lines(fixture_lines(name), name)[0]])


def compared(good: str, bad: str) -> Comparison:
    return compare_sides(side("good", good), side("bad", bad))


def position(ranked: list[Divergence], text: str) -> int:
    return next(i for i, d in enumerate(ranked, start=1) if text in d.summary)


# --- exit check ------------------------------------------------------------------------


@pytest.mark.parametrize(("good", "bad", "cause", "kind"), SAMPLE_PAIRS)
def test_known_cause_ranks_in_top_three(good: str, bad: str, cause: str, kind: str) -> None:
    ranked = rank_divergences(compared(good, bad))
    rank = position(ranked, cause)
    assert rank <= 3, [(d.summary, d.score) for d in ranked[:5]]
    assert ranked[rank - 1].kind == kind


@pytest.mark.parametrize(("good", "bad", "cause", "kind"), SAMPLE_PAIRS)
def test_every_score_has_readable_reasons(good: str, bad: str, cause: str, kind: str) -> None:
    ranked = rank_divergences(compared(good, bad))
    for d in ranked:
        assert d.reasons, d.id
        assert all(isinstance(r, str) and len(r) > 10 for r in d.reasons)
        assert 0.0 <= d.score <= 1.0
    assert [d.score for d in ranked] == sorted((d.score for d in ranked), reverse=True)


def test_missing_file_cause_reasons() -> None:
    ranked = rank_divergences(compared("pair_good", "pair_bad"))
    top = ranked[0]
    assert "settings.toml" in top.summary
    assert severity(top) == "CRITICAL"
    assert "failed on bad (ENOENT) but succeeded on good" in top.reasons


# --- individual signals ----------------------------------------------------------------


def test_exit_status_is_treated_as_the_symptom() -> None:
    ranked = rank_divergences(compared("pair_good", "pair_bad"))
    exit_d = next(d for d in ranked if d.kind == "exit_status_mismatch")
    assert "the exit status is the symptom being explained, not a cause" in exit_d.reasons
    assert position(ranked, "ended differently") > 3


def test_benign_errno_is_not_a_failure() -> None:
    ranked = rank_divergences(compared("pair_good", "pair_bad"))
    enotty = [d for d in ranked if "(ENOTTY)" in d.summary]
    for d in enotty:
        assert not any(r.startswith("failing call") for r in d.reasons)


def test_events_after_runs_stop_matching_are_consequences() -> None:
    ranked = rank_divergences(compared("pair_good", "pair_bad"))
    after = [d for d in ranked if any("likely a consequence" in r for r in d.reasons)]
    for d in after:
        assert d.score < ranked[0].score


def test_env_difference_has_no_exit_distance() -> None:
    ranked = rank_divergences(compared("pair_env_good", "pair_env_bad"))
    env = next(d for d in ranked if d.kind == "env_diff")
    assert not any("before the failing exit" in r for r in env.reasons)
    assert any(r.startswith("1st of") for r in env.reasons)


def test_no_failing_side_means_no_failure_signals() -> None:
    cmp = compare_sides(
        single("local", "local_python_missing_file"), single("docker", "docker_python_missing_file")
    )
    assert cmp.failing_side is None  # both exit 1
    for d in rank_divergences(cmp):
        assert not any("failing exit" in r or "consequence" in r for r in d.reasons)
        assert any("single run on local and docker" in r for r in d.reasons)


def test_weights_come_from_config() -> None:
    cmp = compared("pair_good", "pair_bad")
    only_category = RankConfig(weights={"category": 1.0})
    for d in rank_divergences(cmp, only_category):
        assert d.score == pytest.approx(category_value(d.kind, only_category), abs=1e-3)
    assert category_value("file_only_in_b", only_category) == 0.5
    assert category_value("unknown_kind", only_category) == only_category.default_category_weight


def test_ranking_is_deterministic_and_keeps_ids() -> None:
    cmp = compared("pair_good", "pair_bad")
    first, second = rank_divergences(cmp), rank_divergences(cmp)
    assert first == second
    assert sorted(d.id for d in first) == sorted(d.id for d in cmp.divergences)
    assert all(d.score == 0.0 for d in cmp.divergences)  # input left unscored


def _scored(score: float) -> Divergence:
    return Divergence(id="d1", kind="k", summary="s", a_event_ids=[], b_event_ids=[], score=score)


def test_severity_thresholds() -> None:
    config = RankConfig()
    assert severity(_scored(config.critical_threshold), config) == "CRITICAL"
    assert severity(_scored(config.warning_threshold), config) == "WARNING"
    assert severity(_scored(0.1), config) == "INFO"
