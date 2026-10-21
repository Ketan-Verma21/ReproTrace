"""Phase 5: ranking on the real sample pairs (known causes) and ranking invariants."""

import pytest

from conftest import TRACES, fixture_lines
from reprotrace.diff.compare import Comparison, Evidence, Side, compare_sides
from reprotrace.diff.rank import _category, category_value, rank_divergences, severity
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
    assert "set before the program started" in env.reasons
    assert "APP_MODE is missing on the failing side bad (weight 0.8)" in env.reasons


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


def test_env_grading_on_the_failing_side() -> None:
    cmp = compared("pair_env_good", "pair_env_bad")
    ev = next(cmp.evidence[d.id] for d in cmp.divergences if cmp.evidence[d.id].env_key)
    assert ev.env_key == "APP_MODE" and ev.env_values == ("prod", None)

    def grade(values: tuple[str | None, str | None], key: str = "APP_MODE") -> tuple[float, str]:
        d = Divergence(id="d1", kind="env_diff", summary="s", a_event_ids=[], b_event_ids=[])
        evidence = Evidence([], [], -1, key, values)
        fake = Comparison("good", "bad", 2, 2, [d], evidence={"d1": evidence}, failing_side="b")
        return _category(d, evidence, fake, RankConfig())

    assert grade(("prod", None))[0] == 0.8  # missing on the failing side
    assert grade(("a", "b"))[0] == 0.8  # different values
    value, reason = grade((None, "x"))  # set only on the failing side
    assert value == 0.3 and "set only on the failing side bad" in reason
    assert grade((None, "x"), key="GITHUB_SHA")[0] == 0.1


def test_platform_variables_are_weak() -> None:
    config = RankConfig()
    from reprotrace.diff.rank import _is_platform_var

    for name in ("GITHUB_SHA", "RUNNER_OS", "ACTIONS_ORCHESTRATION_ID", "CI", "ImageOS"):
        assert _is_platform_var(name, config)
    for name in ("APP_MODE", "TZ", "PATH", "LANG"):
        assert not _is_platform_var(name, config)


# --- real GitHub Actions run (ci_github_*: captured by .github/workflows/ci.yml) ---------


@pytest.fixture(scope="module")
def real_ci() -> list[Divergence]:
    """Your machine (pair_good, settings.toml present) vs a real GitHub runner (missing)."""
    return rank_divergences(compare_sides(side("good", "pair_good"), side("ci", "ci_github")))


def test_real_ci_cause_ranks_first(real_ci: list[Divergence]) -> None:
    top = real_ci[0]
    assert top.summary == "openat <cwd>/settings.toml: OK on good, ENOENT on ci"
    assert severity(top) == "CRITICAL"


def test_real_ci_runner_environment_is_not_in_the_top_ten(real_ci: list[Divergence]) -> None:
    for d in real_ci[:10]:
        assert d.kind != "env_diff" or "TZ" in d.summary, d.summary
    platform = next(d for d in real_ci if "GITHUB_SHA" in d.summary)
    assert severity(platform) == "INFO"
    assert any("CI platform variable" in r for r in platform.reasons)


def test_real_ci_noise_stays_low(real_ci: list[Divergence]) -> None:
    warnings = [d for d in real_ci if severity(d) == "WARNING"]
    # Measured 23 of 286 on 2026-10-21 (168 before probe/install-root/env grading).
    assert len(warnings) <= 30, len(warnings)


def test_search_path_probe_gets_no_failure_credit(real_ci: list[Divergence]) -> None:
    probes = [d for d in real_ci if any(r.startswith("search-path probe:") for r in d.reasons)]
    assert probes
    assert all(not any(r.startswith("failing call") for r in d.reasons) for d in probes)


def test_install_folder_of_different_program_is_a_consequence(real_ci: list[Divergence]) -> None:
    under = [
        d for d in real_ci if any("install folder of the different program" in r for r in d.reasons)
    ]
    assert under
    roots = ("/opt/hostedtoolcache/Python/3.11.17/x64/", "~/Code/Python/Reprotrace/.venv/")
    assert all(any(root in d.summary for root in roots) for d in under)
    assert any(roots[0] in d.summary for d in under) and any(roots[1] in d.summary for d in under)
    assert all(d.score < real_ci[0].score for d in under)


def test_session_variables_are_weak_but_behavioural_ones_are_not() -> None:
    config = RankConfig()
    from reprotrace.diff.rank import _is_session_var

    for name in (
        "DISPLAY",
        "XDG_SESSION_TYPE",
        "GNOME_TERMINAL_SCREEN",
        "LS_COLORS",
        "P9K_TTY",
        "TERM",
    ):
        assert _is_session_var(name, config)
    for name in (
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "VIRTUAL_ENV",
        "AWS_DEFAULT_REGION",
        "APP_MODE",
        "TZ",
    ):
        assert not _is_session_var(name, config)
