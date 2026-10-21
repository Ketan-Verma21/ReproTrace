"""Phase 6: Markdown report and terminal helpers."""

from pathlib import Path

import pytest

from conftest import fixture_lines, install_fixture_run
from reprotrace import __version__
from reprotrace.diff.compare import compare_saved
from reprotrace.diff.rank import rank_divergences
from reprotrace.diff.record import record_comparison
from reprotrace.models import DiffConfig, NormalizationConfig, RankConfig
from reprotrace.parse.strace_parser import parse_lines
from reprotrace.report.markdown import sanitize_raw, write_report
from reprotrace.report.terminal import make_console, shorten_middle, shorten_paths
from reprotrace.store.db import connect, list_runs, load_comparison, sync_runs


def _saved_pair(base: Path, good: str, bad: str) -> str:
    for name in (f"{good}_1", f"{good}_2", f"{bad}_1", f"{bad}_2"):
        install_fixture_run(base, name)
    with connect(base) as conn:
        sync_runs(conn, base)
        groups = {r.label: r.group_id for r in list_runs(conn)}
    saved = compare_saved(base, groups["good"], groups["bad"])
    ranked = rank_divergences(saved.comparison)
    return record_comparison(base, saved, ranked, NormalizationConfig(), DiffConfig(), RankConfig())


@pytest.fixture
def report(tmp_path: Path) -> tuple[Path, str]:
    cid = _saved_pair(tmp_path, "pair_good", "pair_bad")
    path = write_report(tmp_path, cid)
    return path, path.read_text()


def test_report_has_every_section(report: tuple[Path, str]) -> None:
    path, text = report
    assert path.name.endswith(".md") and path.parent.name == "reports"
    headings = ["# ReproTrace Report: cmp_", "## Summary", "## Top divergences"]
    headings += ["## How to reproduce", "## Environment differences", "## Limitations"]
    for heading in headings:
        assert heading in text
    assert "**Before sharing:**" in text.split("## Summary")[0]
    assert "Generated " in text and f"by reprotrace {__version__}" in text


def test_report_headline_names_the_likely_cause(report: tuple[Path, str]) -> None:
    _, text = report
    assert "- **Likely cause:** openat &lt;cwd&gt;/settings.toml: OK on good, ENOENT on bad" in text
    assert "### 1. openat &lt;cwd&gt;/settings.toml" in text
    assert "heuristic, not proof" in text


def test_report_evidence_and_reasons(report: tuple[Path, str]) -> None:
    _, text = report
    first = text.split("### 1.")[1].split("### 2.")[0]
    assert '"settings.toml"' in first and "ENOENT" in first
    assert "  - failed on bad (ENOENT) but succeeded on good" in first


def test_report_environment_table_and_reproduction(report: tuple[Path, str]) -> None:
    _, text = report
    assert "| `TZ` | UTC | Asia/Kolkata |" in text
    assert "reprotrace capture --label good --runs 2 -- python3 -c" in text
    assert "reprotrace capture --label bad --runs 2 -- python3 -c" in text


def test_report_never_contains_raw_environment(report: tuple[Path, str]) -> None:
    _, text = report
    assert '"PATH=' not in text and '"HOME=' not in text
    assert "variables, see Environment differences" in text


def test_report_path_is_recorded(tmp_path: Path) -> None:
    cid = _saved_pair(tmp_path, "pair_env_good", "pair_env_bad")
    out = tmp_path / "custom.md"
    assert write_report(tmp_path, cid, out) == out
    with connect(tmp_path) as conn:
        assert load_comparison(conn, cid).report_path == str(out)
    assert "`APP_MODE` | prod | (not set) |" in out.read_text()


def test_sanitize_raw_removes_env_and_redacts_tokens() -> None:
    events, _ = parse_lines(fixture_lines("pair_env_good_1"), "r")
    execve = next(e for e in events if e.syscall == "execve")
    clean = sanitize_raw(execve)
    assert "APP_MODE=prod" not in clean and "PATH=" not in clean
    assert "[/* 4 variables, see Environment differences */]" in clean
    token = "ghp_" + "a1" * 18
    tampered = execve.model_copy(update={"kind": "file", "raw": f'open("{token}") = 3'})
    assert token not in sanitize_raw(tampered)
    long_line = execve.model_copy(update={"kind": "file", "raw": "x" * 500})
    assert len(sanitize_raw(long_line)) <= 240


def test_shorten_helpers() -> None:
    path = "/very/long/" + "a" * 80 + "/file.py"
    short = shorten_middle(path, 40)
    assert len(short) == 40 and "..." in short and short.endswith("file.py")
    assert shorten_paths(f"open {path} failed", 40) == f"open {short} failed"
    assert shorten_paths("no paths here") == "no paths here"


def test_console_respects_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert make_console(no_color=True).color_system is None
    monkeypatch.setenv("NO_COLOR", "1")
    assert make_console().color_system is None
