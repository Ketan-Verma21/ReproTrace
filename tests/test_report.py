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


# --- HTML report (PRD FR-19) and the shared document model ----------------------------


def _visible_text(page: str) -> str:
    """Text a browser would show: tags and the <head> removed, entities decoded."""
    import html as html_lib
    import re

    body = page.split("<body>", 1)[1]
    return html_lib.unescape(re.sub(r"<[^>]+>", " ", body))


def test_html_report_is_standalone_with_the_same_content(tmp_path: Path) -> None:
    cid = _saved_pair(tmp_path, "pair_good", "pair_bad")
    md_text = write_report(tmp_path, cid).read_text()
    path = write_report(tmp_path, cid, html=True)
    assert path.name == f"{cid}.html" and path.parent.name == "reports"
    page = path.read_text()
    assert page.startswith("<!doctype html>") and "<title>ReproTrace Report: " in page
    # Self-contained: no scripts, no external stylesheets, fonts or images.
    for banned in ("<script", "<link", "http://", "https://", "@import", "url("):
        assert banned not in page, banned
    assert "prefers-color-scheme: dark" in page
    # Placeholders are escaped, so they show up as text instead of turning into tags.
    assert "&lt;cwd&gt;/settings.toml" in page and "<cwd>" not in page.split("<body>")[1]
    assert '<span class="sev sev-CRITICAL">CRITICAL</span>' in page
    visible = " ".join(_visible_text(page).split())
    for line in md_text.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("# ").replace("&lt;", "<").replace("&gt;", ">")
            assert heading.replace("&amp;", "&") in visible, heading


def test_report_cli_html_option(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from reprotrace.cli import app

    monkeypatch.chdir(tmp_path)
    cid = _saved_pair(tmp_path, "pair_good", "pair_bad")
    result = CliRunner().invoke(app, ["report", "--html"])
    assert result.exit_code == 0, result.output
    assert f"{cid}.html" in result.output
    out = tmp_path / "custom.html"
    assert CliRunner().invoke(app, ["report", cid, "--html", "--out", str(out)]).exit_code == 0
    assert out.read_text().startswith("<!doctype html>")


def test_document_escaping_in_both_formats() -> None:
    from reprotrace.report.document import (
        Bullets,
        Code,
        CodeBlock,
        Heading,
        Item,
        Paragraph,
        Severity,
        Strong,
        Table,
        Text,
        to_html,
        to_markdown,
    )  # fmt: skip

    blocks = [
        Heading(2, [Text("a <b> & c")]),
        Paragraph([Strong("x<y"), Text(" "), Code("<cwd>"), Text(" "), Severity("WARNING")]),
        Bullets([Item([Text("top")], [[Text("child & 1")]])]),
        CodeBlock(["if a < b && c > d:"]),
        Table([[Text("k")], [Text("v")]], [[[Code("A|B")], [Text("x|y\nz")]]]),
    ]
    md = to_markdown(blocks)
    assert "## a &lt;b&gt; &amp; c" in md
    assert "**x&lt;y** `<cwd>` **WARNING**" in md  # code spans stay literal in Markdown
    assert "- top\n  - child &amp; 1" in md
    assert "```text\nif a < b && c > d:\n```" in md  # code blocks stay literal too
    assert "| `A\\|B` | x\\|y z |" in md
    page = to_html(blocks, "T <1>")
    assert "<title>T &lt;1&gt;</title>" in page
    assert "<h2>a &lt;b&gt; &amp; c</h2>" in page
    assert "<strong>x&lt;y</strong> <code>&lt;cwd&gt;</code>" in page
    assert "<pre><code>if a &lt; b &amp;&amp; c &gt; d:</code></pre>" in page
    assert "<td><code>A|B</code></td>" in page
