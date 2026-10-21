"""Evaluation suite: run each seeded-failure scenario, diff it, and score the ranking.

    python eval/run_eval.py                    # build images, run every scenario, write results
    python eval/run_eval.py --scenario locale  # one scenario
    python eval/run_eval.py --update-readme    # also replace the results block in README.md

Each scenario folder in eval/scenarios/ has an app, a Dockerfile for the working ("good") and
the broken ("bad") environment, run.sh (the traced command) and expected.json (the planted
cause). Both sides are captured inside Docker with `reprotrace capture`, compared with the
library, and the rank of the first divergence matching expected.json is recorded.

Scenarios are written by the author, so the numbers measure these scenarios only; they are
not general proof of accuracy.
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from reprotrace.diff.compare import Side, compare_sides  # noqa: E402
from reprotrace.diff.rank import rank_divergences, severity  # noqa: E402
from reprotrace.models import Divergence  # noqa: E402
from reprotrace.parse.run import parse_run  # noqa: E402
from reprotrace.store.run_files import latest_group_for_label  # noqa: E402

SCENARIOS = ROOT / "eval" / "scenarios"
BASE_IMAGE = "reprotrace-eval-base"
README_START = "<!-- eval:start -->"
README_END = "<!-- eval:end -->"
DOCKER_TIMEOUT_S = 900
SIDES = ("good", "bad")


@dataclass
class ScenarioResult:
    """Measured outcome of one scenario."""

    name: str
    description: str
    cause_rank: int | None
    cause_summary: str | None
    divergences: int
    above_cause: int | None
    warnings: int
    runs_needed: int | None
    rank_with_one_run: int | None
    traced_ms: float
    untraced_ms: float
    exit_codes: dict[str, list[int | None]] = field(default_factory=dict)

    @property
    def overhead(self) -> float | None:
        return self.traced_ms / self.untraced_ms if self.untraced_ms > 0 else None


def run(cmd: list[str], timeout: float = DOCKER_TIMEOUT_S) -> subprocess.CompletedProcess[str]:
    """Run a command (argument list, never a shell string); raise with its output on failure."""
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"command failed ({done.returncode}): {' '.join(cmd)}\n{done.stderr}")
    return done


def build_base() -> None:
    run(["docker", "build", "-q", "-f", str(ROOT / "eval" / "base.Dockerfile"),
         "-t", BASE_IMAGE, str(ROOT)])  # fmt: skip


def image_name(scenario: str, side: str) -> str:
    return f"reprotrace-eval-{scenario.replace('_', '-')}-{side}"


def build_scenario(folder: Path) -> None:
    for side in SIDES:
        run(["docker", "build", "-q", "-f", str(folder / f"Dockerfile.{side}"),
             "-t", image_name(folder.name, side), str(folder)])  # fmt: skip


# Inside the container: capture the command, then time it untraced for the overhead figure.
_TIMING = (
    "import json, subprocess, time\n"
    "times, first = [], None\n"
    "for _ in range({n}):\n"
    "    start = time.perf_counter()\n"
    "    done = subprocess.run(['sh', '/scenario/run.sh'], capture_output=True, text=True)\n"
    "    times.append((time.perf_counter() - start) * 1000)\n"
    "    first = first or {{'exit': done.returncode, 'stderr': done.stderr[-2000:]}}\n"
    "print('UNTRACED=' + json.dumps({{'ms': times, 'first': first}}))\n"
)


class ScenarioSetupError(RuntimeError):
    """A scenario did not behave as planted (good must pass, bad must fail)."""


def check_setup(name: str, side: str, exit_codes: list[int | None], first: dict) -> None:
    """Refuse to score a scenario whose good side fails or whose bad side passes."""
    ok = all(c == 0 for c in exit_codes) if side == "good" else all(c for c in exit_codes)
    if not ok:
        want = "exit 0" if side == "good" else "a non-zero exit"
        raise ScenarioSetupError(
            f"{name}: the {side} side should end with {want}, but the captured runs exited "
            f"{exit_codes}. Untraced run: exit {first.get('exit')}, stderr:\n"
            f"{first.get('stderr') or '(empty)'}"
        )


def capture_side(folder: Path, side: str, runs: int, out: Path) -> dict:
    """Capture one side into ``out/.reprotrace/runs``.

    Returns ``{"ms": [untraced durations], "first": {"exit": ..., "stderr": ...}}``.
    """
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o777)
    # A normal (non-root) user: root would ignore file permissions (permission scenario).
    uid = os.getuid() if os.getuid() != 0 else 10001
    gid = os.getgid() if os.getuid() != 0 else 10001
    script = (
        f"umask 000 && reprotrace capture --label {side} --runs {runs} -- sh /scenario/run.sh"
        f' >/dev/null 2>&1; python3 -c "$TIMING"'
    )
    done = run([
        "docker", "run", "--rm", "--cap-add=SYS_PTRACE", "--user", f"{uid}:{gid}",
        "-e", "HOME=/tmp", "-e", f"TIMING={_TIMING.format(n=runs)}",
        "-v", f"{out}:/out", "-w", "/out",
        image_name(folder.name, side), "sh", "-c", script,
    ])  # fmt: skip
    line = next((ln for ln in done.stdout.splitlines() if ln.startswith("UNTRACED=")), None)
    if line is None:
        raise RuntimeError(f"no timing output from {folder.name}/{side}:\n{done.stdout}")
    return json.loads(line.removeprefix("UNTRACED="))


def merge_runs(sides: dict[str, Path], project: Path) -> None:
    runs_dir = project / ".reprotrace" / "runs"
    runs_dir.mkdir(parents=True)
    for out in sides.values():
        for run_folder in (out / ".reprotrace" / "runs").iterdir():
            shutil.copytree(run_folder, runs_dir / run_folder.name)


def matches(divergence: Divergence, cause: dict[str, list[str]]) -> bool:
    """True if ``divergence`` is the planted cause described in expected.json."""
    kinds = cause.get("kinds") or []
    if kinds and divergence.kind not in kinds:
        return False
    return any(text in divergence.summary for text in cause.get("contains", []))


def cause_position(ranked: list[Divergence], cause: dict[str, list[str]]) -> int | None:
    """1-based rank of the first divergence matching the cause, or None."""
    return next((i for i, d in enumerate(ranked, start=1) if matches(d, cause)), None)


def evaluate_project(project: Path, cause: dict[str, list[str]], runs: int) -> dict:
    """Compare good vs bad in ``project`` with 1..runs runs per side and score each."""
    good = [parse_run(project, r.id).events for r in latest_group_for_label(project, "good")]
    bad = [parse_run(project, r.id).events for r in latest_group_for_label(project, "bad")]
    by_runs: dict[int, tuple[int | None, list[Divergence]]] = {}
    for n in range(1, runs + 1):
        ranked = rank_divergences(compare_sides(Side("good", good[:n]), Side("bad", bad[:n])))
        by_runs[n] = (cause_position(ranked, cause), ranked)
    position, ranked = by_runs[runs]
    needed = next((n for n in sorted(by_runs) if (by_runs[n][0] or 99) <= 3), None)
    return {
        "cause_rank": position,
        "cause_summary": ranked[position - 1].summary if position else None,
        "divergences": len(ranked),
        "above_cause": position - 1 if position else None,
        "warnings": sum(1 for d in ranked if severity(d) in ("WARNING", "CRITICAL")),
        "runs_needed": needed,
        "rank_with_one_run": by_runs[1][0],
    }


def run_scenario(folder: Path, runs: int, work: Path) -> ScenarioResult:
    expected = json.loads((folder / "expected.json").read_text())
    build_scenario(folder)
    outs: dict[str, Path] = {}
    untraced: list[float] = []
    firsts: dict[str, dict] = {}
    for side in SIDES:
        outs[side] = work / folder.name / side
        timing = capture_side(folder, side, runs, outs[side])
        untraced += timing["ms"]
        firsts[side] = timing["first"]
    project = work / folder.name / "project"
    merge_runs(outs, project)
    metas = [json.loads(p.read_text()) for p in project.glob(".reprotrace/runs/*/meta.json")]
    exit_codes = {s: sorted(m["exit_code"] for m in metas if m["label"] == s) for s in SIDES}
    for side in SIDES:
        check_setup(folder.name, side, exit_codes[side], firsts[side])
    scored = evaluate_project(project, expected["cause"], runs)
    return ScenarioResult(
        name=folder.name,
        description=expected["description"],
        traced_ms=statistics.mean(m["duration_ms"] for m in metas),
        untraced_ms=statistics.mean(untraced),
        exit_codes=exit_codes,
        **scored,
    )


def results_table(results: list[ScenarioResult], runs: int, measured_on: str) -> str:
    """Markdown table plus totals; the same text goes to eval/results.md and the README."""
    top1 = sum(1 for r in results if r.cause_rank == 1)
    top3 = sum(1 for r in results if r.cause_rank is not None and r.cause_rank <= 3)
    lines = [
        f"Measured {measured_on} with `python eval/run_eval.py` ({runs} runs per side).",
        "",
        "| Scenario | Cause rank | Top 3 | Divergences | Ranked above cause | "
        "Warnings | Runs needed | Rank with 1 run | Tracing overhead |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        overhead = f"{r.overhead:.1f}x" if r.overhead else "n/a"
        lines.append(
            f"| {r.name} | {r.cause_rank or 'not found'} | "
            f"{'yes' if r.cause_rank and r.cause_rank <= 3 else 'no'} | {r.divergences} | "
            f"{r.above_cause if r.above_cause is not None else '-'} | {r.warnings} | "
            f"{r.runs_needed or '-'} | {r.rank_with_one_run or 'not found'} | {overhead} |"
        )
    lines += [
        "",
        f"**Totals:** top-1 {top1}/{len(results)}, top-3 {top3}/{len(results)}.",
        "",
        "Scenarios are written by the author of ReproTrace, so these numbers describe these "
        "scenarios only; they are not general proof of accuracy. Tracing overhead compares the "
        "mean traced run (including strace start-up) with the mean untraced run of the same "
        "command; the commands are short, so start-up dominates.",
    ]
    return "\n".join(lines)


def update_readme(table: str) -> None:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    block = f"{README_START}\n{table}\n{README_END}"
    if README_START in text and README_END in text:
        head, rest = text.split(README_START, 1)
        text = head + block + rest.split(README_END, 1)[1]
    else:
        text = text.rstrip() + "\n\n## Evaluation\n\n" + block + "\n"
    readme.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenario", action="append", help="run only this scenario (repeatable)")
    parser.add_argument("--runs", type=int, default=3, help="captures per side (default 3)")
    parser.add_argument(
        "--no-build-base", action="store_true", help="reuse the existing base image"
    )
    parser.add_argument(
        "--update-readme", action="store_true", help="write the table into README.md"
    )
    parser.add_argument(
        "--keep", action="store_true", help="keep captured runs (prints the folder)"
    )
    args = parser.parse_args(argv)

    folders = sorted(p for p in SCENARIOS.iterdir() if (p / "expected.json").is_file())
    if args.scenario:
        folders = [p for p in folders if p.name in args.scenario]
        if not folders:
            parser.error(f"unknown scenario(s): {', '.join(args.scenario)}")
    if not args.no_build_base:
        print("Building base image ...", flush=True)
        build_base()

    work = Path(tempfile.mkdtemp(prefix="reprotrace-eval-"))
    results: list[ScenarioResult] = []
    for folder in folders:
        print(f"Running {folder.name} ...", flush=True)
        try:
            result = run_scenario(folder, args.runs, work)
        except ScenarioSetupError as error:
            # Scoring a scenario that did not fail as planted would give a meaningless number,
            # so nothing is written (results files and README stay as they were).
            print(f"\nError: {error}\n\nNo results written.", file=sys.stderr)
            shutil.rmtree(work, ignore_errors=True)
            return 1
        print(f"  cause rank {result.cause_rank}, {result.divergences} divergences", flush=True)
        results.append(result)

    measured_on = datetime.now(UTC).strftime("%Y-%m-%d")
    table = results_table(results, args.runs, measured_on)
    out_dir = ROOT / "eval"
    (out_dir / "results.md").write_text(f"# Evaluation results\n\n{table}\n", encoding="utf-8")
    payload = {
        "measured_on": measured_on,
        "runs_per_side": args.runs,
        "results": [asdict(r) | {"overhead": r.overhead} for r in results],
    }
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.update_readme:
        update_readme(table)
    print()
    print(table)
    if args.keep:
        print(f"\nCaptured runs kept in {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
