"""Phase 8: the evaluation harness (scoring logic only; Docker is not needed here)."""

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from conftest import TRACES, fixture_run
from reprotrace import config
from reprotrace.models import Divergence

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "eval" / "scenarios"


@pytest.fixture(scope="module")
def run_eval():
    spec = importlib.util.spec_from_file_location("run_eval", ROOT / "eval" / "run_eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_eval"] = module
    spec.loader.exec_module(module)
    return module


def div(kind: str, summary: str) -> Divergence:
    return Divergence(id="d1", kind=kind, summary=summary, a_event_ids=[], b_event_ids=[])


def test_every_scenario_is_complete() -> None:
    folders = [p for p in SCENARIOS.iterdir() if p.is_dir()]
    assert len(folders) == 8
    for folder in folders:
        for name in ("app.py", "Dockerfile.good", "Dockerfile.bad", "run.sh", "expected.json"):
            assert (folder / name).is_file(), f"{folder.name}/{name}"
        expected = json.loads((folder / "expected.json").read_text())
        assert expected["description"] and expected["cause"]["contains"]


def test_matching_needs_kind_and_text(run_eval) -> None:
    cause = {"kinds": ["env_diff"], "contains": ["Environment variable TZ:"]}
    assert run_eval.matches(div("env_diff", "Environment variable TZ: x on good"), cause)
    assert not run_eval.matches(div("result_mismatch", "Environment variable TZ: x"), cause)
    assert not run_eval.matches(div("env_diff", "Environment variable LANG: x"), cause)
    ranked = [
        div("env_diff", "Environment variable HOSTNAME"),
        div("env_diff", "Environment variable TZ: a"),
    ]
    assert run_eval.cause_position(ranked, cause) == 2
    assert run_eval.cause_position(ranked[:1], cause) is None


def _project(tmp: Path, prefix: str) -> Path:
    for side in ("good", "bad"):
        for n in (1, 2):
            name = f"{prefix}_{side}_{n}"
            folder = config.run_dir(tmp, fixture_run(name).id)
            folder.mkdir(parents=True)
            shutil.copy(TRACES / f"{name}.strace", folder / config.RAW_TRACE_FILE)
            shutil.copy(TRACES / f"{name}.meta.json", folder / config.META_FILE)
    return tmp


def test_evaluate_project_on_real_scenario_captures(run_eval, tmp_path: Path) -> None:
    expected = json.loads((SCENARIOS / "timezone" / "expected.json").read_text())
    scored = run_eval.evaluate_project(_project(tmp_path, "eval_timezone"), expected["cause"], 2)
    assert scored["cause_rank"] == 1
    assert scored["above_cause"] == 0
    assert scored["runs_needed"] == 1
    assert scored["rank_with_one_run"] == 1
    assert "TZ" in scored["cause_summary"]


def test_results_table_and_readme_block(run_eval, tmp_path: Path, monkeypatch) -> None:
    result = run_eval.ScenarioResult(
        name="timezone", description="d", cause_rank=1, cause_summary="s", divergences=6,
        above_cause=0, warnings=2, runs_needed=1, rank_with_one_run=1,
        traced_ms=40.0, untraced_ms=10.0,
    )  # fmt: skip
    missing = run_eval.ScenarioResult(
        name="locale", description="d", cause_rank=None, cause_summary=None, divergences=3,
        above_cause=None, warnings=0, runs_needed=None, rank_with_one_run=None,
        traced_ms=1.0, untraced_ms=0.0,
    )  # fmt: skip
    table = run_eval.results_table([result, missing], 3, "2026-01-01")
    assert "| timezone | 1 | yes | 6 | 0 | 2 | 1 | 1 | 4.0x |" in table
    assert "| locale | not found | no | 3 | - | 0 | - | not found | n/a |" in table
    assert "top-1 1/2, top-3 1/2" in table

    monkeypatch.setattr(run_eval, "ROOT", tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text("# X\n\n<!-- eval:start -->\nold\n<!-- eval:end -->\n\nTail\n")
    run_eval.update_readme("new table")
    text = readme.read_text()
    assert "old" not in text and "new table" in text and text.endswith("Tail\n")


def test_scenario_that_does_not_fail_as_planted_is_refused(run_eval) -> None:
    """Regression: unreadable app.py made both sides exit 2; env-only causes still 'ranked 1'."""
    first = {
        "exit": 2,
        "stderr": "python3: can't open file '/app/app.py': [Errno 13] Permission denied",
    }
    with pytest.raises(
        run_eval.ScenarioSetupError, match=r"(?s)good side should end with exit 0.*Errno 13"
    ):
        run_eval.check_setup("timezone", "good", [2, 2, 2], first)
    with pytest.raises(
        run_eval.ScenarioSetupError, match="bad side should end with a non-zero exit"
    ):
        run_eval.check_setup("timezone", "bad", [1, 0, 1], {"exit": 0, "stderr": ""})
    run_eval.check_setup("timezone", "good", [0, 0, 0], {"exit": 0, "stderr": ""})
    run_eval.check_setup("timezone", "bad", [1, 1, 1], {"exit": 1, "stderr": ""})


def test_scenario_images_do_not_depend_on_host_file_modes() -> None:
    for dockerfile in SCENARIOS.glob("*/Dockerfile.*"):
        text = dockerfile.read_text()
        assert "RUN chmod 644 /app/app.py /scenario/run.sh" in text, dockerfile


class _CitesFirst:
    """Fake provider: cites the first divergence in the prompt (no network in tests)."""

    name, model = "fake", "fake-1"

    def generate(self, system: str, prompt: str, schema: dict) -> str:
        top = json.loads(prompt.split("\n\n", 1)[1])["divergences"][0]
        event = next(ids[0] for ids in top["event_ids"].values() if ids)
        return json.dumps({"summary": "s", "insufficient_evidence": False, "hypotheses": [{
            "title": "t", "explanation": "e", "divergence_ids": [top["id"]],
            "event_ids": [event], "confidence": "medium", "next_experiment": "n"}]})  # fmt: skip


def test_explain_project_grounding_and_table(run_eval, tmp_path: Path) -> None:
    expected = json.loads((SCENARIOS / "timezone" / "expected.json").read_text())
    project = _project(tmp_path / "timezone" / "project", "eval_timezone")
    ai = run_eval.explain_project(project, expected["cause"], 2, _CitesFirst())
    assert ai["valid"] and ai["top_cites_cause"] and ai["any_cites_cause"]

    class Liar(_CitesFirst):
        def generate(self, system, prompt, schema):
            answer = json.loads(super().generate(system, prompt, schema))
            answer["hypotheses"][0]["event_ids"] = ["run_000000000000:1"]  # made up
            return json.dumps(answer)

    rejected = run_eval.explain_project(project, expected["cause"], 2, Liar())
    assert not rejected["valid"] and "cites evidence that was not in" in rejected["error"]

    base = dict(
        description="d",
        cause_rank=1,
        cause_summary="s",
        divergences=1,
        above_cause=0,
        warnings=0,
        runs_needed=1,
        rank_with_one_run=1,
        traced_ms=2.0,
        untraced_ms=1.0,
    )
    rows = [run_eval.ScenarioResult(name="timezone", ai=ai, **base),
            run_eval.ScenarioResult(name="locale", ai=rejected, **base)]  # fmt: skip
    table = run_eval.results_table(rows, 2, "2026-01-01")
    assert "| timezone | yes | yes | yes | medium |" in table
    assert "| locale | no: " in table
    assert "**AI totals:** valid 1/2, first hypothesis cites the planted cause 1/2." in table
    assert "AI totals" not in run_eval.results_table(
        [run_eval.ScenarioResult(name="x", **base)], 1, "d"
    )
