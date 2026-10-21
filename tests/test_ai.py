"""Phase 9: AI explanation layer. The provider is always faked; no real API call (Rules.md 7)."""

import io
import json
import urllib.error
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import fixture_lines, install_fixture_run
from reprotrace import config
from reprotrace.ai import explain as explain_module
from reprotrace.ai.explain import (
    RESPONSE_SCHEMA,
    SYSTEM_PROMPT,
    citation_problems,
    explain_bundle,
    validate_output,
)
from reprotrace.ai.gemini import API_URL, DEFAULT_MODEL, GeminiProvider
from reprotrace.ai.redact import Bundle, build_bundle, redact_text
from reprotrace.cli import app
from reprotrace.diff.compare import Side, compare_sides
from reprotrace.diff.rank import rank_divergences
from reprotrace.errors import AIError
from reprotrace.models import Divergence, Event, ExplanationDraft, Hypothesis
from reprotrace.parse.strace_parser import parse_lines

runner = CliRunner()


def _events(name: str) -> list[Event]:
    return parse_lines(fixture_lines(name), name)[0]


@pytest.fixture(scope="module")
def timezone() -> tuple[list[Divergence], dict[str, Event]]:
    """Real comparison: TZ set on good, missing on bad (eval scenario captures)."""
    good = [_events(f"eval_timezone_good_{n}") for n in (1, 2)]
    bad = [_events(f"eval_timezone_bad_{n}") for n in (1, 2)]
    ranked = rank_divergences(compare_sides(Side("good", good), Side("bad", bad)))
    events = {e.id: e for e in good[0] + bad[0]}
    return ranked, events


def bundle_of(ranked, events, **kwargs) -> Bundle:
    return build_bundle(
        ranked, events, labels=("good", "bad"), command=["sh", "/scenario/run.sh"],
        exits=("exit 0", "exit 1"), **kwargs,
    )  # fmt: skip


def answer_for(bundle: Bundle, **overrides) -> str:
    """A well-formed answer citing the top divergence and its first event."""
    top = bundle.divergence_ids[0]
    hypothesis = {
        "title": "TZ is not set on the failing side",
        "explanation": "The program likely depends on TZ.",
        "divergence_ids": [top],
        "event_ids": sorted(bundle.events_by_divergence[top])[:1],
        "confidence": "medium",
        "next_experiment": "Set TZ on bad and run again.",
    }
    hypothesis.update(overrides)
    return json.dumps(
        {
            "summary": "Consistent with a missing TZ.",
            "insufficient_evidence": False,
            "hypotheses": [hypothesis],
        }  # fmt: skip
    )


class FakeProvider:
    """Answers from the bundle in the prompt, like a model that follows the rules."""

    name = "fake"
    model = "fake-1"

    def __init__(self, reply=None) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str, dict]] = []

    def generate(self, system: str, prompt: str, schema: dict) -> str:
        self.calls.append((system, prompt, schema))
        if self.reply is not None:
            return self.reply
        data = json.loads(prompt.split("\n\n", 1)[1])
        top = data["divergences"][0]
        first_event = next(ids[0] for ids in top["event_ids"].values() if ids)
        return json.dumps({
            "summary": "Consistent with the top divergence.",
            "insufficient_evidence": False,
            "hypotheses": [{
                "title": top["summary"][:80], "explanation": "Likely related.",
                "divergence_ids": [top["id"]], "event_ids": [first_event],
                "confidence": "low", "next_experiment": "Change only this and rerun.",
            }],
        })  # fmt: skip


# --- redaction and the bounded bundle -------------------------------------------------


def test_redact_text() -> None:
    assert redact_text("API_KEY=short123 ok") == "API_KEY=<redacted> ok"
    assert (
        redact_text("https://bob:hunter2@example.com/x") == "https://bob:<redacted>@example.com/x"
    )
    assert "AKIA" not in redact_text("key AKIAABCDEFGHIJKLMNOP here")
    assert "ghp_" not in redact_text('open("ghp_' + "a" * 36 + '")')
    path = "openat <cwd>/settings.toml: OK on good, ENOENT on bad"
    assert redact_text(path) == path
    assert (
        redact_text("/usr/lib/python3.11/site-packages/x.py")
        == "/usr/lib/python3.11/site-packages/x.py"
    )


def test_bundle_is_bounded_and_has_no_raw_environment(timezone) -> None:
    ranked, events = timezone
    bundle = bundle_of(ranked, events)
    assert len(bundle.text) <= 16_000
    assert bundle.divergence_ids[0] == ranked[0].id
    assert "Environment variable TZ" in bundle.text
    # The execve environment (HOSTNAME=..., HOME=...) never travels, only its count.
    assert "HOME=/tmp" not in bundle.text
    assert "TIMING=" not in bundle.text
    for entry in bundle.data["divergences"]:
        for excerpt in entry.get("excerpts", []):
            assert len(excerpt["text"]) <= 300


def test_bundle_drops_lowest_divergences_to_fit(timezone) -> None:
    ranked, events = timezone
    small = bundle_of(ranked, events, max_chars=2500)
    assert len(small.text) <= 2500
    assert 1 <= len(small.divergence_ids) < min(len(ranked), 8)
    assert small.truncated
    assert small.divergence_ids == [d.id for d in ranked[: len(small.divergence_ids)]]


def test_secret_env_values_never_reach_the_bundle() -> None:
    d = Divergence(id="d1", kind="env_diff", summary="Environment variable API_TOKEN: abc on good, "
                   "def on bad", a_event_ids=["r:1"], b_event_ids=["s:1"])  # fmt: skip
    bundle = build_bundle(
        [d], {}, labels=("good", "bad"), command=["x"], exits=("exit 0", "exit 1")
    )
    assert "API_TOKEN differs (values redacted)" in bundle.text
    assert "abc" not in bundle.text and "def on bad" not in bundle.text


# --- validation: schema and citations (PRD FR-22, FR-23) ------------------------------


def test_valid_answer_is_accepted(timezone) -> None:
    bundle = bundle_of(*timezone)
    draft = validate_output(answer_for(bundle), bundle)
    assert draft.hypotheses[0].confidence == "medium"
    fenced = "```json\n" + answer_for(bundle) + "\n```"
    assert validate_output(fenced, bundle) == draft


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda b: "not json", "not valid JSON"),
        (lambda b: json.dumps({"summary": "x", "hypotheses": []}), "insufficient_evidence"),
        (lambda b: answer_for(b, confidence="certain"), "confidence"),
        (lambda b: answer_for(b, extra="field"), "expected format"),
        (lambda b: answer_for(b, divergence_ids=["d999"]), "unknown divergence"),
        (lambda b: answer_for(b, event_ids=["run_000000000000:1"]), "not in its divergences"),
        (lambda b: answer_for(b, event_ids=[]), "expected format"),
    ],
)
def test_invalid_answers_are_rejected(timezone, mutate, message) -> None:
    bundle = bundle_of(*timezone)
    with pytest.raises(AIError, match=message):
        validate_output(mutate(bundle), bundle)


def test_event_must_belong_to_a_cited_divergence(timezone) -> None:
    bundle = bundle_of(*timezone)
    first, second = bundle.divergence_ids[:2]
    other_event = sorted(bundle.events_by_divergence[second] - bundle.events_by_divergence[first])[
        0
    ]
    with pytest.raises(AIError, match="not in its divergences"):
        validate_output(answer_for(bundle, event_ids=[other_event]), bundle)
    # Citing both divergences makes the same event legitimate.
    validate_output(
        answer_for(bundle, divergence_ids=[first, second], event_ids=[other_event]), bundle
    )


def test_no_hypotheses_needs_insufficient_evidence(timezone) -> None:
    bundle = bundle_of(*timezone)
    empty = {"summary": "Nothing clear.", "hypotheses": []}
    with pytest.raises(AIError, match="does not say the evidence is insufficient"):
        validate_output(json.dumps({**empty, "insufficient_evidence": False}), bundle)
    draft = validate_output(json.dumps({**empty, "insufficient_evidence": True}), bundle)
    assert draft.insufficient_evidence and not citation_problems(draft, bundle)


def test_schema_sent_to_the_model_matches_the_model_class() -> None:
    assert set(RESPONSE_SCHEMA["properties"]) == set(ExplanationDraft.model_fields)
    item = RESPONSE_SCHEMA["properties"]["hypotheses"]["items"]
    assert set(item["properties"]) == set(Hypothesis.model_fields) == set(item["required"])


def test_explain_bundle_with_fake_provider(timezone) -> None:
    bundle = bundle_of(*timezone)
    provider = FakeProvider()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    explanation = explain_bundle(bundle, provider, "cmp_x", now)
    system, prompt, schema = provider.calls[0]
    assert system == SYSTEM_PROMPT and schema == RESPONSE_SCHEMA
    assert bundle.text in prompt
    assert explanation.comparison_id == "cmp_x" and explanation.generated_at == now
    assert (explanation.provider, explanation.model) == ("fake", "fake-1")
    assert explanation.hypotheses[0].divergence_ids == [bundle.divergence_ids[0]]


# --- Gemini provider over a fake HTTP opener ------------------------------------------


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def gemini_reply(text: str, finish: str = "STOP") -> bytes:
    return json.dumps(
        {"candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": finish}]}
    ).encode()


def test_gemini_request_and_response() -> None:
    seen = {}

    def opener(request, timeout):
        seen.update(url=request.full_url, headers=dict(request.header_items()), timeout=timeout,
                    body=json.loads(request.data))  # fmt: skip
        return FakeResponse(gemini_reply('{"ok": true}'))

    provider = GeminiProvider("secret-key-123", opener=opener)
    assert provider.generate("sys", "prompt", {"type": "OBJECT"}) == '{"ok": true}'
    assert seen["url"] == API_URL.format(model=DEFAULT_MODEL)
    assert "secret-key-123" not in seen["url"]
    assert seen["headers"]["X-goog-api-key"] == "secret-key-123"
    body = seen["body"]
    assert body["systemInstruction"]["parts"][0]["text"] == "sys"
    assert body["contents"][0]["parts"][0]["text"] == "prompt"
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert body["generationConfig"]["responseSchema"] == {"type": "OBJECT"}


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        (json.dumps({"promptFeedback": {"blockReason": "SAFETY"}}).encode(), "no answer .SAFETY"),
        (gemini_reply("{}", finish="MAX_TOKENS"), "stopped early"),
        (gemini_reply("   "), "empty answer"),
        (b"<html>", "not JSON"),
    ],
)
def test_gemini_bad_responses(reply: bytes, message: str) -> None:
    provider = GeminiProvider("k", opener=lambda request, timeout: FakeResponse(reply))
    with pytest.raises(AIError, match=message):
        provider.generate("s", "p", {})


def test_gemini_http_errors_have_hints_and_no_key() -> None:
    def opener(request, timeout):
        body = io.BytesIO(json.dumps({"error": {"message": "Quota exceeded"}}).encode())
        raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, body)

    with pytest.raises(AIError) as caught:
        GeminiProvider("topsecret", opener=opener).generate("s", "p", {})
    assert "HTTP 429: Quota exceeded" in caught.value.message
    assert "quota" in caught.value.hint.lower()
    assert "topsecret" not in caught.value.message

    def offline(request, timeout):
        raise urllib.error.URLError("no route")

    with pytest.raises(AIError, match="Could not reach"):
        GeminiProvider("k", opener=offline).generate("s", "p", {})


def test_gemini_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(AIError) as caught:
        GeminiProvider.from_env()
    assert caught.value.exit_code == 2
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("REPROTRACE_GEMINI_MODEL", "gemini-x")
    assert GeminiProvider.from_env().model == "gemini-x"
    assert GeminiProvider.from_env("gemini-y").model == "gemini-y"


# --- CLI and report -------------------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A project with the timezone scenario captures and one saved comparison."""
    monkeypatch.chdir(tmp_path)
    for side in ("good", "bad"):
        for n in (1, 2):
            install_fixture_run(tmp_path, f"eval_timezone_{side}_{n}")
    result = runner.invoke(app, ["diff", "good", "bad"])
    assert result.exit_code == 0, result.output
    return tmp_path


def use_provider(monkeypatch: pytest.MonkeyPatch, provider) -> None:
    monkeypatch.setattr(
        "reprotrace.cli.GeminiProvider.from_env", classmethod(lambda cls, model=None: provider)
    )


def test_explain_then_report(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use_provider(monkeypatch, FakeProvider())
    result = runner.invoke(app, ["--no-color", "explain"])
    assert result.exit_code == 0, result.output
    assert "AI-generated hypotheses" in result.output
    assert "Every citation was checked" in result.output
    saved = list((project / ".reprotrace" / "explanations").glob("cmp_*.json"))
    assert len(saved) == 1 and json.loads(saved[0].read_text())["schema_version"] == 1

    report = runner.invoke(app, ["report"])
    assert report.exit_code == 0, report.output
    text = next((project / ".reprotrace" / "reports").glob("*.md")).read_text()
    assert "## AI explanation" in text
    assert "**AI-generated hypotheses** (fake, model `fake-1`" in text
    assert "### Hypothesis 1:" in text and "(low confidence)" in text
    assert text.index("## AI explanation") < text.index("## Limitations")


def test_rejected_answer_saves_nothing_and_report_still_works(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_provider(monkeypatch, FakeProvider(reply=json.dumps({
        "summary": "x", "insufficient_evidence": False,
        "hypotheses": [{"title": "t", "explanation": "e", "divergence_ids": ["d1"],
                        "event_ids": ["run_ffffffffffff:7"], "confidence": "high",
                        "next_experiment": "n"}],
    })))  # fmt: skip
    result = runner.invoke(app, ["--no-color", "explain"])
    assert result.exit_code == 1
    assert "rejected" in result.output
    assert not (project / ".reprotrace" / "explanations").exists()
    report = runner.invoke(app, ["report"])
    assert report.exit_code == 0
    assert (
        "## AI explanation"
        not in next((project / ".reprotrace" / "reports").glob("*.md")).read_text()
    )


def test_explain_without_key_exits_2_and_nothing_else_breaks(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = runner.invoke(app, ["explain"])
    assert result.exit_code == 2
    assert "GEMINI_API_KEY is not set" in result.output
    assert runner.invoke(app, ["report"]).exit_code == 0


def test_report_leaves_out_broken_or_ungrounded_explanations(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_provider(monkeypatch, FakeProvider())
    assert runner.invoke(app, ["explain"]).exit_code == 0
    path = next((project / ".reprotrace" / "explanations").glob("*.json"))
    data = json.loads(path.read_text())

    data["hypotheses"][0]["event_ids"] = ["run_000000000000:1"]  # edited after the fact
    path.write_text(json.dumps(data))
    assert runner.invoke(app, ["report"]).exit_code == 0
    text = next((project / ".reprotrace" / "reports").glob("*.md")).read_text()
    assert "## AI explanation" not in text
    assert "AI explanation left out: it cites ids not in this comparison" in text

    path.write_text("{broken")
    assert runner.invoke(app, ["report"]).exit_code == 0
    text = next((project / ".reprotrace" / "reports").glob("*.md")).read_text()
    assert "AI explanation left out: Cannot read" in text


def test_explanation_path() -> None:
    assert config.explanation_path(Path("/p"), "cmp_1") == Path(
        "/p/.reprotrace/explanations/cmp_1.json"
    )


def test_ai_module_has_no_way_to_run_commands() -> None:
    """Rules.md 5: the AI layer returns text only."""
    source = Path(explain_module.__file__).parent
    for file in source.glob("*.py"):
        text = file.read_text()
        assert "subprocess" not in text and "os.system" not in text, file.name
