"""Explain ranked divergences with an AI model, grounded in cited evidence (Phase 9).

Flow: build the bounded, redacted bundle -> ask the provider for JSON matching
``ExplanationDraft`` -> validate the schema -> check every citation against the bundle.
Any problem rejects the whole answer (PRD FR-23); nothing is half-accepted. The model only
returns text; nothing it says is ever executed (Rules.md 5).
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from reprotrace.ai.redact import DEFAULT_MAX_CHARS, DEFAULT_TOP, Bundle, build_bundle
from reprotrace.errors import AIError
from reprotrace.models import Explanation, ExplanationDraft, RankConfig
from reprotrace.report.markdown import exit_text, run_events
from reprotrace.store.db import connect, latest_comparison_id, load_comparison
from reprotrace.store.explanations import save_explanation
from reprotrace.store.run_files import load_run


class Provider(Protocol):
    """An LLM provider: one prompt in, one JSON text out."""

    name: str
    model: str

    def generate(self, system: str, prompt: str, schema: dict) -> str: ...


SYSTEM_PROMPT = """\
You help a developer understand why the same command behaves differently in two \
environments. ReproTrace traced both runs with strace, compared them, and ranked the \
differences ("divergences") by a heuristic. You receive only that ranked evidence as JSON.

Rules:
- Use only the evidence given. Do not invent events, files, paths, logs, versions or \
environment details.
- Every hypothesis must cite the divergence ids it relies on (divergence_ids) and event ids \
taken from those divergences' "event_ids" lists (event_ids). Cite nothing else.
- These are hypotheses, not proof. Use wording like "likely", "consistent with", "suggests". \
Never say a divergence proves the cause.
- Give 1 to 3 hypotheses, most likely first, with confidence low, medium or high.
- next_experiment: one concrete check the developer can run, as plain text.
- If the evidence does not explain the failure, set insufficient_evidence to true and say so \
in the summary; hypotheses may then be empty.
- The ranking is a heuristic: a lower-ranked divergence may be the real cause, and some \
divergences are consequences of others.
- Answer with the JSON object only."""

_TYPE = {"type": "STRING"}
RESPONSE_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "summary": _TYPE,
        "insufficient_evidence": {"type": "BOOLEAN"},
        "hypotheses": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "title": _TYPE,
                    "explanation": _TYPE,
                    "divergence_ids": {"type": "ARRAY", "items": _TYPE},
                    "event_ids": {"type": "ARRAY", "items": _TYPE},
                    "confidence": {"type": "STRING", "enum": ["low", "medium", "high"]},
                    "next_experiment": _TYPE,
                },
                "required": [
                    "title", "explanation", "divergence_ids", "event_ids", "confidence",
                    "next_experiment",
                ],
            },
        },
    },
    "required": ["summary", "insufficient_evidence", "hypotheses"],
}  # fmt: skip

_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


def build_prompt(bundle: Bundle) -> str:
    """The user message: the bundle, and a note when it was cut to fit."""
    note = (
        " Only the highest-ranked divergences are included; lower ones were left out."
        if bundle.truncated
        else ""
    )
    return f"Ranked evidence from ReproTrace.{note}\n\n{bundle.text}"


def validate_output(raw: str, bundle: Bundle) -> ExplanationDraft:
    """Parse and check the model's answer; raise AIError if anything is wrong."""
    text = raw.strip()
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group(1)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise AIError(f"The AI answer is not valid JSON ({error.msg}); it was rejected.") from error
    try:
        draft = ExplanationDraft.model_validate(data)
    except ValidationError as error:
        first = error.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "answer"
        raise AIError(
            f"The AI answer does not match the expected format ({where}: {first['msg']}); "
            "it was rejected."
        ) from error
    problems = citation_problems(draft, bundle)
    if problems:
        raise AIError(
            "The AI answer cites evidence that was not in the comparison; it was rejected: "
            + "; ".join(problems[:5])
        )
    if not draft.hypotheses and not draft.insufficient_evidence:
        raise AIError(
            "The AI answer has no hypotheses but does not say the evidence is insufficient."
        )
    return draft


def citation_problems(draft: ExplanationDraft, bundle: Bundle) -> list[str]:
    """Every cited divergence must be in the bundle; every cited event must belong to one of
    the divergences the same hypothesis cites."""
    problems: list[str] = []
    for number, hypothesis in enumerate(draft.hypotheses, start=1):
        unknown = [d for d in hypothesis.divergence_ids if d not in bundle.events_by_divergence]
        if unknown:
            problems.append(f"hypothesis {number} cites unknown divergence(s) {', '.join(unknown)}")
        allowed: set[str] = set()
        for d in hypothesis.divergence_ids:
            allowed |= bundle.events_by_divergence.get(d, set())
        stray = [e for e in hypothesis.event_ids if e not in allowed]
        if stray:
            problems.append(
                f"hypothesis {number} cites event(s) {', '.join(stray[:3])} not in its divergences"
            )
    return problems


def explain_bundle(
    bundle: Bundle,
    provider: Provider,
    comparison_id: str,
    now: datetime | None = None,
) -> Explanation:
    """Ask the provider about ``bundle`` and return the validated explanation."""
    if not bundle.divergence_ids:
        raise AIError("There are no divergences to explain.")
    raw = provider.generate(SYSTEM_PROMPT, build_prompt(bundle), RESPONSE_SCHEMA)
    draft = validate_output(raw, bundle)
    return Explanation(
        **draft.model_dump(),
        comparison_id=comparison_id,
        provider=provider.name,
        model=provider.model,
        generated_at=now or datetime.now(UTC),
    )


def explain_saved(
    base_dir: Path,
    comparison_id: str | None,
    provider: Provider,
    top: int = DEFAULT_TOP,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> tuple[Explanation, Bundle, Path]:
    """Explain a saved comparison (default: the latest), store the result, return it."""
    with connect(base_dir) as conn:
        stored = load_comparison(conn, comparison_id or latest_comparison_id(conn))
    details = stored.details
    a_run = load_run(base_dir, details["a_run_ids"][0])
    b_run = load_run(base_dir, details["b_run_ids"][0])
    events = {e.id: e for run in (a_run, b_run) for e in run_events(base_dir, run.id)}
    bundle = build_bundle(
        stored.divergences,
        events,
        labels=(details["a_label"], details["b_label"]),
        command=a_run.command,
        exits=(exit_text(a_run), exit_text(b_run)),
        rank_config=RankConfig.model_validate(stored.config["rank"]),
        top=top,
        max_chars=max_chars,
    )
    explanation = explain_bundle(bundle, provider, stored.id)
    path = save_explanation(base_dir, explanation)
    return explanation, bundle, path
