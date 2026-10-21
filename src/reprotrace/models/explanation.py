"""Models of the optional AI explanation (Phase 9, PRD FR-21 to FR-23).

``ExplanationDraft`` is exactly what the model must return; ``Explanation`` is the
validated draft plus provenance, as stored and shown. Citation checks (every cited id must
exist in the bundle that was sent) live in ``reprotrace.ai.explain``.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EXPLANATION_SCHEMA_VERSION = 1

Confidence = Literal["low", "medium", "high"]


class Hypothesis(BaseModel):
    """One possible explanation of the failure, tied to the evidence that supports it."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    explanation: str = Field(min_length=1, max_length=2000)
    divergence_ids: list[str] = Field(min_length=1, max_length=10)
    event_ids: list[str] = Field(min_length=1, max_length=20)
    confidence: Confidence
    next_experiment: str = Field(min_length=1, max_length=600)


class ExplanationDraft(BaseModel):
    """The JSON object the model is asked to return."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=1500)
    insufficient_evidence: bool
    hypotheses: list[Hypothesis] = Field(max_length=5)


class Explanation(ExplanationDraft):
    """A validated draft with where it came from."""

    schema_version: int = EXPLANATION_SCHEMA_VERSION
    comparison_id: str
    provider: str
    model: str
    generated_at: datetime
