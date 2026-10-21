"""Terminal output of ``reprotrace explain``: AI hypotheses, clearly labeled as such."""

from pathlib import Path

from rich.text import Text

from reprotrace.models import Explanation
from reprotrace.report.terminal import styled


def render_explanation(
    explanation: Explanation, sent_divergences: int, total: int, saved_to: Path
) -> list[Text]:
    """Lines for the terminal: label, summary, hypotheses with citations, where it was saved."""
    lines = [
        styled("AI-generated hypotheses", "accent"),
        styled(
            f"{explanation.provider} {explanation.model}, from the top {sent_divergences} of "
            f"{total} divergences. Every citation was checked; the reasoning may still be wrong.",
            "muted",
        ),
        Text(),
        Text(explanation.summary),
    ]
    if explanation.insufficient_evidence:
        lines += [Text(), styled("The model judged the evidence insufficient.", "warning")]
    for number, h in enumerate(explanation.hypotheses, start=1):
        lines += [
            Text(),
            Text.assemble(
                styled(f"{number}. {h.title}", "accent"), f"  ({h.confidence} confidence)"
            ),
            Text(f"   {h.explanation}"),
            Text.assemble("   Divergences: ", styled(", ".join(h.divergence_ids), "info")),
            Text.assemble("   Events: ", styled(", ".join(h.event_ids), "muted")),
            Text(f"   Next experiment: {h.next_experiment}"),
        ]
    lines += [
        Text(),
        Text.assemble("Saved to ", styled(str(saved_to), "accent"), ". It is included by:"),
        Text("  reprotrace report"),
    ]
    return lines
