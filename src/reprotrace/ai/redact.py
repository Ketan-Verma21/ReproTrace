"""The bounded, redacted evidence bundle: the only data ever sent to an AI provider.

Rules.md 5 and 8: no raw traces, no full environments, no secrets. The bundle holds the
top-ranked divergences (summary, kind, score, reasons), their event ids, and at most one
short sanitized excerpt per side. Every string is redacted again here, even though summaries
were already redacted when the comparison was made, and the serialized bundle never exceeds
``max_chars``.
"""

import json
import re
import shlex
from dataclasses import dataclass, field

from reprotrace.capture.redact import REDACTED, is_secret_key, looks_like_token, redact_value
from reprotrace.diff.rank import severity
from reprotrace.models import Divergence, Event, RankConfig
from reprotrace.report.markdown import sanitize_raw

DEFAULT_TOP = 8
DEFAULT_MAX_CHARS = 16_000
MAX_IDS_PER_SIDE = 6
MAX_EXCERPT_CHARS = 300
MAX_REASON_CHARS = 200

# NAME=value where NAME looks secret (API_KEY=..., GITHUB_TOKEN=...): the value goes.
_SECRET_ASSIGNMENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=([^\s\"',\]]+)")
# Words are checked one by one; separators keep paths and lists readable.
_WORD = re.compile(r"[^\s\"'\[\](),=]+")


def redact_text(text: str) -> str:
    """Redact anything secret-looking in free text (URL passwords, tokens, secret assignments)."""
    text = redact_value(text)
    text = _SECRET_ASSIGNMENT.sub(
        lambda m: f"{m.group(1)}={REDACTED}" if is_secret_key(m.group(1)) else m.group(0), text
    )
    return _WORD.sub(lambda m: REDACTED if looks_like_token(m.group(0)) else m.group(0), text)


def _redact_env_summary(d: Divergence) -> str:
    """An env_diff summary for a secret-named variable keeps the name only."""
    if d.kind == "env_diff" and d.summary.startswith("Environment variable "):
        key = d.summary.removeprefix("Environment variable ").split(":", 1)[0].split(" ", 1)[0]
        if is_secret_key(key):
            return f"Environment variable {key} differs (values redacted)"
    return redact_text(d.summary)


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 4] + " ..."


@dataclass
class Bundle:
    """What is sent, plus the ids a valid answer may cite."""

    data: dict
    text: str
    divergence_ids: list[str]
    events_by_divergence: dict[str, set[str]] = field(default_factory=dict)
    truncated: bool = False

    @property
    def event_ids(self) -> set[str]:
        return (
            set().union(*self.events_by_divergence.values()) if self.events_by_divergence else set()
        )


def _divergence_entry(
    rank: int,
    d: Divergence,
    labels: tuple[str, str],
    events: dict[str, Event],
    rank_config: RankConfig | None,
    with_excerpts: bool,
) -> tuple[dict, set[str]]:
    ids = {labels[0]: d.a_event_ids[:MAX_IDS_PER_SIDE], labels[1]: d.b_event_ids[:MAX_IDS_PER_SIDE]}
    entry: dict = {
        "id": d.id,
        "rank": rank,
        "kind": d.kind,
        "severity": severity(d, rank_config),
        "score": round(d.score, 3),
        "summary": _redact_env_summary(d),
        "reasons": [_shorten(redact_text(r), MAX_REASON_CHARS) for r in d.reasons],
        "event_ids": ids,
    }
    if with_excerpts:
        excerpts = []
        for label, side_ids in ids.items():
            event = events.get(side_ids[0]) if side_ids else None
            if event is not None:
                text = _shorten(redact_text(sanitize_raw(event)), MAX_EXCERPT_CHARS)
                excerpts.append({"event_id": event.id, "side": label, "text": text})
        entry["excerpts"] = excerpts
    return entry, {i for side_ids in ids.values() for i in side_ids}


def build_bundle(
    ranked: list[Divergence],
    events: dict[str, Event],
    *,
    labels: tuple[str, str],
    command: list[str],
    exits: tuple[str, str],
    rank_config: RankConfig | None = None,
    top: int = DEFAULT_TOP,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> Bundle:
    """Bundle the ``top`` best divergences, dropping the lowest ones until it fits ``max_chars``."""
    header = {
        "command": _shorten(redact_text(shlex.join(command)), 400),
        "sides": [
            {"label": labels[0], "outcome": exits[0]},
            {"label": labels[1], "outcome": exits[1]},
        ],
        "divergences_total": len(ranked),
    }
    entries: list[dict] = []
    allowed: dict[str, set[str]] = {}
    truncated = len(ranked) > top
    for rank, d in enumerate(ranked[:top], start=1):
        for with_excerpts in (True, False):
            entry, ids = _divergence_entry(rank, d, labels, events, rank_config, with_excerpts)
            candidate = {**header, "divergences_included": len(entries) + 1,
                         "divergences": [*entries, entry]}  # fmt: skip
            if len(json.dumps(candidate)) <= max_chars:
                entries.append(entry)
                allowed[d.id] = ids
                break
        else:
            truncated = True
            break
    data = {**header, "divergences_included": len(entries), "divergences": entries}
    return Bundle(
        data=data,
        text=json.dumps(data),
        divergence_ids=[e["id"] for e in entries],
        events_by_divergence=allowed,
        truncated=truncated,
    )
