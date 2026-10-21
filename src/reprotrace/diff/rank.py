"""Score and order divergences so the most likely cause comes first.

The score is a weighted average of six signals, each between 0 and 1. It is a heuristic,
not proof of cause; every score carries the human-readable reasons behind it.

Signals:
- failed_one_side: the same call failed on one side and succeeded on the other (1.0), or
  a failing call appears on one side only (weaker).
- category: how telling this kind of divergence usually is (RankConfig.category_weights).
- earliest_in_process: earlier divergences within a process rank higher; later ones are
  often consequences of earlier ones.
- stability: confirmed by repeated runs on both sides (noise already filtered).
- proximity_to_failing_exit: how close the evidence is to the failing side's exit.
- not_failure_consequence: 0 for the exit-status difference itself (the symptom being
  explained) and for events seen on one side only after that side's process stopped
  matching the other (error handling such as a traceback on the failing side, or the
  normal work the passing side went on to do); else 1. Only applies when exactly one side
  failed.
"""

from collections import defaultdict

from reprotrace.diff.compare import Comparison, Evidence
from reprotrace.models import Divergence, Event, RankConfig, SignalName


def _ordinal(n: int) -> str:
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _side_name(cmp: Comparison, side: str) -> str:
    return cmp.a_label if side == "a" else cmp.b_label


def category_value(kind: str, config: RankConfig) -> float:
    """Value of the ``category`` signal for a divergence kind."""
    base = kind.removesuffix("_in_a").removesuffix("_in_b")
    return config.category_weights.get(
        kind, config.category_weights.get(base, config.default_category_weight)
    )


def _failed_one_side(d: Divergence, ev: Evidence, cmp: Comparison, config: RankConfig
                     ) -> tuple[float, str | None]:  # fmt: skip
    benign = set(config.benign_errnos)
    a_err = next((e.errno for e in ev.a_events if e.errno and e.errno not in benign), None)
    b_err = next((e.errno for e in ev.b_events if e.errno and e.errno not in benign), None)
    if d.kind == "result_mismatch" and bool(a_err) != bool(b_err):
        failed, ok = ("a", "b") if a_err else ("b", "a")
        return 1.0, (
            f"failed on {_side_name(cmp, failed)} ({a_err or b_err}) but succeeded on "
            f"{_side_name(cmp, ok)}"
        )
    one_sided = bool(ev.a_events) != bool(ev.b_events)
    if one_sided and (a_err or b_err):
        side = "a" if ev.a_events else "b"
        return config.one_sided_failure_value, (
            f"failing call ({a_err or b_err}) seen only on {_side_name(cmp, side)}"
        )
    return 0.0, None


def _failing_events(ev: Evidence, cmp: Comparison) -> list[Event]:
    if cmp.failing_side == "a":
        return ev.a_events
    if cmp.failing_side == "b":
        return ev.b_events
    return []


def _proximity(ev: Evidence, cmp: Comparison) -> tuple[float, str | None]:
    events = _failing_events(ev, cmp)
    side = cmp.failing_side
    # Environment differences are fixed before the program runs; distance means nothing.
    if not events or side is None or ev.pair_index < 0:
        return 0.0, None
    exit_seq = max(cmp.exit_seq.get(side, 0), 1)
    seq = max(e.seq for e in events)
    distance = max(exit_seq - seq, 0)
    return min(seq / exit_seq, 1.0), (
        f"{distance} events before the failing exit on {_side_name(cmp, side)}"
    )


def _consequence(d: Divergence, ev: Evidence, cmp: Comparison) -> str | None:
    """Why ``d`` looks like a consequence of the failure rather than its cause, or None."""
    if cmp.failing_side is None:
        return None
    if d.kind == "exit_status_mismatch":
        return "the exit status is the symptom being explained, not a cause"
    if ev.pair_index < 0 or ev.pair_index >= len(cmp.process_pairs):
        return None
    if bool(ev.a_events) == bool(ev.b_events):
        return None
    side = "a" if ev.a_events else "b"
    boundary = cmp.last_matched_seq.get((ev.pair_index, side), -1)
    if all(e.seq > boundary for e in ev.a_events or ev.b_events):
        return (
            f"only on {_side_name(cmp, side)} after the two runs stopped matching: likely a "
            "consequence of an earlier difference"
        )
    return None


def _stability(cmp: Comparison) -> tuple[float, str]:
    a_ok, b_ok = cmp.a_run_count >= 2, cmp.b_run_count >= 2
    if a_ok and b_ok:
        return 1.0, (
            f"stable across repeated runs ({cmp.a_run_count} on {cmp.a_label}, "
            f"{cmp.b_run_count} on {cmp.b_label})"
        )
    single = [label for label, ok in ((cmp.a_label, a_ok), (cmp.b_label, b_ok)) if not ok]
    value = 0.75 if a_ok or b_ok else 0.5
    return value, f"single run on {' and '.join(single)}, so not confirmed against noise"


def _earliest(divergences: list[Divergence], cmp: Comparison) -> dict[str, tuple[float, str]]:
    by_process: dict[int, list[Divergence]] = defaultdict(list)
    for d in divergences:
        pair = cmp.evidence[d.id].pair_index
        # Environment differences are fixed at exec time, before anything in the root ran.
        by_process[0 if pair < 0 else pair].append(d)
    result: dict[str, tuple[float, str]] = {}
    for pair, items in by_process.items():
        name = cmp.process_pairs[pair][0] if pair < len(cmp.process_pairs) else "unmatched"
        for index, d in enumerate(items):
            value = 1.0 - index / len(items)
            result[d.id] = (
                value,
                f"{_ordinal(index + 1)} of {len(items)} divergences in process {name}",
            )
    return result


def rank_divergences(cmp: Comparison, config: RankConfig | None = None) -> list[Divergence]:
    """Return copies of ``cmp.divergences`` with score and reasons, best first.

    Ties keep trace order (divergence id), so output is deterministic.
    """
    config = config or RankConfig()
    total_weight = sum(config.weights.values()) or 1.0
    stability = _stability(cmp)
    earliest = _earliest(cmp.divergences, cmp)
    ranked: list[Divergence] = []
    for d in cmp.divergences:
        ev = cmp.evidence[d.id]
        consequence = _consequence(d, ev, cmp)
        category = category_value(d.kind, config)
        signals: dict[SignalName, tuple[float, str | None]] = {
            "failed_one_side": _failed_one_side(d, ev, cmp, config),
            "category": (category, f"{d.kind} (category weight {category:.1f})"),
            "earliest_in_process": earliest[d.id],
            "stability": stability,
            "proximity_to_failing_exit": _proximity(ev, cmp),
            "not_failure_consequence": (0.0, consequence) if consequence else (1.0, None),
        }
        score = sum(config.weights.get(name, 0.0) * value for name, (value, _) in signals.items())
        reasons = [reason for _, reason in signals.values() if reason]
        ranked.append(
            d.model_copy(update={"score": round(score / total_weight, 3), "reasons": reasons})
        )
    order = {d.id: i for i, d in enumerate(cmp.divergences)}
    ranked.sort(key=lambda d: (-d.score, order[d.id]))
    return ranked


def severity(divergence: Divergence, config: RankConfig | None = None) -> str:
    """``CRITICAL``, ``WARNING`` or ``INFO`` from the score (Design.md 4.1)."""
    config = config or RankConfig()
    if divergence.score >= config.critical_threshold:
        return "CRITICAL"
    if divergence.score >= config.warning_threshold:
        return "WARNING"
    return "INFO"
