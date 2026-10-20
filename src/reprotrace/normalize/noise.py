"""Noise filter: find signatures that vary between runs of the same environment."""

from collections.abc import Sequence

from reprotrace.models import Event, NoiseProfile


def signature_set(events: Sequence[Event]) -> set[str]:
    """Return the signatures present in one normalized run (ignored events excluded)."""
    return {event.signature for event in events if event.signature is not None}


def build_noise_profile(runs: Sequence[Sequence[Event]]) -> NoiseProfile:
    """Mark signatures that are not present in every run as unstable.

    ``runs`` are normalized events of repeated runs of one command in one environment.
    With a single run nothing can be marked unstable, so every signature counts as stable;
    callers should capture with ``--runs 2`` or more to filter noise.
    """
    if not runs:
        raise ValueError("build_noise_profile needs at least one run")
    run_ids = [run[0].run_id if run else "" for run in runs]
    sets = [signature_set(run) for run in runs]
    seen = set().union(*sets)
    stable = set.intersection(*sets)
    return NoiseProfile(run_ids=run_ids, stable_count=len(stable), unstable=sorted(seen - stable))


def stable_events(events: Sequence[Event], profile: NoiseProfile) -> list[Event]:
    """Return events whose signature is stable in ``profile`` (ignored events dropped)."""
    unstable = frozenset(profile.unstable)
    return [e for e in events if e.signature is not None and e.signature not in unstable]
