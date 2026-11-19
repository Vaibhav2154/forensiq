"""Sequence workstream boundary for the HTTP layer.

Conventions taken from ``server/routers/knowledge.py``: the router object lives
here, and the engine is injected through a module-level holder
(``set_sequence_engine`` / ``get_sequence_engine``) rather than constructed per
request.

Deliberately **not** implemented: endpoint paths, request/response envelopes,
status codes and authentication.  ``docs/Developer_Work_Plan.md`` gives
Developer 2 ownership of this file but assigns router registration and
server-wide wiring to the integration owner (conflict-prevention rule 2), and no
design document defines a path or payload for sequence analysis.  Inventing one
would publish an undocumented API, so this module registers no route and exposes
only the contract-level boundary:

* :func:`process_normalized_events` - ``NormalizedEvent`` objects in,
  :class:`services.sequence.BatchResult` (and therefore ``SequenceCue`` objects)
  out.
* :func:`sequence_cues` - the same call narrowed to its cue list.

The engine cannot be built here either: ``SequenceConfig`` requires an approved
model version, window size, threshold and TTL, and the scorer requires an
approved artifact.  Those are open documented decisions, so startup must inject
a configured engine.
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter

from contracts import NormalizedEvent, SequenceCue
from services.sequence import BatchResult, SequenceEngine

#: No routes are attached: see the module docstring.
router = APIRouter(tags=["Sequential Context"])

_sequence_engine: SequenceEngine | None = None


def set_sequence_engine(engine: SequenceEngine | None) -> None:
    """Inject the configured sequence engine (application startup or tests)."""
    global _sequence_engine
    _sequence_engine = engine


def get_sequence_engine() -> SequenceEngine:
    """Return the injected engine.

    Raises:
        RuntimeError: when no engine has been injected, because this workstream
            must not choose the window size, threshold, TTL, model version or
            scorer on its own.
    """
    if _sequence_engine is None:
        raise RuntimeError(
            "No SequenceEngine is configured. Inject an engine built from approved "
            "values with routers.sequence.set_sequence_engine() during startup."
        )
    return _sequence_engine


def process_normalized_events(
    events: Sequence[NormalizedEvent], *, engine: SequenceEngine | None = None
) -> BatchResult:
    """Process a batch of ``NormalizedEvent`` objects for an optional engine."""
    active = engine if engine is not None else get_sequence_engine()
    return active.process_batch(list(events))


def sequence_cues(
    events: Sequence[NormalizedEvent], *, engine: SequenceEngine | None = None
) -> list[SequenceCue]:
    """Return only the cues produced for a batch."""
    return process_normalized_events(events, engine=engine).cues


__all__ = [
    "get_sequence_engine",
    "process_normalized_events",
    "router",
    "sequence_cues",
    "set_sequence_engine",
]
