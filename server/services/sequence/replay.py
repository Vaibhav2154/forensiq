"""Replay of the affected bounded window for late or out-of-order events.

Authority: ``docs/Sequential_Log_Context_Model.md`` (section "Batch processing
behavior", and "Recompute a bounded sequence when late events arrive"):

    When events arrive late or out of order, the system should replay the
    affected bounded window in event-time order rather than append them to a
    later state.

Replay here means: start from the anchor state (the state immediately before
the oldest retained event), then re-run every retained event plus the late
event in event-time order, recomputing both the derived features and the LSTM
state.  No snapshot interval or extra checkpoint is introduced; the bounded
window's own oldest entry is the anchor.

The documentation does not define what to do when a late event belongs before
the retained window and the window has already dropped history.  Rather than
silently appending it to a later state (which the documentation forbids), such
an event is reported as unreplayable and left out of the window.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from contracts.models import NormalizedEvent

from .errors import InvalidEventBatchError
from .features import EventObservation, FeatureExtractor
from .scoring import LstmState, SequenceScorer, validate_score
from .window import WindowEntry, sort_entries


def order_events(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Order events by event time, with ``event_id`` as the deterministic tiebreak."""
    ordered = list(events)
    for event in ordered:
        if not isinstance(event, NormalizedEvent):
            raise InvalidEventBatchError(
                "sequence replay requires contracts.models.NormalizedEvent objects, "
                f"received {type(event).__name__}"
            )
    return sorted(ordered, key=lambda event: (event.event_time, event.event_id))


def rebuild_window(
    events: Iterable[NormalizedEvent],
    *,
    scorer: SequenceScorer,
    extractor: FeatureExtractor,
    anchor_state: LstmState,
) -> list[WindowEntry]:
    """Recompute a whole window in event-time order starting from ``anchor_state``."""
    ordered = order_events(events)
    entries: list[WindowEntry] = []
    state = anchor_state
    previous_event_time = None

    for event in ordered:
        observation = extractor.build(
            event,
            previous_event_time=previous_event_time,
            window_observations=[entry.observation for entry in entries],
        )
        next_state, score = scorer.step(state, observation)
        entries.append(
            WindowEntry(
                event=event,
                observation=observation,
                state_before=state,
                state_after=next_state,
                score=validate_score(score),
            )
        )
        state = next_state
        previous_event_time = event.event_time

    return entries


def score_for_event(entries: Sequence[WindowEntry], event_id: str) -> float | None:
    """Score produced for ``event_id`` by the most recent replay pass.

    The last matching entry wins, which keeps the reported score consistent
    with the retained window when the same event id appears more than once.
    """
    for entry in reversed(entries):
        if entry.event.event_id == event_id:
            return entry.score
    return None


def observations(entries: Sequence[WindowEntry]) -> list[EventObservation]:
    return [entry.observation for entry in entries]


__all__ = [
    "observations",
    "order_events",
    "rebuild_window",
    "score_for_event",
    "sort_entries",
]
