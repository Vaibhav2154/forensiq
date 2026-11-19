"""Bounded event window entries and event-time ordering helpers.

Authority: ``docs/Sequential_Log_Context_Model.md``:

* "The system retains a bounded event window in addition to the LSTM state"
  because the hidden state alone is not auditable evidence.
* "For each scope, events are ordered by event time."
* "Keep the event window and evidence references for every alert-worthy score."

Each entry keeps the original ``NormalizedEvent`` (which carries
``evidence_ref``), the derived observation, and the LSTM state immediately
before and after that event.  Keeping the pre-event state of the oldest
retained event is what makes bounded replay possible without inventing a
snapshot interval: the window's oldest entry is its own anchor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from contracts.models import NormalizedEvent

from .errors import StateCorruptionError
from .features import EventObservation
from .scoring import LstmState


@dataclass(slots=True)
class WindowEntry:
    """One retained event with the state before and after it was processed."""

    event: NormalizedEvent
    observation: EventObservation
    state_before: LstmState
    state_after: LstmState
    score: float

    @property
    def ordering_key(self) -> tuple[datetime, str]:
        """Event time, then ``event_id``.

        The documentation requires event-time ordering but does not define a
        tiebreak; ``event_id`` is used so that equal timestamps still produce a
        deterministic, replayable order.
        """
        return (self.event.event_time, self.event.event_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.model_dump(mode="json"),
            "observation": self.observation.to_dict(),
            "state_before": self.state_before.to_dict(),
            "state_after": self.state_after.to_dict(),
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WindowEntry":
        try:
            return cls(
                event=NormalizedEvent.model_validate(data["event"]),
                observation=EventObservation.from_dict(data["observation"]),
                state_before=LstmState.from_dict(data["state_before"]),
                state_after=LstmState.from_dict(data["state_after"]),
                score=float(data["score"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateCorruptionError(f"invalid window entry: {exc}") from exc


def sort_entries(entries: Iterable[WindowEntry]) -> list[WindowEntry]:
    return sorted(entries, key=lambda entry: entry.ordering_key)


def trim(entries: list[WindowEntry], max_events: int) -> int:
    """Drop the oldest entries beyond ``max_events`` and report how many went."""
    excess = len(entries) - max_events
    if excess <= 0:
        return 0
    del entries[:excess]
    return excess


def window_event_ids(entries: Sequence[WindowEntry]) -> list[str]:
    return [entry.event.event_id for entry in entries]


def window_start(entries: Sequence[WindowEntry]) -> datetime | None:
    return entries[0].event.event_time if entries else None
