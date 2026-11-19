"""Documented feature transformation for normalized events.

Authority: ``docs/Sequential_Log_Context_Model.md`` section "Input features".
The documentation names feature *categories*, not a vector layout, so this
module produces a **named** observation record instead of a fixed-width
vector.  Choosing dimensions, a vocabulary, or an embedding layout is an open
documentation decision, so it is deliberately absent here and is instead
supplied to the scorer (see :class:`services.sequence.scoring.LstmCellScorer`,
which takes an explicit ``vectorise`` callable).

Features implemented, all traceable to normalized logs:

* ``event_type``, ``source`` — the documented event type and source category
  as provided by KCP (kept as identifiers, not encoded).
* ``outcome`` and ``severity`` when present.
* ``time_since_previous_seconds`` — documented "time since the previous event".
* Counts and a novelty indicator inside the current bounded window.
* Presence flags for the documented host, account, process, service and
  network relationship features.  Only presence is recorded so that raw
  identifiers stay linked as evidence rather than leaking into model input,
  as the documentation requires.

Not implemented because the documentation does not define them: the
"time-of-day bucket" boundaries, and any vector encoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from contracts.models import NormalizedEvent

from .errors import InvalidEventBatchError

#: Documented "Host, account, process, service, and network relationship
#: features".  Recorded as presence flags only.
CONTEXT_FEATURE_KEYS: tuple[str, ...] = (
    "host",
    "account",
    "process",
    "service",
    "remote_ip",
)


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) > 0
    return True


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


@dataclass(frozen=True, slots=True)
class EventObservation:
    """Named feature record for one normalized event.

    This is an internal feature record.  It is not a second copy of
    ``NormalizedEvent``: the event itself remains the input contract and
    travels alongside the observation inside the state window.
    """

    event_id: str
    scope_key: str
    event_type: str
    source: str
    outcome: str | None
    severity: float | None
    time_since_previous_seconds: float | None
    window_event_count: int
    event_type_occurrences_in_window: int
    first_event_type_occurrence_in_window: bool
    context_presence: Mapping[str, bool]
    severity_label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "scope_key": self.scope_key,
            "event_type": self.event_type,
            "source": self.source,
            "outcome": self.outcome,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "time_since_previous_seconds": self.time_since_previous_seconds,
            "window_event_count": self.window_event_count,
            "event_type_occurrences_in_window": self.event_type_occurrences_in_window,
            "first_event_type_occurrence_in_window": self.first_event_type_occurrence_in_window,
            "context_presence": dict(self.context_presence),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EventObservation":
        return cls(
            event_id=data["event_id"],
            scope_key=data["scope_key"],
            event_type=data["event_type"],
            source=data["source"],
            outcome=data.get("outcome"),
            severity=data.get("severity"),
            time_since_previous_seconds=data.get("time_since_previous_seconds"),
            window_event_count=int(data["window_event_count"]),
            event_type_occurrences_in_window=int(data["event_type_occurrences_in_window"]),
            first_event_type_occurrence_in_window=bool(
                data["first_event_type_occurrence_in_window"]
            ),
            context_presence={k: bool(v) for k, v in dict(data["context_presence"]).items()},
            severity_label=data.get("severity_label"),
        )


class FeatureExtractor:
    """Builds :class:`EventObservation` records from ``NormalizedEvent`` objects.

    Every key in ``NormalizedEvent.features`` is treated as optional; the
    contract does not validate or guarantee any of them, so a missing or
    oddly typed value never raises.
    """

    def build(
        self,
        event: NormalizedEvent,
        *,
        previous_event_time: datetime | None = None,
        window_observations: Sequence[EventObservation] = (),
    ) -> EventObservation:
        if not isinstance(event, NormalizedEvent):
            raise InvalidEventBatchError(
                "sequence features require contracts.models.NormalizedEvent objects, "
                f"received {type(event).__name__}"
            )

        features = event.features if isinstance(event.features, dict) else {}

        delta: float | None = None
        if previous_event_time is not None:
            delta = (event.event_time - previous_event_time).total_seconds()

        occurrences = sum(
            1 for observation in window_observations if observation.event_type == event.event_type
        )
        raw_sev = features.get("severity")
        severity_label = (
            raw_sev.strip().lower()
            if isinstance(raw_sev, str) and raw_sev.strip()
            else None
        )

        return EventObservation(
            event_id=event.event_id,
            scope_key=event.scope_key,
            event_type=event.event_type,
            source=event.source,
            outcome=_as_str(features.get("outcome")),
            severity=_as_float(raw_sev),
            time_since_previous_seconds=delta,
            window_event_count=len(window_observations) + 1,
            event_type_occurrences_in_window=occurrences,
            first_event_type_occurrence_in_window=occurrences == 0,
            context_presence={key: _is_present(features.get(key)) for key in CONTEXT_FEATURE_KEYS},
            severity_label=severity_label,
        )
