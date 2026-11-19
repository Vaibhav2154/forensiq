"""Shared helpers for the sequence workstream tests.

``ScriptedCueScorer`` is a deterministic **test double**, not a detector.  It
stands in for an approved model artifact so the engine's ordering, state
carry-over, replay and cue-emission *mechanism* can be exercised.  Its scores
carry no forensic meaning and are never presented as detection results.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from contracts.models import EvidenceReference, NormalizedEvent

from services.sequence import EventObservation, LstmState, SequenceConfig

UTC = timezone.utc

#: Fixed wall clock used for cue timestamps in tests.
FIXED_NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sequence"

DEFAULT_SCOPE = "host:workstation-17|account:alex"
OTHER_SCOPE = "host:server-04|account:svc-backup"

MODEL_VERSION = "lstm-sequence-v0.1"
THRESHOLD = 0.75
WINDOW_EVENTS = 4
TTL_SECONDS = 3600.0

AUTH_FAILURE = "authentication_failure"
PRIV_ESCALATION = "privilege_escalation"


def fixed_clock() -> datetime:
    return FIXED_NOW


def at(hour: int, minute: int = 0, second: int = 0) -> datetime:
    return datetime(2026, 11, 19, hour, minute, second, tzinfo=UTC)


def make_config(**overrides: Any) -> SequenceConfig:
    values: dict[str, Any] = {
        "model_version": MODEL_VERSION,
        "window_events": WINDOW_EVENTS,
        "threshold": THRESHOLD,
        "state_ttl_seconds": TTL_SECONDS,
    }
    values.update(overrides)
    return SequenceConfig(**values)


def make_event(
    event_id: str,
    *,
    event_time: datetime,
    event_type: str = AUTH_FAILURE,
    scope_key: str = DEFAULT_SCOPE,
    source: str = "linux-auth",
    features: dict[str, Any] | None = None,
    reference_id: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        scope_key=scope_key,
        event_time=event_time,
        event_type=event_type,
        source=source,
        features=features
        if features is not None
        else {
            "host": "workstation-17",
            "account": "alex",
            "outcome": "failure",
            "remote_ip": "203.0.113.25",
        },
        evidence_ref=EvidenceReference(
            reference_id=reference_id or f"evidence-{event_id}",
            uri=f"s3://forensiq-evidence/{event_id}.log",
        ),
    )


def load_fixture(name: str) -> list[NormalizedEvent]:
    payload = json.loads((FIXTURES / name).read_text())
    return [NormalizedEvent.model_validate(item) for item in payload]


class ScriptedCueScorer:
    """Deterministic stand-in for a model artifact (see module docstring).

    The state records how many events have been consumed and which of the two
    scripted event types have been observed *in this scope's own context*.  A
    crossing only happens once both types appear, so no single batch of the
    cross-batch fixture is sufficient on its own.
    """

    def initial_state(self) -> LstmState:
        return LstmState(hidden=(0.0, 0.0, 0.0), cell=(0.0,))

    def step(
        self, state: LstmState, observation: EventObservation
    ) -> tuple[LstmState, float]:
        count, seen_auth, seen_priv = state.hidden
        if observation.event_type == AUTH_FAILURE:
            seen_auth = 1.0
        if observation.event_type == PRIV_ESCALATION:
            seen_priv = 1.0
        next_count = count + 1.0
        score = 0.9 if (seen_auth and seen_priv) else 0.1
        return LstmState(hidden=(next_count, seen_auth, seen_priv), cell=(next_count,)), score


class ConstantScorer:
    """Scorer returning a fixed score, used to probe threshold behaviour."""

    def __init__(self, score: float) -> None:
        self._score = score

    def initial_state(self) -> LstmState:
        return LstmState(hidden=(0.0,), cell=(0.0,))

    def step(
        self, state: LstmState, observation: EventObservation
    ) -> tuple[LstmState, float]:
        return LstmState(hidden=(state.hidden[0] + 1.0,), cell=state.cell), self._score


def l2_scorer() -> object:
    """Reference LSTM cell artifact with two hidden units and three inputs.

    The weights are a fixed, explicitly arbitrary test artifact: this is not a
    trained model and its scores carry no meaning beyond exercising the cell.
    """

    from services.sequence import LstmCellScorer

    def vectorise(observation: EventObservation) -> list[float]:
        return [
            1.0 if observation.outcome == "failure" else 0.0,
            float(observation.window_event_count),
            float(observation.event_type_occurrences_in_window),
        ]

    return LstmCellScorer(
        {
            "w_i": [[0.1, 0.2, 0.0], [0.0, 0.1, 0.2]],
            "w_f": [[0.2, 0.0, 0.1], [0.1, 0.0, 0.0]],
            "w_o": [[0.0, 0.3, 0.1], [0.2, 0.0, 0.1]],
            "w_g": [[0.3, 0.1, 0.0], [0.0, 0.4, 0.2]],
            "u_i": [[0.1, 0.0], [0.0, 0.1]],
            "u_f": [[0.2, 0.0], [0.0, 0.2]],
            "u_o": [[0.0, 0.1], [0.1, 0.0]],
            "u_g": [[0.1, 0.1], [0.1, 0.1]],
            "b_i": [0.0, 0.0],
            "b_f": [0.0, 0.0],
            "b_o": [0.0, 0.0],
            "b_g": [0.0, 0.0],
            "w_out": [0.5, -0.5],
            "b_out": 0.0,
        },
        vectorise=vectorise,
    )


def times(minutes: Sequence[int], *, hour: int = 9) -> list[datetime]:
    base = at(hour)
    return [base + timedelta(minutes=offset) for offset in minutes]
