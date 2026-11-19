"""Fixed-width feature vector encoding for ``EventObservation`` records."""

from __future__ import annotations

import math

from .features import CONTEXT_FEATURE_KEYS, EventObservation

EVENT_TYPE_VOCAB: tuple[str, ...] = (
    "authentication_failure",
    "authentication_success",
    "privilege_escalation",
    "security_alert",
    "network_connection_error",
    "application_error",
    "application_warning",
)

SEVERITY_LABEL_MAP: dict[str, float] = {
    "critical": 1.0,
    "alert": 0.9,
    "error": 0.75,
    "warning": 0.5,
    "warn": 0.5,
    "info": 0.25,
    "debug": 0.1,
}

_FAILURE_OUTCOMES = frozenset({"failure", "failed", "denied", "rejected", "error"})
_SUCCESS_OUTCOMES = frozenset({"success", "accepted", "ok"})
_EXECUTED_OUTCOMES = frozenset({"executed", "completed", "started"})

VECTOR_SIZE: int = len(EVENT_TYPE_VOCAB) + 1 + 3 + 1 + 5 + len(CONTEXT_FEATURE_KEYS)


def _normalize_severity(observation: EventObservation) -> float:
    if observation.severity is not None and math.isfinite(observation.severity):
        value = float(observation.severity)
        if value <= 0.0:
            return 0.0
        if value <= 1.0:
            return value
        return min(value / 10.0, 1.0)
    if observation.severity_label:
        return SEVERITY_LABEL_MAP.get(observation.severity_label.strip().lower(), 0.25)
    return 0.0


def vectorize_observation(observation: EventObservation) -> list[float]:
    """Encode an ``EventObservation`` into a bounded 22-element float vector."""
    event_vec = [0.0] * (len(EVENT_TYPE_VOCAB) + 1)
    try:
        idx = EVENT_TYPE_VOCAB.index(observation.event_type)
    except ValueError:
        idx = len(EVENT_TYPE_VOCAB)
    event_vec[idx] = 1.0

    outcome = (observation.outcome or "").strip().lower()
    outcome_vec = [
        1.0 if outcome in _FAILURE_OUTCOMES else 0.0,
        1.0 if outcome in _SUCCESS_OUTCOMES else 0.0,
        1.0 if outcome in _EXECUTED_OUTCOMES else 0.0,
    ]

    severity_norm = _normalize_severity(observation)

    delta = observation.time_since_previous_seconds
    if delta is None or not math.isfinite(delta):
        delta_norm = 0.0
        burst_flag = 0.0
    else:
        clamped_delta = max(float(delta), 0.0)
        delta_norm = min(math.log1p(clamped_delta) / math.log1p(3600.0), 1.0)
        burst_flag = 1.0 if clamped_delta <= 300.0 else 0.0

    window_count_norm = min(max(float(observation.window_event_count), 0.0) / 10.0, 1.0)
    type_occ_norm = min(
        max(float(observation.event_type_occurrences_in_window), 0.0) / 5.0, 1.0
    )
    first_occ_flag = 1.0 if observation.first_event_type_occurrence_in_window else 0.0

    context_vec = [
        1.0 if observation.context_presence.get(key) else 0.0
        for key in CONTEXT_FEATURE_KEYS
    ]

    return [
        *event_vec,
        *outcome_vec,
        severity_norm,
        delta_norm,
        burst_flag,
        window_count_norm,
        type_occ_norm,
        first_occ_flag,
        *context_vec,
    ]

