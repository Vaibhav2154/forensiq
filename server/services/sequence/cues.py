"""Construction of the shared ``SequenceCue`` contract object.

Authority: ``docs/Developer_Work_Plan.md`` Developer 2 task 6 and
``docs/Sequential_Log_Context_Model.md`` section "Model outputs and handoff".

The cue carries exactly the fields the shared contract supports: scope key,
the event ids of the retained context window that produced the signal, the risk
score, the threshold, the model version, a context-window reference and a
creation time.  The contract has no field for confidence, predicted class,
calibration or evidence beyond these, so none is invented here.

Documentation gap recorded, not worked around: "Model outputs and handoff"
lists "confidence/calibration information" as an output, and ``SequenceCue``
cannot represent it.  Adding an optional field requires approval from every
affected producer and consumer of the contract, so it is left to that review.

``cue_id`` and ``window_ref`` formats are not documented.  Both are derived
deterministically from documented inputs so that replaying the same events for
the same scope and model version yields the same identifiers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from contracts.models import SequenceCue

from .errors import ScoringError

#: Fixed namespace for deterministic cue identifiers.
CUE_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "forensiq.sequence.cue")

#: Prefix for the context-window reference, matching the shape of the shared
#: ``sequence_cue.json`` fixture.
WINDOW_REF_PREFIX = "window"

_CUE_ID_PREFIX = "cue-"


def build_window_ref(scope_key: str, window_start: datetime | None) -> str:
    """Reference to the context window that produced a cue.

    Format: ``window:<scope_key>:<iso-8601 start time>``.
    """
    if not scope_key:
        raise ScoringError("window_ref requires a scope key")
    stamp = (window_start or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return f"{WINDOW_REF_PREFIX}:{scope_key}:{stamp.isoformat().replace('+00:00', 'Z')}"


def build_cue_id(model_version: str, scope_key: str, event_ids: list[str]) -> str:
    """Deterministic cue identifier for the same scope, model and event set."""
    key = "|".join([model_version, scope_key, *event_ids])
    return f"{_CUE_ID_PREFIX}{uuid.uuid5(CUE_ID_NAMESPACE, key).hex}"


def build_cue(
    *,
    scope_key: str,
    event_ids: list[str],
    risk_score: float,
    threshold: float,
    model_version: str,
    window_ref: str,
    created_at: datetime,
) -> SequenceCue:
    """Build and validate a ``SequenceCue``.

    Raises:
        ScoringError: if a value cannot be represented by the shared contract.
            The sequence workstream must never emit a cue the orchestrator
            cannot consume.
    """
    if not event_ids:
        raise ScoringError(
            "a SequenceCue requires at least one contributing event id "
            "(contract requirement: event_ids min_length=1)"
        )
    if not 0.0 <= float(risk_score) <= 1.0:
        raise ScoringError(f"risk_score {risk_score!r} is outside [0.0, 1.0]")
    if not 0.0 <= float(threshold) <= 1.0:
        raise ScoringError(f"threshold {threshold!r} is outside [0.0, 1.0]")

    created = created_at.astimezone(timezone.utc)

    return SequenceCue(
        cue_id=build_cue_id(model_version, scope_key, event_ids),
        scope_key=scope_key,
        event_ids=list(event_ids),
        risk_score=float(risk_score),
        threshold=float(threshold),
        model_version=model_version,
        window_ref=window_ref,
        created_at=created,
    )
