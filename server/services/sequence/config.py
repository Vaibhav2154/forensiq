"""Configuration for the sequence workstream.

Every value in :class:`SequenceConfig` corresponds to a decision that
``docs/Sequential_Log_Context_Model.md`` records as open
("First implementation decision points" 1, 3 and 5):

1. scope keys and context time-to-live values,
3. sequence/window length and state-store design,
5. escalation thresholds and the orchestrator handoff contract.

No defaults are supplied here on purpose.  The workstream must not pick a
window size, threshold or TTL on its own, so the integration owner passes
approved values in explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import SequenceConfigError


@dataclass(frozen=True, slots=True)
class SequenceConfig:
    """Values the sequence engine requires from the approved decision set.

    Attributes:
        model_version: Stable identifier written into every ``SequenceCue``.
            Also used as the state-partition key, because the documentation
            requires state to be persisted per scope *and* model version.
        window_events: Maximum number of normalized events retained in each
            scope's bounded event window.
        threshold: Risk-score threshold above which a cue is emitted.  Must
            already be the approved value for this model version.
        state_ttl_seconds: Inactivity time-to-live for a scope's context.
    """

    model_version: str
    window_events: int
    threshold: float
    state_ttl_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.model_version, str) or not self.model_version.strip():
            raise SequenceConfigError("model_version must be a non-empty string")
        if (
            not isinstance(self.window_events, int)
            or isinstance(self.window_events, bool)
            or self.window_events < 1
        ):
            raise SequenceConfigError("window_events must be a positive integer")
        try:
            threshold = float(self.threshold)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise SequenceConfigError("threshold must be a number within [0.0, 1.0]") from exc
        if not 0.0 <= threshold <= 1.0:
            raise SequenceConfigError("threshold must be within [0.0, 1.0]")
        try:
            ttl = float(self.state_ttl_seconds)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise SequenceConfigError("state_ttl_seconds must be a positive number") from exc
        if ttl <= 0.0:
            raise SequenceConfigError("state_ttl_seconds must be positive")
