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

import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import SequenceConfigError

SERVER_ROOT = Path(__file__).resolve().parents[2]


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
        if isinstance(self.threshold, bool):
            raise SequenceConfigError("threshold must be a finite number within [0.0, 1.0]")
        try:
            threshold = float(self.threshold)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise SequenceConfigError("threshold must be a finite number within [0.0, 1.0]") from exc
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise SequenceConfigError("threshold must be a finite number within [0.0, 1.0]")
        if isinstance(self.state_ttl_seconds, bool):
            raise SequenceConfigError("state_ttl_seconds must be a positive finite number")
        try:
            ttl = float(self.state_ttl_seconds)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise SequenceConfigError("state_ttl_seconds must be a positive finite number") from exc
        if not math.isfinite(ttl) or ttl <= 0.0:
            raise SequenceConfigError("state_ttl_seconds must be a positive finite number")


class SequenceSettings(BaseSettings):
    """Environment-backed runtime settings for wiring the LSTM sequence service."""

    model_config = SettingsConfigDict(env_prefix="SEQUENCE_", extra="ignore")

    model_version: str = "lstm-sequence-v1.0"
    window_events: int = 32
    threshold: float = 0.70
    state_ttl_seconds: float = 3600.0
    store_backend: Literal["sqlite", "memory"] = "sqlite"
    state_db_path: Path = Field(
        default_factory=lambda: (
            Path(os.getenv("SEQUENCE_STATE_DB_PATH"))
            if os.getenv("SEQUENCE_STATE_DB_PATH")
            else SERVER_ROOT / ".forensiq_sequence" / "sequence_state.sqlite3"
        )
    )
    artifact_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent / "artifacts" / "lstm_v1_0.json"
    )

    def to_config(self) -> SequenceConfig:
        """Convert settings into a validated ``SequenceConfig``."""
        return SequenceConfig(
            model_version=self.model_version,
            window_events=self.window_events,
            threshold=self.threshold,
            state_ttl_seconds=self.state_ttl_seconds,
        )
