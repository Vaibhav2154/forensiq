"""Loader, factory, and InvestigationService adapter for the LSTM sequence engine."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Mapping

from contracts.models import NormalizedEvent, SequenceCue

from .config import SequenceSettings
from .engine import SequenceEngine
from .errors import SequenceConfigError
from .scoring import LstmCellScorer
from .sqlite_store import SQLiteStateStore
from .state import InMemoryStateStore, StateStore
from .vectorizer import VECTOR_SIZE, vectorize_observation


def load_lstm_scorer(artifact_path: Path | None = None) -> LstmCellScorer:
    """Load trained LSTM weights from disk into a :class:`LstmCellScorer`."""
    resolved = Path(artifact_path) if artifact_path is not None else SequenceSettings().artifact_path
    if not resolved.exists():
        raise SequenceConfigError(f"LSTM artifact not found at {resolved}")

    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SequenceConfigError(f"failed to read LSTM artifact {resolved}: {exc}") from exc

    if not isinstance(payload, Mapping):
        raise SequenceConfigError(f"invalid LSTM artifact at {resolved}: expected JSON object")

    input_size = payload.get("input_size")
    if input_size != VECTOR_SIZE:
        raise SequenceConfigError(
            f"LSTM artifact input_size {input_size!r} does not match vectorizer size {VECTOR_SIZE}"
        )

    weights = payload.get("weights")
    if not isinstance(weights, Mapping):
        raise SequenceConfigError(f"LSTM artifact {resolved} missing 'weights' object")

    return LstmCellScorer(weights, vectorise=vectorize_observation)


def build_default_sequence_engine(
    settings: SequenceSettings | None = None,
) -> SequenceEngine:
    """Build the runtime ``SequenceEngine`` using approved settings and trained artifact."""
    active_settings = settings or SequenceSettings()
    config = active_settings.to_config()
    scorer = load_lstm_scorer(active_settings.artifact_path)

    store: StateStore
    if active_settings.store_backend == "sqlite":
        store = SQLiteStateStore(active_settings.state_db_path)
    else:
        store = InMemoryStateStore()

    return SequenceEngine(config, scorer, store=store)


class SequenceEngineCueProvider:
    """Async ``SequenceCueProvider`` adapter wrapping :class:`SequenceEngine`."""

    def __init__(self, engine: SequenceEngine) -> None:
        self._engine = engine

    @property
    def engine(self) -> SequenceEngine:
        return self._engine

    async def get_cues(self, events: list[NormalizedEvent]) -> list[SequenceCue]:
        """Process normalized events and emit cross-batch ``SequenceCue`` objects."""
        result = await asyncio.to_thread(self._engine.process_batch, list(events))
        return result.cues


def get_artifact_metadata(artifact_path: Path | None = None) -> dict[str, Any]:
    """Read non-weight metadata from the LSTM artifact JSON."""
    resolved = Path(artifact_path) if artifact_path is not None else SequenceSettings().artifact_path
    if not resolved.exists():
        return {}
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {k: v for k, v in payload.items() if k != "weights"}

