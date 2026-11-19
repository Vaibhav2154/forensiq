"""LSTM sequential-context workstream (Developer 2).

Consumes the shared ``NormalizedEvent`` contract and produces shared
``SequenceCue`` contract objects.  Nothing in this package imports another
workstream's implementation: the only shared surface is
``server/contracts/``.

Public API:

* :class:`SequenceConfig` - approved values the engine requires.
* :class:`SequenceEngine` - batch processing with per-scope retained context.
* :class:`BatchResult` - cues plus reset/expiry/replay reporting.
* :class:`SequenceScorer` / :class:`LstmCellScorer` - model boundary and a
  dependency-free LSTM cell driven by an injected artifact.
* :class:`StateStore` / :class:`InMemoryStateStore` - storage boundary and the
  process-local implementation (a durable backend is an open decision).
* :class:`ScopeState` - the retained per-scope context record.

Known documentation gaps are recorded in the module docstrings rather than
worked around: confidence/calibration output has no contract field, the
time-of-day bucket boundaries are undefined, and the feature vector encoding,
window size, threshold, TTL, persistence backend and HTTP surface are open
decisions.
"""

from __future__ import annotations

from .config import SequenceConfig, SequenceSettings
from .cues import build_cue, build_cue_id, build_window_ref
from .engine import BatchResult, SequenceEngine
from .errors import (
    InvalidEventBatchError,
    ScoringError,
    SequenceConfigError,
    SequenceError,
    StateCorruptionError,
)
from .features import CONTEXT_FEATURE_KEYS, EventObservation, FeatureExtractor
from .provider import (
    SequenceEngineCueProvider,
    build_default_sequence_engine,
    load_lstm_scorer,
)
from .replay import order_events, rebuild_window
from .scoring import LstmCellScorer, LstmState, SequenceScorer, validate_score
from .sqlite_store import SQLiteStateStore
from .state import STATE_FORMAT_VERSION, InMemoryStateStore, ScopeState, StateStore
from .vectorizer import VECTOR_SIZE, vectorize_observation

__all__ = [
    "BatchResult",
    "CONTEXT_FEATURE_KEYS",
    "EventObservation",
    "FeatureExtractor",
    "InMemoryStateStore",
    "InvalidEventBatchError",
    "LstmCellScorer",
    "LstmState",
    "STATE_FORMAT_VERSION",
    "SQLiteStateStore",
    "ScoringError",
    "ScopeState",
    "SequenceConfig",
    "SequenceConfigError",
    "SequenceEngine",
    "SequenceEngineCueProvider",
    "SequenceError",
    "SequenceScorer",
    "SequenceSettings",
    "StateCorruptionError",
    "StateStore",
    "VECTOR_SIZE",
    "build_cue",
    "build_cue_id",
    "build_default_sequence_engine",
    "build_window_ref",
    "load_lstm_scorer",
    "order_events",
    "rebuild_window",
    "validate_score",
    "vectorize_observation",
]
