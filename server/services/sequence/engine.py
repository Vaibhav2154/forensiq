"""Batch processing engine for per-scope sequential context.

Authority: ``docs/Sequential_Log_Context_Model.md`` ("Batch processing
behavior", "State lifecycle and safeguards") and ``docs/Developer_Work_Plan.md``
Developer 2 tasks 4-8.

What this engine does, and nothing more:

* groups a batch by ``scope_key`` so unrelated scopes never share state;
* orders each scope's events by event time before processing;
* continues from that scope's stored LSTM state instead of resetting at the
  batch boundary ("A batch boundary must not be treated as an attack
  boundary");
* keeps the bounded event window alongside the state for auditability;
* replays the affected window when a late event arrives;
* expires inactive context and resets state on a model-version change;
* emits a ``SequenceCue`` when a score crosses the configured threshold.

It does not declare incidents, findings or verdicts; a cue is a prioritisation
signal for the investigation orchestrator.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Sequence

from contracts.models import NormalizedEvent, SequenceCue

from . import replay, window
from .config import SequenceConfig
from .cues import build_cue, build_window_ref
from .errors import InvalidEventBatchError, StateCorruptionError
from .features import FeatureExtractor
from .scoring import SequenceScorer, validate_score
from .state import InMemoryStateStore, ScopeState, StateStore
from .window import WindowEntry


@dataclass(slots=True)
class BatchResult:
    """Outcome of processing one batch of normalized events."""

    cues: list[SequenceCue] = field(default_factory=list)
    processed_event_ids: list[str] = field(default_factory=list)
    #: Late events whose required history is no longer retained, so they could
    #: not be replayed and were not appended to a later state.
    skipped_event_ids: list[str] = field(default_factory=list)
    duplicate_event_ids: list[str] = field(default_factory=list)
    expired_scope_keys: list[str] = field(default_factory=list)
    reset_scope_keys: list[str] = field(default_factory=list)
    replay_incomplete_scope_keys: list[str] = field(default_factory=list)

    @property
    def has_replay_incomplete(self) -> bool:
        return bool(self.replay_incomplete_scope_keys)


class SequenceEngine:
    """Stateful, per-scope sequence processor.

    Args:
        config: Approved values (model version, window size, threshold, TTL).
            Nothing here is defaulted, because every one of them is an open
            documented decision.
        scorer: Model boundary.  An approved LSTM artifact or any other
            implementation of :class:`SequenceScorer` can be supplied; an
            untrained scorer produces scores that are not detection results.
        store: State storage boundary.  Defaults to the in-memory store, which
            is process-local and *not* the durable store the documentation
            requires; see :mod:`services.sequence.state`.
        extractor: Feature extractor override.
        clock: Callable returning the cue creation time; injectable for tests.
    """

    def __init__(
        self,
        config: SequenceConfig,
        scorer: SequenceScorer,
        *,
        store: StateStore | None = None,
        extractor: FeatureExtractor | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._scorer = scorer
        self._store: StateStore = store if store is not None else InMemoryStateStore()
        self._extractor = extractor if extractor is not None else FeatureExtractor()
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()

    @property
    def config(self) -> SequenceConfig:
        return self._config

    @property
    def store(self) -> StateStore:
        return self._store

    def state_for(self, scope_key: str) -> ScopeState | None:
        """Inspect the retained context for one scope (read-only usage)."""
        with self._lock:
            return self._store.get(scope_key)

    def process_batch(self, events: Sequence[NormalizedEvent]) -> BatchResult:
        """Process one batch, continuing each scope's stored context."""
        batch = list(events)
        for event in batch:
            if not isinstance(event, NormalizedEvent):
                raise InvalidEventBatchError(
                    "SequenceEngine.process_batch accepts contracts.models.NormalizedEvent "
                    f"objects; received {type(event).__name__}"
                )

        result = BatchResult()
        if not batch:
            return result

        grouped: dict[str, list[NormalizedEvent]] = {}
        for event in batch:
            grouped.setdefault(event.scope_key, []).append(event)

        with self._lock:
            for scope_key in sorted(grouped):
                state = self._load_state(scope_key, result)

                for event in replay.order_events(grouped[scope_key]):
                    state = self._apply_expiry(state, scope_key, event.event_time, result)
                    if state is None:
                        state = ScopeState(
                            scope_key=scope_key, model_version=self._config.model_version
                        )
                    self._process_event(state, event, result)

                if state is not None:
                    self._store.put(state)

        return result

    def expire(self, now: datetime) -> list[str]:
        """Drop context that has been inactive longer than the configured TTL."""
        expired: list[str] = []
        with self._lock:
            for scope_key in sorted(self._store.scope_keys()):
                state = self._store.get(scope_key)
                if state is None or state.last_event_time is None:
                    continue
                if self._is_expired(state, now):
                    self._store.delete(scope_key)
                    expired.append(scope_key)
        return expired

    # ---------------------------------------------------------------- state

    def _load_state(self, scope_key: str, result: BatchResult) -> ScopeState | None:
        try:
            state = self._store.get(scope_key)
        except StateCorruptionError:
            # Documented safeguard: reset on corrupted state.
            self._store.delete(scope_key)
            result.reset_scope_keys.append(scope_key)
            return self._fresh_state(scope_key, "corrupted-state")

        if state is None:
            return None
        if state.model_version != self._config.model_version:
            # Documented safeguard: reset on a material model change.
            self._store.delete(scope_key)
            result.reset_scope_keys.append(scope_key)
            return self._fresh_state(scope_key, "model-version-change")
        return state

    def _fresh_state(self, scope_key: str, reason: str) -> ScopeState:
        return ScopeState(
            scope_key=scope_key,
            model_version=self._config.model_version,
            reset_reason=reason,
        )

    def _apply_expiry(
        self,
        state: ScopeState | None,
        scope_key: str,
        now: datetime,
        result: BatchResult,
    ) -> ScopeState | None:
        if state is None or state.last_event_time is None:
            return state
        if not self._is_expired(state, now):
            return state
        self._store.delete(scope_key)
        if scope_key not in result.expired_scope_keys:
            result.expired_scope_keys.append(scope_key)
        return self._fresh_state(scope_key, "ttl-expired")

    def _is_expired(self, state: ScopeState, now: datetime) -> bool:
        if state.last_event_time is None:
            return False
        age = (now - state.last_event_time).total_seconds()
        return age > self._config.state_ttl_seconds

    # -------------------------------------------------------------- events

    def _process_event(
        self, state: ScopeState, event: NormalizedEvent, result: BatchResult
    ) -> None:
        if any(entry.event.event_id == event.event_id for entry in state.entries):
            result.duplicate_event_ids.append(event.event_id)
            return
        if state.entries and (event.event_time, event.event_id) < state.entries[-1].ordering_key:
            self._replay_late_event(state, event, result)
            return
        self._append_event(state, event, result)

    def _append_event(
        self, state: ScopeState, event: NormalizedEvent, result: BatchResult
    ) -> None:
        state_before = state.current_state or self._scorer.initial_state()
        observation = self._extractor.build(
            event,
            previous_event_time=state.last_event_time,
            window_observations=replay.observations(state.entries),
        )
        state_after, raw_score = self._scorer.step(state_before, observation)
        score = validate_score(raw_score)

        state.entries.append(
            WindowEntry(
                event=event,
                observation=observation,
                state_before=state_before,
                state_after=state_after,
                score=score,
            )
        )
        state.last_event_time = event.event_time
        if window.trim(state.entries, self._config.window_events):
            state.trimmed = True

        result.processed_event_ids.append(event.event_id)
        self._emit_cue_if_crossed(state, score, result)

    def _replay_late_event(
        self, state: ScopeState, event: NormalizedEvent, result: BatchResult
    ) -> None:
        if not state.entries:
            self._append_event(state, event, result)
            return

        if (
            (event.event_time, event.event_id) < state.entries[0].ordering_key
            and state.trimmed
        ):
            # The history needed to recompute this event has already been
            # dropped, and the documentation forbids appending it to a later
            # state.  Record it instead of inventing a result.
            state.replay_incomplete = True
            result.skipped_event_ids.append(event.event_id)
            if state.scope_key not in result.replay_incomplete_scope_keys:
                result.replay_incomplete_scope_keys.append(state.scope_key)
            return

        previous_scores = {entry.event.event_id: entry.score for entry in state.entries}
        anchor = state.anchor_state or self._scorer.initial_state()
        candidates = [entry.event for entry in state.entries]
        candidates.append(event)

        state.entries = replay.rebuild_window(
            candidates,
            scorer=self._scorer,
            extractor=self._extractor,
            anchor_state=anchor,
        )
        if window.trim(state.entries, self._config.window_events):
            state.trimmed = True
        state.last_event_time = (
            state.entries[-1].event.event_time if state.entries else None
        )
        state.replay_incomplete = False

        result.processed_event_ids.append(event.event_id)
        inserted_idx = next(
            (
                idx
                for idx, entry in enumerate(state.entries)
                if entry.event.event_id == event.event_id
            ),
            0,
        )
        for idx in range(inserted_idx, len(state.entries)):
            entry = state.entries[idx]
            if entry.score >= self._config.threshold and (
                entry.event.event_id == event.event_id
                or previous_scores.get(entry.event.event_id, -1.0) < self._config.threshold
            ):
                self._emit_cue_if_crossed(
                    state, entry.score, result, entries=state.entries[: idx + 1]
                )

    # ---------------------------------------------------------------- cues

    def _emit_cue_if_crossed(
        self,
        state: ScopeState,
        score: float,
        result: BatchResult,
        *,
        entries: Sequence[WindowEntry] | None = None,
    ) -> None:
        if score < self._config.threshold:
            return
        active_entries = list(entries) if entries is not None else state.entries
        event_ids = window.window_event_ids(active_entries)
        if not event_ids:
            return
        result.cues.append(
            build_cue(
                scope_key=state.scope_key,
                event_ids=event_ids,
                risk_score=score,
                threshold=self._config.threshold,
                model_version=self._config.model_version,
                window_ref=build_window_ref(
                    state.scope_key, window.window_start(active_entries)
                ),
                created_at=self._clock(),
            )
        )
