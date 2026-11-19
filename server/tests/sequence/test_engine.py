"""Engine tests: cue construction, invalid input, expiry and reset behaviour."""

from __future__ import annotations

import unittest
from datetime import timedelta

from contracts.models import SequenceCue
from services.sequence import (
    BatchResult,
    InMemoryStateStore,
    InvalidEventBatchError,
    ScoringError,
    SequenceConfig,
    SequenceConfigError,
    SequenceEngine,
    StateCorruptionError,
    build_cue,
    build_window_ref,
)

from .support import (
    AUTH_FAILURE,
    DEFAULT_SCOPE,
    FIXED_NOW,
    MODEL_VERSION,
    PRIV_ESCALATION,
    ConstantScorer,
    ScriptedCueScorer,
    at,
    fixed_clock,
    make_config,
    make_event,
)


class SequenceConfigTests(unittest.TestCase):
    def test_requires_every_open_decision_value(self) -> None:
        with self.assertRaises(TypeError):
            SequenceConfig()  # type: ignore[call-arg]

    def test_rejects_unusable_values(self) -> None:
        with self.assertRaises(SequenceConfigError):
            make_config(window_events=0)
        with self.assertRaises(SequenceConfigError):
            make_config(threshold=1.5)
        with self.assertRaises(SequenceConfigError):
            make_config(state_ttl_seconds=0)
        with self.assertRaises(SequenceConfigError):
            make_config(model_version="  ")


class CueConstructionTests(unittest.TestCase):
    def test_cue_is_built_from_documented_fields_only(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        engine.process_batch([make_event("evt-1", event_time=at(9, 0), event_type=AUTH_FAILURE)])

        result = engine.process_batch(
            [make_event("evt-2", event_time=at(9, 1), event_type=PRIV_ESCALATION)]
        )

        self.assertEqual(len(result.cues), 1)
        cue = result.cues[0]
        self.assertIsInstance(cue, SequenceCue)
        self.assertEqual(cue.scope_key, DEFAULT_SCOPE)
        self.assertEqual(cue.event_ids, ["evt-1", "evt-2"])
        self.assertEqual(cue.risk_score, 0.9)
        self.assertEqual(cue.threshold, 0.75)
        self.assertEqual(cue.model_version, MODEL_VERSION)
        self.assertEqual(cue.created_at, FIXED_NOW)
        self.assertTrue(cue.window_ref.startswith(f"window:{DEFAULT_SCOPE}:"))
        self.assertEqual(cue.schema_version, "1.0")

    def test_cue_identifier_is_deterministic(self) -> None:
        def run() -> str:
            engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
            engine.process_batch(
                [make_event("evt-1", event_time=at(9, 0), event_type=AUTH_FAILURE)]
            )
            result = engine.process_batch(
                [make_event("evt-2", event_time=at(9, 1), event_type=PRIV_ESCALATION)]
            )
            return result.cues[0].cue_id

        self.assertEqual(run(), run())

    def test_cue_requires_a_contributing_event(self) -> None:
        with self.assertRaises(ScoringError):
            build_cue(
                scope_key=DEFAULT_SCOPE,
                event_ids=[],
                risk_score=0.9,
                threshold=0.75,
                model_version=MODEL_VERSION,
                window_ref=build_window_ref(DEFAULT_SCOPE, at(9, 0)),
                created_at=FIXED_NOW,
            )

    def test_cue_rejects_values_outside_the_contract(self) -> None:
        with self.assertRaises(ScoringError):
            build_cue(
                scope_key=DEFAULT_SCOPE,
                event_ids=["evt-1"],
                risk_score=1.4,
                threshold=0.75,
                model_version=MODEL_VERSION,
                window_ref=build_window_ref(DEFAULT_SCOPE, at(9, 0)),
                created_at=FIXED_NOW,
            )

    def test_threshold_comparison_is_inclusive(self) -> None:
        crossing = SequenceEngine(make_config(), ConstantScorer(0.75), clock=fixed_clock)
        below = SequenceEngine(make_config(), ConstantScorer(0.74), clock=fixed_clock)
        event = [make_event("evt-1", event_time=at(9, 0))]

        self.assertEqual(len(crossing.process_batch(event).cues), 1)
        self.assertEqual(len(below.process_batch(event).cues), 0)


class InvalidInputTests(unittest.TestCase):
    def test_empty_batch_is_a_no_op(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)

        result = engine.process_batch([])

        self.assertIsInstance(result, BatchResult)
        self.assertEqual(result.cues, [])
        self.assertEqual(result.processed_event_ids, [])
        self.assertIsNone(engine.state_for(DEFAULT_SCOPE))

    def test_non_contract_events_are_rejected(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)

        with self.assertRaises(InvalidEventBatchError):
            engine.process_batch([{"event_id": "evt-1"}])  # type: ignore[list-item]

    def test_naive_timestamps_cannot_reach_the_engine(self) -> None:
        from datetime import datetime

        with self.assertRaises(Exception):
            make_event("evt-1", event_time=datetime(2026, 11, 19, 9, 0))


class ExpiryAndResetTests(unittest.TestCase):
    def test_inactive_context_expires(self) -> None:
        engine = SequenceEngine(
            make_config(state_ttl_seconds=600), ScriptedCueScorer(), clock=fixed_clock
        )
        engine.process_batch([make_event("evt-1", event_time=at(9, 0), event_type=AUTH_FAILURE)])

        result = engine.process_batch(
            [make_event("evt-2", event_time=at(11, 0), event_type=PRIV_ESCALATION)]
        )

        self.assertEqual(result.expired_scope_keys, [DEFAULT_SCOPE])
        self.assertEqual(result.cues, [])
        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.event_ids, ["evt-2"])
        self.assertEqual(state.reset_reason, "ttl-expired")

    def test_expire_sweeps_inactive_scopes(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        engine.process_batch([make_event("evt-1", event_time=at(9, 0))])

        self.assertEqual(engine.expire(at(9)), [])
        self.assertEqual(engine.expire(at(12)), [DEFAULT_SCOPE])
        self.assertIsNone(engine.state_for(DEFAULT_SCOPE))

    def test_model_version_change_resets_state(self) -> None:
        store = InMemoryStateStore()
        old_engine = SequenceEngine(
            make_config(model_version="lstm-sequence-v0.0"),
            ScriptedCueScorer(),
            store=store,
            clock=fixed_clock,
        )
        old_engine.process_batch(
            [make_event("evt-1", event_time=at(9, 0), event_type=AUTH_FAILURE)]
        )

        new_engine = SequenceEngine(
            make_config(model_version="lstm-sequence-v0.1"),
            ScriptedCueScorer(),
            store=store,
            clock=fixed_clock,
        )
        result = new_engine.process_batch(
            [make_event("evt-2", event_time=at(9, 1), event_type=PRIV_ESCALATION)]
        )

        self.assertEqual(result.reset_scope_keys, [DEFAULT_SCOPE])
        self.assertEqual(result.cues, [])
        state = new_engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.event_ids, ["evt-2"])
        self.assertEqual(state.reset_reason, "model-version-change")

    def test_corrupted_state_is_reset_instead_of_reused(self) -> None:
        class CorruptingStore(InMemoryStateStore):
            def get(self, scope_key: str):  # type: ignore[override]
                raise StateCorruptionError("stored record is unreadable")

        engine = SequenceEngine(
            make_config(), ScriptedCueScorer(), store=CorruptingStore(), clock=fixed_clock
        )

        result = engine.process_batch(
            [make_event("evt-1", event_time=at(9, 0), event_type=PRIV_ESCALATION)]
        )

        self.assertEqual(result.reset_scope_keys, [DEFAULT_SCOPE])
        self.assertEqual(result.cues, [])


if __name__ == "__main__":
    unittest.main()
