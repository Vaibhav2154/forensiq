"""Critical acceptance test: a batch-12 + batch-13 pattern produces a cue.

Authority: ``docs/Developer_Work_Plan.md`` Developer 2 task 8 and
``docs/Sequential_Log_Context_Model.md`` ("batch 12 and batch 13 may each look
benign when evaluated alone, while their ordered combination indicates an attack
pattern").

The scorer here is the deterministic test double from ``support``; the test
proves the state-carrying mechanism, not detection accuracy of a model.
"""

from __future__ import annotations

import unittest

from services.sequence import InMemoryStateStore, SequenceEngine

from .support import (
    DEFAULT_SCOPE,
    OTHER_SCOPE,
    ScriptedCueScorer,
    fixed_clock,
    load_fixture,
    make_config,
)


class CrossBatchDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.batch_12 = load_fixture("batch_12_events.json")
        self.batch_13 = load_fixture("batch_13_events.json")
        self.unrelated = load_fixture("unrelated_scope_events.json")

    def _engine(self, store: InMemoryStateStore | None = None) -> SequenceEngine:
        return SequenceEngine(
            make_config(),
            ScriptedCueScorer(),
            store=store if store is not None else InMemoryStateStore(),
            clock=fixed_clock,
        )

    def test_batch_12_alone_produces_no_cue(self) -> None:
        result = self._engine().process_batch(self.batch_12)

        self.assertEqual(result.cues, [])
        self.assertEqual(len(result.processed_event_ids), 2)

    def test_batch_13_alone_produces_no_cue(self) -> None:
        result = self._engine().process_batch(self.batch_13)

        self.assertEqual(result.cues, [])
        self.assertEqual(result.processed_event_ids, ["evt-1301"])

    def test_retained_state_makes_batch_12_plus_13_raise_a_cue(self) -> None:
        engine = self._engine()

        first = engine.process_batch(self.batch_12)
        second = engine.process_batch(self.batch_13)

        self.assertEqual(first.cues, [])
        self.assertEqual(len(second.cues), 1)

        cue = second.cues[0]
        self.assertEqual(cue.scope_key, DEFAULT_SCOPE)
        # The cue explains itself with the retained window across both batches.
        self.assertEqual(cue.event_ids, ["evt-1201", "evt-1202", "evt-1301"])
        self.assertGreaterEqual(cue.risk_score, cue.threshold)
        self.assertIn(DEFAULT_SCOPE, cue.window_ref)

    def test_restored_state_also_detects_the_pattern(self) -> None:
        store = InMemoryStateStore()
        self._engine(store).process_batch(self.batch_12)

        resumed = self._engine(store)
        result = resumed.process_batch(self.batch_13)

        self.assertEqual(len(result.cues), 1)
        self.assertEqual(result.cues[0].event_ids, ["evt-1201", "evt-1202", "evt-1301"])

    def test_unrelated_scope_does_not_influence_the_result(self) -> None:
        engine = self._engine()
        engine.process_batch(self.batch_12)

        combined = engine.process_batch(self.batch_13 + self.unrelated)

        cues = combined.cues
        self.assertEqual(len(cues), 1)
        self.assertEqual(cues[0].scope_key, DEFAULT_SCOPE)

        unrelated_state = engine.state_for(OTHER_SCOPE)
        assert unrelated_state is not None
        self.assertEqual(unrelated_state.event_ids, ["evt-1302"])
        self.assertEqual(unrelated_state.last_event_time.isoformat(), "2026-11-19T09:20:00+00:00")

    def test_unrelated_scope_alone_produces_no_cue(self) -> None:
        engine = self._engine()
        engine.process_batch(self.batch_12)

        result = engine.process_batch(self.unrelated)

        self.assertEqual(result.cues, [])
        self.assertEqual(result.processed_event_ids, ["evt-1302"])

    def test_two_scopes_each_holding_half_do_not_cross(self) -> None:
        engine = self._engine()
        engine.process_batch(self.batch_12)

        half = [
            event.model_copy(update={"scope_key": OTHER_SCOPE}) for event in self.batch_13
        ]
        result = engine.process_batch(half)

        self.assertEqual(result.cues, [])
        other_state = engine.state_for(OTHER_SCOPE)
        assert other_state is not None
        self.assertEqual(other_state.event_ids, ["evt-1301"])


if __name__ == "__main__":
    unittest.main()
