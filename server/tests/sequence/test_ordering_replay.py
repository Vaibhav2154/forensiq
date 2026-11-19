"""Event-time ordering, late-event handling and bounded replay tests."""

from __future__ import annotations

import unittest

from services.sequence import FeatureExtractor, SequenceEngine, rebuild_window

from .support import (
    AUTH_FAILURE,
    DEFAULT_SCOPE,
    ScriptedCueScorer,
    at,
    fixed_clock,
    make_config,
    make_event,
)


class EventOrderingTests(unittest.TestCase):
    def test_batch_is_processed_in_event_time_order(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)

        engine.process_batch(
            [
                make_event("evt-late", event_time=at(9, 5)),
                make_event("evt-early", event_time=at(9, 2)),
                make_event("evt-middle", event_time=at(9, 4)),
            ]
        )

        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(
            state.event_ids, ["evt-early", "evt-middle", "evt-late"]
        )
        self.assertEqual(state.last_event_time, at(9, 5))
        self.assertEqual(
            [entry.observation.time_since_previous_seconds for entry in state.entries],
            [None, 120.0, 60.0],
        )

    def test_equal_timestamps_are_ordered_by_event_id(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)

        engine.process_batch(
            [
                make_event("evt-b", event_time=at(9, 0)),
                make_event("evt-a", event_time=at(9, 0)),
            ]
        )

        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.event_ids, ["evt-a", "evt-b"])


class LateEventReplayTests(unittest.TestCase):
    def test_late_event_is_replayed_in_event_time_order(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        engine.process_batch(
            [
                make_event("e1", event_time=at(9, 0)),
                make_event("e3", event_time=at(9, 4)),
            ]
        )

        result = engine.process_batch([make_event("e2", event_time=at(9, 2))])

        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.event_ids, ["e1", "e2", "e3"])
        self.assertFalse(state.replay_incomplete)
        self.assertIn("e2", result.processed_event_ids)
        self.assertEqual(result.skipped_event_ids, [])

    def test_replay_matches_a_full_recompute(self) -> None:
        events = [
            make_event("e1", event_time=at(9, 0)),
            make_event("e2", event_time=at(9, 2)),
            make_event("e3", event_time=at(9, 4)),
        ]

        incremental = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        incremental.process_batch([events[0], events[2]])
        incremental.process_batch([events[1]])
        incremental_state = incremental.state_for(DEFAULT_SCOPE)
        assert incremental_state is not None

        fresh = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        fresh.process_batch(events)
        fresh_state = fresh.state_for(DEFAULT_SCOPE)
        assert fresh_state is not None

        self.assertEqual(incremental_state.event_ids, fresh_state.event_ids)
        self.assertEqual(
            [entry.score for entry in incremental_state.entries],
            [entry.score for entry in fresh_state.entries],
        )
        self.assertEqual(
            [entry.state_after.hidden for entry in incremental_state.entries],
            [entry.state_after.hidden for entry in fresh_state.entries],
        )

    def test_replay_recomputes_from_the_window_anchor(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        engine.process_batch(
            [
                make_event("e1", event_time=at(9, 0)),
                make_event("e3", event_time=at(9, 4)),
            ]
        )
        engine.process_batch([make_event("e2", event_time=at(9, 2))])

        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        scorer = ScriptedCueScorer()
        expected = rebuild_window(
            [entry.event for entry in state.entries],
            scorer=scorer,
            extractor=FeatureExtractor(),
            anchor_state=state.entries[0].state_before,
        )
        self.assertEqual(
            [entry.state_after.hidden for entry in expected],
            [entry.state_after.hidden for entry in state.entries],
        )

    def test_late_event_older_than_a_trimmed_window_is_not_appended(self) -> None:
        engine = SequenceEngine(
            make_config(window_events=2), ScriptedCueScorer(), clock=fixed_clock
        )
        engine.process_batch(
            [
                make_event("e1", event_time=at(9, 0)),
                make_event("e2", event_time=at(9, 1)),
                make_event("e3", event_time=at(9, 2)),
            ]
        )

        result = engine.process_batch([make_event("e0", event_time=at(8, 59))])

        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.event_ids, ["e2", "e3"])
        self.assertTrue(state.replay_incomplete)
        self.assertEqual(result.skipped_event_ids, ["e0"])
        self.assertEqual(result.replay_incomplete_scope_keys, [DEFAULT_SCOPE])

    def test_early_late_event_extends_an_untrimmed_window(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        engine.process_batch([make_event("e1", event_time=at(9, 5))])

        engine.process_batch([make_event("e0", event_time=at(9, 0))])

        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.event_ids, ["e0", "e1"])
        self.assertFalse(state.trimmed)
        self.assertEqual(state.last_event_time, at(9, 5))
        self.assertEqual(
            state.entries[1].observation.time_since_previous_seconds, 300.0
        )

    def test_a_batch_boundary_is_not_a_sequence_boundary(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)

        first = engine.process_batch(
            [make_event("e1", event_time=at(9, 0), event_type=AUTH_FAILURE)]
        )

        state_after_first = engine.state_for(DEFAULT_SCOPE)
        assert state_after_first is not None
        self.assertEqual(state_after_first.event_ids, ["e1"])
        self.assertEqual(state_after_first.current_state.hidden, (1.0, 1.0, 0.0))

        second = engine.process_batch(
            [make_event("e2", event_time=at(9, 1), event_type="privilege_escalation")]
        )

        self.assertEqual(first.cues, [])
        self.assertEqual(len(second.cues), 1)

        state_after_second = engine.state_for(DEFAULT_SCOPE)
        assert state_after_second is not None
        self.assertEqual(state_after_second.event_ids, ["e1", "e2"])
        self.assertEqual(state_after_second.current_state.hidden, (2.0, 1.0, 1.0))


if __name__ == "__main__":
    unittest.main()
