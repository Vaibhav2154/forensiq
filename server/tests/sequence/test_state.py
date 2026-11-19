"""Per-scope state tests: boundedness, persistence and isolation."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from services.sequence import (
    InMemoryStateStore,
    ScopeState,
    SQLiteStateStore,
    SequenceEngine,
    StateCorruptionError,
)

from .support import (
    AUTH_FAILURE,
    DEFAULT_SCOPE,
    OTHER_SCOPE,
    ScriptedCueScorer,
    at,
    fixed_clock,
    load_fixture,
    make_config,
    make_event,
)


class StateWindowTests(unittest.TestCase):
    def test_event_window_is_bounded(self) -> None:
        engine = SequenceEngine(
            make_config(window_events=4), ScriptedCueScorer(), clock=fixed_clock
        )
        events = [
            make_event(f"evt-{index}", event_time=at(9, index)) for index in range(7)
        ]

        engine.process_batch(events)

        state = engine.state_for(DEFAULT_SCOPE)
        self.assertIsNotNone(state)
        assert state is not None
        self.assertEqual(state.window_size, 4)
        self.assertTrue(state.trimmed)
        self.assertEqual(state.event_ids, ["evt-3", "evt-4", "evt-5", "evt-6"])
        self.assertEqual(state.last_event_time, at(9, 6))

    def test_window_retains_evidence_references(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)

        engine.process_batch([make_event("evt-a", event_time=at(9, 0))])

        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.evidence_references, ["evidence-evt-a"])
        self.assertEqual(state.entries[0].event.evidence_ref.reference_id, "evidence-evt-a")


class StateSerializationTests(unittest.TestCase):
    def _state(self) -> ScopeState:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        engine.process_batch(load_fixture("batch_12_events.json"))
        state = engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        return state

    def test_state_round_trips_through_serialization(self) -> None:
        state = self._state()

        restored = ScopeState.from_dict(state.to_dict())

        self.assertEqual(restored.scope_key, state.scope_key)
        self.assertEqual(restored.model_version, state.model_version)
        self.assertEqual(restored.window_size, state.window_size)
        self.assertEqual(restored.event_ids, state.event_ids)
        self.assertEqual(restored.last_event_time, state.last_event_time)
        self.assertEqual(
            [entry.score for entry in restored.entries],
            [entry.score for entry in state.entries],
        )
        self.assertEqual(
            restored.current_state.hidden if restored.current_state else None,
            state.current_state.hidden if state.current_state else None,
        )

    def test_incompatible_state_format_is_rejected(self) -> None:
        payload = self._state().to_dict()
        payload["state_format_version"] = 99

        with self.assertRaises(StateCorruptionError):
            ScopeState.from_dict(payload)

    def test_malformed_state_is_rejected(self) -> None:
        with self.assertRaises(StateCorruptionError):
            ScopeState.from_dict({"scope_key": DEFAULT_SCOPE})

        with self.assertRaises(StateCorruptionError):
            ScopeState.from_dict(
                {
                    "state_format_version": 1,
                    "scope_key": DEFAULT_SCOPE,
                    "model_version": "lstm-sequence-v0.1",
                    "entries": [{"event": {"event_id": "broken"}}],
                }
            )

        corrupt_lstm_payload = self._state().to_dict()
        corrupt_lstm_payload["entries"][0]["state_before"]["hidden"] = "corrupted"
        with self.assertRaises(StateCorruptionError):
            ScopeState.from_dict(corrupt_lstm_payload)

        naive_ts_payload = self._state().to_dict()
        naive_ts_payload["last_event_time"] = "2026-11-19T09:16:00"
        with self.assertRaises(StateCorruptionError):
            ScopeState.from_dict(naive_ts_payload)


class StateRestorationTests(unittest.TestCase):
    def test_state_is_restored_by_a_new_engine_from_the_same_store(self) -> None:
        store = InMemoryStateStore()
        first_engine = SequenceEngine(
            make_config(), ScriptedCueScorer(), store=store, clock=fixed_clock
        )
        first_engine.process_batch(load_fixture("batch_12_events.json"))

        # A separate engine instance stands in for a later process reusing the
        # persisted per-scope record.
        second_engine = SequenceEngine(
            make_config(), ScriptedCueScorer(), store=store, clock=fixed_clock
        )
        result = second_engine.process_batch(load_fixture("batch_13_events.json"))

        state = second_engine.state_for(DEFAULT_SCOPE)
        assert state is not None
        self.assertEqual(state.event_ids, ["evt-1201", "evt-1202", "evt-1301"])
        self.assertEqual(
            state.entries[-1].observation.time_since_previous_seconds, 240.0
        )
        self.assertEqual(len(result.cues), 1)

    def test_scopes_are_isolated_from_each_other(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        engine.process_batch(
            [
                make_event("evt-main", event_time=at(9, 0), event_type=AUTH_FAILURE),
                make_event(
                    "evt-other",
                    event_time=at(9, 1),
                    event_type=AUTH_FAILURE,
                    scope_key=OTHER_SCOPE,
                ),
            ]
        )

        main_state = engine.state_for(DEFAULT_SCOPE)
        other_state = engine.state_for(OTHER_SCOPE)
        assert main_state is not None and other_state is not None

        self.assertEqual(main_state.event_ids, ["evt-main"])
        self.assertEqual(other_state.event_ids, ["evt-other"])
        self.assertEqual(main_state.scope_key, DEFAULT_SCOPE)
        self.assertEqual(other_state.scope_key, OTHER_SCOPE)
        self.assertEqual(main_state.last_event_time, at(9, 0))
        self.assertEqual(other_state.last_event_time, at(9, 1))


class SQLiteStateStoreTests(unittest.TestCase):
    def test_persists_across_reopen_and_resets_corrupt_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "seq_state.sqlite3"
            store1 = SQLiteStateStore(db_path)
            engine1 = SequenceEngine(
                make_config(), ScriptedCueScorer(), store=store1, clock=fixed_clock
            )
            engine1.process_batch(load_fixture("batch_12_events.json"))
            store1.close()

            store2 = SQLiteStateStore(db_path)
            engine2 = SequenceEngine(
                make_config(), ScriptedCueScorer(), store=store2, clock=fixed_clock
            )
            result = engine2.process_batch(load_fixture("batch_13_events.json"))
            self.assertEqual(len(result.cues), 1)
            self.assertEqual(
                result.cues[0].event_ids, ["evt-1201", "evt-1202", "evt-1301"]
            )
            store2.close()

            # Directly corrupt JSON in SQLite row and ensure engine recovers cleanly
            raw_conn = sqlite3.connect(str(db_path))
            raw_conn.execute(
                "UPDATE sequence_scope_state SET state_json = ? WHERE scope_key = ?",
                ("{not-valid-json", DEFAULT_SCOPE),
            )
            raw_conn.commit()
            raw_conn.close()

            store3 = SQLiteStateStore(db_path)
            engine3 = SequenceEngine(
                make_config(), ScriptedCueScorer(), store=store3, clock=fixed_clock
            )
            recovered = engine3.process_batch(load_fixture("batch_13_events.json"))
            self.assertEqual(recovered.reset_scope_keys, [DEFAULT_SCOPE])
            self.assertEqual(recovered.cues, [])
            restored_state = engine3.state_for(DEFAULT_SCOPE)
            assert restored_state is not None
            self.assertEqual(restored_state.reset_reason, "corrupted-state")
            self.assertEqual(restored_state.event_ids, ["evt-1301"])
            store3.close()


if __name__ == "__main__":
    unittest.main()
