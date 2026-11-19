"""Router boundary tests.

The router deliberately registers no route, because no design document defines a
path, payload or authentication rule for sequence analysis.  These tests pin
that decision and cover the contract-level boundary function.
"""

from __future__ import annotations

import unittest

from routers import sequence as sequence_router
from services.sequence import SequenceEngine

from .support import ScriptedCueScorer, fixed_clock, load_fixture, make_config


class RouterBoundaryTests(unittest.TestCase):
    def tearDown(self) -> None:
        sequence_router.set_sequence_engine(None)

    def test_no_undocumented_route_is_registered(self) -> None:
        self.assertEqual(sequence_router.router.routes, [])

    def test_engine_must_be_injected_explicitly(self) -> None:
        with self.assertRaises(RuntimeError):
            sequence_router.get_sequence_engine()

    def test_boundary_function_processes_a_batch(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        sequence_router.set_sequence_engine(engine)
        batch_12 = load_fixture("batch_12_events.json")
        batch_13 = load_fixture("batch_13_events.json")

        first = sequence_router.process_normalized_events(batch_12)
        second = sequence_router.process_normalized_events(batch_13)

        self.assertEqual(first.cues, [])
        self.assertEqual(len(second.cues), 1)
        self.assertEqual(
            [cue.cue_id for cue in sequence_router.sequence_cues([])],
            [],
        )

    def test_boundary_function_accepts_explicit_engine(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        batch_12 = load_fixture("batch_12_events.json")
        batch_13 = load_fixture("batch_13_events.json")

        sequence_router.process_normalized_events(batch_12, engine=engine)
        cues = sequence_router.sequence_cues(batch_13, engine=engine)

        self.assertEqual(len(cues), 1)
        self.assertEqual(cues[0].event_ids, ["evt-1201", "evt-1202", "evt-1301"])


if __name__ == "__main__":
    unittest.main()
