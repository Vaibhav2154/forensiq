"""Scorer boundary and LSTM cell tests.

The reference cell artifact is arbitrary and untrained: these tests exercise the
documented recurrence, not detection quality.
"""

from __future__ import annotations

import unittest

from services.sequence import (
    EventObservation,
    LstmCellScorer,
    LstmState,
    ScoringError,
    validate_score,
)

from .support import at, l2_scorer, make_event

from services.sequence import FeatureExtractor


class ValidateScoreTests(unittest.TestCase):
    def test_accepts_contract_range(self) -> None:
        self.assertEqual(validate_score(0.0), 0.0)
        self.assertEqual(validate_score(1), 1.0)

    def test_rejects_out_of_range_and_nan(self) -> None:
        for invalid in (1.5, -0.1, float("nan")):
            with self.assertRaises(ScoringError):
                validate_score(invalid)

    def test_rejects_non_numeric(self) -> None:
        with self.assertRaises(ScoringError):
            validate_score("0.5")  # type: ignore[arg-type]

        with self.assertRaises(ScoringError):
            validate_score(True)  # type: ignore[arg-type]


class LstmCellScorerTests(unittest.TestCase):
    def _observation(self, event_id: str = "evt-1") -> EventObservation:
        return FeatureExtractor().build(make_event(event_id, event_time=at(9, 0)))

    def test_state_shape_and_score_bounds_follow_the_artifact(self) -> None:
        scorer = l2_scorer()

        state, score = scorer.step(scorer.initial_state(), self._observation())

        self.assertEqual(len(state.hidden), 2)
        self.assertEqual(len(state.cell), 2)
        self.assertGreater(score, 0.0)
        self.assertLess(score, 1.0)

    def test_cell_is_deterministic(self) -> None:
        scorer = l2_scorer()
        observation = self._observation()

        first = scorer.step(scorer.initial_state(), observation)
        second = scorer.step(scorer.initial_state(), observation)

        self.assertEqual(first[0].hidden, second[0].hidden)
        self.assertEqual(first[0].cell, second[0].cell)
        self.assertEqual(first[1], second[1])

    def test_hidden_and_cell_state_advance_between_steps(self) -> None:
        scorer = l2_scorer()
        observation = self._observation()

        state_one, _ = scorer.step(scorer.initial_state(), observation)
        state_two, _ = scorer.step(state_one, observation)

        self.assertNotEqual(state_one.hidden, state_two.hidden)
        self.assertNotEqual(state_one.cell, state_two.cell)

    def test_input_size_mismatch_is_rejected(self) -> None:
        scorer = LstmCellScorer(
            {
                "w_i": [[0.1, 0.2]],
                "w_f": [[0.1, 0.0]],
                "w_o": [[0.1, 0.0]],
                "w_g": [[0.1, 0.0]],
                "u_i": [[0.1]],
                "u_f": [[0.1]],
                "u_o": [[0.1]],
                "u_g": [[0.1]],
                "b_i": [0.0],
                "b_f": [0.0],
                "b_o": [0.0],
                "b_g": [0.0],
                "w_out": [0.5],
                "b_out": 0.0,
            },
            vectorise=lambda observation: [1.0, 2.0, 3.0],
        )

        with self.assertRaises(ScoringError):
            scorer.step(scorer.initial_state(), self._observation())

    def test_incomplete_artifact_is_rejected(self) -> None:
        with self.assertRaises(ScoringError):
            LstmCellScorer({"w_i": [[0.1]]}, vectorise=lambda observation: [1.0])

    def test_ragged_weights_are_rejected(self) -> None:
        with self.assertRaises(ScoringError):
            LstmCellScorer(
                {
                    "w_i": [[0.1, 0.2], [0.3]],
                    "w_f": [[0.1, 0.0]],
                    "w_o": [[0.1, 0.0]],
                    "w_g": [[0.1, 0.0]],
                    "u_i": [[0.1]],
                    "u_f": [[0.1]],
                    "u_o": [[0.1]],
                    "u_g": [[0.1]],
                    "b_i": [0.0],
                    "b_f": [0.0],
                    "b_o": [0.0],
                    "b_g": [0.0],
                    "w_out": [0.5],
                    "b_out": 0.0,
                },
                vectorise=lambda observation: [1.0, 2.0],
            )

    def test_incoming_state_must_match_the_artifact(self) -> None:
        scorer = l2_scorer()

        with self.assertRaises(ScoringError):
            scorer.step(LstmState(hidden=(0.0,), cell=(0.0,)), self._observation())

    def test_mismatched_gate_column_count_is_rejected(self) -> None:
        with self.assertRaises(ScoringError):
            LstmCellScorer(
                {
                    "w_i": [[0.1, 0.2]],
                    "w_f": [[0.1]],
                    "w_o": [[0.1, 0.0]],
                    "w_g": [[0.1, 0.0]],
                    "u_i": [[0.1]],
                    "u_f": [[0.1]],
                    "u_o": [[0.1]],
                    "u_g": [[0.1]],
                    "b_i": [0.0],
                    "b_f": [0.0],
                    "b_o": [0.0],
                    "b_g": [0.0],
                    "w_out": [0.5],
                    "b_out": 0.0,
                },
                vectorise=lambda observation: [1.0, 2.0],
            )

    def test_non_finite_or_boolean_weights_and_state_are_rejected(self) -> None:
        with self.assertRaises(ScoringError):
            LstmState.from_dict({"hidden": "not-a-list", "cell": [0.0]})
        with self.assertRaises(ScoringError):
            LstmState.from_dict({"hidden": [float("nan")], "cell": [0.0]})
        with self.assertRaises(ScoringError):
            LstmCellScorer(
                {
                    "w_i": [[float("nan")]],
                    "w_f": [[0.1]],
                    "w_o": [[0.1]],
                    "w_g": [[0.1]],
                    "u_i": [[0.1]],
                    "u_f": [[0.1]],
                    "u_o": [[0.1]],
                    "u_g": [[0.1]],
                    "b_i": [0.0],
                    "b_f": [0.0],
                    "b_o": [0.0],
                    "b_g": [0.0],
                    "w_out": [0.5],
                    "b_out": 0.0,
                },
                vectorise=lambda observation: [1.0],
            )


if __name__ == "__main__":
    unittest.main()
