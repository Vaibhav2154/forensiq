"""Feature transformation tests (documented "Input features" behaviour)."""

from __future__ import annotations

import unittest

from services.sequence import FeatureExtractor, InvalidEventBatchError

from .support import AUTH_FAILURE, at, make_event


class FeatureExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = FeatureExtractor()

    def test_transforms_documented_attributes(self) -> None:
        event = make_event(
            "evt-1",
            event_time=at(9, 15),
            event_type=AUTH_FAILURE,
            features={
                "host": "workstation-17",
                "account": "alex",
                "outcome": "failure",
                "remote_ip": "203.0.113.25",
                "severity": 4,
            },
        )

        observation = self.extractor.build(event, previous_event_time=at(9, 10))

        self.assertEqual(observation.event_id, "evt-1")
        self.assertEqual(observation.scope_key, event.scope_key)
        self.assertEqual(observation.event_type, AUTH_FAILURE)
        self.assertEqual(observation.source, "linux-auth")
        self.assertEqual(observation.outcome, "failure")
        self.assertEqual(observation.severity, 4.0)
        self.assertEqual(observation.time_since_previous_seconds, 300.0)
        self.assertEqual(observation.window_event_count, 1)
        self.assertEqual(observation.event_type_occurrences_in_window, 0)
        self.assertTrue(observation.first_event_type_occurrence_in_window)

    def test_context_presence_flags_follow_documented_keys(self) -> None:
        event = make_event(
            "evt-2",
            event_time=at(9, 15),
            features={"host": "workstation-17", "process": "", "service": None},
        )

        presence = self.extractor.build(event).context_presence

        self.assertTrue(presence["host"])
        self.assertFalse(presence["account"])
        self.assertFalse(presence["process"])
        self.assertFalse(presence["service"])
        self.assertFalse(presence["remote_ip"])

    def test_absent_features_are_not_assumed(self) -> None:
        event = make_event("evt-3", event_time=at(9, 15), features={})

        observation = self.extractor.build(event)

        self.assertIsNone(observation.outcome)
        self.assertIsNone(observation.severity)
        self.assertIsNone(observation.time_since_previous_seconds)
        self.assertFalse(any(observation.context_presence.values()))

    def test_non_numeric_severity_is_not_coerced(self) -> None:
        event = make_event("evt-4", event_time=at(9, 15), features={"severity": "high"})
        self.assertIsNone(self.extractor.build(event).severity)

        boolean = make_event("evt-5", event_time=at(9, 15), features={"severity": True})
        self.assertIsNone(self.extractor.build(boolean).severity)

    def test_window_counts_and_novelty(self) -> None:
        first = self.extractor.build(make_event("evt-6", event_time=at(9, 0)))
        second = self.extractor.build(
            make_event("evt-7", event_time=at(9, 1)),
            previous_event_time=at(9, 0),
            window_observations=[first],
        )
        third = self.extractor.build(
            make_event("evt-8", event_time=at(9, 2)),
            previous_event_time=at(9, 1),
            window_observations=[first, second],
        )

        self.assertEqual(second.window_event_count, 2)
        self.assertEqual(third.window_event_count, 3)
        self.assertEqual(third.event_type_occurrences_in_window, 2)
        self.assertFalse(third.first_event_type_occurrence_in_window)
        self.assertEqual(third.time_since_previous_seconds, 60.0)

    def test_novel_event_type_within_window(self) -> None:
        first = self.extractor.build(make_event("evt-9", event_time=at(9, 0)))

        other = self.extractor.build(
            make_event("evt-10", event_time=at(9, 1), event_type="process_start"),
            previous_event_time=at(9, 0),
            window_observations=[first],
        )

        self.assertEqual(other.event_type_occurrences_in_window, 0)
        self.assertTrue(other.first_event_type_occurrence_in_window)

    def test_rejects_objects_outside_the_shared_contract(self) -> None:
        with self.assertRaises(InvalidEventBatchError):
            self.extractor.build({"event_id": "evt-x"})  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
