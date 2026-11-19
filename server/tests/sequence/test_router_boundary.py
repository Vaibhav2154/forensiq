"""Sequence router unit and HTTP boundary tests."""

from __future__ import annotations

import unittest
from urllib.parse import quote

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers import sequence as sequence_router
from services.sequence import SequenceEngine

from .support import (
    AUTH_FAILURE,
    DEFAULT_SCOPE,
    PRIV_ESCALATION,
    ScriptedCueScorer,
    at,
    fixed_clock,
    load_fixture,
    make_config,
    make_event,
)


class RouterBoundaryTests(unittest.TestCase):
    def tearDown(self) -> None:
        sequence_router.set_sequence_engine(None)

    def _client(self) -> TestClient:
        app = FastAPI()
        app.include_router(sequence_router.router)
        return TestClient(app)

    def test_engine_must_be_injected_explicitly(self) -> None:
        with self.assertRaises(RuntimeError):
            sequence_router.get_sequence_engine()

    def test_http_endpoints_return_503_when_engine_not_configured(self) -> None:
        client = self._client()
        resp = client.get("/api/v1/sequence/status")
        self.assertEqual(resp.status_code, 503)

    def test_http_endpoints_evaluate_inspect_and_expire(self) -> None:
        engine = SequenceEngine(make_config(), ScriptedCueScorer(), clock=fixed_clock)
        sequence_router.set_sequence_engine(engine)
        client = self._client()

        status_resp = client.get("/api/v1/sequence/status")
        self.assertEqual(status_resp.status_code, 200)
        status_body = status_resp.json()
        self.assertTrue(status_body["lstm_ready"])
        self.assertEqual(status_body["active_scopes_count"], 0)

        batch_12 = [
            evt.model_dump(mode="json") for evt in load_fixture("batch_12_events.json")
        ]
        batch_13 = [
            evt.model_dump(mode="json") for evt in load_fixture("batch_13_events.json")
        ]

        r1 = client.post("/api/v1/sequence/evaluate", json={"events": batch_12})
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json()["cues"], [])
        self.assertEqual(len(r1.json()["processed_event_ids"]), 2)

        r2 = client.post("/api/v1/sequence/evaluate", json={"events": batch_13})
        self.assertEqual(r2.status_code, 200)
        body2 = r2.json()
        self.assertEqual(len(body2["cues"]), 1)
        self.assertEqual(
            body2["cues"][0]["event_ids"], ["evt-1201", "evt-1202", "evt-1301"]
        )

        scope_resp = client.get(f"/api/v1/sequence/scopes/{quote(DEFAULT_SCOPE, safe='')}")
        self.assertEqual(scope_resp.status_code, 200)
        scope_body = scope_resp.json()
        self.assertEqual(scope_body["scope_key"], DEFAULT_SCOPE)
        self.assertEqual(scope_body["event_ids"], ["evt-1201", "evt-1202", "evt-1301"])
        self.assertEqual(scope_body["latest_score"], 0.9)

        missing_resp = client.get("/api/v1/sequence/scopes/nonexistent")
        self.assertEqual(missing_resp.status_code, 404)

        expire_resp = client.post("/api/v1/sequence/expire")
        self.assertEqual(expire_resp.status_code, 200)
        self.assertEqual(expire_resp.json()["expired_scope_keys"], [DEFAULT_SCOPE])

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
