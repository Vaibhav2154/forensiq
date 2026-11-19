"""Validate the shared JSON fixtures against the public contract models."""

from __future__ import annotations

import unittest
from pathlib import Path

from contracts import (
    BatchIngestRequest,
    InvestigationInput,
    KnowledgeRecord,
    NormalizedEvent,
    SequenceCue,
)


FIXTURES = Path(__file__).parents[1] / "fixtures"


class ContractFixtureTests(unittest.TestCase):
    def test_normalized_event_fixture(self) -> None:
        NormalizedEvent.model_validate_json((FIXTURES / "normalized_event.json").read_text())

    def test_knowledge_record_fixture(self) -> None:
        KnowledgeRecord.model_validate_json((FIXTURES / "knowledge_record.json").read_text())

    def test_sequence_cue_fixture(self) -> None:
        SequenceCue.model_validate_json((FIXTURES / "sequence_cue.json").read_text())

    def test_batch_ingest_fixture(self) -> None:
        BatchIngestRequest.model_validate_json((FIXTURES / "batch_ingest_request.json").read_text())

    def test_investigation_input_fixture(self) -> None:
        InvestigationInput.model_validate_json((FIXTURES / "investigation_input.json").read_text())
