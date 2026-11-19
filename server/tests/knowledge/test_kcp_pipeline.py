"""Tests for KCP normalization, auditable compression, dedup, and log normalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contracts import BatchIngestRequest, KnowledgeRecord, NormalizedEvent
from services.knowledge.config import KnowledgeSettings
from services.knowledge.kcp import (
    KCPPipeline,
    compress_text,
    normalize_batch,
)
from services.knowledge.storage import ManifestStore


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
MITRE_SAMPLE = FIXTURES_ROOT / "knowledge" / "mitre_sample_bundle.json"


def test_compress_text_is_auditable_and_preserves_meaning() -> None:
    raw = (
        "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) "
        "to brute force logins (Citation: TrendMicro Pawn Storm Dec 2020).  "
        "<p>See <code>auth.log</code> for failures.</p>"
    )
    cleaned, stats = compress_text(raw)
    assert "Valid Accounts" in cleaned
    assert "https://attack.mitre.org" not in cleaned
    assert "(Citation:" not in cleaned
    assert "<p>" not in cleaned
    assert "`auth.log`" in cleaned
    assert stats["stripped_citations"] == 1
    assert stats["stripped_html_tags"] >= 2
    assert len(cleaned) < len(raw)


@pytest.mark.asyncio
async def test_kcp_duplicate_handling_and_version_lineage(tmp_path: Path) -> None:
    manifest = ManifestStore(tmp_path / "manifest.db")
    manifest.initialize()

    class _ManifestBackedStore:
        async def initialize(self) -> None:
            manifest.initialize()

        async def close(self) -> None:
            manifest.close()

        async def upsert_records(self, records: list[KnowledgeRecord]):
            summary, _ = manifest.upsert_records(records)
            return summary

        async def get_by_record_id(self, record_id: str):
            return manifest.get_by_record_id(record_id)

        async def get_by_source_id(self, source_type: str, source_id: str):
            return manifest.get_by_source_id(source_type, source_id)

        async def get_related(self, record: KnowledgeRecord):
            return manifest.get_related(record)

        async def search(self, query):
            return manifest.lexical_search(query)

        async def stats(self):
            return manifest.stats("manifest")

        async def save_ingestion_run(self, run) -> None:
            manifest.save_ingestion_run(run)

        async def get_ingestion_run(self, run_id: str):
            return manifest.get_ingestion_run(run_id)

        async def list_ingestion_runs(self, limit: int = 20):
            return manifest.list_ingestion_runs(limit)

    store = _ManifestBackedStore()
    pipeline = KCPPipeline(
        settings=KnowledgeSettings(data_dir=tmp_path, store_backend="memory"),
        store=store,
    )

    run1 = await pipeline.ingest_mitre(path=MITRE_SAMPLE)
    assert run1.status == "completed"
    assert run1.inserted == run1.parsed
    assert run1.updated == 0
    assert run1.skipped == 0
    assert run1.compression_summary["total_stripped_citations"] > 0

    t1110 = await store.get_by_record_id("okf-mitre-t1110")
    assert t1110 is not None
    assert t1110.provenance["source_sha256"]
    assert t1110.provenance["content_sha256"]
    assert t1110.provenance["compression"]["raw_chars"] >= t1110.provenance["compression"]["compressed_chars"]

    # Re-ingest identical bundle: every record must be skipped cleanly
    run2 = await pipeline.ingest_mitre(path=MITRE_SAMPLE)
    assert run2.inserted == 0
    assert run2.updated == 0
    assert run2.skipped == run1.parsed

    # Modify a single object's description and bump version -> exactly 1 updated
    bundle = json.loads(MITRE_SAMPLE.read_text(encoding="utf-8"))
    for obj in bundle["objects"]:
        if obj.get("type") == "x-mitre-collection":
            obj["x_mitre_version"] = "17.2"
        if obj.get("type") == "attack-pattern" and obj.get("name") == "Brute Force":
            obj["description"] += " Updated guidance for password spraying."
    modified_bundle = tmp_path / "mitre_v17_2.json"
    modified_bundle.write_text(json.dumps(bundle), encoding="utf-8")

    run3 = await pipeline.ingest_mitre(path=modified_bundle)
    assert run3.updated == run3.parsed  # source_version bumped on all records
    history = manifest.get_version_history("okf-mitre-t1110")
    assert [h["source_version"] for h in history] == ["17.1", "17.2"]
    manifest.close()


def test_log_normalizer_matches_golden_batch_ingest_fixture() -> None:
    batch = BatchIngestRequest.model_validate_json(
        (FIXTURES_ROOT / "batch_ingest_request.json").read_text(encoding="utf-8")
    )
    expected = NormalizedEvent.model_validate_json(
        (FIXTURES_ROOT / "normalized_event.json").read_text(encoding="utf-8")
    )

    events = normalize_batch(batch)
    assert len(events) == 1
    actual = events[0]

    assert actual.event_id == expected.event_id
    assert actual.scope_key == expected.scope_key
    assert actual.event_time == expected.event_time
    assert actual.event_type == expected.event_type
    assert actual.source == expected.source
    assert actual.features == expected.features
    assert actual.evidence_ref == expected.evidence_ref


def test_log_normalizer_handles_accepted_sudo_and_generic_logs() -> None:
    payload = {
        "schema_version": "1.0",
        "batch_id": "batch-0013",
        "source": "cli-agent:web-02",
        "sent_at": "2026-11-19T09:20:00Z",
        "records": [
            {
                "record_id": "log-101",
                "observed_at": "2026-11-19T09:18:00Z",
                "message": "Accepted publickey for deploy from 198.51.100.10 port 51234",
                "source_type": "linux-auth",
                "evidence_ref": {
                    "reference_id": "ev-101",
                    "uri": "file:///var/log/auth.log",
                    "line_start": 10,
                    "line_end": 10,
                },
                "metadata": {},
            },
            {
                "record_id": "log-102",
                "observed_at": "2026-11-19T09:19:00Z",
                "message": "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                "source_type": "linux-auth",
                "evidence_ref": {
                    "reference_id": "ev-102",
                    "uri": "file:///var/log/auth.log",
                    "line_start": 11,
                    "line_end": 11,
                },
                "metadata": {},
            },
            {
                "record_id": "log-103",
                "observed_at": "2026-11-19T09:19:30Z",
                "message": "2026-11-19 09:19:30 ERROR Security alert: Unusual access pattern detected",
                "source_type": "app-security",
                "evidence_ref": {
                    "reference_id": "ev-103",
                    "uri": "file:///var/log/app.log",
                },
                "metadata": {"host": "api-01"},
            },
        ],
    }
    batch = BatchIngestRequest.model_validate(payload)
    events = normalize_batch(batch)

    assert len(events) == 3
    assert events[0].event_type == "authentication_success"
    assert events[0].scope_key == "host:web-02|account:deploy"
    assert events[0].features["remote_port"] == 51234

    assert events[1].event_type == "privilege_escalation"
    assert events[1].scope_key == "host:web-02|account:deploy"
    assert events[1].features["command"] == "/bin/cat /etc/shadow"

    assert events[2].event_type == "security_alert"
    assert events[2].scope_key == "host:api-01"
    assert events[2].evidence_ref.reference_id == "ev-103"
