"""End-to-end tests with the trained LSTM artifact, SQLite persistence, KCP, and InvestigationService."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from contracts import BatchIngestRequest, EvidenceReference, RawLogRecord
from services.investigation import InvestigationService, InvestigationSettings
from services.investigation.service import SequenceCueProvider
from services.knowledge import KnowledgeService, KnowledgeSettings
from services.sequence import (
    SequenceEngineCueProvider,
    SequenceSettings,
    build_default_sequence_engine,
)

from .support import load_fixture


class TrainedLstmIntegrationTests(unittest.TestCase):
    def test_cross_batch_fixtures_fire_real_lstm_across_sqlite_reopen(self) -> None:
        batch_12 = load_fixture("batch_12_events.json")
        batch_13 = load_fixture("batch_13_events.json")

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "sequence_state.sqlite3"
            settings = SequenceSettings(store_backend="sqlite", state_db_path=db_path)

            solo_12 = build_default_sequence_engine(
                SequenceSettings(store_backend="memory")
            )
            self.assertEqual(solo_12.process_batch(batch_12).cues, [])

            solo_13 = build_default_sequence_engine(
                SequenceSettings(store_backend="memory")
            )
            self.assertEqual(solo_13.process_batch(batch_13).cues, [])

            engine1 = build_default_sequence_engine(settings)
            res1 = engine1.process_batch(batch_12)
            self.assertEqual(res1.cues, [])
            engine1.store.close()  # type: ignore[attr-defined]

            engine2 = build_default_sequence_engine(settings)
            res2 = engine2.process_batch(batch_13)
            self.assertEqual(len(res2.cues), 1)
            cue = res2.cues[0]
            self.assertEqual(cue.event_ids, ["evt-1201", "evt-1202", "evt-1301"])
            self.assertGreaterEqual(cue.risk_score, cue.threshold)
            self.assertEqual(cue.model_version, "lstm-sequence-v1.0")
            engine2.store.close()  # type: ignore[attr-defined]

    def test_kcp_normalized_attack_vs_benign_admin_workflow(self) -> None:
        kn = KnowledgeService(settings=KnowledgeSettings(store_backend="memory"))
        base = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)

        def make_batch(batch_id: str, lines: list[tuple[int, str, str]]) -> BatchIngestRequest:
            return BatchIngestRequest(
                batch_id=batch_id,
                source="linux:workstation-17",
                sent_at=base + timedelta(seconds=600),
                records=[
                    RawLogRecord(
                        record_id=f"raw-{batch_id}-{idx}",
                        observed_at=base + timedelta(seconds=offset),
                        message=msg,
                        source_type=src_type,
                        evidence_ref=EvidenceReference(
                            reference_id=f"ref-{batch_id}-{idx}",
                            uri=f"file:///var/log/{batch_id}.log",
                            line_start=idx,
                            line_end=idx,
                        ),
                        metadata={"host": "workstation-17"},
                    )
                    for idx, (offset, src_type, msg) in enumerate(lines, start=1)
                ],
            )

        attack_events = kn.normalize_batch(
            make_batch(
                "atk",
                [
                    (0, "linux-auth", "Failed password for alex from 203.0.113.25 port 22 ssh2"),
                    (45, "linux-auth", "Failed password for alex from 203.0.113.25 port 22 ssh2"),
                    (180, "linux-audit", "sudo: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/bin/cat /etc/shadow"),
                ],
            )
        )
        atk_engine = build_default_sequence_engine(SequenceSettings(store_backend="memory"))
        atk_result = atk_engine.process_batch(attack_events)
        self.assertEqual(len(atk_result.cues), 1)
        self.assertGreaterEqual(atk_result.cues[0].risk_score, 0.80)

        benign_events = kn.normalize_batch(
            make_batch(
                "benign",
                [
                    (0, "linux-auth", "Accepted publickey for alex from 10.0.0.5 port 55210 ssh2"),
                    (60, "linux-audit", "sudo: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/usr/bin/apt update"),
                ],
            )
        )
        benign_engine = build_default_sequence_engine(SequenceSettings(store_backend="memory"))
        benign_result = benign_engine.process_batch(benign_events)
        self.assertEqual(benign_result.cues, [])

    def test_investigation_service_provider_activates_sequence_analyst(self) -> None:
        async def _run() -> None:
            kn = KnowledgeService(settings=KnowledgeSettings(store_backend="memory"))
            await kn.initialize()

            def offline_runner(schema, system_prompt: str, user_prompt: str):
                raise RuntimeError("offline deterministic fallback mode")

            with tempfile.TemporaryDirectory() as tmpdir:
                seq_settings = SequenceSettings(
                    store_backend="sqlite",
                    state_db_path=Path(tmpdir) / "seq.sqlite3",
                )
                seq_engine = build_default_sequence_engine(seq_settings)
                provider = SequenceEngineCueProvider(seq_engine)
                self.assertIsInstance(provider, SequenceCueProvider)

                inv_svc = InvestigationService(
                    knowledge_service=kn,
                    settings=InvestigationSettings(_env_file=None, default_gemini_api_key="test-key"),
                    custom_runner=offline_runner,
                    sequence_provider=provider,
                )
                self.assertTrue(inv_svc.get_sanitized_config()["lstm_connected"])

                base = datetime(2026, 11, 19, 11, 0, 0, tzinfo=timezone.utc)
                batch1 = BatchIngestRequest(
                    batch_id="b12",
                    source="linux:workstation-17",
                    sent_at=base + timedelta(seconds=90),
                    records=[
                        RawLogRecord(
                            record_id="raw-b12-1",
                            observed_at=base,
                            message="Failed password for alex from 203.0.113.25 port 22 ssh2",
                            source_type="linux-auth",
                            evidence_ref=EvidenceReference(
                                reference_id="ev-b12-1",
                                uri="file:///var/log/auth.log",
                                line_start=1,
                                line_end=1,
                            ),
                            metadata={"host": "workstation-17"},
                        ),
                        RawLogRecord(
                            record_id="raw-b12-2",
                            observed_at=base + timedelta(seconds=60),
                            message="Failed password for alex from 203.0.113.25 port 22 ssh2",
                            source_type="linux-auth",
                            evidence_ref=EvidenceReference(
                                reference_id="ev-b12-2",
                                uri="file:///var/log/auth.log",
                                line_start=2,
                                line_end=2,
                            ),
                            metadata={"host": "workstation-17"},
                        ),
                    ],
                )
                res1 = await inv_svc.investigate_batch(batch1, top_k_knowledge=2)
                self.assertEqual(res1.sequence_assessment.status, "skipped_no_cues")

                batch2 = BatchIngestRequest(
                    batch_id="b13",
                    source="linux:workstation-17",
                    sent_at=base + timedelta(seconds=310),
                    records=[
                        RawLogRecord(
                            record_id="raw-b13-1",
                            observed_at=base + timedelta(seconds=300),
                            message="sudo: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                            source_type="linux-audit",
                            evidence_ref=EvidenceReference(
                                reference_id="ev-b13-1",
                                uri="file:///var/log/audit.log",
                                line_start=44,
                                line_end=44,
                            ),
                            metadata={"host": "workstation-17"},
                        ),
                    ],
                )
                res2 = await inv_svc.investigate_batch(batch2, top_k_knowledge=2)
                self.assertEqual(res2.sequence_assessment.status, "analyzed")
                self.assertEqual(len(res2.sequence_assessment.reviews), 1)
                review = res2.sequence_assessment.reviews[0]
                self.assertTrue(review.corroborated_by_events)
                self.assertIn("evt-b13-1", review.supporting_event_ids)
                self.assertEqual(
                    set(review.missing_event_ids),
                    {"evt-b12-1", "evt-b12-2"},
                )

                seq_engine.store.close()  # type: ignore[attr-defined]
                await kn.close()

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()

