"""Integration and unit tests for the Cognee OKF knowledge adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.knowledge import KnowledgeSearchQuery, KnowledgeService, KnowledgeSettings
from services.knowledge.storage import matches_filters


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "knowledge"
MITRE_SAMPLE = FIXTURES_DIR / "mitre_sample_bundle.json"
CVE_SAMPLE = FIXTURES_DIR / "cve_sample"


@pytest.mark.asyncio
async def test_cognee_end_to_end_ingest_dedup_and_provenance_retrieval(
    tmp_path: Path,
) -> None:
    settings = KnowledgeSettings(data_dir=tmp_path / "cognee_store", store_backend="cognee")
    service = KnowledgeService(settings=settings)

    try:
        await service.initialize()

        mitre_run = await service.ingest_mitre(path=MITRE_SAMPLE)
        assert mitre_run.status == "completed"
        assert mitre_run.inserted == mitre_run.parsed
        assert mitre_run.parsed > 0

        cve_run = await service.ingest_cve(path=CVE_SAMPLE)
        assert cve_run.status == "completed_with_errors"
        assert cve_run.inserted == 3
        assert cve_run.rejected_or_filtered == 1
        assert cve_run.failed == 1

        # Re-ingesting identical samples skips everything cleanly without calling Cognee again
        mitre_rerun = await service.ingest_mitre(path=MITRE_SAMPLE)
        assert mitre_rerun.inserted == 0
        assert mitre_rerun.updated == 0
        assert mitre_rerun.skipped == mitre_run.parsed

        # Exact provenance retrieval for T1110 and 1-hop related records
        t1110_detail = await service.get_by_source(
            "mitre_attack", "T1110", include_related=True
        )
        assert t1110_detail is not None
        assert t1110_detail.record.record_id == "okf-mitre-t1110"
        assert t1110_detail.record.provenance["source_uri"] == "https://attack.mitre.org/techniques/T1110"
        assert len(t1110_detail.record.provenance["source_sha256"]) == 64
        related_ids = {r.source_id for r in t1110_detail.related_records}
        assert "TA0006" in related_ids

        # Exact provenance retrieval for CVE-2025-39447
        cve_detail = await service.get_by_source("cve", "CVE-2025-39447")
        assert cve_detail is not None
        assert cve_detail.record.record_id == "okf-cve-2025-39447"
        assert cve_detail.record.content["severity"]["base_score"] == 7.5
        assert "source_sha256" in cve_detail.record.provenance

        # Semantic Cognee vector retrieval for ATT&CK
        mitre_hits = await service.search(
            KnowledgeSearchQuery(
                query="password guessing brute force credential access",
                source_type="mitre_attack",
                top_k=3,
                search_mode="semantic",
            )
        )
        assert mitre_hits.total_hits >= 1
        top_ids = {h.record.source_id for h in mitre_hits.hits}
        assert top_ids & {"T1110", "T1110.001"}
        assert all(h.is_evidence_proof is False for h in mitre_hits.hits)
        assert all("source_sha256" in h.record.provenance for h in mitre_hits.hits)

        # Semantic Cognee vector retrieval for CVE with min_cvss filter
        cve_hits = await service.search(
            KnowledgeSearchQuery(
                query="WordPress Elementor broken access control plugin",
                source_type="cve",
                min_cvss=7.0,
                top_k=3,
                search_mode="semantic",
            )
        )
        assert cve_hits.total_hits >= 1
        assert cve_hits.hits[0].record.source_id == "CVE-2025-39447"

        # Graph search mode traverses Kuzu relationships (e.g., T1110 -> TA0006)
        graph_hits = await service.search(
            KnowledgeSearchQuery(
                query="Brute Force",
                source_type="mitre_attack",
                top_k=5,
                search_mode="graph",
            )
        )
        graph_ids = {h.record.source_id for h in graph_hits.hits}
        assert "T1110" in graph_ids
        assert "TA0006" in graph_ids

        stats = await service.stats()
        assert stats.backend == "cognee"
        assert stats.total_records == mitre_run.parsed + 3
        assert stats.counts_by_source_type["mitre_attack"] == mitre_run.parsed
        assert stats.counts_by_source_type["cve"] == 3
    finally:
        await service.close()


@pytest.mark.asyncio
async def test_matches_filters_unit(tmp_path: Path) -> None:
    service = KnowledgeService(
        settings=KnowledgeSettings(data_dir=tmp_path / "mem", store_backend="memory")
    )
    await service.ingest_mitre(path=MITRE_SAMPLE)
    await service.ingest_cve(path=CVE_SAMPLE)

    t1110 = (await service.get_by_source("mitre_attack", "T1110")).record
    cve_1999 = (await service.get_by_source("cve", "CVE-1999-1585")).record

    assert matches_filters(
        t1110, KnowledgeSearchQuery(query="x", tactic="credential-access", platform="Linux")
    )
    assert not matches_filters(
        t1110, KnowledgeSearchQuery(query="x", tactic="impact")
    )
    assert not matches_filters(
        cve_1999, KnowledgeSearchQuery(query="x", min_cvss=5.0)
    )
