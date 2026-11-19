"""Tests for the CVE List v5 JSON and delta.json parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.knowledge.config import KnowledgeSettings
from services.knowledge.kcp import KCPPipeline, normalize_item
from services.knowledge.parsers import CveParseError, iter_cve_files, parse_cve_file
from services.knowledge.storage import InMemoryKnowledgeStore


CVE_SAMPLE_DIR = (
    Path(__file__).resolve().parents[1] / "fixtures" / "knowledge" / "cve_sample"
)


def test_parse_published_cve_with_cvss_31_and_adp() -> None:
    path = CVE_SAMPLE_DIR / "2025" / "39xxx" / "CVE-2025-39447.json"
    item = parse_cve_file(path)
    assert item is not None
    norm = normalize_item(item)

    assert norm.source_id == "CVE-2025-39447"
    assert norm.fields["severity"]["version"] == "3.1"
    assert norm.fields["severity"]["base_score"] == 7.5
    assert norm.fields["severity"]["base_severity"] == "HIGH"
    assert norm.fields["cwe_ids"] == ["CWE-862"]
    assert norm.fields["capec_ids"] == ["CAPEC-1"]
    assert norm.fields["ssvc"]["options"]["automatable"] == "yes"
    assert "crocoblock:jetelements_for_elementor" in norm.fields["affected_products_normalized"]

    rels = {(r.relationship_type, r.target_source_id, r.source) for r in norm.relationships}
    assert ("has_weakness", "CWE-862", "source") in rels
    assert ("has_attack_pattern", "CAPEC-1", "source") in rels
    assert ("affects_product", "crocoblock:jetelements_for_elementor", "kcp") in rels


def test_parse_cve_cvss_40_and_legacy_v4_records() -> None:
    v4_item = normalize_item(
        parse_cve_file(CVE_SAMPLE_DIR / "2025" / "39xxx" / "CVE-2025-39664.json")
    )
    assert v4_item.fields["severity"]["version"] == "4.0"
    assert v4_item.fields["severity"]["base_score"] == 7.1
    assert "checkmk_gmbh:checkmk" in v4_item.fields["affected_products_normalized"]

    legacy_item = normalize_item(
        parse_cve_file(CVE_SAMPLE_DIR / "1999" / "1xxx" / "CVE-1999-1585.json")
    )
    assert legacy_item.source_id == "CVE-1999-1585"
    assert "severity" not in legacy_item.fields
    assert legacy_item.fields["affected"] == []
    assert "x_legacyV4Record" in legacy_item.omitted_fields


def test_rejected_cve_filtered_unless_included_and_malformed_isolated() -> None:
    rejected_path = CVE_SAMPLE_DIR / "2025" / "39xxx" / "CVE-2025-39751.json"
    assert parse_cve_file(rejected_path, include_rejected=False) is None

    rejected_item = parse_cve_file(rejected_path, include_rejected=True)
    assert rejected_item is not None
    assert rejected_item.status == "rejected"

    malformed_path = CVE_SAMPLE_DIR / "2025" / "39xxx" / "CVE-2025-MALFORMED.json"
    with pytest.raises(CveParseError):
        parse_cve_file(malformed_path)


def test_iter_cve_files_supports_delta_years_and_explicit_ids() -> None:
    delta_files = list(
        iter_cve_files(CVE_SAMPLE_DIR, delta_file=CVE_SAMPLE_DIR / "delta.json")
    )
    assert [p.name for p in delta_files] == [
        "CVE-2025-39447.json",
        "CVE-2025-39664.json",
    ]

    explicit = list(
        iter_cve_files(CVE_SAMPLE_DIR, cve_ids=["cve-1999-1585", "CVE-2025-999999"])
    )
    assert [p.name for p in explicit] == ["CVE-1999-1585.json"]

    y1999 = list(iter_cve_files(CVE_SAMPLE_DIR, years=[1999]))
    assert [p.name for p in y1999] == ["CVE-1999-1585.json"]


@pytest.mark.asyncio
async def test_cve_pipeline_isolates_malformed_and_rejected_records() -> None:
    store = InMemoryKnowledgeStore()
    pipeline = KCPPipeline(
        settings=KnowledgeSettings(store_backend="memory"),
        store=store,
    )
    run = await pipeline.ingest_cve(path=CVE_SAMPLE_DIR)
    assert run.status == "completed_with_errors"
    assert run.parsed == 3
    assert run.inserted == 3
    assert run.rejected_or_filtered == 1
    assert run.failed == 1
    assert any("CVE-2025-MALFORMED.json" in err for err in run.errors)
