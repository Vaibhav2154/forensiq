"""Tests for the MITRE Enterprise ATT&CK STIX 2.1 parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.knowledge.kcp import KCPPipeline
from services.knowledge.config import KnowledgeSettings
from services.knowledge.parsers import parse_mitre_stix_file
from services.knowledge.storage import InMemoryKnowledgeStore


FIXTURE_BUNDLE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "knowledge"
    / "mitre_sample_bundle.json"
)


def test_parse_mitre_resolves_active_t1110_without_deprecated_collision() -> None:
    items, meta = parse_mitre_stix_file(FIXTURE_BUNDLE)

    assert meta["source_version"] == "17.1"
    assert meta["attack_spec_version"] == "3.2.0"
    assert meta["filtered_count"] == 1  # deprecated Brute Force Mitigation filtered

    by_id = {item.source_id: item for item in items}
    assert "T1110" in by_id
    t1110 = by_id["T1110"]
    assert t1110.kind == "attack-pattern"
    assert t1110.name == "Brute Force"
    assert t1110.status == "active"

    rel_pairs = {(r.relationship_type, r.target_source_id) for r in t1110.relationships}
    assert ("uses_tactic", "TA0006") in rel_pairs


def test_parse_mitre_extracts_subtechnique_mitigation_group_and_data_component_links() -> None:
    items, _ = parse_mitre_stix_file(FIXTURE_BUNDLE)
    by_id = {item.source_id: item for item in items}

    sub = by_id["T1110.001"]
    assert sub.fields["is_subtechnique"] is True
    assert ("subtechnique_of", "T1110") in {
        (r.relationship_type, r.target_source_id) for r in sub.relationships
    }

    mit = by_id["M1032"]
    assert ("mitigates", "T1110") in {
        (r.relationship_type, r.target_source_id) for r in mit.relationships
    }

    grp = by_id["G0117"]
    assert ("uses", "T1110") in {
        (r.relationship_type, r.target_source_id) for r in grp.relationships
    }

    data_components = [i for i in items if i.kind == "x-mitre-data-component"]
    assert len(data_components) == 2
    by_name = {dc.name: dc for dc in data_components}
    user_auth_dc = by_name["User Account Authentication"]
    dc_rels = {(r.relationship_type, r.target_source_id) for r in user_auth_dc.relationships}
    assert ("part_of_data_source", "DS0002") in dc_rels
    assert ("detects", "T1110") in dc_rels


@pytest.mark.asyncio
async def test_include_deprecated_uses_non_colliding_record_ids() -> None:
    store = InMemoryKnowledgeStore()
    pipeline = KCPPipeline(
        settings=KnowledgeSettings(store_backend="memory"),
        store=store,
    )
    run = await pipeline.ingest_mitre(path=FIXTURE_BUNDLE, include_deprecated=True)
    assert run.status == "completed"

    t1110_active = await store.get_by_record_id("okf-mitre-t1110")
    assert t1110_active is not None
    assert t1110_active.content["name"] == "Brute Force"

    # Deprecated Brute Force Mitigation shares T1110 external_id but must not overwrite active T1110
    stats = await store.stats()
    assert stats.total_records == run.parsed
    assert run.inserted == run.parsed
