"""Build validated contracts.KnowledgeRecord OKF objects with provenance."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Literal

from contracts import KnowledgeRecord, KnowledgeRelationship
from services.knowledge.models import CompressionAudit, ParsedKnowledgeItem


def make_record_id(
    source_type: Literal["mitre_attack", "cve"],
    source_id: str,
    status: str = "active",
    disambiguator: str | None = None,
) -> str:
    """Create deterministic OKF record identifiers matching shared fixtures."""
    slug = source_id.strip().lower()
    if source_type == "mitre_attack":
        base = f"okf-mitre-{slug}"
        if disambiguator and status in ("deprecated", "revoked"):
            return f"{base}-{status}-{disambiguator[:8].lower()}"
        return base
    return f"okf-{slug}"


def _canonical_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_knowledge_record(
    item: ParsedKnowledgeItem,
    audit: CompressionAudit,
    kcp_version: str,
    run_id: str,
    ingested_at: datetime | None = None,
) -> KnowledgeRecord:
    """Transform a normalized, compressed item into a validated KnowledgeRecord."""
    ts = ingested_at or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)

    record_id = make_record_id(
        source_type=item.source_type,
        source_id=item.source_id,
        status=item.status,
        disambiguator=item.disambiguator,
    )

    content: dict[str, Any] = dict(item.fields)
    content["kind"] = item.kind
    if item.name and "name" not in content:
        content["name"] = item.name
    content["description"] = item.description

    dedup_rels: list[KnowledgeRelationship] = []
    seen_rels: set[tuple[str, str, str]] = set()
    for rel in item.relationships:
        key = (rel.relationship_type, rel.target_source_id, rel.source)
        if key not in seen_rels:
            seen_rels.add(key)
            dedup_rels.append(rel)

    content_sha256 = _canonical_sha256(
        {
            "source_type": item.source_type,
            "source_id": item.source_id,
            "source_version": item.source_version,
            "content": content,
            "relationships": [rel.model_dump() for rel in dedup_rels],
        }
    )

    provenance: dict[str, Any] = {
        "source_uri": item.source_uri,
        "source_file": item.source_file,
        "source_object_id": item.source_object_id,
        "source_sha256": item.raw_sha256,
        "content_sha256": content_sha256,
        "source_format": item.source_format,
        "kcp_version": kcp_version,
        "ingestion_run_id": run_id,
        "compression": audit.model_dump(),
    }
    if item.dataset_sha256:
        provenance["dataset_sha256"] = item.dataset_sha256

    return KnowledgeRecord(
        record_id=record_id,
        source_type=item.source_type,
        source_id=item.source_id,
        source_version=item.source_version,
        content=content,
        relationships=dedup_rels,
        provenance=provenance,
        ingested_at=ts,
    )

