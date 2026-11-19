"""Internal service and API DTOs for KCP, OKF, and Cognee retrieval.

Shared boundary contracts (``KnowledgeRecord``, ``KnowledgeRelationship``,
``BatchIngestRequest``, ``NormalizedEvent``) are imported directly from
``contracts`` and never duplicated here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from contracts import (
    BatchIngestRequest,
    EvidenceReference,
    KnowledgeRecord,
    KnowledgeRelationship,
    NormalizedEvent,
    RawLogRecord,
)

__all__ = [
    "BatchIngestRequest",
    "CompressionAudit",
    "EvidenceReference",
    "IngestionRunStatus",
    "KnowledgeRecord",
    "KnowledgeRecordDetailResponse",
    "KnowledgeRelationship",
    "KnowledgeSearchHit",
    "KnowledgeSearchQuery",
    "KnowledgeSearchResponse",
    "KnowledgeStoreStats",
    "NormalizedEvent",
    "ParsedKnowledgeItem",
    "RawLogRecord",
    "UpsertSummary",
]


class CompressionAudit(BaseModel):
    """Auditable metrics for a single KCP text/payload compression step."""

    raw_chars: int = Field(ge=0)
    compressed_chars: int = Field(ge=0)
    compression_ratio: float = Field(ge=0.0)
    stripped_citations: int = Field(default=0, ge=0)
    stripped_html_tags: int = Field(default=0, ge=0)
    omitted_fields: list[str] = Field(default_factory=list)


class ParsedKnowledgeItem(BaseModel):
    """Intermediate normalized-candidate item emitted by source parsers."""

    source_type: Literal["mitre_attack", "cve"]
    source_id: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    name: str = Field(default="")
    description: str = Field(default="")
    status: str = Field(default="active")
    disambiguator: str | None = None
    raw_sha256: str = Field(min_length=64, max_length=64)
    dataset_sha256: str | None = None
    source_uri: str = Field(default="")
    source_file: str = Field(default="")
    source_object_id: str = Field(default="")
    source_format: str = Field(default="")
    fields: dict[str, Any] = Field(default_factory=dict)
    relationships: list[KnowledgeRelationship] = Field(default_factory=list)
    omitted_fields: list[str] = Field(default_factory=list)


class UpsertSummary(BaseModel):
    """Result counts returned by a KnowledgeStore upsert call."""

    inserted: int = Field(default=0, ge=0)
    updated: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    record_ids: list[str] = Field(default_factory=list)


class IngestionRunStatus(BaseModel):
    """Status and provenance audit summary for an ingestion run."""

    run_id: str
    source_type: Literal["mitre_attack", "cve"]
    status: Literal["running", "completed", "completed_with_errors", "failed"]
    started_at: datetime
    completed_at: datetime | None = None
    source_path: str
    source_version: str = ""
    dry_run: bool = False
    parsed: int = Field(default=0, ge=0)
    inserted: int = Field(default=0, ge=0)
    updated: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    rejected_or_filtered: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list)
    compression_summary: dict[str, Any] = Field(default_factory=dict)


class KnowledgeSearchQuery(BaseModel):
    """Structured query parameters for knowledge retrieval."""

    query: str = Field(min_length=1)
    source_type: Literal["mitre_attack", "cve"] | None = None
    kind: str | None = None
    tactic: str | None = None
    platform: str | None = None
    min_cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    top_k: int = Field(default=5, ge=1, le=50)
    search_mode: Literal["auto", "semantic", "lexical", "graph"] = "auto"


class KnowledgeSearchHit(BaseModel):
    """A single retrieved KnowledgeRecord with score and safety disclaimer."""

    record: KnowledgeRecord
    score: float = Field(ge=0.0)
    retrieval_mode: str
    matched_via: str
    is_evidence_proof: Literal[False] = False


class KnowledgeSearchResponse(BaseModel):
    """API response wrapper for knowledge search results."""

    query: str
    total_hits: int = Field(ge=0)
    retrieval_mode: str
    hits: list[KnowledgeSearchHit] = Field(default_factory=list)
    notice: str = (
        "Retrieved ATT&CK and CVE records provide investigative context only "
        "and are not proof of compromise or exploitation."
    )


class KnowledgeRecordDetailResponse(BaseModel):
    """Exact OKF record lookup response with optional 1-hop related records."""

    record: KnowledgeRecord
    related_records: list[KnowledgeRecord] = Field(default_factory=list)


class KnowledgeStoreStats(BaseModel):
    """Aggregate statistics for the active knowledge store."""

    backend: str
    total_records: int = Field(default=0, ge=0)
    counts_by_source_type: dict[str, int] = Field(default_factory=dict)
    counts_by_kind: dict[str, int] = Field(default_factory=dict)
    active_versions: dict[str, list[str]] = Field(default_factory=dict)
    total_ingestion_runs: int = Field(default=0, ge=0)
    last_ingested_at: datetime | None = None

