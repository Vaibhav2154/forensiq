"""Stable data contracts shared by the ForensIQ workstreams.

These models are intentionally provider-neutral.  They define the data passed
between ingestion, knowledge processing, sequence detection, the CLI, and the
future investigation orchestrator; they do not contain service logic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CONTRACT_VERSION = "1.0"


class ContractModel(BaseModel):
    """Base configuration for all externally exchanged contract objects."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class EvidenceReference(ContractModel):
    """A durable pointer to raw forensic evidence."""

    reference_id: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    sha256: str | None = Field(default=None, min_length=64, max_length=64)

    @model_validator(mode="after")
    def line_range_is_valid(self) -> "EvidenceReference":
        if self.line_start and self.line_end and self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self


class RawLogRecord(ContractModel):
    """Raw log input received from a collector before KCP processing."""

    record_id: str = Field(min_length=1)
    observed_at: datetime
    message: str = Field(min_length=1)
    source_type: str = Field(min_length=1)
    evidence_ref: EvidenceReference
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc)


class NormalizedEvent(ContractModel):
    """Traceable event emitted by KCP and consumed by sequence analysis."""

    schema_version: str = CONTRACT_VERSION
    event_id: str = Field(min_length=1)
    scope_key: str = Field(min_length=1)
    event_time: datetime
    event_type: str = Field(min_length=1)
    source: str = Field(min_length=1)
    features: dict[str, Any] = Field(default_factory=dict)
    evidence_ref: EvidenceReference

    @field_validator("event_time")
    @classmethod
    def event_time_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_time must include a timezone")
        return value.astimezone(timezone.utc)


class KnowledgeRelationship(ContractModel):
    """A typed relationship supplied by the source dataset or KCP."""

    relationship_type: str = Field(min_length=1)
    target_source_id: str = Field(min_length=1)
    source: Literal["source", "kcp"] = "source"


class KnowledgeRecord(ContractModel):
    """OKF-format record stored in Cognee after KCP processing."""

    schema_version: str = CONTRACT_VERSION
    record_id: str = Field(min_length=1)
    source_type: Literal["mitre_attack", "cve"]
    source_id: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    content: dict[str, Any] = Field(default_factory=dict)
    relationships: list[KnowledgeRelationship] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime

    @field_validator("ingested_at")
    @classmethod
    def ingested_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("ingested_at must include a timezone")
        return value.astimezone(timezone.utc)


class SequenceCue(ContractModel):
    """Explainable sequence-model output for the future orchestrator."""

    schema_version: str = CONTRACT_VERSION
    cue_id: str = Field(min_length=1)
    scope_key: str = Field(min_length=1)
    event_ids: list[str] = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    model_version: str = Field(min_length=1)
    window_ref: str = Field(min_length=1)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value.astimezone(timezone.utc)


class BatchIngestRequest(ContractModel):
    """CLI-to-server batch submitted for KCP processing."""

    schema_version: str = CONTRACT_VERSION
    batch_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    records: list[RawLogRecord] = Field(min_length=1)
    sent_at: datetime

    @field_validator("sent_at")
    @classmethod
    def sent_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("sent_at must include a timezone")
        return value.astimezone(timezone.utc)


class InvestigationInput(ContractModel):
    """Stable input handed to the future multi-agent investigation system."""

    schema_version: str = CONTRACT_VERSION
    investigation_id: str = Field(min_length=1)
    normalized_events: list[NormalizedEvent] = Field(min_length=1)
    knowledge_records: list[KnowledgeRecord] = Field(default_factory=list)
    sequence_cues: list[SequenceCue] = Field(default_factory=list)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value.astimezone(timezone.utc)
