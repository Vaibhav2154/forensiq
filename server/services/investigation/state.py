"""Shared LangGraph state definition for the multi-agent investigation workflow."""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from contracts import InvestigationInput, KnowledgeRecord, NormalizedEvent
from services.investigation.models import (
    AttackPathOutput,
    AuditEntry,
    CorrelationTimelineOutput,
    EventAnalysisOutput,
    InvestigationResult,
    KnowledgeEnrichmentOutput,
    OrchestratorReviewOutput,
    RecommendationOutput,
    SequenceAnalysisOutput,
)


class InvestigationState(TypedDict, total=False):
    """Shared state passed across all LangGraph orchestrator and sub-agent nodes."""

    # Immutable input & lookup indexes
    investigation_input: InvestigationInput
    raw_log_excerpts: dict[str, str]  # evidence_ref.reference_id -> raw log line
    event_index: dict[str, NormalizedEvent]  # event_id -> NormalizedEvent
    knowledge_catalog: dict[str, KnowledgeRecord]  # source_id.upper() -> KnowledgeRecord
    knowledge_scores: dict[str, float]  # source_id.upper() -> best retrieval score
    related_knowledge_map: dict[str, list[KnowledgeRecord]]  # source_id.upper() -> 1-hop records

    # Orchestrator control flags
    dispatch_sequence_agent: bool
    refinement_round: int
    max_refinement_rounds: int
    refinement_instructions: str
    workflow_started_perf: float

    # Specialist sub-agent outputs
    event_analysis: EventAnalysisOutput
    knowledge_enrichment: KnowledgeEnrichmentOutput
    sequence_analysis: SequenceAnalysisOutput
    correlation_timeline: CorrelationTimelineOutput
    attack_path: AttackPathOutput
    orchestrator_review: OrchestratorReviewOutput
    recommendations: RecommendationOutput

    # Parallel-safe accumulated state
    extra_knowledge_records: Annotated[list[KnowledgeRecord], operator.add]
    audit_trail: Annotated[list[AuditEntry], operator.add]
    guardrail_warnings: Annotated[list[str], operator.add]

    # Final assembled investigation result
    final_result: InvestigationResult
