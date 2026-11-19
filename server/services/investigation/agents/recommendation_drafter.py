"""Recommendation Drafting specialist sub-agent node (approval-gated)."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from services.investigation.guardrails import build_verified_source_ids
from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import (
    AuditEntry,
    RecommendationDraftOutput,
    RecommendationItem,
    RecommendationOutput,
)
from services.investigation.playbook_tagger import tag_recommendations_for_tui
from services.investigation.prompts import RECOMMENDATION_DRAFTER_SYSTEM_PROMPT
from services.investigation.state import InvestigationState


logger = logging.getLogger(__name__)


def _fallback_recommendations(state: InvestigationState) -> RecommendationOutput:
    """Deterministic conservative fallback recommendation when LLM fails."""
    events = state["investigation_input"].normalized_events
    ev_ids = [e.event_id for e in events[:5]]
    return RecommendationOutput(
        status="drafted",
        rationale="Fallback recommendation generated because LLM drafting encountered an error.",
        recommendations=[
            RecommendationItem(
                recommendation_id="rec-001",
                priority="immediate",
                title="Audit Affected Scopes and Preserve Forensic Evidence",
                target=", ".join(sorted({e.scope_key for e in events})[:4]) or "affected-host",
                action="Review raw logs, verify account authorization, and preserve host evidence before making changes.",
                expected_effect="Prevents evidence destruction while confirming whether unauthorized access occurred.",
                supporting_finding_ids=["find-001"],
                evidence_event_ids=ev_ids,
                knowledge_mitigation_ids=[],
                requires_human_approval=True,
                auto_executable=False,
                rollback_notes="Read-only forensic preservation; no system state altered.",
            )
        ],
    )


def make_recommendation_drafter_node(llm_factory: GeminiAgentFactory):
    """Create the async LangGraph node for approval-gated Recommendation Drafting."""

    async def recommendation_drafter_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]
        event_analysis = state.get("event_analysis")
        knowledge_enrichment = state.get("knowledge_enrichment")
        attack_path = state.get("attack_path")
        review = state.get("orchestrator_review")

        catalog = state.get("knowledge_catalog") or {}
        related_map = state.get("related_knowledge_map") or {}
        verified_ids = sorted(build_verified_source_ids(catalog, related_map))
        mitigation_ids = [i for i in verified_ids if i.startswith("M")]

        user_prompt = (
            f"Investigation ID: {inv_input.investigation_id}\n\n"
            f"VERIFIED MITIGATION IDS FROM COGNEE GRAPH: {mitigation_ids}\n\n"
            f"EVENT ANALYSIS:\n{event_analysis.model_dump_json(indent=2) if event_analysis else '{}'}\n\n"
            f"ENRICHED KNOWLEDGE:\n{knowledge_enrichment.model_dump_json(indent=2) if knowledge_enrichment else '{}'}\n\n"
            f"ATTACK PATH HYPOTHESIS:\n{attack_path.model_dump_json(indent=2) if attack_path else '{}'}\n\n"
            f"ORCHESTRATOR REVIEW NOTES:\n{review.model_dump_json(indent=2) if review else '{}'}\n\n"
            "Draft prioritized, evidence-linked, human-approval-gated recommendations "
            "(requires_human_approval=true, auto_executable=false)."
        )

        status = "completed"
        notes: list[str] = []
        model_name = ""
        key_slot = ""

        try:
            # Use Gemini-safe RecommendationDraftOutput (no arbitrary dict fields) for live
            # Gemini calls; preserve RecommendationOutput schema when custom mock runners are used.
            target_schema = (
                RecommendationOutput
                if getattr(llm_factory, "_custom_runner", None) is not None
                else RecommendationDraftOutput
            )
            raw_output, model_name, key_slot = await llm_factory.invoke_structured(
                role="recommendation_drafter",
                schema=target_schema,
                system_prompt=RECOMMENDATION_DRAFTER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
            if isinstance(raw_output, RecommendationDraftOutput):
                converted_items = [
                    RecommendationItem(**item.model_dump())
                    for item in raw_output.recommendations
                ]
                output = RecommendationOutput(
                    status=raw_output.status,
                    recommendations=converted_items,
                    rationale=raw_output.rationale,
                )
            else:
                output = raw_output

            if output.recommendations:
                tagged_items = tag_recommendations_for_tui(
                    recommendations=output.recommendations,
                    events=inv_input.normalized_events,
                    event_analysis=event_analysis,
                )
                output = output.model_copy(
                    update={"status": "drafted", "recommendations": tagged_items}
                )
        except Exception as exc:
            logger.warning("RecommendationDrafter LLM call failed, using fallback: %s", exc)
            output = _fallback_recommendations(state)
            status = "fallback"
            notes.append(f"LLM error fallback: {exc}")

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="recommendation_drafter",
            agent_role="recommendation_drafter",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=f"{len(mitigation_ids)} retrieved MITRE mitigation ID(s)",
            output_summary=f"status={output.status}, {len(output.recommendations)} recommendation(s)",
            notes=notes,
        )
        return {
            "recommendations": output,
            "audit_trail": [audit],
        }

    return recommendation_drafter_node
