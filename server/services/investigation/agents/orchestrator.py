"""Orchestrator lifecycle nodes: plan, review/conflict resolution, and final synthesis."""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from services.investigation.guardrails import (
    build_record_to_source_map,
    build_verified_source_ids,
    sanitize_attack_path,
    sanitize_enriched_knowledge,
    sanitize_findings,
    sanitize_recommendations,
    validate_subagent_outputs,
)
from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import (
    AuditEntry,
    FinalSynthesisDraft,
    InvestigationFinding,
    InvestigationResult,
    OrchestratorReviewOutput,
    SequenceAnalysisOutput,
)
from services.investigation.prompts import (
    ORCHESTRATOR_REVIEW_SYSTEM_PROMPT,
    ORCHESTRATOR_SYNTHESIS_SYSTEM_PROMPT,
)
from services.investigation.renderer import render_markdown_report, render_summary
from services.investigation.state import InvestigationState


logger = logging.getLogger(__name__)


def make_orchestrator_plan_node(max_refinement_rounds: int):
    """Create the Orchestrator Intake & Task Dispatch node."""

    async def orchestrator_plan_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]

        event_index = {evt.event_id: evt for evt in inv_input.normalized_events}
        knowledge_catalog = {
            rec.source_id.upper(): rec for rec in inv_input.knowledge_records
        }
        knowledge_scores = dict(state.get("knowledge_scores") or {})
        for src_key in knowledge_catalog:
            knowledge_scores.setdefault(src_key, 0.75)

        dispatch_seq = bool(inv_input.sequence_cues)
        assigned = ["event_analyst", "knowledge_enricher"]
        if dispatch_seq:
            assigned.append("sequence_analyst")

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="orchestrator_plan",
            agent_role="orchestrator",
            status="completed",
            model_name="deterministic",
            api_key_slot="n/a",
            duration_ms=duration_ms,
            input_summary=(
                f"investigation_id={inv_input.investigation_id}, "
                f"{len(event_index)} event(s), {len(knowledge_catalog)} pre-retrieved OKF record(s), "
                f"{len(inv_input.sequence_cues)} LSTM sequence cue(s)"
            ),
            output_summary=f"Dispatched parallel specialists: {', '.join(assigned)}",
            notes=(
                []
                if dispatch_seq
                else ["LSTM sequence_cues empty; sequence_analyst will short-circuit without LLM call."]
            ),
        )

        return {
            "event_index": event_index,
            "knowledge_catalog": knowledge_catalog,
            "knowledge_scores": knowledge_scores,
            "related_knowledge_map": dict(state.get("related_knowledge_map") or {}),
            "dispatch_sequence_agent": dispatch_seq,
            "refinement_round": 0,
            "max_refinement_rounds": max_refinement_rounds,
            "refinement_instructions": "",
            "workflow_started_perf": started,
            "audit_trail": [audit],
        }

    return orchestrator_plan_node


def _fallback_review(
    state: InvestigationState,
    guardrail_issues: list,
) -> OrchestratorReviewOutput:
    """Deterministic fallback review when orchestrator LLM call fails."""
    event_analysis = state.get("event_analysis")
    has_anomalies = bool(
        event_analysis
        and (
            event_analysis.noteworthy_event_ids
            or any(o.is_anomalous or o.severity in ("critical", "high") for o in event_analysis.observations)
        )
    )
    has_hallucination = any(i.issue_type == "hallucinated_knowledge_id" for i in guardrail_issues)
    targets: list[Literal["knowledge_enricher", "attack_path_analyst"]] = []
    if has_hallucination:
        if any(i.target_agent == "knowledge_enricher" for i in guardrail_issues):
            targets.append("knowledge_enricher")
        else:
            targets.append("attack_path_analyst")
    return OrchestratorReviewOutput(
        approved=not has_hallucination,
        issues=guardrail_issues,
        remediation_justified=has_anomalies,
        refinement_targets=targets,
        refinement_instructions=(
            "Remove unverified ATT&CK/CVE IDs and cite only verified OKF catalog records."
            if has_hallucination
            else ""
        ),
        conflict_resolution_notes=["Deterministic fallback review applied."],
    )


def make_orchestrator_review_node(llm_factory: GeminiAgentFactory):
    """Create the Orchestrator Verification & Conflict Resolution node."""

    async def orchestrator_review_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]
        event_index = state.get("event_index") or {e.event_id: e for e in inv_input.normalized_events}
        catalog = state.get("knowledge_catalog") or {}
        related_map = state.get("related_knowledge_map") or {}
        refinement_round = int(state.get("refinement_round", 0))
        max_rounds = int(state.get("max_refinement_rounds", 1))

        event_analysis = state.get("event_analysis")
        knowledge_enrichment = state.get("knowledge_enrichment")
        sequence_analysis = state.get("sequence_analysis")
        correlation_timeline = state.get("correlation_timeline")
        attack_path = state.get("attack_path")

        # 1. Deterministic guardrail pass
        guardrail_issues, guardrail_warnings = validate_subagent_outputs(
            event_index=event_index,
            knowledge_catalog=catalog,
            related_knowledge_map=related_map,
            event_analysis=event_analysis,
            knowledge_enrichment=knowledge_enrichment,
            attack_path=attack_path,
        )

        # 2. Orchestrator LLM cross-agent conflict & justification review
        user_prompt = (
            f"Investigation ID: {inv_input.investigation_id}\n"
            f"Refinement Round: {refinement_round} / {max_rounds}\n"
            f"Can Request Another Refinement Round: {refinement_round < max_rounds}\n\n"
            f"PROGRAMMATIC GUARDRAIL ISSUES:\n"
            f"{json.dumps([i.model_dump() for i in guardrail_issues], indent=2)}\n\n"
            f"EVENT ANALYSIS:\n{event_analysis.model_dump_json(indent=2) if event_analysis else '{}'}\n\n"
            f"KNOWLEDGE ENRICHMENT:\n{knowledge_enrichment.model_dump_json(indent=2) if knowledge_enrichment else '{}'}\n\n"
            f"SEQUENCE ANALYSIS:\n{sequence_analysis.model_dump_json(indent=2) if sequence_analysis else '{}'}\n\n"
            f"CORRELATION & TIMELINE:\n{correlation_timeline.model_dump_json(indent=2) if correlation_timeline else '{}'}\n\n"
            f"ATTACK PATH:\n{attack_path.model_dump_json(indent=2) if attack_path else '{}'}\n\n"
            "Evaluate grounding, conflicts, coverage gaps, and whether remediation recommendations are justified."
        )

        status = "completed"
        notes: list[str] = []
        model_name = ""
        key_slot = ""

        try:
            review, model_name, key_slot = await llm_factory.invoke_structured(
                role="orchestrator",
                schema=OrchestratorReviewOutput,
                system_prompt=ORCHESTRATOR_REVIEW_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
        except Exception as exc:
            logger.warning("OrchestratorReview LLM call failed, using deterministic fallback: %s", exc)
            review = _fallback_review(state, guardrail_issues)
            status = "fallback"
            notes.append(f"LLM error fallback: {exc}")

        # Merge programmatic guardrail issues so they are never lost
        merged_issues = list(guardrail_issues)
        existing_descs = {i.description for i in merged_issues}
        for issue in review.issues:
            if issue.description not in existing_descs:
                merged_issues.append(issue)

        has_hallucination = any(
            i.issue_type == "hallucinated_knowledge_id" for i in merged_issues
        )

        # Enforce strict termination cap and concrete refinement routing
        can_refine = refinement_round < max_rounds
        should_refine = can_refine and (not review.approved or has_hallucination)

        next_round = refinement_round
        refinement_instructions = review.refinement_instructions
        refinement_targets = list(review.refinement_targets)

        if should_refine:
            next_round = refinement_round + 1
            if not refinement_targets:
                if any(i.target_agent == "knowledge_enricher" for i in merged_issues):
                    refinement_targets = ["knowledge_enricher"]
                else:
                    refinement_targets = ["attack_path_analyst"]
            if not refinement_instructions.strip():
                refinement_instructions = "Resolve the following guardrail/review issues: " + "; ".join(
                    f"[{i.issue_type}] {i.description}" for i in merged_issues[:5]
                )
            approved = False
            status = "retried" if status == "completed" else status
        else:
            approved = True
            refinement_targets = []
            if not can_refine and has_hallucination:
                notes.append(
                    "Max refinement rounds reached; programmatic synthesis guardrails will strip unverified IDs."
                )

        final_review = review.model_copy(
            update={
                "approved": approved,
                "issues": merged_issues,
                "refinement_targets": refinement_targets,
                "refinement_instructions": refinement_instructions,
            }
        )

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="orchestrator_review",
            agent_role="orchestrator",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=f"round={refinement_round}/{max_rounds}, {len(guardrail_issues)} guardrail issue(s)",
            output_summary=(
                f"approved={final_review.approved}, remediation_justified={final_review.remediation_justified}, "
                f"issues={len(merged_issues)}, targets={refinement_targets}"
            ),
            notes=notes,
        )

        return {
            "orchestrator_review": final_review,
            "refinement_round": next_round,
            "refinement_instructions": refinement_instructions,
            "guardrail_warnings": guardrail_warnings,
            "audit_trail": [audit],
        }

    return orchestrator_review_node


def route_after_review(
    state: InvestigationState,
) -> Literal["refine_knowledge", "refine_attack_path", "draft_recommendations", "synthesize_only"]:
    """LangGraph conditional router executed after ``orchestrator_review``."""
    review = state.get("orchestrator_review")
    if review is None:
        return "synthesize_only"
    if not review.approved:
        if "knowledge_enricher" in review.refinement_targets:
            return "refine_knowledge"
        return "refine_attack_path"
    if review.remediation_justified:
        return "draft_recommendations"
    return "synthesize_only"


def _fallback_synthesis(
    state: InvestigationState,
    sanitized_knowledge: list,
) -> FinalSynthesisDraft:
    """Deterministic synthesis fallback when orchestrator LLM fails."""
    ea = state.get("event_analysis")
    obs = ea.observations if ea else []
    high_or_crit = [o for o in obs if o.severity in ("critical", "high")]
    threat_level = "high" if high_or_crit else "medium" if any(o.is_anomalous for o in obs) else "informational"
    findings: list[InvestigationFinding] = []
    if obs:
        findings.append(
            InvestigationFinding(
                finding_id="find-001",
                title="Correlated Security Event Activity",
                severity=threat_level,
                confidence="medium",
                observed_facts=[f"[{o.event_id}] {o.summary}" for o in obs[:5]],
                inferences=["Event sequence warrants analyst verification against host and network telemetry."],
                uncertainty="Orchestrator LLM synthesis used deterministic fallback; review raw evidence.",
                supporting_event_ids=[o.event_id for o in obs[:5]],
                evidence_ref_ids=[o.evidence_ref_id for o in obs[:5]],
                knowledge_source_ids=[k.source_id for k in sanitized_knowledge[:5]],
            )
        )
    return FinalSynthesisDraft(
        overall_threat_level=threat_level,
        overall_confidence="medium" if obs else "low",
        executive_summary=(
            f"Analyzed {len(state['investigation_input'].normalized_events)} normalized event(s) "
            f"with {len(sanitized_knowledge)} verified OKF knowledge record(s)."
        ),
        findings=findings,
        potential_impact=["Potential unauthorized access or privilege misuse if compromise is confirmed."],
        uncertainty_and_gaps=(ea.telemetry_gaps if ea else []) or [
            "Command outcome and downstream telemetry not confirmed in provided log batch."
        ],
    )


def make_orchestrator_synthesize_node(llm_factory: GeminiAgentFactory):
    """Create the final Orchestrator Synthesis & Report Assembly node."""

    async def orchestrator_synthesize_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]
        event_index = state.get("event_index") or {e.event_id: e for e in inv_input.normalized_events}
        valid_event_ids = set(event_index.keys())
        catalog = state.get("knowledge_catalog") or {}
        scores = state.get("knowledge_scores") or {}
        related_map = state.get("related_knowledge_map") or {}
        valid_source_ids = build_verified_source_ids(catalog, related_map)
        record_to_source = build_record_to_source_map(catalog, related_map)

        event_analysis = state.get("event_analysis")
        knowledge_enrichment = state.get("knowledge_enrichment")
        sequence_analysis = state.get("sequence_analysis") or SequenceAnalysisOutput()
        correlation_timeline = state.get("correlation_timeline")
        attack_path = state.get("attack_path")
        review = state.get("orchestrator_review")
        recommendations_out = state.get("recommendations")

        # 1. Deterministically sanitize enriched knowledge and attack path BEFORE final synthesis
        sanitized_knowledge, kn_warnings = sanitize_enriched_knowledge(
            knowledge_enrichment=knowledge_enrichment,
            knowledge_catalog=catalog,
            knowledge_scores=scores,
            related_knowledge_map=related_map,
            valid_event_ids=valid_event_ids,
        )
        sanitized_ap, ap_warnings = sanitize_attack_path(
            attack_path=attack_path,
            valid_event_ids=valid_event_ids,
            valid_source_ids=valid_source_ids,
            record_to_source=record_to_source,
        )

        # 2. Orchestrator LLM synthesis over verified components
        user_prompt = (
            f"Investigation ID: {inv_input.investigation_id}\n\n"
            f"EVENT ANALYSIS:\n{event_analysis.model_dump_json(indent=2) if event_analysis else '{}'}\n\n"
            f"VERIFIED ENRICHED KNOWLEDGE (ONLY cite these source_ids):\n"
            f"{json.dumps([k.model_dump() for k in sanitized_knowledge], indent=2)}\n\n"
            f"SEQUENCE ANALYSIS:\n{sequence_analysis.model_dump_json(indent=2)}\n\n"
            f"CORRELATION & TIMELINE:\n"
            f"{correlation_timeline.model_dump_json(indent=2) if correlation_timeline else '{}'}\n\n"
            f"SANITIZED ATTACK PATH:\n{sanitized_ap.model_dump_json(indent=2)}\n\n"
            f"ORCHESTRATOR REVIEW:\n{review.model_dump_json(indent=2) if review else '{}'}\n\n"
            "Produce FinalSynthesisDraft separating observed_facts from inferences and documenting "
            "explicit confidence and uncertainty."
        )

        status = "completed"
        notes: list[str] = []
        model_name = ""
        key_slot = ""

        try:
            draft, model_name, key_slot = await llm_factory.invoke_structured(
                role="orchestrator",
                schema=FinalSynthesisDraft,
                system_prompt=ORCHESTRATOR_SYNTHESIS_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
        except Exception as exc:
            logger.warning("OrchestratorSynthesize LLM call failed, using fallback: %s", exc)
            draft = _fallback_synthesis(state, sanitized_knowledge)
            status = "fallback"
            notes.append(f"LLM error fallback: {exc}")

        # 3. Deterministically sanitize findings & recommendations
        sanitized_findings, find_warnings = sanitize_findings(
            draft=draft,
            event_index=event_index,
            valid_source_ids=valid_source_ids,
            record_to_source=record_to_source,
        )
        valid_finding_ids = {f.finding_id for f in sanitized_findings}
        sanitized_recs = sanitize_recommendations(
            recommendations_output=recommendations_out,
            valid_event_ids=valid_event_ids,
            valid_finding_ids=valid_finding_ids,
            valid_source_ids=valid_source_ids,
            record_to_source=record_to_source,
        )

        # Combine uncertainty & telemetry gaps cleanly
        combined_gaps: list[str] = []
        seen_gaps: set[str] = set()
        for gap in (
            list(draft.uncertainty_and_gaps)
            + list(sanitized_ap.missing_evidence)
            + (list(event_analysis.telemetry_gaps) if event_analysis else [])
        ):
            cleaned = gap.strip()
            if cleaned and cleaned not in seen_gaps:
                seen_gaps.add(cleaned)
                combined_gaps.append(cleaned)

        new_warnings = kn_warnings + ap_warnings + find_warnings
        all_warnings = list(state.get("guardrail_warnings") or []) + new_warnings

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        synth_audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="orchestrator_synthesize",
            agent_role="orchestrator",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=(
                f"{len(sanitized_knowledge)} verified OKF record(s), "
                f"{len(sanitized_recs)} recommendation(s)"
            ),
            output_summary=(
                f"threat={draft.overall_threat_level}, confidence={draft.overall_confidence}, "
                f"findings={len(sanitized_findings)}, warnings={len(all_warnings)}"
            ),
            notes=notes,
        )

        full_audit = list(state.get("audit_trail") or []) + [synth_audit]
        workflow_start = float(state.get("workflow_started_perf", started))
        total_ms = round((time.perf_counter() - workflow_start) * 1000.0, 2)

        # Filter observations & IOCs to valid event_ids
        clean_obs = []
        if event_analysis is not None:
            for obs in event_analysis.observations:
                evt = event_index.get(obs.event_id)
                if evt is not None:
                    clean_obs.append(
                        obs.model_copy(update={"evidence_ref_id": evt.evidence_ref.reference_id})
                    )
        clean_iocs = list(event_analysis.iocs) if event_analysis is not None else []

        rec_status: Literal["drafted", "skipped_unjustified"] = (
            "drafted" if sanitized_recs else "skipped_unjustified"
        )

        result = InvestigationResult(
            investigation_id=inv_input.investigation_id,
            status="completed_with_warnings" if all_warnings else "completed",
            overall_threat_level=draft.overall_threat_level,
            overall_confidence=draft.overall_confidence,
            executive_summary=draft.executive_summary,
            observations=clean_obs,
            findings=sanitized_findings,
            retrieved_knowledge=sanitized_knowledge,
            timeline=list(correlation_timeline.timeline) if correlation_timeline else [],
            relationships=list(correlation_timeline.relationships) if correlation_timeline else [],
            attack_path=sanitized_ap,
            iocs=clean_iocs,
            recommendations=sanitized_recs,
            recommendation_status=rec_status,
            sequence_assessment=sequence_analysis,
            potential_impact=list(draft.potential_impact),
            uncertainty_and_gaps=combined_gaps,
            guardrail_warnings=all_warnings,
            refinement_rounds_executed=int(state.get("refinement_round", 0)),
            audit_trail=full_audit,
            completed_at=datetime.now(timezone.utc),
            processing_time_ms=total_ms,
        )

        result = result.model_copy(
            update={
                "rendered_summary": render_summary(result),
                "rendered_markdown_report": render_markdown_report(result),
            }
        )

        return {
            "final_result": result,
            "guardrail_warnings": new_warnings,
            "audit_trail": [synth_audit],
        }

    return orchestrator_synthesize_node
