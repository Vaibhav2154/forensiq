"""Attack-Path Hypothesis specialist sub-agent node."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from services.investigation.guardrails import (
    build_verified_source_ids,
    render_attack_path_mermaid,
    sanitize_attack_path,
)
from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import (
    AttackPathEdge,
    AttackPathNode,
    AttackPathOutput,
    AuditEntry,
)
from services.investigation.prompts import ATTACK_PATH_SYSTEM_PROMPT
from services.investigation.state import InvestigationState


logger = logging.getLogger(__name__)


def _fallback_attack_path(state: InvestigationState) -> AttackPathOutput:
    """Deterministic fallback building an observed-only sequence path from timeline."""
    corr = state.get("correlation_timeline")
    entries = corr.timeline if corr else []
    nodes: list[AttackPathNode] = []
    edges: list[AttackPathEdge] = []

    for idx, entry in enumerate(entries, start=1):
        nid = f"step_{idx}"
        nodes.append(
            AttackPathNode(
                node_id=nid,
                label=entry.summary[:80],
                stage=entry.event_type.replace("_", " ").title(),
                status="observed",
                event_ids=[entry.event_id],
                knowledge_source_ids=[],
                confidence="high",
                notes=f"Observed at {entry.timestamp_ist}",
            )
        )
        if idx > 1:
            edges.append(
                AttackPathEdge(
                    source_node_id=f"step_{idx - 1}",
                    target_node_id=nid,
                    label="followed by",
                    status="inferred",
                    evidence_event_ids=[entries[idx - 2].event_id, entry.event_id],
                    reasoning="Chronological proximity on shared scope.",
                    confidence="medium",
                )
            )

    ap = AttackPathOutput(
        hypothesis_title="Observed Event Sequence (Fallback)",
        summary="Deterministic fallback attack-path constructed from chronological observations.",
        nodes=nodes,
        edges=edges,
        missing_evidence=["Post-command execution status and outbound network telemetry not present."],
        alternative_hypotheses=["Authorized user activity cannot be fully ruled out without baseline context."],
    )
    return ap.model_copy(update={"mermaid_diagram": render_attack_path_mermaid(ap)})


def make_attack_path_node(llm_factory: GeminiAgentFactory):
    """Create the async LangGraph node for Attack-Path Hypothesis Analysis."""

    async def attack_path_analyst_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]
        event_analysis = state.get("event_analysis")
        knowledge_enrichment = state.get("knowledge_enrichment")
        correlation_timeline = state.get("correlation_timeline")
        sequence_analysis = state.get("sequence_analysis")
        refinement_instructions = (state.get("refinement_instructions") or "").strip()

        catalog = state.get("knowledge_catalog") or {}
        related_map = state.get("related_knowledge_map") or {}
        verified_ids = sorted(build_verified_source_ids(catalog, related_map))
        valid_event_ids = set((state.get("event_index") or {}).keys()) or {
            e.event_id for e in inv_input.normalized_events
        }

        user_prompt = (
            f"Investigation ID: {inv_input.investigation_id}\n\n"
            f"VERIFIED ALLOWED OKF IDS (DO NOT cite any ID outside this list):\n{verified_ids}\n\n"
            f"EVENT ANALYSIS:\n"
            f"{event_analysis.model_dump_json(indent=2) if event_analysis else '{}'}\n\n"
            f"ENRICHED KNOWLEDGE:\n"
            f"{knowledge_enrichment.model_dump_json(indent=2) if knowledge_enrichment else '{}'}\n\n"
            f"CORRELATION & TIMELINE:\n"
            f"{correlation_timeline.model_dump_json(indent=2) if correlation_timeline else '{}'}\n\n"
            f"SEQUENCE ANALYSIS:\n"
            f"{sequence_analysis.model_dump_json(indent=2) if sequence_analysis else '{}'}\n"
        )
        if refinement_instructions:
            user_prompt += (
                f"\nORCHESTRATOR REFINEMENT INSTRUCTIONS (resolve every issue):\n"
                f"{refinement_instructions}\n"
            )
        user_prompt += (
            "\nConstruct an AttackPathOutput that strictly separates 'observed', 'inferred', "
            "and 'unconfirmed' steps, makes missing_evidence explicit, and uses ONLY verified OKF IDs."
        )

        status = "completed"
        notes: list[str] = []
        model_name = ""
        key_slot = ""

        try:
            output, model_name, key_slot = await llm_factory.invoke_structured(
                role="attack_path_analyst",
                schema=AttackPathOutput,
                system_prompt=ATTACK_PATH_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
            # Attach deterministic Mermaid diagram (do NOT strip before orchestrator_review so
            # review can detect & trigger refinement if an unverified ID was emitted; mermaid
            # renders cleanly regardless)
            output = output.model_copy(
                update={"mermaid_diagram": render_attack_path_mermaid(output)}
            )
        except Exception as exc:
            logger.warning("AttackPathAnalyst LLM call failed, using deterministic fallback: %s", exc)
            output = _fallback_attack_path(state)
            output, _ = sanitize_attack_path(output, valid_event_ids, set(verified_ids))
            status = "fallback"
            notes.append(f"LLM error fallback: {exc}")

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="attack_path_analyst",
            agent_role="attack_path_analyst",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=f"{len(verified_ids)} verified OKF ID(s), round={state.get('refinement_round', 0)}",
            output_summary=(
                f"{len(output.nodes)} node(s), {len(output.edges)} edge(s), "
                f"{len(output.missing_evidence)} evidence gap(s)"
            ),
            notes=notes,
        )
        return {
            "attack_path": output,
            "audit_trail": [audit],
        }

    return attack_path_analyst_node
