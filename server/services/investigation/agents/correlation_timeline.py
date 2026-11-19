"""Correlation & Timeline specialist sub-agent node."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import (
    AuditEntry,
    CorrelationTimelineOutput,
    EntityRelationship,
    TimelineEntry,
)
from services.investigation.prompts import (
    CORRELATION_TIMELINE_SYSTEM_PROMPT,
    format_utc_and_ist,
    serialize_events_for_prompt,
)
from services.investigation.state import InvestigationState


logger = logging.getLogger(__name__)


def _fallback_correlation_timeline(state: InvestigationState) -> CorrelationTimelineOutput:
    """Deterministic chronological timeline & observed entity relationships."""
    events = sorted(state["investigation_input"].normalized_events, key=lambda e: e.event_time)
    timeline: list[TimelineEntry] = []
    relationships: list[EntityRelationship] = []
    scopes: list[str] = []

    for evt in events:
        utc_str, ist_str = format_utc_and_ist(evt)
        f = evt.features or {}
        if evt.scope_key not in scopes:
            scopes.append(evt.scope_key)
        actor = str(f.get("account") or "unknown")
        source_ip = str(f.get("remote_ip") or "")
        host = str(f.get("host") or "")
        cmd = str(f.get("command") or "")
        summary = f"{evt.event_type}"
        if cmd:
            summary += f" (command={cmd})"
        elif source_ip:
            summary += f" from {source_ip}"
        sev = (
            "high"
            if evt.event_type in ("privilege_escalation", "security_alert")
            else "medium"
            if evt.event_type == "authentication_failure"
            else "informational"
        )
        timeline.append(
            TimelineEntry(
                timestamp_utc=utc_str,
                timestamp_ist=ist_str,
                event_id=evt.event_id,
                evidence_ref_id=evt.evidence_ref.reference_id,
                scope_key=evt.scope_key,
                event_type=evt.event_type,
                actor=actor,
                source_ip=source_ip,
                host=host,
                summary=summary,
                significance=sev,
            )
        )
        if source_ip and actor != "unknown":
            relationships.append(
                EntityRelationship(
                    source_entity=f"ip:{source_ip}",
                    relation=evt.event_type,
                    target_entity=f"account:{actor}",
                    evidence_type="observed",
                    supporting_event_ids=[evt.event_id],
                    reasoning="Directly observed in normalized event features.",
                    confidence="high",
                )
            )
        if cmd and actor != "unknown":
            relationships.append(
                EntityRelationship(
                    source_entity=f"account:{actor}",
                    relation="invoked_command",
                    target_entity=f"command:{cmd}",
                    evidence_type="observed",
                    supporting_event_ids=[evt.event_id],
                    reasoning="Directly observed sudo/command invocation.",
                    confidence="high",
                )
            )

    return CorrelationTimelineOutput(
        timeline=timeline,
        relationships=relationships,
        correlated_scopes=scopes,
        temporal_patterns=[],
    )


def make_correlation_timeline_node(llm_factory: GeminiAgentFactory):
    """Create the async LangGraph node for Correlation & Timeline Analysis."""

    async def correlation_timeline_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]
        events = sorted(inv_input.normalized_events, key=lambda e: e.event_time)
        raw_excerpts = state.get("raw_log_excerpts") or {}
        event_analysis = state.get("event_analysis")
        knowledge_enrichment = state.get("knowledge_enrichment")
        sequence_analysis = state.get("sequence_analysis")

        user_prompt = (
            f"Investigation ID: {inv_input.investigation_id}\n\n"
            f"NORMALIZED EVENTS (chronological):\n{serialize_events_for_prompt(events, raw_excerpts)}\n\n"
            f"EVENT ANALYSIS SUMMARY:\n"
            f"{event_analysis.model_dump_json(indent=2) if event_analysis else '{}'}\n\n"
            f"KNOWLEDGE ENRICHMENT SUMMARY:\n"
            f"{knowledge_enrichment.model_dump_json(indent=2) if knowledge_enrichment else '{}'}\n\n"
            f"SEQUENCE ANALYSIS SUMMARY:\n"
            f"{sequence_analysis.model_dump_json(indent=2) if sequence_analysis else '{}'}\n\n"
            "Build the chronological timeline (exact UTC & IST timestamps), correlated scopes, "
            "temporal patterns, and observed-vs-inferred entity relationships."
        )

        status = "completed"
        notes: list[str] = []
        model_name = ""
        key_slot = ""

        try:
            output, model_name, key_slot = await llm_factory.invoke_structured(
                role="correlation_timeline",
                schema=CorrelationTimelineOutput,
                system_prompt=CORRELATION_TIMELINE_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
            # Enforce exact timestamps, evidence_ref_ids, and deduplication by event_id
            event_index = state.get("event_index") or {e.event_id: e for e in events}
            fixed_timeline: list[TimelineEntry] = []
            seen_timeline_events: set[str] = set()
            for entry in output.timeline:
                if entry.event_id in seen_timeline_events:
                    continue
                seen_timeline_events.add(entry.event_id)
                evt = event_index.get(entry.event_id)
                if evt is not None:
                    utc_str, ist_str = format_utc_and_ist(evt)
                    entry = entry.model_copy(
                        update={
                            "timestamp_utc": utc_str,
                            "timestamp_ist": ist_str,
                            "evidence_ref_id": evt.evidence_ref.reference_id,
                            "scope_key": evt.scope_key,
                        }
                    )
                fixed_timeline.append(entry)
            fixed_timeline.sort(key=lambda t: t.timestamp_utc)
            output = output.model_copy(update={"timeline": fixed_timeline})
        except Exception as exc:
            logger.warning("CorrelationTimeline LLM call failed, using deterministic fallback: %s", exc)
            output = _fallback_correlation_timeline(state)
            status = "fallback"
            notes.append(f"LLM error fallback: {exc}")

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="correlation_timeline",
            agent_role="correlation_timeline",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=f"{len(events)} event(s)",
            output_summary=(
                f"{len(output.timeline)} timeline entry(s), "
                f"{len(output.relationships)} relationship(s)"
            ),
            notes=notes,
        )
        return {
            "correlation_timeline": output,
            "audit_trail": [audit],
        }

    return correlation_timeline_node
