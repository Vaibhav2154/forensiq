"""Event Analysis specialist sub-agent node."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import (
    AuditEntry,
    EventAnalysisOutput,
    EvidenceObservation,
    ObservedIOC,
)
from services.investigation.prompts import (
    EVENT_ANALYST_SYSTEM_PROMPT,
    format_utc_and_ist,
    serialize_events_for_prompt,
)
from services.investigation.state import InvestigationState


logger = logging.getLogger(__name__)


def _fallback_event_analysis(state: InvestigationState) -> EventAnalysisOutput:
    """Deterministic fallback extracting factual observations directly from NormalizedEvents."""
    events = state["investigation_input"].normalized_events
    observations: list[EvidenceObservation] = []
    iocs: list[ObservedIOC] = []
    seen_iocs: set[tuple[str, str]] = set()
    noteworthy: list[str] = []
    entities: set[str] = set()

    for idx, evt in enumerate(events, start=1):
        utc_str, _ = format_utc_and_ist(evt)
        f = evt.features or {}
        is_anom = evt.event_type in (
            "authentication_failure",
            "privilege_escalation",
            "security_alert",
        )
        sev = (
            "high"
            if evt.event_type in ("privilege_escalation", "security_alert")
            else "medium"
            if evt.event_type == "authentication_failure"
            else "informational"
        )
        obs_entities: list[str] = []
        for k, ioc_type in (
            ("host", "host"),
            ("account", "account"),
            ("remote_ip", "ip"),
            ("command", "command"),
            ("process", "process"),
        ):
            val = f.get(k)
            if val:
                sval = str(val)
                obs_entities.append(f"{ioc_type}:{sval}")
                entities.add(f"{ioc_type}:{sval}")
                if (ioc_type, sval) not in seen_iocs and ioc_type in ("ip", "account", "command"):
                    seen_iocs.add((ioc_type, sval))
                    iocs.append(
                        ObservedIOC(
                            ioc_type=ioc_type,
                            value=sval,
                            event_ids=[evt.event_id],
                            evidence_ref_ids=[evt.evidence_ref.reference_id],
                            context=f"Observed in {evt.event_type} event",
                        )
                    )
        if is_anom:
            noteworthy.append(evt.event_id)
        observations.append(
            EvidenceObservation(
                observation_id=f"obs-{idx:03d}",
                event_id=evt.event_id,
                evidence_ref_id=evt.evidence_ref.reference_id,
                timestamp_utc=utc_str,
                scope_key=evt.scope_key,
                summary=f"{evt.event_type} on scope {evt.scope_key} (features: {json.dumps(f)})",
                severity=sev,
                entities=obs_entities,
                is_anomalous=is_anom,
            )
        )

    return EventAnalysisOutput(
        observations=observations,
        iocs=iocs,
        noteworthy_event_ids=noteworthy,
        observed_behaviors=sorted({e.event_type.replace("_", " ") for e in events}),
        entities_summary=sorted(entities),
        telemetry_gaps=[
            "Fallback deterministic extraction used; verify command exit codes, process trees, and network egress."
        ],
    )


def make_event_analyst_node(llm_factory: GeminiAgentFactory):
    """Create the async LangGraph node for Event Analysis."""

    async def event_analyst_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        events = state["investigation_input"].normalized_events
        raw_excerpts = state.get("raw_log_excerpts") or {}

        user_prompt = (
            f"Investigation ID: {state['investigation_input'].investigation_id}\n"
            f"Total normalized events: {len(events)}\n\n"
            f"NORMALIZED EVENTS:\n{serialize_events_for_prompt(events, raw_excerpts)}\n\n"
            "Produce a factual, evidence-backed EventAnalysisOutput citing exact event_id and "
            "evidence_ref_id values."
        )

        status = "completed"
        notes: list[str] = []
        model_name = ""
        key_slot = ""

        try:
            output, model_name, key_slot = await llm_factory.invoke_structured(
                role="event_analyst",
                schema=EventAnalysisOutput,
                system_prompt=EVENT_ANALYST_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
        except Exception as exc:
            logger.warning("EventAnalyst LLM call failed, using deterministic fallback: %s", exc)
            output = _fallback_event_analysis(state)
            status = "fallback"
            notes.append(f"LLM error fallback: {exc}")

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="event_analyst",
            agent_role="event_analyst",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=f"{len(events)} normalized event(s)",
            output_summary=(
                f"{len(output.observations)} observation(s), {len(output.iocs)} IOC(s), "
                f"{len(output.noteworthy_event_ids)} noteworthy event(s)"
            ),
            notes=notes,
        )
        return {
            "event_analysis": output,
            "audit_trail": [audit],
        }

    return event_analyst_node
