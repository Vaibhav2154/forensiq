"""Sequence Analysis specialist sub-agent node (LSTM-ready conditional hook)."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import (
    AuditEntry,
    SequenceAnalysisOutput,
    SequenceCueReview,
)
from services.investigation.prompts import (
    SEQUENCE_ANALYST_SYSTEM_PROMPT,
    serialize_events_for_prompt,
    serialize_sequence_cues_for_prompt,
)
from services.investigation.state import InvestigationState


logger = logging.getLogger(__name__)


def _fallback_sequence_analysis(state: InvestigationState) -> SequenceAnalysisOutput:
    """Deterministic fallback reviewing SequenceCue event coverage without LLM."""
    event_index = state.get("event_index") or {
        e.event_id: e for e in state["investigation_input"].normalized_events
    }
    reviews: list[SequenceCueReview] = []
    for cue in state["investigation_input"].sequence_cues:
        present = [eid for eid in cue.event_ids if eid in event_index]
        missing = [eid for eid in cue.event_ids if eid not in event_index]
        corroborated = bool(present) and cue.risk_score >= cue.threshold
        reviews.append(
            SequenceCueReview(
                cue_id=cue.cue_id,
                scope_key=cue.scope_key,
                risk_score=cue.risk_score,
                threshold=cue.threshold,
                corroborated_by_events=corroborated,
                supporting_event_ids=present,
                missing_event_ids=missing,
                assessment=(
                    f"LSTM cue scored {cue.risk_score:.2f} (threshold {cue.threshold:.2f}) across "
                    f"{len(present)} retained event(s) and {len(missing)} unavailable event(s). "
                    "Treated as an investigative prioritization signal, not proof."
                ),
                confidence="medium" if present and not missing else "low",
            )
        )
    return SequenceAnalysisOutput(
        status="analyzed",
        reviews=reviews,
        summary=f"Reviewed {len(reviews)} LSTM sequence cue(s) against retained normalized events.",
    )


def make_sequence_analyst_node(llm_factory: GeminiAgentFactory):
    """Create the async LangGraph node for LSTM Sequence Cue Analysis."""

    async def sequence_analyst_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]
        cues = inv_input.sequence_cues

        # Clean zero-cost bypass until LSTM is connected (or when batch produces no cues)
        if not cues:
            output = SequenceAnalysisOutput(
                status="skipped_no_cues",
                reviews=[],
                summary=(
                    "No LSTM sequence cues provided; sequence analysis node bypassed "
                    "(ready for future LSTM SequenceCueProvider integration)."
                ),
            )
            duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
            audit = AuditEntry(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                node_name="sequence_analyst",
                agent_role="sequence_analyst",
                status="skipped",
                model_name="",
                api_key_slot="",
                duration_ms=duration_ms,
                input_summary="0 LSTM sequence cues",
                output_summary="Skipped (no LSTM sequence_cues present; hook ready)",
                notes=["Zero LLM calls made while LSTM is not yet connected."],
            )
            return {
                "sequence_analysis": output,
                "audit_trail": [audit],
            }

        events = inv_input.normalized_events
        raw_excerpts = state.get("raw_log_excerpts") or {}
        event_index = state.get("event_index") or {e.event_id: e for e in events}

        user_prompt = (
            f"Investigation ID: {inv_input.investigation_id}\n\n"
            f"LSTM SEQUENCE CUES:\n{serialize_sequence_cues_for_prompt(cues)}\n\n"
            f"RETAINED NORMALIZED EVENTS:\n{serialize_events_for_prompt(events, raw_excerpts)}\n\n"
            "Evaluate each LSTM SequenceCue strictly against the retained normalized events. "
            "Never accept a model risk score as proof of compromise."
        )

        status = "completed"
        notes: list[str] = []
        model_name = ""
        key_slot = ""

        try:
            output, model_name, key_slot = await llm_factory.invoke_structured(
                role="sequence_analyst",
                schema=SequenceAnalysisOutput,
                system_prompt=SEQUENCE_ANALYST_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
            # Deterministically verify event_id coverage on every cue review
            verified_reviews: list[SequenceCueReview] = []
            cue_by_id = {c.cue_id: c for c in cues}
            for rev in output.reviews:
                src_cue = cue_by_id.get(rev.cue_id)
                if src_cue is not None:
                    present = [eid for eid in src_cue.event_ids if eid in event_index]
                    missing = [eid for eid in src_cue.event_ids if eid not in event_index]
                    rev = rev.model_copy(
                        update={
                            "supporting_event_ids": present,
                            "missing_event_ids": missing,
                            "risk_score": src_cue.risk_score,
                            "threshold": src_cue.threshold,
                        }
                    )
                verified_reviews.append(rev)
            output = output.model_copy(update={"status": "analyzed", "reviews": verified_reviews})
        except Exception as exc:
            logger.warning("SequenceAnalyst LLM call failed, using deterministic fallback: %s", exc)
            output = _fallback_sequence_analysis(state)
            status = "fallback"
            notes.append(f"LLM error fallback: {exc}")

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name="sequence_analyst",
            agent_role="sequence_analyst",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=f"{len(cues)} LSTM sequence cue(s), {len(events)} event(s)",
            output_summary=f"Reviewed {len(output.reviews)} sequence cue(s)",
            notes=notes,
        )
        return {
            "sequence_analysis": output,
            "audit_trail": [audit],
        }

    return sequence_analyst_node
