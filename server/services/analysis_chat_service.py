"""Gemini-powered forensic chatbot service grounded in stored MongoDB analyses."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from typing import Any, Callable, Iterable, Optional

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, Field

from model.logs_model import AnalysisChatResponse, AnalysisChatTurn
from services.investigation.config import InvestigationSettings


logger = logging.getLogger(__name__)


class _StructuredChatAnswer(BaseModel):
    """Structured Pydantic output requested from Gemini for analysis Q&A."""

    answer: str = Field(
        description=(
            "Clear, thorough, Markdown-formatted answer grounded strictly in the stored "
            "analysis data. Clearly distinguish observed facts from inferences and gaps."
        )
    )
    referenced_event_ids: list[str] = Field(
        default_factory=list,
        description="Exact event_id values from the stored analysis that support this answer",
    )
    referenced_knowledge_ids: list[str] = Field(
        default_factory=list,
        description="Exact MITRE ATT&CK or CVE IDs (e.g. T1021.004, M1032, CVE-2025-39447) present in the stored analysis",
    )
    follow_up_questions: list[str] = Field(
        default_factory=list,
        description="2 to 3 concise, high-value follow-up questions the analyst may want to ask next",
    )
    evidence_caveats: list[str] = Field(
        default_factory=list,
        description="Any important uncertainties, missing telemetry, or evidence-vs-inference caveats relevant to this answer",
    )


_SYSTEM_PROMPT = """You are the ForensIQ Stored Analysis Assistant, an expert cybersecurity and digital forensics analyst powered by Gemini.
You answer an analyst's questions strictly using the decrypted ForensIQ multi-agent analysis record(s) retrieved from MongoDB below.

CRITICAL GROUNDING RULES:
1. Base all incident-specific claims strictly on the provided STORED ANALYSIS CONTEXT. If a detail (such as command exit code, stdout, outbound exfiltration, or sudoers file contents) is NOT in the stored analysis, explicitly state that it is unconfirmed or missing from the stored evidence.
2. Clearly separate **observed log facts** (citing exact `event_id` / `evidence_ref_id` values when present) from **inferences / hypotheses**.
3. For `referenced_knowledge_ids`, ONLY list MITRE ATT&CK or CVE IDs that actually appear in the stored analysis context. Never treat a retrieved ATT&CK/CVE record as standalone proof of compromise.
4. When discussing recommendations or containment actions, emphasize that all proposed actions require explicit human review and approval (`requires_human_approval=True`) and are not auto-executed.
5. Format `answer` in clean GitHub-flavored Markdown (headings, bullet lists, inline code for IPs/commands/event IDs/technique IDs) so it is easy to scan in a SOC terminal UI.
6. Provide 2-3 helpful, specific `follow_up_questions` tailored to the stored analysis and the user's current question."""


def _dedupe_preserve(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        cleaned = str(item).strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


def _extract_allowed_ids(analyses: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """Collect verified event_ids and ATT&CK/CVE/mitigation IDs across loaded stored analyses."""
    allowed_events: set[str] = set()
    allowed_knowledge: set[str] = set()

    for item in analyses:
        for tech in item.get("matched_techniques") or []:
            if isinstance(tech, dict) and tech.get("technique_id"):
                allowed_knowledge.add(str(tech["technique_id"]).upper())

        inv = item.get("investigation")
        if not isinstance(inv, dict):
            continue

        for obs in inv.get("observations") or []:
            if isinstance(obs, dict) and obs.get("event_id"):
                allowed_events.add(str(obs["event_id"]))
        for entry in inv.get("timeline") or []:
            if isinstance(entry, dict) and entry.get("event_id"):
                allowed_events.add(str(entry["event_id"]))
        for finding in inv.get("findings") or []:
            if isinstance(finding, dict):
                for eid in finding.get("supporting_event_ids") or []:
                    allowed_events.add(str(eid))
                for kid in finding.get("knowledge_source_ids") or []:
                    allowed_knowledge.add(str(kid).upper())
        for kn in inv.get("retrieved_knowledge") or []:
            if isinstance(kn, dict):
                if kn.get("source_id"):
                    allowed_knowledge.add(str(kn["source_id"]).upper())
                for mit in kn.get("related_mitigations") or []:
                    token = str(mit).split(":", 1)[0].strip().upper()
                    if token.startswith("M"):
                        allowed_knowledge.add(token)
        for rec in inv.get("recommendations") or []:
            if isinstance(rec, dict):
                for eid in rec.get("evidence_event_ids") or []:
                    allowed_events.add(str(eid))
                for mid in rec.get("knowledge_mitigation_ids") or []:
                    allowed_knowledge.add(str(mid).upper())
        ap = inv.get("attack_path")
        if isinstance(ap, dict):
            for node in ap.get("nodes") or []:
                if isinstance(node, dict):
                    for eid in node.get("event_ids") or []:
                        allowed_events.add(str(eid))
                    for kid in node.get("knowledge_source_ids") or []:
                        allowed_knowledge.add(str(kid).upper())

    return allowed_events, allowed_knowledge


def _serialize_analysis_for_chat(
    analysis: dict[str, Any],
    *,
    compact: bool = False,
) -> dict[str, Any]:
    """Build a structured, token-budgeted representation of a decrypted MongoDB analysis."""
    inv = analysis.get("investigation")
    techniques = analysis.get("matched_techniques") or []

    payload: dict[str, Any] = {
        "analysis_id": analysis.get("id"),
        "analysis_timestamp": analysis.get("analysis_timestamp"),
        "processing_time_ms": analysis.get("processing_time_ms"),
        "matched_techniques": [
            {
                "technique_id": t.get("technique_id"),
                "name": t.get("name"),
                "kill_chain_phases": t.get("kill_chain_phases", []),
                "platforms": t.get("platforms", []),
                "relevance_score": t.get("relevance_score"),
                **({} if compact else {"description": str(t.get("description", ""))[:320]}),
            }
            for t in techniques[: (5 if compact else 15)]
            if isinstance(t, dict)
        ],
    }

    if isinstance(inv, dict):
        if compact:
            payload["investigation_summary"] = {
                "investigation_id": inv.get("investigation_id"),
                "overall_threat_level": inv.get("overall_threat_level"),
                "overall_confidence": inv.get("overall_confidence"),
                "executive_summary": str(inv.get("executive_summary", ""))[:500],
                "findings": [
                    {
                        "finding_id": f.get("finding_id"),
                        "title": f.get("title"),
                        "severity": f.get("severity"),
                        "confidence": f.get("confidence"),
                        "knowledge_source_ids": f.get("knowledge_source_ids", []),
                    }
                    for f in (inv.get("findings") or [])[:5]
                    if isinstance(f, dict)
                ],
                "iocs": [
                    {"ioc_type": i.get("ioc_type"), "value": i.get("value")}
                    for i in (inv.get("iocs") or [])[:10]
                    if isinstance(i, dict)
                ],
                "uncertainty_and_gaps": (inv.get("uncertainty_and_gaps") or [])[:4],
            }
        else:
            payload["investigation"] = {
                "investigation_id": inv.get("investigation_id"),
                "status": inv.get("status"),
                "overall_threat_level": inv.get("overall_threat_level"),
                "overall_confidence": inv.get("overall_confidence"),
                "executive_summary": inv.get("executive_summary"),
                "observations": (inv.get("observations") or [])[:25],
                "findings": (inv.get("findings") or [])[:15],
                "retrieved_knowledge": (inv.get("retrieved_knowledge") or [])[:15],
                "timeline": (inv.get("timeline") or [])[:30],
                "relationships": (inv.get("relationships") or [])[:25],
                "attack_path": inv.get("attack_path"),
                "iocs": (inv.get("iocs") or [])[:25],
                "recommendations": (inv.get("recommendations") or [])[:15],
                "recommendation_status": inv.get("recommendation_status"),
                "sequence_assessment": inv.get("sequence_assessment"),
                "potential_impact": (inv.get("potential_impact") or [])[:10],
                "uncertainty_and_gaps": (inv.get("uncertainty_and_gaps") or [])[:12],
                "guardrail_warnings": (inv.get("guardrail_warnings") or [])[:10],
                "refinement_rounds_executed": inv.get("refinement_rounds_executed"),
                "audit_trail": [
                    {
                        "node_name": a.get("node_name"),
                        "agent_role": a.get("agent_role"),
                        "status": a.get("status"),
                        "model_name": a.get("model_name"),
                        "duration_ms": a.get("duration_ms"),
                        "output_summary": a.get("output_summary"),
                    }
                    for a in (inv.get("audit_trail") or [])[:20]
                    if isinstance(a, dict)
                ],
            }
    else:
        # Legacy stored analysis (pre-multi-agent): include summary & enhanced_analysis
        payload["summary"] = str(analysis.get("summary") or "")[: (800 if compact else 4000)]
        if not compact and analysis.get("enhanced_analysis"):
            payload["enhanced_analysis"] = str(analysis.get("enhanced_analysis"))[:5000]

    return payload


def _is_transient_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(
        marker in msg
        for marker in (
            "429",
            "resourceexhausted",
            "resource_exhausted",
            "quota",
            "rate limit",
            "too many requests",
            "503",
            "unavailable",
            "deadline exceeded",
            "timeout",
        )
    )


ChatRunner = Callable[[list[BaseMessage]], Any]


class AnalysisChatService:
    """Gemini-backed conversational assistant over encrypted MongoDB analyses."""

    def __init__(
        self,
        settings: Optional[InvestigationSettings] = None,
        custom_runner: Optional[ChatRunner] = None,
    ) -> None:
        self.settings = settings or InvestigationSettings()
        self._custom_runner = custom_runner
        self._client_cache: dict[tuple[str, str], ChatGoogleGenerativeAI] = {}

    def _get_client(self, api_key: str, model_name: str) -> ChatGoogleGenerativeAI:
        cache_key = (api_key, model_name)
        client = self._client_cache.get(cache_key)
        if client is None:
            client = ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=api_key,
                temperature=0.2,
                timeout=self.settings.request_timeout_seconds,
                max_retries=0,
            )
            self._client_cache[cache_key] = client
        return client

    async def chat_about_analyses(
        self,
        *,
        message: str,
        primary_analysis: Optional[dict[str, Any]],
        additional_analyses: Optional[list[dict[str, Any]]] = None,
        conversation_history: Optional[list[AnalysisChatTurn]] = None,
    ) -> AnalysisChatResponse:
        """Answer an analyst question grounded in one primary stored analysis and/or recent history."""
        started = time.perf_counter()
        extras = additional_analyses or []
        all_analyses: list[dict[str, Any]] = []
        if primary_analysis is not None:
            all_analyses.append(primary_analysis)
        all_analyses.extend(extras)

        if not all_analyses:
            raise ValueError("At least one stored analysis is required for chat context.")

        consulted_ids = _dedupe_preserve(
            str(a["id"]) for a in all_analyses if a.get("id")
        )
        allowed_events, allowed_knowledge = _extract_allowed_ids(all_analyses)

        context_obj: dict[str, Any] = {}
        if primary_analysis is not None:
            context_obj["primary_stored_analysis"] = _serialize_analysis_for_chat(
                primary_analysis, compact=False
            )
            if extras:
                context_obj["recent_other_stored_analyses"] = [
                    _serialize_analysis_for_chat(a, compact=True) for a in extras
                ]
        else:
            context_obj["stored_analyses_history"] = [
                _serialize_analysis_for_chat(a, compact=len(extras) > 2) for a in extras
            ]

        context_json = json.dumps(context_obj, indent=2, default=str)
        system_content = (
            f"{_SYSTEM_PROMPT}\n\n"
            f"VERIFIED ALLOWED EVENT IDS: {sorted(allowed_events)}\n"
            f"VERIFIED ALLOWED KNOWLEDGE IDS: {sorted(allowed_knowledge)}\n\n"
            f"STORED ANALYSIS CONTEXT (DECRYPTED FROM MONGODB):\n{context_json}"
        )

        messages: list[BaseMessage] = [SystemMessage(content=system_content)]
        for turn in (conversation_history or [])[-12:]:
            if turn.role == "user":
                messages.append(HumanMessage(content=turn.content))
            else:
                messages.append(AIMessage(content=turn.content))
        messages.append(HumanMessage(content=message))

        creds = self.settings.resolve_agent_credentials("orchestrator")
        model_used = creds.model_name

        parsed: _StructuredChatAnswer
        if self._custom_runner is not None:
            raw = self._custom_runner(messages)
            if inspect.isawaitable(raw):
                raw = await raw
            parsed = (
                raw
                if isinstance(raw, _StructuredChatAnswer)
                else _StructuredChatAnswer.model_validate(raw)
            )
        else:
            if not creds.api_key:
                raise RuntimeError(
                    "No Gemini API key configured for stored analysis chat. "
                    "Set GEMINI_API_KEY or INVESTIGATION_GEMINI_API_KEYS."
                )

            attempts: list[tuple[str, str]] = [(creds.api_key, creds.key_slot_label)]
            attempts.extend(self.settings.fallback_key_candidates(creds.api_key))
            max_attempts = max(1, self.settings.max_retries + 1)
            last_exc: Optional[Exception] = None
            parsed = None  # type: ignore[assignment]

            for idx in range(max_attempts):
                api_key, slot = attempts[idx % len(attempts)]
                try:
                    llm = self._get_client(api_key=api_key, model_name=creds.model_name)
                    structured = llm.with_structured_output(_StructuredChatAnswer)
                    resp = await structured.ainvoke(messages)
                    if resp is None:
                        raise ValueError("Empty structured response from Gemini")
                    parsed = (
                        resp
                        if isinstance(resp, _StructuredChatAnswer)
                        else _StructuredChatAnswer.model_validate(resp)
                    )
                    break
                except Exception as exc:
                    last_exc = exc
                    if idx + 1 < max_attempts and _is_transient_error(exc):
                        backoff = min(4.0, 0.75 * (2**idx))
                        logger.warning(
                            "AnalysisChat Gemini transient error (slot=%s, attempt %d/%d): %s",
                            slot,
                            idx + 1,
                            max_attempts,
                            exc,
                        )
                        await asyncio.sleep(backoff)
                        continue
                    raise

            if parsed is None:
                assert last_exc is not None
                raise last_exc

        # Programmatically filter citations so only verified stored IDs are returned
        verified_event_ids = (
            [eid for eid in _dedupe_preserve(parsed.referenced_event_ids) if eid in allowed_events]
            if allowed_events
            else []
        )
        verified_knowledge_ids = (
            [
                kid.upper()
                for kid in _dedupe_preserve(parsed.referenced_knowledge_ids)
                if kid.upper() in allowed_knowledge
            ]
            if allowed_knowledge
            else []
        )

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return AnalysisChatResponse(
            analysis_id=str(primary_analysis["id"]) if primary_analysis and primary_analysis.get("id") else None,
            analyses_consulted=consulted_ids,
            answer=parsed.answer.strip(),
            referenced_event_ids=verified_event_ids,
            referenced_knowledge_ids=verified_knowledge_ids,
            follow_up_questions=_dedupe_preserve(parsed.follow_up_questions)[:4],
            evidence_caveats=_dedupe_preserve(parsed.evidence_caveats)[:5],
            model_used=model_used,
            processing_time_ms=duration_ms,
        )


analysis_chat_service = AnalysisChatService()
