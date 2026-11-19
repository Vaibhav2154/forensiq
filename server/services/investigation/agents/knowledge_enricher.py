"""Knowledge Enrichment specialist sub-agent backed by Cognee/OKF KnowledgeService."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from contracts import KnowledgeRecord
from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import (
    AuditEntry,
    EnrichedKnowledgeItem,
    FollowUpQueryPlan,
    KnowledgeEnrichmentOutput,
)
from services.investigation.prompts import (
    KNOWLEDGE_ENRICHER_SYSTEM_PROMPT,
    KNOWLEDGE_QUERY_PLANNER_SYSTEM_PROMPT,
    serialize_events_for_prompt,
    serialize_knowledge_catalog_for_prompt,
)
from services.investigation.state import InvestigationState
from services.knowledge import KnowledgeSearchQuery, KnowledgeService


logger = logging.getLogger(__name__)


def _fallback_enrichment(
    knowledge_catalog: dict[str, KnowledgeRecord],
    knowledge_scores: dict[str, float],
    related_map: dict[str, list[KnowledgeRecord]],
    event_ids: list[str],
    queries_executed: list[str],
    cves_checked: bool,
) -> KnowledgeEnrichmentOutput:
    """Deterministic fallback converting verified OKF catalog records to EnrichedKnowledgeItem."""
    items: list[EnrichedKnowledgeItem] = []
    for src_key, rec in knowledge_catalog.items():
        content = rec.content or {}
        tactics = content.get("tactics") or []
        if isinstance(tactics, str):
            tactics = [t.strip() for t in tactics.split(",") if t.strip()]
        platforms = content.get("platforms") or []
        if isinstance(platforms, str):
            platforms = [p.strip() for p in platforms.split(",") if p.strip()]
        mitigations: list[str] = []
        detections: list[str] = []
        for rel in related_map.get(src_key, []):
            rc = rel.content or {}
            kind = str(rc.get("kind", "")).lower()
            label = f"{rel.source_id}: {rc.get('name') or rc.get('title') or rel.source_id}"
            if kind in ("mitigation", "course-of-action") or rel.source_id.upper().startswith("M"):
                mitigations.append(label)
            elif kind in ("data_component", "data_source", "x-mitre-data-component"):
                detections.append(label)
        items.append(
            EnrichedKnowledgeItem(
                record_id=rec.record_id,
                source_type=rec.source_type,
                source_id=rec.source_id,
                source_version=rec.source_version,
                name=str(content.get("name") or content.get("title") or rec.source_id),
                description_excerpt=str(content.get("summary") or content.get("description") or "")[:360],
                tactics=[str(t) for t in tactics],
                platforms=[str(p) for p in platforms],
                relevance_score=round(max(0.0, min(1.0, float(knowledge_scores.get(src_key, 0.5)))), 4),
                is_evidence_proof=False,
                supporting_event_ids=event_ids[:5],
                relevance_rationale="Retrieved from OKF/Cognee as investigative context (fallback mode).",
                missing_confirmation_evidence=[
                    "Additional host/network telemetry required to confirm technique execution."
                ],
                related_mitigations=mitigations,
                related_detections=detections,
                provenance_uri=str((rec.provenance or {}).get("source_uri", "")),
            )
        )
    items.sort(key=lambda x: x.relevance_score, reverse=True)
    return KnowledgeEnrichmentOutput(
        enriched_records=items[:8],
        follow_up_queries_executed=queries_executed,
        unmapped_behaviors=[],
        cves_checked=cves_checked,
    )


def make_knowledge_enricher_node(
    llm_factory: GeminiAgentFactory,
    knowledge_service: KnowledgeService | None = None,
    node_name: str = "knowledge_enricher",
):
    """Create the async LangGraph node for Cognee/OKF Knowledge Enrichment."""

    async def knowledge_enricher_node(state: InvestigationState) -> dict[str, Any]:
        started = time.perf_counter()
        inv_input = state["investigation_input"]
        events = inv_input.normalized_events
        raw_excerpts = state.get("raw_log_excerpts") or {}
        refinement_instructions = (state.get("refinement_instructions") or "").strip()

        # Copy current verified catalog so we can safely enrich it with live Cognee searches
        catalog: dict[str, KnowledgeRecord] = dict(state.get("knowledge_catalog") or {})
        scores: dict[str, float] = dict(state.get("knowledge_scores") or {})
        related_map: dict[str, list[KnowledgeRecord]] = {
            k: list(v) for k, v in (state.get("related_knowledge_map") or {}).items()
        }
        newly_retrieved: list[KnowledgeRecord] = []
        queries_executed: list[str] = []
        cves_checked = False
        notes: list[str] = []
        model_name = ""
        key_slot = ""
        status = "completed"

        # Step 1: Plan & execute targeted follow-up queries against Cognee/OKF when available
        if knowledge_service is not None and llm_factory.settings.max_followup_queries > 0:
            planner_prompt = (
                f"Normalized Events:\n{serialize_events_for_prompt(events, raw_excerpts)}\n\n"
                f"Already Retrieved OKF IDs: {sorted(catalog.keys())}\n"
            )
            if refinement_instructions:
                planner_prompt += (
                    f"\nORCHESTRATOR REFINEMENT REQUEST:\n{refinement_instructions}\n"
                )
            planner_prompt += (
                f"\nPropose up to {llm_factory.settings.max_followup_queries} focused Cognee/OKF "
                "queries to ensure complete MITRE ATT&CK and (if applicable) CVE coverage."
            )

            try:
                plan, model_name, key_slot = await llm_factory.invoke_structured(
                    role="knowledge_enricher",
                    schema=FollowUpQueryPlan,
                    system_prompt=KNOWLEDGE_QUERY_PLANNER_SYSTEM_PROMPT,
                    user_prompt=planner_prompt,
                )
                for qspec in plan.queries[: llm_factory.settings.max_followup_queries]:
                    src_filter = None if qspec.source_type == "any" else qspec.source_type
                    if src_filter == "cve" or plan.should_check_cves:
                        cves_checked = True
                    kind_filter = "attack-pattern" if src_filter == "mitre_attack" else None
                    try:
                        search_resp = await knowledge_service.search(
                            KnowledgeSearchQuery(
                                query=qspec.query,
                                source_type=src_filter,
                                kind=kind_filter,
                                top_k=llm_factory.settings.top_k_knowledge,
                                search_mode="auto",
                            )
                        )
                        queries_executed.append(f"[{qspec.source_type}] {qspec.query}")
                        for hit in search_resp.hits:
                            rec = hit.record
                            src_key = rec.source_id.upper()
                            hit_score = round(max(0.0, min(1.0, float(hit.score))), 4)
                            if src_key not in catalog:
                                catalog[src_key] = rec
                                newly_retrieved.append(rec)
                            scores[src_key] = max(scores.get(src_key, 0.0), hit_score)
                    except Exception as search_exc:
                        logger.warning(
                            "KnowledgeService search failed for %r: %s", qspec.query, search_exc
                        )
                        notes.append(f"Search error for '{qspec.query}': {search_exc}")
            except Exception as plan_exc:
                logger.warning("Knowledge query planner failed (continuing with existing catalog): %s", plan_exc)
                notes.append(f"Query planner skipped: {plan_exc}")

            # Step 2: 1-hop graph expansion (mitigations & detections) for top retrieved records
            ranked_keys = sorted(
                catalog.keys(), key=lambda k: scores.get(k, 0.0), reverse=True
            )[:6]
            for src_key in ranked_keys:
                if src_key in related_map and related_map[src_key]:
                    continue
                rec = catalog[src_key]
                try:
                    detail = await knowledge_service.get_by_source(
                        rec.source_type, rec.source_id, include_related=True
                    )
                    if detail and detail.related_records:
                        related_map[src_key] = list(detail.related_records)
                except Exception as rel_exc:
                    logger.debug("1-hop graph expansion failed for %s: %s", src_key, rel_exc)

        # Step 3: Grounded synthesis of EnrichedKnowledgeOutput strictly over verified catalog
        enrich_prompt = (
            f"Investigation ID: {inv_input.investigation_id}\n\n"
            f"NORMALIZED EVENTS:\n{serialize_events_for_prompt(events, raw_excerpts)}\n\n"
            f"VERIFIED OKF CATALOG (ONLY cite IDs from this catalog):\n"
            f"{serialize_knowledge_catalog_for_prompt(catalog, scores, related_map)}\n"
        )
        if refinement_instructions:
            enrich_prompt += (
                f"\nORCHESTRATOR REFINEMENT INSTRUCTIONS (address every point):\n"
                f"{refinement_instructions}\n"
            )
        enrich_prompt += (
            "\nSelect and contextualize the most relevant OKF records from the VERIFIED OKF CATALOG. "
            "Never invent any technique or CVE ID. Set is_evidence_proof=false on every item."
        )

        if not catalog:
            output = KnowledgeEnrichmentOutput(
                enriched_records=[],
                follow_up_queries_executed=queries_executed,
                unmapped_behaviors=[e.event_type for e in events],
                cves_checked=cves_checked,
            )
            notes.append("No OKF records available in catalog for enrichment.")
        else:
            try:
                output, model_name, key_slot = await llm_factory.invoke_structured(
                    role="knowledge_enricher",
                    schema=KnowledgeEnrichmentOutput,
                    system_prompt=KNOWLEDGE_ENRICHER_SYSTEM_PROMPT,
                    user_prompt=enrich_prompt,
                )
                output = output.model_copy(
                    update={
                        "follow_up_queries_executed": queries_executed or output.follow_up_queries_executed,
                        "cves_checked": cves_checked or output.cves_checked,
                    }
                )
            except Exception as exc:
                logger.warning("KnowledgeEnricher LLM call failed, using deterministic fallback: %s", exc)
                output = _fallback_enrichment(
                    knowledge_catalog=catalog,
                    knowledge_scores=scores,
                    related_map=related_map,
                    event_ids=[e.event_id for e in events],
                    queries_executed=queries_executed,
                    cves_checked=cves_checked,
                )
                status = "fallback"
                notes.append(f"LLM error fallback: {exc}")

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        audit = AuditEntry(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            node_name=node_name,
            agent_role="knowledge_enricher",
            status=status,
            model_name=model_name,
            api_key_slot=key_slot,
            duration_ms=duration_ms,
            input_summary=(
                f"{len(events)} event(s), {len(catalog)} verified OKF record(s)"
                + (f", refinement='{refinement_instructions[:60]}'" if refinement_instructions else "")
            ),
            output_summary=(
                f"{len(output.enriched_records)} enriched record(s), "
                f"{len(queries_executed)} follow-up query(s), cves_checked={output.cves_checked}"
            ),
            notes=notes,
        )

        return {
            "knowledge_catalog": catalog,
            "knowledge_scores": scores,
            "related_knowledge_map": related_map,
            "extra_knowledge_records": newly_retrieved,
            "knowledge_enrichment": output,
            "audit_trail": [audit],
        }

    return knowledge_enricher_node
