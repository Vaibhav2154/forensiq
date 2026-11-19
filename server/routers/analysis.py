from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List, Optional
import time
from model.logs_model import LogAnalysisRequest, LogAnalysisResponse, AttackTechnique
from model.analysis_model import AnalysisHistoryItem, UserAnalyticsStats
from services import GeminiService
from services.investigation import (
    EnrichedKnowledgeItem,
    InvestigationService,
    build_batch_from_raw_logs,
)
from services.knowledge import KnowledgeSearchQuery, KnowledgeService
from services.analysis_storage_service import analysis_storage_service
from services.visualization_metrics import compute_visualization_metrics
from routers.auth import get_current_user
from core import logger

router = APIRouter(prefix="/api/v1", tags=["Log Analysis"])

# Global service instances (will be initialized in main app)
gemini_service: Optional[GeminiService] = None
knowledge_service: Optional[KnowledgeService] = None
investigation_service: Optional[InvestigationService] = None


def set_services(
    gemini: Optional[GeminiService],
    knowledge: Optional[KnowledgeService],
    investigation: Optional[InvestigationService] = None,
):
    """Set service instances for the router."""
    global gemini_service, knowledge_service, investigation_service
    gemini_service = gemini
    knowledge_service = knowledge
    investigation_service = investigation


def _hit_to_technique_dict(hit) -> Dict[str, Any]:
    """Convert an OKF KnowledgeSearchHit to the AttackTechnique dictionary shape."""
    rec = hit.record
    content = rec.content or {}
    tactics = content.get("tactics") or []
    if isinstance(tactics, str):
        tactics = [t.strip() for t in tactics.split(",") if t.strip()]
    platforms = content.get("platforms") or []
    if isinstance(platforms, str):
        platforms = [p.strip() for p in platforms.split(",") if p.strip()]
    description = str(content.get("description") or content.get("summary") or "")
    score = max(0.0, min(1.0, float(hit.score)))
    return {
        "technique_id": rec.source_id,
        "name": str(content.get("name") or content.get("title") or rec.source_id),
        "description": description,
        "kill_chain_phases": [str(t) for t in tactics],
        "platforms": [str(p) for p in platforms],
        "relevance_score": round(score, 4),
    }


def _enriched_item_to_technique(item: EnrichedKnowledgeItem) -> AttackTechnique:
    """Convert a verified OKF MITRE ATT&CK EnrichedKnowledgeItem to AttackTechnique."""
    return AttackTechnique(
        technique_id=item.source_id,
        name=item.name or item.source_id,
        description=item.description_excerpt or item.relevance_rationale or "",
        kill_chain_phases=[str(t) for t in item.tactics],
        platforms=[str(p) for p in item.platforms],
        relevance_score=round(max(0.0, min(1.0, float(item.relevance_score))), 4),
    )


@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(request: LogAnalysisRequest, current_user: dict = Depends(get_current_user)) -> LogAnalysisResponse:
    """
    Analyze system logs through KCP normalization, OKF/Cognee knowledge retrieval,
    and the LangGraph multi-agent investigation workflow.

    This endpoint:
    1. Wraps raw logs into a traceable BatchIngestRequest (preserving timestamps, hosts, and SHA-256 hashes)
    2. Normalizes logs via KCP into NormalizedEvent records and retrieves OKF/Cognee ATT&CK & CVE context
    3. Runs the LangGraph multi-agent investigation workflow (when enhance_with_ai=True) using Gemini sub-agents
    4. Returns both backward-compatible LogAnalysisResponse fields and the structured InvestigationResult
    """
    start_time = time.time()

    try:
        if not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Knowledge service not properly initialized",
            )

        username = current_user.get("username", "anonymous")
        max_results = request.max_results or 5
        logger.info(f"Starting log analysis for {len(request.logs)} characters of logs")

        if request.enhance_with_ai:
            active_investigation = investigation_service or InvestigationService(
                knowledge_service=knowledge_service
            )
            logger.info("Executing LangGraph multi-agent investigation workflow")
            inv_result = await active_investigation.investigate_raw_logs(
                raw_logs=request.logs,
                username=username,
                max_results=max_results,
            )

            mitre_items = [
                item
                for item in inv_result.retrieved_knowledge
                if item.source_type == "mitre_attack"
            ][:max_results]
            matched_techniques = [_enriched_item_to_technique(item) for item in mitre_items]
            summary = inv_result.rendered_summary or inv_result.executive_summary
            enhanced_analysis = inv_result.rendered_markdown_report
            investigation_payload = inv_result.model_dump(mode="json")
        else:
            # Lightweight non-LLM path: KCP normalization + OKF/Cognee retrieval only
            batch_request, _ = build_batch_from_raw_logs(request.logs, username)
            normalized_events = knowledge_service.normalize_batch(batch_request)
            query_terms = sorted(
                {
                    evt.event_type.replace("_", " ")
                    for evt in normalized_events
                    if evt.event_type != "system_log_event"
                }
            )
            search_query = " ".join(query_terms) if query_terms else request.logs[:300]
            search_resp = await knowledge_service.search(
                KnowledgeSearchQuery(
                    query=search_query,
                    source_type="mitre_attack",
                    kind="attack-pattern",
                    top_k=max_results,
                    search_mode="auto",
                )
            )
            matched_techniques = [
                AttackTechnique(**_hit_to_technique_dict(hit))
                for hit in search_resp.hits
            ]
            summary = (
                f"KCP normalized {len(normalized_events)} event(s) across "
                f"{len({e.scope_key for e in normalized_events})} scope(s); "
                f"retrieved {len(matched_techniques)} OKF/Cognee technique(s) (AI enhancement disabled)."
            )
            enhanced_analysis = None
            investigation_payload = None

        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        visualization_metrics = compute_visualization_metrics(
            matched_techniques, investigation_payload, processing_time
        )

        logger.info(f"Analysis completed in {processing_time:.2f}ms with {len(matched_techniques)} matches")

        response = LogAnalysisResponse(
            summary=summary,
            matched_techniques=matched_techniques,
            enhanced_analysis=enhanced_analysis,
            investigation=investigation_payload,
            visualization_metrics=visualization_metrics,
            processing_time_ms=processing_time,
        )

        # Store the analysis result in encrypted format
        try:
            analysis_id = await analysis_storage_service.store_analysis_result(
                user_id=current_user["username"],
                request=request,
                response=response,
            )
            logger.info(f"Stored analysis result with ID {analysis_id} for user {current_user['username']}")
        except Exception as e:
            logger.error(f"Failed to store analysis result: {str(e)}")
            # Continue without failing the request - storage is not critical for the response

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in log analysis: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}",
        )


@router.post("/search-techniques")
async def search_techniques(query: str, max_results: int = 5) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK techniques directly from the OKF/Cognee knowledge store.
    """
    try:
        if not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Knowledge service not initialized"
            )
        
        search_resp = await knowledge_service.search(
            KnowledgeSearchQuery(
                query=query,
                source_type="mitre_attack",
                kind="attack-pattern",
                top_k=max_results,
                search_mode="auto",
            )
        )
        techniques = [_hit_to_technique_dict(hit) for hit in search_resp.hits]
        
        return {
            "query": query,
            "results_count": len(techniques),
            "techniques": techniques
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in technique search: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )

@router.get("/stats")
async def get_database_stats() -> Dict[str, Any]:
    """Get statistics about the OKF/Cognee knowledge store."""
    try:
        if not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Knowledge service not initialized"
            )
        
        stats = await knowledge_service.stats()
        return {
            "total_techniques": stats.counts_by_kind.get("attack-pattern", stats.total_records),
            "total_records": stats.total_records,
            "collection_name": f"okf-{stats.backend}",
            "embedding_model": knowledge_service.settings.cognee_embedding_model,
            "counts_by_source_type": stats.counts_by_source_type,
            "counts_by_kind": stats.counts_by_kind,
            "last_updated": stats.last_ingested_at.isoformat() if stats.last_ingested_at else None,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting database stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get stats: {str(e)}"
        )

@router.get("/history/count")
async def get_analysis_count(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Get total number of analyses done by the authenticated user.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        {
            "total": int
        }
    """
    try:
        user_id = current_user["username"]
        total_count = await analysis_storage_service.get_total_analysis_count(user_id)

        logger.info(f"Total analysis count for user '{user_id}': {total_count}")

        return {"total": total_count}

    except Exception as e:
        logger.error(f"Error getting total analysis count: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get total analysis count: {str(e)}"
        )

@router.get("/history", response_model=List[AnalysisHistoryItem])
async def get_analysis_history(
    limit: int = 10, 
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
) -> List[AnalysisHistoryItem]:
    """
    Get user's analysis history.
    
    Args:
        limit: Maximum number of results to return (default: 10, max: 50)
        offset: Number of results to skip for pagination (default: 0)
        current_user: Current authenticated user
        
    Returns:
        List of analysis history items (without sensitive data)
    """
    try:
        # Validate parameters
        if limit > 50:
            limit = 50
        if limit < 1:
            limit = 10
        if offset < 0:
            offset = 0
            
        history = await analysis_storage_service.get_user_analysis_history(
            user_id=current_user["username"],
            limit=limit,
            offset=offset
        )
        
        logger.info(f"Retrieved {len(history)} history items for user {current_user['username']}")
        return history
        
    except Exception as e:
        logger.error(f"Error getting analysis history: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get analysis history: {str(e)}"
        )

@router.get("/history/{analysis_id}", response_model=LogAnalysisResponse)
async def get_analysis_result(
    analysis_id: str,
    current_user: dict = Depends(get_current_user)
) -> LogAnalysisResponse:
    """
    Get a specific analysis result by ID.
    
    Args:
        analysis_id: The analysis ID to retrieve
        current_user: Current authenticated user
        
    Returns:
        Complete analysis result with decrypted data
    """
    try:
        result = await analysis_storage_service.get_analysis_result(
            user_id=current_user["username"],
            analysis_id=analysis_id
        )
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Analysis result not found"
            )
            
        logger.info(f"Retrieved analysis result {analysis_id} for user {current_user['username']}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting analysis result {analysis_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get analysis result: {str(e)}"
        )

@router.delete("/history/{analysis_id}")
async def delete_analysis_result(
    analysis_id: str,
    current_user: dict = Depends(get_current_user)
) -> Dict[str, str]:
    """
    Delete a specific analysis result.
    
    Args:
        analysis_id: The analysis ID to delete
        current_user: Current authenticated user
        
    Returns:
        Success confirmation
    """
    try:
        success = await analysis_storage_service.delete_analysis_result(
            user_id=current_user["username"],
            analysis_id=analysis_id
        )
        
        if not success:
            raise HTTPException(
                status_code=404,
                detail="Analysis result not found"
            )
            
        logger.info(f"Deleted analysis result {analysis_id} for user {current_user['username']}")
        return {"message": "Analysis result deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting analysis result {analysis_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete analysis result: {str(e)}"
        )

@router.get("/analytics", response_model=UserAnalyticsStats)
async def get_user_analytics(
    current_user: dict = Depends(get_current_user)
) -> UserAnalyticsStats:
    """
    Get user analytics and statistics.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User analytics statistics
    """
    try:
        analytics = await analysis_storage_service.get_user_analytics(
            user_id=current_user["username"]
        )
        
        logger.info(f"Retrieved analytics for user {current_user['username']}")
        return analytics
        
    except Exception as e:
        logger.error(f"Error getting user analytics: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get analytics: {str(e)}"
        )


@router.get("/latest")
async def get_latest_analysis(
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get the most recent analysis result for the authenticated user.
    Used by the visualization page to load the latest data without relying
    solely on browser localStorage.

    Returns:
        {"analysis": LogAnalysisResponse} or {"analysis": null} if none found
    """
    try:
        history = await analysis_storage_service.get_user_analysis_history(
            user_id=current_user["username"],
            limit=1,
            offset=0
        )
        if not history:
            logger.info(f"No analysis history found for user {current_user['username']}")
            return {"analysis": None}

        first_item = history[0]
        latest_id = first_item["id"] if isinstance(first_item, dict) else first_item.id
        result = await analysis_storage_service.get_analysis_result(
            user_id=current_user["username"],
            analysis_id=latest_id
        )

        if not result:
            return {"analysis": None}

        logger.info(f"Returning latest analysis {latest_id} for user {current_user['username']}")
        return {"analysis": result}

    except Exception as e:
        logger.error(f"Error getting latest analysis: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get latest analysis: {str(e)}"
        )