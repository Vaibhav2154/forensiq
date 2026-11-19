from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from datetime import datetime, timezone
import hashlib
import time
import uuid
from contracts import BatchIngestRequest, EvidenceReference, RawLogRecord
from model.logs_model import LogAnalysisRequest, LogAnalysisResponse, AttackTechnique
from model.analysis_model import AnalysisHistoryItem, UserAnalyticsStats
from services import GeminiService
from services.knowledge import KnowledgeSearchQuery, KnowledgeService
from services.analysis_storage_service import analysis_storage_service
from routers.auth import get_current_user
from core import logger

router = APIRouter(prefix="/api/v1", tags=["Log Analysis"])

# Global service instances (will be initialized in main app)
gemini_service: GeminiService = None
knowledge_service: KnowledgeService = None

def set_services(gemini: GeminiService, knowledge: KnowledgeService):
    """Set service instances for the router."""
    global gemini_service, knowledge_service
    gemini_service = gemini
    knowledge_service = knowledge


def _build_batch_from_raw_logs(raw_logs: str, username: str) -> BatchIngestRequest:
    """Wrap raw log text into a traceable BatchIngestRequest for KCP normalization."""
    now = datetime.now(timezone.utc)
    batch_id = f"batch-{uuid.uuid4().hex[:12]}"
    raw_lines = [line for line in raw_logs.splitlines() if line.strip()]
    if not raw_lines:
        raw_lines = [raw_logs.strip() or "(empty)"]

    records: list[RawLogRecord] = []
    for idx, line in enumerate(raw_lines, start=1):
        line_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        records.append(
            RawLogRecord(
                record_id=f"raw-{batch_id}-{idx:04d}",
                observed_at=now,
                message=line,
                source_type="api-analyze",
                evidence_ref=EvidenceReference(
                    reference_id=f"ev-{batch_id}-{idx:04d}",
                    uri=f"api://analyze/{username}/{batch_id}",
                    line_start=idx,
                    line_end=idx,
                    sha256=line_hash,
                ),
                metadata={"submitted_by": username},
            )
        )

    return BatchIngestRequest(
        batch_id=batch_id,
        source=f"api:{username}",
        records=records,
        sent_at=now,
    )


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


@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(request: LogAnalysisRequest, current_user: dict = Depends(get_current_user)) -> LogAnalysisResponse:
    """
    Analyze system logs through KCP normalization, OKF/Cognee knowledge retrieval, and Gemini AI.
    
    This endpoint:
    1. Runs raw logs through KCP to produce traceable NormalizedEvent records
    2. Uses Gemini AI to summarize the provided logs and extract a focused search query
    3. Queries the OKF/Cognee knowledge store for matching MITRE ATT&CK techniques
    4. Optionally enhances the analysis with additional AI insights
    """
    start_time = time.time()
    
    try:
        if not gemini_service or not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Services not properly initialized"
            )
        
        logger.info(f"Starting log analysis for {len(request.logs)} characters of logs")

        # Step 1: Normalize logs through KCP (preserving raw evidence references)
        batch_request = _build_batch_from_raw_logs(
            request.logs, current_user.get("username", "anonymous")
        )
        normalized_events = knowledge_service.normalize_batch(batch_request)
        logger.info(
            f"KCP normalized {len(normalized_events)} event(s) for batch {batch_request.batch_id}"
        )

        # Step 2: Summarize logs with Gemini AI
        logger.info("Generating log summary with Gemini AI")
        summary = await gemini_service.summarize_logs(request.logs)
        
        if not summary:
            logger.error("Failed to generate summary: empty response")
            raise HTTPException(
                status_code=500,
                detail="Failed to generate log summary: empty response"
            )
        
        if summary.startswith("Error generating summary:"):
            logger.error(f"Failed to generate summary: {summary}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate log summary: {summary}"
            )
        
        # Step 3: Extract a focused search query enriched with KCP event signals
        logger.info("Extracting focused search query from summary")
        search_query = await gemini_service.extract_search_query(request.logs, summary)
        kcp_event_types = sorted(
            {
                evt.event_type.replace("_", " ")
                for evt in normalized_events
                if evt.event_type != "system_log_event"
            }
        )
        if kcp_event_types:
            search_query = f"{search_query} {' '.join(kcp_event_types)}".strip()
        logger.info(f"Search query extracted ({len(search_query)} chars)")

        # Step 4: Search OKF/Cognee knowledge store for matching MITRE ATT&CK techniques
        logger.info("Searching OKF/Cognee knowledge store for matching ATT&CK techniques")
        search_resp = await knowledge_service.search(
            KnowledgeSearchQuery(
                query=search_query,
                source_type="mitre_attack",
                kind="technique",
                top_k=request.max_results or 5,
                search_mode="auto",
            )
        )
        techniques_data = [_hit_to_technique_dict(hit) for hit in search_resp.hits]
        
        matched_techniques = [
            AttackTechnique(**tech)
            for tech in techniques_data
        ]
        
        # Step 5: Enhanced analysis (if requested)
        enhanced_analysis = None
        if request.enhance_with_ai and matched_techniques:
            logger.info("Generating enhanced threat analysis")
            enhanced_analysis = await gemini_service.enhance_threat_analysis(
                summary, techniques_data
            )
        
        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        logger.info(f"Analysis completed in {processing_time:.2f}ms with {len(matched_techniques)} matches")
        
        response = LogAnalysisResponse(
            summary=summary,
            matched_techniques=matched_techniques,
            enhanced_analysis=enhanced_analysis,
            processing_time_ms=processing_time
        )
        
        # Store the analysis result in encrypted format
        try:
            analysis_id = await analysis_storage_service.store_analysis_result(
                user_id=current_user["username"],
                request=request,
                response=response
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
            detail=f"Internal server error: {str(e)}"
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
                kind="technique",
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
            "total_techniques": stats.counts_by_kind.get("technique", stats.total_records),
            "total_records": stats.total_records,
            "collection_name": f"okf-{stats.backend}",
            "embedding_model": knowledge_service.settings.embedding_model,
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

        latest_id = history[0].id
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