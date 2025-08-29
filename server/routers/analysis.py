from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
import time

from pydantic import BaseModel
from model.logs_model import LogAnalysisRequest, LogAnalysisResponse, AttackTechnique
from model.analysis_model import AnalysisHistoryItem, UserAnalyticsStats
from services import GeminiService, ChromaDBService
from services.analysis_storage_service import analysis_storage_service
from routers.auth import get_current_user
from core import logger

router = APIRouter(prefix="/api/v1", tags=["Log Analysis"])

# Global service instances (will be initialized in main app)
gemini_service: GeminiService = None
chromadb_service: ChromaDBService = None

def set_services(gemini: GeminiService, chromadb: ChromaDBService):
    """Set service instances for the router."""
    global gemini_service, chromadb_service
    gemini_service = gemini
    chromadb_service = chromadb

@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(request: LogAnalysisRequest, current_user: dict = Depends(get_current_user)) -> LogAnalysisResponse:
    """
    Analyze system logs using AI summarization and MITRE ATT&CK technique matching.
    
    This endpoint:
    1. Uses Gemini AI to summarize the provided logs
    2. Searches the ChromaDB vector database for matching MITRE ATT&CK techniques
    3. Optionally enhances the analysis with additional AI insights
    
    Args:
        request: LogAnalysisRequest containing logs and analysis parameters
        
    Returns:
        LogAnalysisResponse with summary, matched techniques, and enhanced analysis
    """
    start_time = time.time()
    
    try:
        if not gemini_service or not chromadb_service:
            raise HTTPException(
                status_code=500,
                detail="Services not properly initialized"
            )
        
        logger.info(f"Starting log analysis for {len(request.logs)} characters of logs")
        
        # Step 1: Summarize logs with Gemini AI
        logger.info("Generating log summary with Gemini AI")
        summary = await gemini_service.summarize_logs(request.logs)
        
        if not summary:
            logger.error("Failed to generate summary: empty response")
            raise HTTPException(
                status_code=500,
                detail="Failed to generate log summary: empty response"
            )
        
        # Clean the summary - remove any error prefixes that might be mistaken for actual errors
        if summary.startswith("Error generating summary:"):
            logger.error(f"Failed to generate summary: {summary}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate log summary: {summary}"
            )
        
        # Step 2: Search for matching MITRE ATT&CK techniques
        logger.info("Searching for matching ATT&CK techniques")
        techniques_data = await chromadb_service.search_techniques(
            query=summary,
            n_results=request.max_results
        )
        
        # Convert to response models
        matched_techniques = [
            AttackTechnique(
                technique_id=tech['technique_id'],
                name=tech['name'],
                description=tech['description'],
                kill_chain_phases=tech['kill_chain_phases'],
                platforms=tech['platforms'],
                relevance_score=tech['relevance_score']
            )
            for tech in techniques_data
        ]
        
        # Step 3: Enhanced analysis (if requested)
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
    Search MITRE ATT&CK techniques directly by query.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        
    Returns:
        Dictionary with search results
    """
    try:
        if not chromadb_service:
            raise HTTPException(
                status_code=500,
                detail="ChromaDB service not initialized"
            )
        
        techniques = await chromadb_service.search_techniques(query, max_results)
        
        return {
            "query": query,
            "results_count": len(techniques),
            "techniques": techniques
        }
        
    except Exception as e:
        logger.error(f"Error in technique search: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )

@router.get("/stats")
async def get_database_stats() -> Dict[str, Any]:
    """Get statistics about the MITRE ATT&CK database."""
    try:
        if not chromadb_service:
            raise HTTPException(
                status_code=500,
                detail="ChromaDB service not initialized"
            )
        
        stats = await chromadb_service.get_collection_stats()
        return stats
        
    except Exception as e:
        logger.error(f"Error getting database stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get stats: {str(e)}"
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
