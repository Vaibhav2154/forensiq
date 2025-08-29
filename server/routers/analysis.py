from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
import time

from pydantic import BaseModel
from model.logs_model import LogAnalysisRequest, LogAnalysisResponse, AttackTechnique
from services import GeminiService, ChromaDBService
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
async def analyze_logs(request: LogAnalysisRequest) -> LogAnalysisResponse:
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
        
        return LogAnalysisResponse(
            summary=summary,
            matched_techniques=matched_techniques,
            enhanced_analysis=enhanced_analysis,
            processing_time_ms=processing_time
        )
        
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
