"""
API endpoints for monitoring and analysis storage.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

from routers.auth import get_current_user
from services.analysis_storage_service import AnalysisStorageService
from model.analysis_storage import StoredAnalysis, MonitoringSession, AnalysisStats
from core import logger

router = APIRouter(prefix="/api/v1", tags=["Monitoring & Storage"])

# Initialize storage service
storage_service = AnalysisStorageService()

# Request/Response models
class CreateSessionRequest(BaseModel):
    """Request model for creating monitoring session."""
    log_path: str = Field(..., description="Path to log file to monitor")
    interval_seconds: int = Field(default=300, description="Monitoring interval in seconds")
    ai_agent_enabled: bool = Field(default=True, description="Enable AI agent for analysis")

class StoreAnalysisRequest(BaseModel):
    """Request model for storing analysis result."""
    log_content: str = Field(..., description="Original log content")
    analysis_result: Dict[str, Any] = Field(..., description="Analysis result from API")
    session_id: Optional[str] = Field(None, description="Associated monitoring session ID")
    log_file_path: Optional[str] = Field(None, description="Path to original log file")
    username: Optional[str] = Field(None, description="Username of the authenticated user")

class SessionResponse(BaseModel):
    """Response model for session operations."""
    session_id: str = Field(..., description="Session ID")
    status: str = Field(..., description="Operation status")
    message: str = Field(..., description="Status message")

class AnalysisResponse(BaseModel):
    """Response model for analysis storage."""
    analysis_id: str = Field(..., description="Analysis ID")
    status: str = Field(..., description="Storage status")
    message: str = Field(..., description="Status message")

@router.post("/monitoring/sessions", response_model=SessionResponse)
async def create_monitoring_session(
    request: CreateSessionRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create a new monitoring session."""
    try:
        username = current_user.get('username')
        
        session_id = await storage_service.create_monitoring_session(
            username=username,
            log_path=request.log_path,
            interval_seconds=request.interval_seconds,
            ai_agent_enabled=request.ai_agent_enabled
        )
        
        logger.info(f"Created monitoring session {session_id} for user {username}")
        
        return SessionResponse(
            session_id=session_id,
            status="created",
            message="Monitoring session created successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to create monitoring session: {e}")
        raise HTTPException(status_code=500, detail="Failed to create monitoring session")

@router.post("/monitoring/sessions/{session_id}/stop", response_model=SessionResponse)
async def stop_monitoring_session(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Stop a monitoring session."""
    try:
        success = await storage_service.stop_monitoring_session(session_id)
        
        if success:
            logger.info(f"Stopped monitoring session {session_id}")
            return SessionResponse(
                session_id=session_id,
                status="stopped",
                message="Monitoring session stopped successfully"
            )
        else:
            raise HTTPException(status_code=404, detail="Session not found or already stopped")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop monitoring session: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop monitoring session")

@router.get("/monitoring/sessions", response_model=List[Dict[str, Any]])
async def get_monitoring_sessions(
    active_only: bool = True,
    current_user: dict = Depends(get_current_user)
):
    """Get monitoring sessions for the current user."""
    try:
        username = current_user.get('username')
        
        if active_only:
            sessions = await storage_service.get_active_sessions(username)
        else:
            # For now, only return active sessions
            # Can be extended to include historical sessions
            sessions = await storage_service.get_active_sessions(username)
        
        return sessions
        
    except Exception as e:
        logger.error(f"Failed to retrieve monitoring sessions: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve monitoring sessions")

@router.get("/monitoring/sessions/{session_id}", response_model=Dict[str, Any])
async def get_monitoring_session(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get specific monitoring session details."""
    try:
        session = await storage_service.get_monitoring_session(session_id)
        
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Check if user owns this session
        if session.get('username') != current_user.get('username'):
            raise HTTPException(status_code=403, detail="Access denied")
        
        return session
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve monitoring session: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve monitoring session")

@router.post("/analysis/store", response_model=AnalysisResponse)
async def store_analysis_result(
    request: StoreAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """Store analysis result in MongoDB."""
    try:
        # Use the provided username if available, otherwise use the authenticated user
        user_id = request.username if request.username else current_user.get('username')
        
        # Extract the actual analysis data from additionalProp1
        actual_analysis_data = request.analysis_result.get('additionalProp1', {})
        
        # Create proper technique objects
        class MockTechnique:
            def __init__(self, technique_data):
                self.data = technique_data
                
            def model_dump(self):
                return self.data
        
        # Create response object using the actual data from additionalProp1
        class MockResponse:
            def __init__(self, analysis_data):
                self.summary = analysis_data.get('summary', 'No summary provided')
                self.enhanced_analysis = analysis_data.get('enhanced_analysis', None)
                
                # Convert techniques to proper objects
                self.matched_techniques = []
                techniques = analysis_data.get('matched_techniques', [])
                
                for tech in techniques:
                    mock_tech = MockTechnique(tech)
                    self.matched_techniques.append(mock_tech)
                
                self.processing_time_ms = analysis_data.get('processing_time_ms', 0)
        
        class MockRequest:
            def __init__(self, log_content):
                self.logs = log_content
        
        mock_request = MockRequest(request.log_content)
        mock_response = MockResponse(actual_analysis_data)
        
        analysis_id = await storage_service.store_analysis_result(
            user_id=user_id,
            request=mock_request,
            response=mock_response
        )
        
        return AnalysisResponse(
            analysis_id=analysis_id,
            status="stored",
            message="Analysis result stored successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to store analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/analysis/{analysis_id}", response_model=Dict[str, Any])
async def get_analysis_result(
    analysis_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Retrieve stored analysis result."""
    try:
        user_id = current_user.get('username')
        
        analysis = await storage_service.get_analysis_result(user_id, analysis_id)
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        return analysis
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analysis")

@router.get("/analysis/user/history", response_model=List[Dict[str, Any]])
async def get_user_analysis_history(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """Get analysis history for the current user."""
    try:
        user_id = current_user.get('username')
        analyses = await storage_service.get_user_analysis_history(user_id, limit, offset)
        
        return analyses
        
    except Exception as e:
        logger.error(f"Failed to retrieve user analysis history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analysis history")

@router.get("/analysis/stats", response_model=AnalysisStats)
async def get_analysis_statistics(
    days: int = 30,
    current_user: dict = Depends(get_current_user)
):
    """Get analysis statistics for the system."""
    try:
        stats = await storage_service.get_analysis_stats(days)
        return stats
        
    except Exception as e:
        logger.error(f"Failed to retrieve analysis statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")

@router.delete("/analysis/cleanup")
async def cleanup_old_analyses(
    days: int = 90,
    current_user: dict = Depends(get_current_user)
):
    """Clean up old analysis records (admin only)."""
    try:
        # Note: In a real implementation, you'd check for admin privileges
        deleted_count = await storage_service.cleanup_old_analyses(days)
        
        return {
            "status": "success",
            "message": f"Cleaned up {deleted_count} old analysis records",
            "deleted_count": deleted_count
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup old analyses: {e}")
        raise HTTPException(status_code=500, detail="Failed to cleanup old analyses")
