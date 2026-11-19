from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class MonitoringSession(BaseModel):
    """Model for tracking monitoring sessions."""
    session_id: str = Field(..., description="Unique session identifier")
    username: str = Field(..., description="User who started the session")
    log_path: str = Field(..., description="Path to the monitored log file")
    start_time: datetime = Field(default_factory=datetime.utcnow, description="Session start time")
    end_time: Optional[datetime] = Field(None, description="Session end time")
    status: str = Field(default="active", description="Session status: active, stopped, error")
    interval_seconds: int = Field(default=300, description="Monitoring interval in seconds")
    total_analyses: int = Field(default=0, description="Total number of analyses performed")
    last_analysis: Optional[datetime] = Field(None, description="Last analysis timestamp")
    ai_agent_enabled: bool = Field(default=True, description="Whether AI agent is enabled")
    
class StoredAnalysis(BaseModel):
    """Model for storing analysis results in MongoDB."""
    analysis_id: str = Field(..., description="Unique analysis identifier")
    session_id: Optional[str] = Field(None, description="Associated monitoring session ID")
    username: str = Field(..., description="User who requested the analysis")
    log_content_hash: str = Field(..., description="Hash of the analyzed log content")
    log_file_path: Optional[str] = Field(None, description="Path to the original log file")
    
    # Analysis request details
    request_timestamp: datetime = Field(default_factory=datetime.utcnow, description="When analysis was requested")
    enhance_with_ai: bool = Field(default=True, description="Whether AI enhancement was used")
    max_results: int = Field(default=5, description="Maximum MITRE techniques requested")
    
    # Analysis results
    summary: str = Field(..., description="AI-generated summary of the logs")
    matched_techniques: List[Dict[str, Any]] = Field(default_factory=list, description="Matching MITRE ATT&CK techniques")
    enhanced_analysis: Optional[str] = Field(None, description="Enhanced AI analysis")
    processing_time_ms: Optional[float] = Field(None, description="Processing time in milliseconds")
    
    # AI Agent data (if available)
    ai_agent_analysis: Optional[Dict[str, Any]] = Field(None, description="AI agent enhanced analysis")
    detected_patterns: Optional[List[Dict[str, Any]]] = Field(None, description="Detected log patterns")
    threat_context: Optional[Dict[str, Any]] = Field(None, description="Threat context analysis")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Record creation time")
    file_size: Optional[int] = Field(None, description="Size of analyzed log content")
    analysis_source: str = Field(default="cli_tool", description="Source of analysis: cli_tool, web_ui, api")

class AnalysisStats(BaseModel):
    """Model for analysis statistics."""
    total_analyses: int = Field(..., description="Total number of analyses")
    analyses_today: int = Field(..., description="Analyses performed today")
    unique_users: int = Field(..., description="Number of unique users")
    active_sessions: int = Field(..., description="Number of active monitoring sessions")
    top_techniques: List[Dict[str, Any]] = Field(default_factory=list, description="Most frequently detected techniques")
    average_processing_time: float = Field(..., description="Average processing time in milliseconds")
