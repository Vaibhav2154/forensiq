from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class LogAnalysisRequest(BaseModel):
    """Request model for log analysis."""
    logs: str = Field(..., description="System logs to analyze", max_length=50000)
    enhance_with_ai: bool = Field(default=True, description="Whether to enhance analysis with AI")
    max_results: Optional[int] = Field(default=5, description="Maximum number of ATT&CK techniques to return", ge=1, le=20)

class AttackTechnique(BaseModel):
    """Model for MITRE ATT&CK technique."""
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID (e.g., T1059)")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    kill_chain_phases: List[str] = Field(default_factory=list, description="Kill chain phases")
    platforms: List[str] = Field(default_factory=list, description="Applicable platforms")
    relevance_score: float = Field(..., description="Relevance score (0-1, where higher is more relevant)", ge=0, le=1)

class LogAnalysisResponse(BaseModel):
    """Response model for log analysis."""
    summary: str = Field(..., description="AI-generated summary of the logs")
    matched_techniques: List[AttackTechnique] = Field(default_factory=list, description="Matching MITRE ATT&CK techniques")
    enhanced_analysis: Optional[str] = Field(None, description="Enhanced AI analysis with threat intelligence")
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the analysis was performed")
    processing_time_ms: Optional[float] = Field(None, description="Processing time in milliseconds")

class DatabaseStats(BaseModel):
    """Model for database statistics."""
    total_techniques: int = Field(..., description="Total number of techniques in database")
    collection_name: str = Field(..., description="ChromaDB collection name")
    embedding_model: str = Field(..., description="Embedding model used")
    last_updated: Optional[datetime] = Field(None, description="When the database was last updated")

class HealthCheck(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    services: Dict[str, str] = Field(default_factory=dict, description="Status of individual services")
    database_stats: Optional[DatabaseStats] = Field(None, description="Database statistics")

class ErrorResponse(BaseModel):
    """Error response model."""
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
