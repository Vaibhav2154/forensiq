from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any, Annotated
from datetime import datetime
from bson import ObjectId

class StoredAnalysisRequest(BaseModel):
    """Model for storing analysis request data."""
    logs_hash: str = Field(..., description="Hash of the original logs for deduplication")
    encrypted_logs: str = Field(..., description="Encrypted original logs")
    max_results: int = Field(default=5, description="Maximum results requested")
    enhance_with_ai: bool = Field(default=True, description="Whether AI enhancement was requested")

class StoredAttackTechnique(BaseModel):
    """Model for storing MITRE ATT&CK technique results."""
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    kill_chain_phases: List[str] = Field(default_factory=list, description="Kill chain phases")
    platforms: List[str] = Field(default_factory=list, description="Applicable platforms")
    relevance_score: float = Field(..., description="Relevance score (0-1)")

class AnalysisResult(BaseModel):
    """Model for storing complete analysis results in database."""
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str = Field(..., description="User identifier")
    
    # Request information (encrypted)
    request_data: StoredAnalysisRequest = Field(..., description="Original request data")
    
    # Results (encrypted)
    encrypted_summary: str = Field(..., description="Encrypted AI-generated summary")
    encrypted_techniques: str = Field(..., description="Encrypted matched techniques JSON")
    encrypted_enhanced_analysis: Optional[str] = Field(None, description="Encrypted enhanced analysis")
    
    # Metadata (not encrypted)
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Analysis timestamp")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    techniques_count: int = Field(..., description="Number of matched techniques")
    
    # Security metadata
    encryption_key_id: str = Field(..., description="ID of encryption key used")
    data_hash: str = Field(..., description="Hash of decrypted data for integrity verification")

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )

class AnalysisHistoryItem(BaseModel):
    """Model for analysis history list items (without sensitive data)."""
    id: str = Field(..., description="Analysis ID")
    analysis_timestamp: datetime = Field(..., description="When analysis was performed")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    techniques_count: int = Field(..., description="Number of matched techniques")
    logs_preview: str = Field(..., description="First 100 characters of logs")

class UserAnalyticsStats(BaseModel):
    """Model for user analytics statistics."""
    total_analyses: int = Field(..., description="Total number of analyses performed")
    avg_processing_time: float = Field(..., description="Average processing time")
    most_common_techniques: List[Dict[str, Any]] = Field(..., description="Most frequently matched techniques")
    analysis_timeline: List[Dict[str, Any]] = Field(..., description="Analysis activity over time")
