from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
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
    id: Optional[str] = Field(None, description="Stored MongoDB analysis ID when persisted")
    summary: str = Field(..., description="Structured summary of observed log events")
    matched_techniques: List[AttackTechnique] = Field(default_factory=list, description="Verified MITRE ATT&CK techniques retrieved from OKF/Cognee")
    enhanced_analysis: Optional[str] = Field(None, description="Evidence-backed multi-agent investigation report (Markdown)")
    investigation: Optional[Dict[str, Any]] = Field(None, description="Structured LangGraph multi-agent InvestigationResult payload")
    visualization_metrics: Optional[Dict[str, Any]] = Field(None, description="Deterministic metrics for threat visualization dashboard")
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the analysis was performed")
    processing_time_ms: Optional[float] = Field(None, description="Processing time in milliseconds")


class AnalysisChatTurn(BaseModel):
    """A single turn in a multi-turn conversation about stored analysis results."""
    role: Literal["user", "assistant"] = Field(..., description="Speaker role")
    content: str = Field(..., min_length=1, max_length=6000, description="Turn message content")


class AnalysisChatRequest(BaseModel):
    """Request payload for chatting with Gemini about a specific stored analysis."""
    message: str = Field(..., min_length=1, max_length=4000, description="Analyst question about the stored analysis")
    conversation_history: List[AnalysisChatTurn] = Field(
        default_factory=list,
        max_length=20,
        description="Optional prior turns for multi-turn conversation continuity",
    )
    include_recent_context: bool = Field(
        default=False,
        description="When True, also include compact context from up to 4 other recent stored analyses for cross-incident comparison",
    )


class HistoryChatRequest(BaseModel):
    """Request payload for chatting with Gemini across multiple stored analyses."""
    message: str = Field(..., min_length=1, max_length=4000, description="Analyst question across stored analyses")
    analysis_ids: Optional[List[str]] = Field(
        default=None,
        max_length=10,
        description="Optional list of specific stored analysis IDs to inspect (defaults to most recent analyses)",
    )
    limit: int = Field(default=5, ge=1, le=10, description="Maximum number of recent stored analyses to load when analysis_ids is omitted")
    conversation_history: List[AnalysisChatTurn] = Field(
        default_factory=list,
        max_length=20,
        description="Optional prior turns for multi-turn conversation continuity",
    )


class AnalysisChatResponse(BaseModel):
    """Grounded Gemini chatbot response for stored multi-agent analyses."""
    analysis_id: Optional[str] = Field(None, description="Primary MongoDB analysis ID (None for cross-history chat)")
    analyses_consulted: List[str] = Field(default_factory=list, description="MongoDB analysis IDs included in context")
    answer: str = Field(..., description="Evidence-grounded Markdown answer from Gemini")
    referenced_event_ids: List[str] = Field(default_factory=list, description="Verified event_ids cited from stored analysis")
    referenced_knowledge_ids: List[str] = Field(default_factory=list, description="Verified MITRE ATT&CK / CVE IDs cited from stored analysis")
    follow_up_questions: List[str] = Field(default_factory=list, description="Suggested next questions for the analyst")
    evidence_caveats: List[str] = Field(default_factory=list, description="Distinctions between observed facts, inferences, and missing telemetry")
    model_used: str = Field(default="", description="Gemini model name used to generate the answer")
    processing_time_ms: float = Field(default=0.0, ge=0.0, description="End-to-end chatbot processing time in milliseconds")


class RemediationStatusUpdateRequest(BaseModel):
    """Audit sync payload reported by the local HITL TUI after approval, rejection, or rollback."""
    recommendation_id: str = Field(..., min_length=1, description="Target RecommendationItem.recommendation_id")
    execution_status: Literal[
        "pending_approval",
        "approved",
        "executed",
        "failed",
        "rejected",
        "rolled_back",
    ] = Field(..., description="Updated HITL execution status")
    receipt_id: Optional[str] = Field(default=None, description="Local rollback journal receipt ID")
    executed_by: Optional[str] = Field(default=None, description="Local host username who authorized the action")
    notes: Optional[str] = Field(default=None, max_length=1000, description="Optional analyst or execution notes")
    analysis_id: Optional[str] = Field(default=None, description="Optional MongoDB analysis ID for direct lookup")


class RemediationStatusUpdateResponse(BaseModel):
    """Confirmation payload returned when a remediation status update is persisted."""
    analysis_id: str
    investigation_id: Optional[str] = None
    recommendation_id: str
    execution_status: str
    receipt_id: Optional[str] = None
    recorded_at: datetime = Field(default_factory=datetime.utcnow)

class DatabaseStats(BaseModel):
    """Model for database statistics."""
    total_techniques: int = Field(..., description="Total number of techniques in database")
    collection_name: str = Field(..., description="Knowledge store backend/collection name")
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
