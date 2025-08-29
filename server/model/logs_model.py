from pydantic import BaseModel
from typing import List,Optional,Dict,Any

class LogAnalysisRequest(BaseModel):
    logs: str
    max_results: int = 5
    enhance_with_ai: bool = True

class AttackTechnique(BaseModel):
    technique_id: str
    name: str
    description: str
    kill_chain_phases: List[str]
    platforms: List[str]
    relevance_score: float

class LogAnalysisResponse(BaseModel):
    summary: str
    matched_techniques: List[AttackTechnique]
    enhanced_analysis: Optional[str] = None
    processing_time_ms: float
    extracted_iocs: List[Dict[str, Any]] = []
