from fastapi import APIRouter, HTTPException
import time
from services.bedrock_service import BedrockService
from services import ioc_extractor
from model.logs_model import LogAnalysisRequest,LogAnalysisResponse,AttackTechnique

router = APIRouter(prefix="/api/v2", tags=["Log Analysis"])

# Global service instance - only need BedrockService now
bedrock_service: BedrockService = None

def set_services(bedrock: BedrockService):
    """Set service instance for the router."""
    global bedrock_service
    bedrock_service = bedrock


@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(request: LogAnalysisRequest) -> LogAnalysisResponse:
    """
    Analyze system logs using AWS Bedrock Knowledge Base.
    
    This endpoint uses a unified approach:
    1. Retrieves relevant MITRE ATT&CK techniques from the Knowledge Base
    2. Generates a context-aware summary using the retrieved techniques
    3. Extracts IOCs from the raw logs
    4. Optionally provides enhanced analysis
    
    Args:
        request: LogAnalysisRequest containing logs and analysis parameters
        
    Returns:
        LogAnalysisResponse with summary, matched techniques, and IOCs
    """
    start_time = time.time()
    
    try:
        if not bedrock_service:
            raise HTTPException(
                status_code=500,
                detail="Bedrock service not properly initialized"
            )
        
        print(f"Starting unified log analysis for {len(request.logs)} characters of logs")
        
        # Step 1: Extract IOCs from raw logs
        extracted_iocs = ioc_extractor.extract_iocs(request.logs)
        
        # Step 2: Use unified retrieve_and_summarize method
        kb_id = "U2T0MRIA0H"  # Replace with your actual KB ID
        analysis_result = await bedrock_service.retrieve_and_summarize(
            logs=request.logs,
            kb_id=kb_id,
            n_results=request.max_results
        )
        
        summary = analysis_result["summary"]
        if summary.startswith("Error during analysis:"):
            raise HTTPException(
                status_code=500,
                detail=summary
            )
        
        # Convert technique dictionaries to Pydantic models
        matched_techniques = [
            AttackTechnique(
                technique_id=tech.get('technique_id', tech.get('id', 'Unknown')),  # Handle both field names
                name=tech.get('name', 'Unknown Technique'),
                description=tech.get('description', 'Description not available.'),
                kill_chain_phases=tech.get('kill_chain_phases', []),
                platforms=tech.get('platforms', []),
                relevance_score=tech.get('relevance_score', 0.0)
            )
            for tech in analysis_result["matched_techniques"]
        ]
        
        # Step 3: Enhanced analysis (optional)
        enhanced_analysis = None
        if request.enhance_with_ai and matched_techniques:
            print("Generating enhanced threat analysis")
            enhanced_analysis = await bedrock_service.enhance_threat_analysis(
                summary, analysis_result["matched_techniques"], kb_id
            )
        
        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        print(f"Analysis completed in {processing_time:.2f}ms with {len(matched_techniques)} matches")
        
        return LogAnalysisResponse(
            summary=summary,
            matched_techniques=matched_techniques,
            enhanced_analysis=enhanced_analysis,
            extracted_iocs=extracted_iocs,
            processing_time_ms=processing_time
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in log analysis: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )