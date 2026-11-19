from fastapi import APIRouter, HTTPException, Depends, Query, Body
from typing import List, Dict, Any, Optional
import json
from pydantic import BaseModel, Field
import json
from core import logger
from services import GeminiService
from services.knowledge import KnowledgeSearchQuery, KnowledgeService

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK Framework"])

# Global services (will be set from main.py)
knowledge_service: Optional[KnowledgeService] = None
gemini_service: Optional[GeminiService] = None

def set_mitre_services(knowledge_svc: Optional[KnowledgeService], gemini_svc: Optional[GeminiService] = None):
    """Set the services for the MITRE router."""
    global knowledge_service, gemini_service
    knowledge_service = knowledge_svc
    gemini_service = gemini_svc


def _hit_to_mitre_technique(hit) -> Dict[str, Any]:
    """Convert an OKF KnowledgeSearchHit to the MITRE technique dict expected by clients."""
    rec = hit.record
    content = rec.content or {}
    tactics = content.get("tactics") or []
    if isinstance(tactics, str):
        tactics = [t.strip() for t in tactics.split(",") if t.strip()]
    platforms = content.get("platforms") or []
    if isinstance(platforms, str):
        platforms = [p.strip() for p in platforms.split(",") if p.strip()]
    return {
        "technique_id": rec.source_id,
        "name": str(content.get("name") or content.get("title") or rec.source_id),
        "description": str(content.get("description") or content.get("summary") or ""),
        "kill_chain_phases": [str(t) for t in tactics],
        "platforms": [str(p) for p in platforms],
        "relevance_score": round(max(0.0, min(1.0, float(hit.score))), 4),
    }

# Request/Response Models
class MitreSearchRequest(BaseModel):
    query: str = Field(..., description="Search query for MITRE techniques")
    max_results: Optional[int] = Field(5, description="Maximum number of results to return", ge=1, le=20)

class MitreSearchResponse(BaseModel):
    query: str
    relevant_techniques: List[Dict[str, Any]]
    summary: str
    context: str
    embedding_model: str
    total_techniques: int
    top_match: Optional[Dict[str, Any]] = None
    common_tactics: Optional[List[str]] = None
    common_platforms: Optional[List[str]] = None

class TechniqueDetailResponse(BaseModel):
    technique_id: str
    name: str
    description: str
    kill_chain_phases: List[str]
    platforms: List[str]
    relevance_score: float
    embedding_model: str

class RagQueryRequest(BaseModel):
    query: str = Field(..., description="User query for RAG-based MITRE analysis")
    max_context_techniques: Optional[int] = Field(5, description="Maximum number of techniques to include in context", ge=1, le=10)
    include_source_techniques: Optional[bool] = Field(True, description="Whether to include source technique details in response")

class RagQueryResponse(BaseModel):
    query: str
    response: str
    relevant_techniques: List[Dict[str, Any]]
    confidence_score: float
    processing_time_ms: float
    embedding_model: str
    total_techniques_found: int

async def search_mitre_techniques(request: MitreSearchRequest):
    """
    Search MITRE ATT&CK techniques using the OKF/Cognee knowledge store and Gemini AI.
    """
    try:
        if not knowledge_service or not gemini_service:
            raise HTTPException(
                status_code=503, 
                detail="MITRE search services not available"
            )
        
        logger.info(f"Searching MITRE techniques with query: {request.query}")
        
        search_resp = await knowledge_service.search(
            KnowledgeSearchQuery(
                query=request.query,
                source_type="mitre_attack",
                kind="attack-pattern",
                top_k=request.max_results or 5,
                search_mode="auto",
            )
        )
        techniques = [_hit_to_mitre_technique(hit) for hit in search_resp.hits]
        
        response = await gemini_service.generate_mitre_response(
            query=request.query,
            context_techniques=techniques
        )
        
        return MitreSearchResponse(**response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in MITRE search endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during MITRE search: {str(e)}"
        )

@router.get("/search", response_model=MitreSearchResponse)
async def search_mitre_techniques_get(
    q: str = Query(..., description="Search query for MITRE techniques"),
    max_results: int = Query(5, description="Maximum number of results", ge=1, le=20)
):
    """
    GET endpoint for searching MITRE ATT&CK techniques using the OKF/Cognee knowledge store.
    
    Alternative to POST endpoint for simple URL-based queries.
    """
    request = MitreSearchRequest(query=q, max_results=max_results)
    return await search_mitre_techniques(request)

@router.get("/tactics", response_model=List[str])
async def get_all_tactics():
    """
    Get all available MITRE ATT&CK tactics from the OKF/Cognee knowledge store.
    """
    try:
        if not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Knowledge service not available"
            )

        records = await knowledge_service.list_records(
            source_type="mitre_attack", kind="attack-pattern", limit=2000, offset=0
        )
        all_tactics = set()
        for rec in records:
            tactics_val = (rec.content or {}).get("tactics") or []
            if isinstance(tactics_val, list):
                for t in tactics_val:
                    if t:
                        all_tactics.add(str(t).strip())
            elif isinstance(tactics_val, str):
                all_tactics.update(t.strip() for t in tactics_val.split(",") if t.strip())

        return sorted(t for t in all_tactics if t)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting tactics: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@router.get("/platforms", response_model=List[str])
async def get_all_platforms():
    """
    Get all available MITRE ATT&CK platforms from the OKF/Cognee knowledge store.
    """
    try:
        if not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Knowledge service not available"
            )

        records = await knowledge_service.list_records(
            source_type="mitre_attack", kind="attack-pattern", limit=2000, offset=0
        )
        all_platforms = set()
        for rec in records:
            platforms_val = (rec.content or {}).get("platforms") or []
            if isinstance(platforms_val, list):
                for p in platforms_val:
                    if p:
                        all_platforms.add(str(p).strip())
            elif isinstance(platforms_val, str):
                all_platforms.update(p.strip() for p in platforms_val.split(",") if p.strip())

        return sorted(p for p in all_platforms if p)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting platforms: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@router.get("/stats", response_model=Dict[str, Any])
async def get_mitre_stats():
    """
    Get statistics about the MITRE ATT&CK knowledge store.
    """
    try:
        if not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Knowledge service not available"
            )
        
        stats = await knowledge_service.stats()
        return {
            "total_techniques": stats.counts_by_kind.get("attack-pattern", stats.total_records),
            "total_records": stats.total_records,
            "collection_name": f"okf-{stats.backend}",
            "embedding_model": knowledge_service.settings.cognee_embedding_model,
            "counts_by_source_type": stats.counts_by_source_type,
            "counts_by_kind": stats.counts_by_kind,
            "last_updated": stats.last_ingested_at.isoformat() if stats.last_ingested_at else None,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting MITRE stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@router.get("/techniques", response_model=List[Dict[str, Any]])
async def get_all_techniques(
    limit: int = Query(100, description="Maximum number of techniques to return", ge=1, le=500),
    offset: int = Query(0, description="Number of techniques to skip", ge=0)
):
    """
    Get all MITRE ATT&CK techniques from the OKF/Cognee knowledge store.
    """
    try:
        if not knowledge_service:
            raise HTTPException(
                status_code=503,
                detail="Knowledge service not available"
            )

        records = await knowledge_service.list_records(
            source_type="mitre_attack",
            kind="attack-pattern",
            limit=limit,
            offset=offset,
        )
        
        techniques = []
        for rec in records:
            content = rec.content or {}
            tactics = content.get("tactics") or []
            platforms = content.get("platforms") or []
            techniques.append({
                "id": rec.source_id,
                "name": str(content.get("name") or rec.source_id),
                "description": str(content.get("description") or content.get("summary") or ""),
                "phase": str(tactics[0]) if isinstance(tactics, list) and tactics else "unknown",
                "platforms": [str(p) for p in platforms] if isinstance(platforms, list) else [],
            })
        
        return techniques
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting all techniques: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@router.post("/rag-query", response_model=RagQueryResponse)
async def rag_mitre_query(request: RagQueryRequest):
    """
    RAG-based query endpoint for conversational MITRE ATT&CK analysis.
    
    Queries the OKF/Cognee knowledge store for relevant techniques and generates
    conversational responses using Gemini AI.
    """
    import time
    start_time = time.time()
    
    try:
        if not knowledge_service or not gemini_service:
            raise HTTPException(
                status_code=503,
                detail="MITRE RAG services not available: missing KnowledgeService or Gemini service"
            )
        
        logger.info(f"Processing RAG query: {request.query}")

        search_resp = await knowledge_service.search(
            KnowledgeSearchQuery(
                query=request.query,
                source_type="mitre_attack",
                kind="attack-pattern",
                top_k=request.max_context_techniques or 5,
                search_mode="auto",
            )
        )
        relevant_techniques = [_hit_to_mitre_technique(hit) for hit in search_resp.hits]

        # Detect if the user is asking for a general MITRE ATT&CK overview (high-level intent)
        lower_q = (request.query or "").lower()
        overview_triggers = [
            'what is mitre', 'what is mitre attack', 'explain mitre', 'explain mitre attack',
            'mitre overview', 'mitre attack overview', 'overview of mitre', 'what is the mitre'
        ]
        is_overview_intent = any(trigger in lower_q for trigger in overview_triggers) or (len(request.query.split()) <= 4 and ('mitre' in lower_q or 'attack' in lower_q))

        if is_overview_intent:
            logger.info('Detected overview intent; generating MITRE ATT&CK overview context.')
            context = _prepare_overview_context(request.query, relevant_techniques)
        else:
            if not relevant_techniques:
                logger.info('No relevant techniques found; generating a general conversational response.')
                # Create a general context prompting the model to act as a knowledgeable security assistant
                context = _prepare_general_context(request.query)
            else:
                # Prepare context for AI response generation from found techniques
                context = _prepare_rag_context(request.query, relevant_techniques)
        
        # Generate conversational response using Gemini
        try:
            response_text = await gemini_service.generate_conversational_response(
                query=request.query,
                context=context
            )
        except Exception as e:
            logger.warning(f"LLM response generation failed (gemini): {str(e)}, using fallback")
            response_text = _generate_fallback_response(request.query, relevant_techniques)
        
        # Calculate confidence score based on relevance scores (guard against empty list)
        if relevant_techniques:
            avg_relevance = sum(tech.get('relevance_score', 0.0) for tech in relevant_techniques) / len(relevant_techniques)
            confidence_score = min(avg_relevance * 1.2, 1.0)  # Boost confidence slightly
        else:
            confidence_score = 0.0
        
        processing_time = (time.time() - start_time) * 1000
        
        # Prepare response techniques (include full details if requested)
        response_techniques = relevant_techniques if request.include_source_techniques else []
        
        return RagQueryResponse(
            query=request.query,
            response=response_text,
            relevant_techniques=response_techniques,
            confidence_score=round(confidence_score, 3),
            processing_time_ms=round(processing_time, 2),
            embedding_model=knowledge_service.settings.cognee_embedding_model,
            total_techniques_found=len(relevant_techniques)
        )
        
    except Exception as e:
        logger.error(f"Error in MITRE RAG query: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during RAG query: {str(e)}"
        )

def _prepare_rag_context(query: str, techniques: List[Dict[str, Any]]) -> str:
    """Prepare a high-quality instruction prompt for the model using the top techniques.

    The prompt asks the model to act as a senior incident responder and MITRE ATT&CK expert.
    It requests a single JSON object with a clear schema (answer, summary, prioritized findings,
    detection queries, recommendations, references, follow-up questions, and a confidence score).
    An example JSON is included to guide the model.
    """
    # Limit to top 5 techniques for context
    context_parts = []
    for i, technique in enumerate(techniques[:5]):
        context_parts.append(
            {
                "rank": i + 1,
                "technique_id": technique.get('technique_id', ''),
                "name": technique.get('name', ''),
                "description": technique.get('description', ''),
                "tactics": technique.get('kill_chain_phases', []),
                "platforms": technique.get('platforms', []),
                "relevance_score": round(float(technique.get('relevance_score', 0.0)), 3),
                "source_document": technique.get('document', '')
            }
        )

    schema_instructions = (
        "Return a single, valid JSON object ONLY (no leading/trailing text, no markdown).\n"
        "Schema (keys and types):\n"
        "{\n"
        "  \"version\": string,                    // prompt schema version, e.g. \"1.0\"\n"
        "  \"answer\": string,                     // concise human-friendly answer (<= 400 words)\n"
        "  \"summary\": string,                    // 2-3 sentence technical summary\n"
        "  \"top_findings\": [                     // prioritized findings\n"
        "    {\n"
        "      \"technique_id\": string,\n"
        "      \"name\": string,\n"
        "      \"relevance_score\": number,\n"
        "      \"impact\": string,                // Low/Medium/High\n"
        "      \"recommended_detections\": [string],\n"
        "      \"recommended_mitigations\": [string]\n"
        "    }\n"
        "  ],\n"
        "  \"detection_queries\": [                 // actionable SIEM/search snippets\n"
        "    { \"name\": string, \"query\": string, \"log_source\": string, \"priority\": string, \"confidence\": number }\n"
        "  ],\n"
        "  \"recommendations\": [string],\n"
        "  \"references\": [{ \"technique_id\": string, \"url\": string }],\n"
        "  \"follow_up_questions\": [string],\n"
        "  \"evidence\": [string],                 // short snippets or doc refs used to justify findings\n"
        "  \"confidence\": number                  // 0.0 - 1.0\n"
        "}\n"
    )

    example = (
        "Example JSON (must follow schema exactly):\n"
        "{\n"
        "  \"version\": \"1.0\",\n"
        "  \"answer\": \"Short, clear answer focusing on practical steps.\",\n"
        "  \"summary\": \"Two to three sentence summary.\",\n"
        "  \"top_findings\": [\n"
        "    {\n"
        "      \"technique_id\": \"T1055\",\n"
        "      \"name\": \"Process Injection\",\n"
        "      \"relevance_score\": 0.92,\n"
        "      \"impact\": \"High\",\n"
        "      \"recommended_detections\": [\"Monitor for suspicious DLL loads\"],\n"
        "      \"recommended_mitigations\": [\"Enable code signing policies\"]\n"
        "    }\n"
        "  ],\n"
        "  \"detection_queries\": [\n"
        "    {\n"
        "      \"name\": \"Process Injection - Windows\",\n"
        "      \"query\": \"EventID=4688 AND CommandLine LIKE '%-Inject%'%\",\n"
        "      \"log_source\": \"windows_security\",\n"
        "      \"priority\": \"high\",\n"
        "      \"confidence\": 0.9\n"
        "    }\n"
        "  ],\n"
        "  \"recommendations\": [\"Investigate hosts X,Y\", \"Collect memory for analysis\"],\n"
        "  \"references\": [ { \"technique_id\": \"T1055\", \"url\": \"https://attack.mitre.org/techniques/T1055/\" } ],\n"
        "  \"follow_up_questions\": [\"When did you first observe the activity?\"],\n"
        "  \"evidence\": [\"Technique description excerpt or source doc link\"],\n"
        "  \"confidence\": 0.87\n"
        "}\n"
    )

    prompt = (
        f"You are a senior incident responder and MITRE ATT&CK expert.\n"
        f"User Query: {query}\n\n"
        f"Relevant Techniques (top {min(5, len(techniques))}):\n"
        f"{json.dumps(context_parts, indent=2)}\n\n"
        "Instructions (important):\n"
        "- Use the techniques provided to produce a prioritized, operationally-focused analysis.\n"
        "- Output MUST be valid JSON that adheres exactly to the schema below. Do NOT include any explanatory text, markdown, or commentary.\n"
        "- Ensure detection queries are copy-paste ready for common SIEMs and label the log source.\n"
        "- Include brief 'evidence' entries that point to the part of the technique or doc used to justify each top finding.\n"
        "- Keep 'answer' concise and actionable; keep technical details in 'summary' and 'top_findings'.\n"
        "- If uncertain, lower the 'confidence' and call out assumptions in 'evidence'.\n\n"
        f"{schema_instructions}\n\n"
        f"{example}\n\n"
        "Now produce the JSON output exactly as specified." 
    )

    return prompt


def _prepare_general_context(query: str) -> str:
    """Prepare a strong general prompt when no specific techniques were found.

    The prompt asks the model to provide structured, actionable guidance across common tactics
    and to return a JSON object with the same schema as `_prepare_rag_context`.
    """
    schema_short = (
        "Return a single JSON object with keys: answer, summary, top_findings, detection_queries, recommendations, references, follow_up_questions, confidence."
    )

    prompt = (
        "You are a senior incident responder and MITRE ATT&CK expert.\n"
        f"User Query: {query}\n\n"
        "No matching MITRE ATT&CK techniques were found in the vector store.\n"
        "Provide a structured, actionable response that covers: high-level guidance, likely relevant tactics, prioritized detection strategies, investigation steps, and recommended mitigations.\n"
        "Return a single JSON object only. "
        f"{schema_short}\n\n"
        "When listing detection queries, include example queries for common log sources (Windows Security, Sysmon, DNS, proxy logs) if applicable.\n"
        "Also include 2-3 follow-up questions that help narrow scope or obtain telemetry.\n"
        "Now produce the JSON output."
    )

    return prompt


def _prepare_overview_context(query: str, techniques: List[Dict[str, Any]]) -> str:
    """Prepare a detailed overview prompt about MITRE ATT&CK.

    The overview should explain what MITRE ATT&CK is, key components (tactics, techniques,
    mitigations, detections), how to use it in programmatic defenses, examples, and suggested next steps.
    Returns a prompt requesting a single JSON object with: overview, key_components, examples, and next_steps.
    """
    tech_count = len(techniques) if techniques else 0
    prompt = (
        "You are a senior cybersecurity analyst and educator.\n"
        f"User Query: {query}\n\n"
        "Provide a clear, structured overview of the MITRE ATT&CK framework suitable for a security team lead.\n"
        "Include: a concise definition, core components (tactics, techniques, mitigations, detection ideas), how teams commonly apply the framework operationally, and practical examples.\n"
        "If any relevant techniques were identified in the user's environment, briefly list their names and why they might be relevant.\n\n"
        "Return a single JSON object with keys:\n"
        "  - overview: string,\n"
        "  - key_components: { tactics: string, techniques: string, mitigations: string, detections: string },\n"
        "  - examples: [ { 'scenario', 'relevant_techniques', 'actionable_steps' } ],\n"
        "  - next_steps: [ string ],\n"
        "  - detected_techniques_count: number,\n"
        "  - detected_techniques: [ { 'technique_id', 'name', 'relevance_score' } ],\n"
        "  - confidence: number\n\n"
        f"Detected techniques count: {tech_count}\n"
        "Now produce the JSON output only."
    )

    return prompt

def _generate_fallback_response(query: str, techniques: List[Dict[str, Any]]) -> str:
    """Generate fallback response when LLM generation fails."""
    if not techniques:
        return f"I couldn't find specific MITRE ATT&CK techniques for '{query}', but the framework contains thousands of documented attack patterns. Try rephrasing your query or ask about specific tactics like 'initial access', 'execution', 'persistence', or 'lateral movement'."
    
    top_technique = techniques[0]
    tactics = ', '.join(top_technique['kill_chain_phases'][:3])
    
    response = f"Based on your query about '{query}', I found the most relevant MITRE ATT&CK technique is **{top_technique['name']}** ({top_technique['technique_id']}). "
    
    if tactics:
        response += f"This technique is associated with the **{tactics}** tactics. "
    
    response += f"The technique involves {top_technique['description'][:200]}... "
    
    if len(techniques) > 1:
        response += f"I also found {len(techniques)-1} other related techniques that might be relevant to your security analysis."
    
    response += "\n\nFor detection, monitor for indicators of these techniques in your logs and network traffic. Consider implementing the relevant mitigations from the MITRE ATT&CK framework."
    
    return response
