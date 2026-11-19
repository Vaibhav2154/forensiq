"""FastAPI endpoints for the ForensIQ LangGraph multi-agent investigation orchestrator."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from contracts import BatchIngestRequest, InvestigationInput
from services.investigation import InvestigationResult, InvestigationService


router = APIRouter(prefix="/api/v1/investigations", tags=["Multi-Agent Investigations"])

_investigation_service: InvestigationService | None = None


def set_investigation_service(service: InvestigationService | None) -> None:
    """Inject a shared InvestigationService instance (used by lifespan or tests)."""
    global _investigation_service
    _investigation_service = service


def get_investigation_service() -> InvestigationService:
    """Resolve the active InvestigationService instance."""
    global _investigation_service
    if _investigation_service is None:
        _investigation_service = InvestigationService()
    return _investigation_service


@router.get("/config", response_model=dict[str, Any])
async def get_investigation_config(
    service: InvestigationService = Depends(get_investigation_service),
) -> dict[str, Any]:
    """Return sanitized multi-agent configuration (models, key slots, LSTM hook status)."""
    return service.get_sanitized_config()


@router.post("/run", response_model=InvestigationResult)
async def run_investigation(
    payload: InvestigationInput,
    service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationResult:
    """Execute the LangGraph multi-agent investigation on a validated InvestigationInput."""
    try:
        return await service.run_investigation(payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}") from exc


@router.post("/from-batch", response_model=InvestigationResult)
async def run_investigation_from_batch(
    batch: BatchIngestRequest,
    top_k_knowledge: int = Query(default=8, ge=1, le=30),
    service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationResult:
    """Run KCP normalization, OKF/Cognee retrieval, and the LangGraph multi-agent workflow."""
    if service.knowledge_service is None:
        raise HTTPException(
            status_code=503,
            detail="KnowledgeService is not attached to InvestigationService",
        )
    try:
        return await service.investigate_batch(
            batch=batch,
            top_k_knowledge=top_k_knowledge,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Batch investigation failed: {exc}") from exc
