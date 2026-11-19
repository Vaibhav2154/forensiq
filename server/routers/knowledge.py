"""FastAPI endpoints for KCP ingestion, OKF/Cognee retrieval, and log normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from contracts import BatchIngestRequest, NormalizedEvent
from services.knowledge.models import (
    IngestionRunStatus,
    KnowledgeRecordDetailResponse,
    KnowledgeSearchQuery,
    KnowledgeSearchResponse,
    KnowledgeStoreStats,
)
from services.knowledge.service import KnowledgeService


router = APIRouter(prefix="/api/v1/knowledge", tags=["Knowledge Pipeline & OKF"])

_knowledge_service: KnowledgeService | None = None


def set_knowledge_service(service: KnowledgeService | None) -> None:
    """Inject a shared KnowledgeService instance (used by lifespan or tests)."""
    global _knowledge_service
    _knowledge_service = service


def get_knowledge_service() -> KnowledgeService:
    """Resolve the active KnowledgeService, initializing defaults lazily if needed."""
    global _knowledge_service
    if _knowledge_service is None:
        _knowledge_service = KnowledgeService()
    return _knowledge_service


class MitreIngestRequest(BaseModel):
    """Request parameters for MITRE ATT&CK STIX ingestion."""

    file_path: str | None = Field(
        default=None, description="Optional override path to MITRE STIX JSON bundle"
    )
    entity_types: list[str] | None = Field(
        default=None, description="Optional subset of STIX object types to ingest"
    )
    include_deprecated: bool = False
    limit: int | None = Field(default=None, ge=1)
    dry_run: bool = False


class CveIngestRequest(BaseModel):
    """Request parameters for CVE List v5 JSON ingestion."""

    path: str | None = Field(
        default=None, description="Optional override path to CVE root dir or JSON file"
    )
    years: list[int] | None = None
    cve_ids: list[str] | None = None
    delta_file: str | None = None
    include_rejected: bool = False
    limit: int | None = Field(default=None, ge=1)
    dry_run: bool = False


@router.post("/ingest/mitre", response_model=IngestionRunStatus)
async def ingest_mitre(
    request: MitreIngestRequest = MitreIngestRequest(),
    service: KnowledgeService = Depends(get_knowledge_service),
) -> IngestionRunStatus:
    """Run KCP ingestion over a MITRE Enterprise ATT&CK STIX bundle."""
    try:
        run = await service.ingest_mitre(
            path=Path(request.file_path) if request.file_path else None,
            entity_types=set(request.entity_types) if request.entity_types else None,
            include_deprecated=request.include_deprecated,
            limit=request.limit,
            dry_run=request.dry_run,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if run.status == "failed" and run.errors:
        raise HTTPException(status_code=400, detail=run.errors[0])
    return run


@router.post("/ingest/cve", response_model=IngestionRunStatus)
async def ingest_cve(
    request: CveIngestRequest = CveIngestRequest(),
    service: KnowledgeService = Depends(get_knowledge_service),
) -> IngestionRunStatus:
    """Run streaming KCP ingestion over CVE List v5 JSON files."""
    run = await service.ingest_cve(
        path=Path(request.path) if request.path else None,
        years=request.years,
        cve_ids=request.cve_ids,
        delta_file=Path(request.delta_file) if request.delta_file else None,
        include_rejected=request.include_rejected,
        limit=request.limit,
        dry_run=request.dry_run,
    )
    if run.status == "failed" and run.parsed == 0 and run.errors:
        raise HTTPException(status_code=400, detail=run.errors[0])
    return run


@router.get("/ingestion/status", response_model=list[IngestionRunStatus])
async def list_ingestion_status(
    limit: int = Query(default=20, ge=1, le=100),
    service: KnowledgeService = Depends(get_knowledge_service),
) -> list[IngestionRunStatus]:
    """List recent knowledge ingestion runs."""
    return await service.list_ingestion_runs(limit=limit)


@router.get("/ingestion/status/{run_id}", response_model=IngestionRunStatus)
async def get_ingestion_status(
    run_id: str,
    service: KnowledgeService = Depends(get_knowledge_service),
) -> IngestionRunStatus:
    """Fetch status and compression audit metrics for a single ingestion run."""
    run = await service.get_ingestion_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Ingestion run {run_id!r} not found")
    return run


@router.post("/search", response_model=KnowledgeSearchResponse)
async def search_knowledge_post(
    query: KnowledgeSearchQuery,
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeSearchResponse:
    """Retrieve relevant OKF MITRE ATT&CK and CVE records with provenance."""
    return await service.search(query)


@router.get("/search", response_model=KnowledgeSearchResponse)
async def search_knowledge_get(
    q: str = Query(..., min_length=1, description="Search query text"),
    source_type: Literal["mitre_attack", "cve"] | None = Query(default=None),
    kind: str | None = Query(default=None),
    tactic: str | None = Query(default=None),
    platform: str | None = Query(default=None),
    min_cvss: float | None = Query(default=None, ge=0.0, le=10.0),
    top_k: int = Query(default=5, ge=1, le=50),
    search_mode: Literal["auto", "semantic", "lexical", "graph"] = Query(default="auto"),
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeSearchResponse:
    """GET endpoint for querying OKF MITRE ATT&CK and CVE records."""
    return await service.search(
        KnowledgeSearchQuery(
            query=q,
            source_type=source_type,
            kind=kind,
            tactic=tactic,
            platform=platform,
            min_cvss=min_cvss,
            top_k=top_k,
            search_mode=search_mode,
        )
    )


@router.get("/records/{record_id}", response_model=KnowledgeRecordDetailResponse)
async def get_knowledge_record(
    record_id: str,
    include_related: bool = Query(default=False),
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeRecordDetailResponse:
    """Fetch a single OKF KnowledgeRecord by its deterministic record_id."""
    detail = await service.get_record(record_id, include_related=include_related)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Knowledge record {record_id!r} not found")
    return detail


@router.get(
    "/source/{source_type}/{source_id}",
    response_model=KnowledgeRecordDetailResponse,
)
async def get_knowledge_by_source(
    source_type: Literal["mitre_attack", "cve"],
    source_id: str,
    include_related: bool = Query(default=False),
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeRecordDetailResponse:
    """Fetch a single OKF KnowledgeRecord by (source_type, source_id)."""
    detail = await service.get_by_source(
        source_type, source_id, include_related=include_related
    )
    if detail is None:
        raise HTTPException(
            status_code=404,
            detail=f"Knowledge record for {source_type}/{source_id} not found",
        )
    return detail


@router.get("/stats", response_model=KnowledgeStoreStats)
async def get_knowledge_stats(
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeStoreStats:
    """Return aggregate counts and active dataset versions."""
    return await service.stats()


@router.post("/normalize/batch", response_model=list[NormalizedEvent])
async def normalize_log_batch(
    request: BatchIngestRequest,
    service: KnowledgeService = Depends(get_knowledge_service),
) -> list[NormalizedEvent]:
    """Normalize a BatchIngestRequest into traceable NormalizedEvent records."""
    return service.normalize_batch(request)
