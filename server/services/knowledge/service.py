"""High-level KnowledgeService facade for KCP, OKF, and Cognee retrieval."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import uuid

from contracts import (
    BatchIngestRequest,
    InvestigationInput,
    KnowledgeRecord,
    NormalizedEvent,
    SequenceCue,
)
from services.knowledge.config import KnowledgeSettings
from services.knowledge.kcp import KCPPipeline, normalize_batch as kcp_normalize_batch
from services.knowledge.models import (
    IngestionRunStatus,
    KnowledgeRecordDetailResponse,
    KnowledgeSearchQuery,
    KnowledgeSearchResponse,
    KnowledgeStoreStats,
)
from services.knowledge.storage import (
    CogneeKnowledgeStore,
    InMemoryKnowledgeStore,
    KnowledgeStore,
)


class KnowledgeService:
    """Provider-neutral facade coordinating KCP ingestion, OKF storage, and retrieval."""

    def __init__(
        self,
        settings: KnowledgeSettings | None = None,
        store: KnowledgeStore | None = None,
    ) -> None:
        self.settings = settings or KnowledgeSettings()
        if store is not None:
            self.store: KnowledgeStore = store
        elif self.settings.store_backend == "memory":
            self.store = InMemoryKnowledgeStore()
        else:
            self.store = CogneeKnowledgeStore(self.settings)
        self.pipeline = KCPPipeline(settings=self.settings, store=self.store)

    async def initialize(self) -> None:
        await self.store.initialize()

    async def close(self) -> None:
        await self.store.close()

    async def ingest_mitre(
        self,
        path: Path | None = None,
        entity_types: set[str] | None = None,
        include_deprecated: bool = False,
        limit: int | None = None,
        dry_run: bool = False,
    ) -> IngestionRunStatus:
        return await self.pipeline.ingest_mitre(
            path=path,
            entity_types=entity_types,
            include_deprecated=include_deprecated,
            limit=limit,
            dry_run=dry_run,
        )

    async def ingest_cve(
        self,
        path: Path | None = None,
        years: list[int] | None = None,
        cve_ids: list[str] | None = None,
        delta_file: Path | None = None,
        include_rejected: bool = False,
        limit: int | None = None,
        dry_run: bool = False,
    ) -> IngestionRunStatus:
        return await self.pipeline.ingest_cve(
            path=path,
            years=years,
            cve_ids=cve_ids,
            delta_file=delta_file,
            include_rejected=include_rejected,
            limit=limit,
            dry_run=dry_run,
        )

    async def search(self, query: KnowledgeSearchQuery) -> KnowledgeSearchResponse:
        hits = await self.store.search(query)
        mode = hits[0].retrieval_mode if hits else query.search_mode
        return KnowledgeSearchResponse(
            query=query.query,
            total_hits=len(hits),
            retrieval_mode=mode,
            hits=hits,
        )

    async def get_record(
        self, record_id: str, include_related: bool = False
    ) -> KnowledgeRecordDetailResponse | None:
        record = await self.store.get_by_record_id(record_id)
        if record is None:
            return None
        related = await self.store.get_related(record) if include_related else []
        return KnowledgeRecordDetailResponse(record=record, related_records=related)

    async def get_by_source(
        self, source_type: str, source_id: str, include_related: bool = False
    ) -> KnowledgeRecordDetailResponse | None:
        record = await self.store.get_by_source_id(source_type, source_id)
        if record is None:
            return None
        related = await self.store.get_related(record) if include_related else []
        return KnowledgeRecordDetailResponse(record=record, related_records=related)

    async def get_ingestion_run(self, run_id: str) -> IngestionRunStatus | None:
        return await self.store.get_ingestion_run(run_id)

    async def list_ingestion_runs(self, limit: int = 20) -> list[IngestionRunStatus]:
        return await self.store.list_ingestion_runs(limit=limit)

    async def stats(self) -> KnowledgeStoreStats:
        return await self.store.stats()

    async def list_records(
        self,
        source_type: str | None = None,
        kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[KnowledgeRecord]:
        return await self.store.list_records(
            source_type=source_type,
            kind=kind,
            limit=limit,
            offset=offset,
        )

    def normalize_batch(self, request: BatchIngestRequest) -> list[NormalizedEvent]:
        return kcp_normalize_batch(request)

    async def prepare_investigation_input(
        self,
        request: BatchIngestRequest,
        top_k_knowledge: int = 10,
        sequence_cues: list[SequenceCue] | None = None,
    ) -> InvestigationInput:
        """Run KCP log normalization and OKF/Cognee retrieval to produce InvestigationInput."""
        normalized_events = self.normalize_batch(request)

        # Build concise retrieval terms from KCP-normalized events
        query_terms: list[str] = []
        seen_terms: set[str] = set()
        for evt in normalized_events:
            candidates = [evt.event_type.replace("_", " ")]
            for key in ("process", "command", "outcome", "severity", "service"):
                val = evt.features.get(key)
                if val:
                    candidates.append(str(val))
            for term in candidates:
                cleaned = term.strip()
                if cleaned and cleaned.lower() not in seen_terms:
                    seen_terms.add(cleaned.lower())
                    query_terms.append(cleaned)

        knowledge_records: list[KnowledgeRecord] = []
        seen_record_ids: set[str] = set()
        if query_terms and top_k_knowledge > 0:
            search_text = " ".join(query_terms[:16])
            mitre_resp = await self.search(
                KnowledgeSearchQuery(
                    query=search_text,
                    source_type="mitre_attack",
                    kind="attack-pattern",
                    top_k=top_k_knowledge,
                    search_mode="auto",
                )
            )
            cve_resp = await self.search(
                KnowledgeSearchQuery(
                    query=search_text,
                    source_type="cve",
                    top_k=top_k_knowledge,
                    search_mode="auto",
                )
            )
            for hit in (*mitre_resp.hits, *cve_resp.hits):
                if hit.record.record_id not in seen_record_ids:
                    seen_record_ids.add(hit.record.record_id)
                    knowledge_records.append(hit.record)

        return InvestigationInput(
            investigation_id=f"inv-{uuid.uuid4().hex[:12]}",
            normalized_events=normalized_events,
            knowledge_records=knowledge_records,
            sequence_cues=sequence_cues or [],
            created_at=datetime.now(timezone.utc),
        )
