"""In-memory KnowledgeStore implementation for fast unit and router tests."""

from __future__ import annotations

from datetime import datetime

from contracts import KnowledgeRecord
from services.knowledge.models import (
    IngestionRunStatus,
    KnowledgeSearchHit,
    KnowledgeSearchQuery,
    KnowledgeStoreStats,
    UpsertSummary,
)
from services.knowledge.storage.base import (
    build_searchable_text,
    extract_source_id_candidates,
    lexical_score,
    matches_filters,
)


class InMemoryKnowledgeStore:
    """Thread-safe/async-compatible in-memory KnowledgeStore for isolated tests."""

    def __init__(self) -> None:
        self._records: dict[str, KnowledgeRecord] = {}
        self._searchable: dict[str, str] = {}
        self._versions: dict[str, list[dict[str, str]]] = {}
        self._runs: dict[str, IngestionRunStatus] = {}

    async def initialize(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def upsert_records(self, records: list[KnowledgeRecord]) -> UpsertSummary:
        inserted = 0
        updated = 0
        skipped = 0
        record_ids: list[str] = []

        for record in records:
            record_ids.append(record.record_id)
            content_sha = str(record.provenance.get("content_sha256") or "")
            existing = self._records.get(record.record_id)
            if existing is not None:
                existing_sha = str(existing.provenance.get("content_sha256") or "")
                if (
                    existing_sha == content_sha
                    and existing.source_version == record.source_version
                ):
                    skipped += 1
                    continue
                updated += 1
            else:
                inserted += 1

            self._records[record.record_id] = record
            self._searchable[record.record_id] = build_searchable_text(record)
            self._versions.setdefault(record.record_id, []).append(
                {
                    "source_version": record.source_version,
                    "content_sha256": content_sha,
                    "ingested_at": record.ingested_at.isoformat(),
                }
            )

        return UpsertSummary(
            inserted=inserted,
            updated=updated,
            skipped=skipped,
            record_ids=record_ids,
        )

    async def get_by_record_id(self, record_id: str) -> KnowledgeRecord | None:
        return self._records.get(record_id)

    async def get_by_source_id(
        self, source_type: str, source_id: str
    ) -> KnowledgeRecord | None:
        target = source_id.strip().upper()
        for record in self._records.values():
            if record.source_type == source_type and record.source_id.upper() == target:
                return record
        return None

    async def get_related(self, record: KnowledgeRecord) -> list[KnowledgeRecord]:
        targets = {rel.target_source_id.upper() for rel in record.relationships}
        if not targets:
            return []
        related: list[KnowledgeRecord] = []
        for candidate in self._records.values():
            if (
                candidate.record_id != record.record_id
                and candidate.source_id.upper() in targets
            ):
                related.append(candidate)
        return related

    async def search(self, query: KnowledgeSearchQuery) -> list[KnowledgeSearchHit]:
        hits_by_id: dict[str, KnowledgeSearchHit] = {}
        id_candidates = set(extract_source_id_candidates(query.query))

        for record in self._records.values():
            if not matches_filters(record, query):
                continue
            if record.source_id.upper() in id_candidates:
                hits_by_id[record.record_id] = KnowledgeSearchHit(
                    record=record,
                    score=1.0,
                    retrieval_mode="exact_id",
                    matched_via=f"source_id:{record.source_id}",
                )
                continue
            score = lexical_score(
                query.query, record, self._searchable.get(record.record_id, "")
            )
            if score > 0:
                hits_by_id[record.record_id] = KnowledgeSearchHit(
                    record=record,
                    score=score,
                    retrieval_mode="lexical",
                    matched_via="memory_tokens",
                )

        hits = sorted(hits_by_id.values(), key=lambda h: h.score, reverse=True)
        return hits[: query.top_k]

    async def stats(self) -> KnowledgeStoreStats:
        by_source: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        versions: dict[str, set[str]] = {}
        latest: datetime | None = None

        for rec in self._records.values():
            by_source[rec.source_type] = by_source.get(rec.source_type, 0) + 1
            kind = str(rec.content.get("kind") or "unknown")
            by_kind[kind] = by_kind.get(kind, 0) + 1
            versions.setdefault(rec.source_type, set()).add(rec.source_version)
            if latest is None or rec.ingested_at > latest:
                latest = rec.ingested_at

        return KnowledgeStoreStats(
            backend="memory",
            total_records=len(self._records),
            counts_by_source_type=by_source,
            counts_by_kind=by_kind,
            active_versions={k: sorted(v) for k, v in versions.items()},
            total_ingestion_runs=len(self._runs),
            last_ingested_at=latest,
        )

    async def save_ingestion_run(self, run: IngestionRunStatus) -> None:
        self._runs[run.run_id] = run

    async def get_ingestion_run(self, run_id: str) -> IngestionRunStatus | None:
        return self._runs.get(run_id)

    async def list_ingestion_runs(self, limit: int = 20) -> list[IngestionRunStatus]:
        ordered = sorted(
            self._runs.values(), key=lambda r: r.started_at, reverse=True
        )
        return ordered[:limit]

    async def list_records(
        self,
        source_type: str | None = None,
        kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[KnowledgeRecord]:
        items = list(self._records.values())
        if source_type:
            items = [r for r in items if r.source_type == source_type]
        if kind:
            target = kind.lower()
            items = [r for r in items if str(r.content.get("kind", "")).lower() == target]
        items.sort(key=lambda r: r.source_id)
        return items[offset : offset + limit]

