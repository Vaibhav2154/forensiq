"""Cognee graph + vector knowledge store adapter for OKF records."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from contracts import KnowledgeRecord
from services.knowledge.config import KnowledgeSettings
from services.knowledge.models import (
    IngestionRunStatus,
    KnowledgeSearchHit,
    KnowledgeSearchQuery,
    KnowledgeStoreStats,
    UpsertSummary,
)
from services.knowledge.storage.base import (
    build_searchable_text,
    matches_filters,
    node_uuid_for_concept,
    node_uuid_for_record,
)
from services.knowledge.storage.manifest_store import ManifestStore


logger = logging.getLogger(__name__)

RECORD_VECTOR_COLLECTION = "OKFRecordNode_searchable_text"
_CONCEPT_REL_TYPES = {"has_weakness", "has_attack_pattern", "affects_product"}

_COGNEE_LOCK = asyncio.Lock()
_ACTIVE_DATA_DIR: Path | None = None
_NODE_MODELS_CACHE: tuple[type[Any], type[Any]] | None = None


def _get_node_models() -> tuple[type[Any], type[Any]]:
    """Lazily define Cognee DataPoint subclasses after env configuration."""
    global _NODE_MODELS_CACHE
    if _NODE_MODELS_CACHE is not None:
        return _NODE_MODELS_CACHE

    from cognee.infrastructure.engine import DataPoint

    class OKFRecordNode(DataPoint):
        record_id: str
        source_type: str
        source_id: str
        source_version: str
        kind: str
        name: str
        searchable_text: str
        source_uri: str
        content_sha256: str
        metadata: dict[str, Any] = {"index_fields": ["searchable_text"]}

    class OKFConceptNode(DataPoint):
        concept_id: str
        concept_type: str
        name: str
        metadata: dict[str, Any] = {"index_fields": []}

    _NODE_MODELS_CACHE = (OKFRecordNode, OKFConceptNode)
    return _NODE_MODELS_CACHE


def _apply_cognee_env(settings: KnowledgeSettings, system_dir: Path, data_dir: Path) -> None:
    """Set process environment variables before Cognee initializes singletons."""
    os.environ["SYSTEM_ROOT_DIRECTORY"] = str(system_dir)
    os.environ["DATA_ROOT_DIRECTORY"] = str(data_dir)
    os.environ["ENABLE_BACKEND_ACCESS_CONTROL"] = "false"
    os.environ["CACHING"] = "false"
    os.environ["TELEMETRY_DISABLED"] = "1"
    os.environ["VECTOR_DB_PROVIDER"] = settings.cognee_vector_db
    os.environ["GRAPH_DATABASE_PROVIDER"] = settings.cognee_graph_db
    os.environ["EMBEDDING_PROVIDER"] = settings.cognee_embedding_provider
    os.environ["EMBEDDING_MODEL"] = settings.cognee_embedding_model
    os.environ["EMBEDDING_DIMENSIONS"] = str(settings.cognee_embedding_dimensions)

    if settings.cognee_embedding_api_key:
        os.environ["EMBEDDING_API_KEY"] = settings.cognee_embedding_api_key
    if settings.cognee_llm_provider:
        os.environ["LLM_PROVIDER"] = settings.cognee_llm_provider
    if settings.cognee_llm_model:
        os.environ["LLM_MODEL"] = settings.cognee_llm_model
    if settings.cognee_llm_api_key:
        os.environ["LLM_API_KEY"] = settings.cognee_llm_api_key


def _apply_cognee_runtime_config(
    settings: KnowledgeSettings, system_dir: Path, data_dir: Path
) -> None:
    """Apply explicit cognee.config settings so directory switches stay isolated."""
    import cognee

    db_dir = system_dir / "databases"
    db_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    cognee.config.system_root_directory(str(system_dir))
    cognee.config.data_root_directory(str(data_dir))
    cognee.config.set_vector_db_config(
        {
            "vector_db_provider": settings.cognee_vector_db,
            "vector_db_url": str(db_dir / "cognee.lancedb"),
        }
    )
    cognee.config.set_graph_db_config(
        {
            "graph_database_provider": settings.cognee_graph_db,
            "graph_file_path": str(db_dir / "cognee_graph.kuzu"),
        }
    )
    cognee.config.set_relational_db_config(
        {
            "db_provider": "sqlite",
            "db_name": "cognee_db",
            "db_path": str(db_dir),
        }
    )
    cognee.config.set_migration_db_config(
        {
            "migration_db_provider": "sqlite",
            "migration_db_name": "cognee_db",
            "migration_db_path": str(db_dir),
        }
    )
    cognee.config.set_embedding_provider(settings.cognee_embedding_provider)
    cognee.config.set_embedding_model(settings.cognee_embedding_model)
    cognee.config.set_embedding_dimensions(settings.cognee_embedding_dimensions)
    if settings.cognee_embedding_api_key:
        cognee.config.set_embedding_api_key(settings.cognee_embedding_api_key)
    if settings.cognee_llm_provider:
        cognee.config.set_llm_provider(settings.cognee_llm_provider)
    if settings.cognee_llm_model:
        cognee.config.set_llm_model(settings.cognee_llm_model)
    if settings.cognee_llm_api_key:
        cognee.config.set_llm_api_key(settings.cognee_llm_api_key)


class CogneeKnowledgeStore:
    """KnowledgeStore backed by Cognee (LanceDB + Kuzu) and SQLite ManifestStore."""

    def __init__(self, settings: KnowledgeSettings | None = None) -> None:
        self.settings = settings or KnowledgeSettings()
        self._data_dir = self.settings.data_dir.resolve()
        self._manifest = ManifestStore(self._data_dir / "manifest.db")
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize ManifestStore and Cognee storage backends idempotently."""
        global _ACTIVE_DATA_DIR
        self._manifest.initialize()

        async with _COGNEE_LOCK:
            if self._initialized and _ACTIVE_DATA_DIR == self._data_dir:
                return

            system_dir = self._data_dir / "cognee_system"
            data_dir = self._data_dir / "cognee_data"
            _apply_cognee_env(self.settings, system_dir=system_dir, data_dir=data_dir)

            import cognee
            from cognee.modules.engine.operations.setup import setup

            if _ACTIVE_DATA_DIR is not None and _ACTIVE_DATA_DIR != self._data_dir:
                try:
                    await cognee.disconnect()
                except Exception:
                    logger.debug("Ignoring disconnect error while switching Cognee dir")

            _apply_cognee_runtime_config(
                self.settings, system_dir=system_dir, data_dir=data_dir
            )
            await setup()
            _ACTIVE_DATA_DIR = self._data_dir
            self._initialized = True

    async def close(self) -> None:
        """Close local manifest and Cognee backend connections."""
        global _ACTIVE_DATA_DIR
        self._manifest.close()
        async with _COGNEE_LOCK:
            if _ACTIVE_DATA_DIR == self._data_dir:
                try:
                    import cognee

                    await cognee.disconnect()
                except Exception:
                    logger.debug("Ignoring Cognee disconnect error on close")
                _ACTIVE_DATA_DIR = None
            self._initialized = False

    async def upsert_records(self, records: list[KnowledgeRecord]) -> UpsertSummary:
        """Deduplicate via manifest hashes, then upsert changed OKF nodes/edges to Cognee."""
        await self.initialize()
        summary, changed = self._manifest.upsert_records(records)
        if not changed:
            return summary

        from cognee.tasks.storage import add_data_points

        OKFRecordNode, OKFConceptNode = _get_node_models()

        nodes_by_uuid: dict[str, Any] = {}
        changed_by_source_id: dict[str, KnowledgeRecord] = {}
        all_target_ids: list[str] = []

        for rec in changed:
            changed_by_source_id[rec.source_id.upper()] = rec
            node_uuid = node_uuid_for_record(rec.record_id)
            title = str(rec.content.get("name") or rec.content.get("title") or rec.source_id)
            nodes_by_uuid[str(node_uuid)] = OKFRecordNode(
                id=node_uuid,
                record_id=rec.record_id,
                source_type=rec.source_type,
                source_id=rec.source_id,
                source_version=rec.source_version,
                kind=str(rec.content.get("kind") or rec.source_type),
                name=title,
                searchable_text=build_searchable_text(rec),
                source_uri=str(rec.provenance.get("source_uri") or ""),
                content_sha256=str(rec.provenance.get("content_sha256") or ""),
            )
            for rel in rec.relationships:
                all_target_ids.append(rel.target_source_id)

        existing_targets = self._manifest.find_existing_source_records(all_target_ids)
        edges: list[tuple[str, str, str, dict[str, Any]]] = []
        seen_edges: set[tuple[str, str, str]] = set()

        for rec in changed:
            src_uuid = str(node_uuid_for_record(rec.record_id))
            for rel in rec.relationships:
                tgt_upper = rel.target_source_id.strip().upper()
                tgt_rec = changed_by_source_id.get(tgt_upper) or existing_targets.get(
                    tgt_upper
                )
                if tgt_rec is not None:
                    tgt_uuid = str(node_uuid_for_record(tgt_rec.record_id))
                elif (
                    rel.relationship_type in _CONCEPT_REL_TYPES
                    or tgt_upper.startswith("CWE-")
                    or tgt_upper.startswith("CAPEC-")
                ):
                    concept_uuid = node_uuid_for_concept(tgt_upper)
                    tgt_uuid = str(concept_uuid)
                    if tgt_uuid not in nodes_by_uuid:
                        nodes_by_uuid[tgt_uuid] = OKFConceptNode(
                            id=concept_uuid,
                            concept_id=rel.target_source_id,
                            concept_type=rel.relationship_type,
                            name=rel.target_source_id,
                        )
                else:
                    # Target OKF record has not been ingested yet; link when it arrives.
                    continue

                edge_key = (src_uuid, tgt_uuid, rel.relationship_type)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append(
                        (
                            src_uuid,
                            tgt_uuid,
                            rel.relationship_type,
                            {
                                "relationship_type": rel.relationship_type,
                                "source": rel.source,
                            },
                        )
                    )

        # Materialize edges from previously stored records pointing at newly ingested nodes.
        incoming_links = self._manifest.find_incoming_links(list(changed_by_source_id.keys()))
        for src_rec, tgt_upper, rel_type, rel_source in incoming_links:
            tgt_rec = changed_by_source_id.get(tgt_upper)
            if tgt_rec is None:
                continue
            src_uuid = str(node_uuid_for_record(src_rec.record_id))
            tgt_uuid = str(node_uuid_for_record(tgt_rec.record_id))
            edge_key = (src_uuid, tgt_uuid, rel_type)
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                edges.append(
                    (
                        src_uuid,
                        tgt_uuid,
                        rel_type,
                        {"relationship_type": rel_type, "source": rel_source},
                    )
                )

        await add_data_points(
            list(nodes_by_uuid.values()),
            custom_edges=edges or None,
            index_edges=False,
        )
        return summary

    async def get_by_record_id(self, record_id: str) -> KnowledgeRecord | None:
        self._manifest.initialize()
        return self._manifest.get_by_record_id(record_id)

    async def get_by_source_id(
        self, source_type: str, source_id: str
    ) -> KnowledgeRecord | None:
        self._manifest.initialize()
        return self._manifest.get_by_source_id(source_type, source_id)

    async def get_related(self, record: KnowledgeRecord) -> list[KnowledgeRecord]:
        """Resolve 1-hop related records via Cognee graph and manifest fallback."""
        await self.initialize()
        related_by_id: dict[str, KnowledgeRecord] = {}

        try:
            from cognee.infrastructure.databases.graph import get_graph_engine

            ge = await get_graph_engine()
            node_uuid = str(node_uuid_for_record(record.record_id))
            connections = await ge.get_connections(node_uuid)
            neighbor_uuids: list[str] = []
            for src_node, _edge_props, tgt_node in connections:
                for node_dict in (src_node, tgt_node):
                    if isinstance(node_dict, dict):
                        nid = str(node_dict.get("id") or "")
                        if nid and nid != node_uuid:
                            neighbor_uuids.append(nid)
            hydrated = self._manifest.get_by_node_uuids(neighbor_uuids)
            for rec in hydrated.values():
                related_by_id[rec.record_id] = rec
        except Exception as exc:
            logger.debug("Cognee graph neighbor lookup fell back to manifest: %s", exc)

        for rec in self._manifest.get_related(record):
            related_by_id.setdefault(rec.record_id, rec)

        return list(related_by_id.values())

    async def _vector_search(
        self, query: KnowledgeSearchQuery
    ) -> list[KnowledgeSearchHit]:
        from cognee.infrastructure.databases.vector import get_vector_engine_async

        ve = await get_vector_engine_async()
        if not await ve.has_collection(RECORD_VECTOR_COLLECTION):
            return []

        raw_limit = min(max(query.top_k * 5, 25), 200)
        raw_hits = await ve.search(
            collection_name=RECORD_VECTOR_COLLECTION,
            query_text=query.query,
            limit=raw_limit,
        )
        if not raw_hits:
            return []

        uuids = [str(item.id) for item in raw_hits]
        records_by_uuid = self._manifest.get_by_node_uuids(uuids)

        hits: list[KnowledgeSearchHit] = []
        for item in raw_hits:
            rec = records_by_uuid.get(str(item.id))
            if rec is None or not matches_filters(rec, query):
                continue
            distance = float(item.score) if item.score is not None else 2.0
            similarity = round(max(0.0, min(1.0, 1.0 - (distance / 2.0))), 4)
            hits.append(
                KnowledgeSearchHit(
                    record=rec,
                    score=similarity,
                    retrieval_mode="cognee_vector",
                    matched_via=RECORD_VECTOR_COLLECTION,
                )
            )
        return hits

    async def _expand_graph_hits(
        self, seed_hits: list[KnowledgeSearchHit], query: KnowledgeSearchQuery
    ) -> list[KnowledgeSearchHit]:
        if not seed_hits:
            return []
        from cognee.infrastructure.databases.graph import get_graph_engine

        ge = await get_graph_engine()
        neighbor_scores: dict[str, float] = {}
        for seed in seed_hits[:3]:
            seed_uuid = str(node_uuid_for_record(seed.record.record_id))
            try:
                conns = await ge.get_connections(seed_uuid)
            except Exception:
                continue
            for src_node, _edge_props, tgt_node in conns:
                for node_dict in (src_node, tgt_node):
                    if isinstance(node_dict, dict):
                        nid = str(node_dict.get("id") or "")
                        if nid and nid != seed_uuid:
                            neighbor_scores[nid] = max(
                                neighbor_scores.get(nid, 0.0),
                                round(seed.score * 0.85, 4),
                            )

        hydrated = self._manifest.get_by_node_uuids(list(neighbor_scores.keys()))
        graph_hits: list[KnowledgeSearchHit] = []
        for nid, rec in hydrated.items():
            if matches_filters(rec, query):
                graph_hits.append(
                    KnowledgeSearchHit(
                        record=rec,
                        score=neighbor_scores[nid],
                        retrieval_mode="cognee_graph",
                        matched_via="kuzu_1hop",
                    )
                )
        return graph_hits

    async def search(self, query: KnowledgeSearchQuery) -> list[KnowledgeSearchHit]:
        """Retrieve matching OKF KnowledgeRecords via Cognee vector/graph + exact IDs."""
        await self.initialize()

        merged: dict[str, KnowledgeSearchHit] = {}

        def _merge(hit: KnowledgeSearchHit) -> None:
            existing = merged.get(hit.record.record_id)
            if existing is None or hit.score > existing.score:
                merged[hit.record.record_id] = hit

        for exact_hit in self._manifest.find_exact_id_matches(query):
            _merge(exact_hit)

        if query.search_mode == "lexical":
            for lex_hit in self._manifest.lexical_search(query):
                _merge(lex_hit)
        else:
            vector_hits = await self._vector_search(query)
            for vhit in vector_hits:
                _merge(vhit)

            if query.search_mode == "graph":
                for ghit in await self._expand_graph_hits(vector_hits, query):
                    _merge(ghit)

            if query.search_mode == "auto" and not merged:
                for lex_hit in self._manifest.lexical_search(query):
                    _merge(lex_hit)

        ranked = sorted(merged.values(), key=lambda h: h.score, reverse=True)
        return ranked[: query.top_k]

    async def stats(self) -> KnowledgeStoreStats:
        self._manifest.initialize()
        return self._manifest.stats(backend_name="cognee")

    async def list_records(
        self,
        source_type: str | None = None,
        kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[KnowledgeRecord]:
        self._manifest.initialize()
        return self._manifest.list_records(
            source_type=source_type,
            kind=kind,
            limit=limit,
            offset=offset,
        )

    async def save_ingestion_run(self, run: IngestionRunStatus) -> None:
        self._manifest.initialize()
        self._manifest.save_ingestion_run(run)

    async def get_ingestion_run(self, run_id: str) -> IngestionRunStatus | None:
        self._manifest.initialize()
        return self._manifest.get_ingestion_run(run_id)

    async def list_ingestion_runs(self, limit: int = 20) -> list[IngestionRunStatus]:
        self._manifest.initialize()
        return self._manifest.list_ingestion_runs(limit=limit)
