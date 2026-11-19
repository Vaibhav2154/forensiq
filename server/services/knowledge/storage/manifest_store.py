"""SQLite provenance manifest, version history, and ingestion-run store."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

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
    node_uuid_for_record,
)


class ManifestStore:
    """Durable SQLite catalog paired with Cognee for exact provenance & dedup."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        with self._lock:
            if self._conn is not None:
                return
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS records (
                    record_id TEXT PRIMARY KEY,
                    node_uuid TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    searchable_text TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_records_node_uuid
                    ON records (node_uuid);
                CREATE INDEX IF NOT EXISTS idx_records_source
                    ON records (source_type, source_id);
                CREATE INDEX IF NOT EXISTS idx_records_source_id_only
                    ON records (source_id);
                CREATE INDEX IF NOT EXISTS idx_records_kind
                    ON records (kind);

                CREATE TABLE IF NOT EXISTS record_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    ingestion_run_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_record_versions_rid
                    ON record_versions (record_id);

                CREATE TABLE IF NOT EXISTS ingestion_runs (
                    run_id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    run_json TEXT NOT NULL
                );
                """
            )
            conn.commit()
            self._conn = conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _ensure_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        assert self._conn is not None
        return self._conn

    def upsert_records(
        self, records: list[KnowledgeRecord]
    ) -> tuple[UpsertSummary, list[KnowledgeRecord]]:
        """Persist validated KnowledgeRecords and return changed records for indexing."""
        conn = self._ensure_conn()
        inserted = 0
        updated = 0
        skipped = 0
        record_ids: list[str] = []
        changed: list[KnowledgeRecord] = []

        with self._lock:
            cur = conn.cursor()
            for record in records:
                record_ids.append(record.record_id)
                content_sha = str(record.provenance.get("content_sha256") or "")
                source_sha = str(record.provenance.get("source_sha256") or "")
                run_id = str(record.provenance.get("ingestion_run_id") or "")
                kind = str(record.content.get("kind") or "")
                searchable = build_searchable_text(record)
                payload_json = record.model_dump_json()
                ingested_iso = record.ingested_at.isoformat()

                existing = cur.execute(
                    "SELECT source_version, content_sha256 FROM records WHERE record_id = ?",
                    (record.record_id,),
                ).fetchone()

                if existing is not None:
                    if (
                        existing["content_sha256"] == content_sha
                        and existing["source_version"] == record.source_version
                    ):
                        skipped += 1
                        continue
                    updated += 1
                else:
                    inserted += 1

                cur.execute(
                    """
                    INSERT INTO records (
                        record_id, node_uuid, source_type, source_id, source_version, kind,
                        content_sha256, source_sha256, ingested_at, searchable_text, record_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(record_id) DO UPDATE SET
                        node_uuid = excluded.node_uuid,
                        source_type = excluded.source_type,
                        source_id = excluded.source_id,
                        source_version = excluded.source_version,
                        kind = excluded.kind,
                        content_sha256 = excluded.content_sha256,
                        source_sha256 = excluded.source_sha256,
                        ingested_at = excluded.ingested_at,
                        searchable_text = excluded.searchable_text,
                        record_json = excluded.record_json
                    """,
                    (
                        record.record_id,
                        str(node_uuid_for_record(record.record_id)),
                        record.source_type,
                        record.source_id,
                        record.source_version,
                        kind,
                        content_sha,
                        source_sha,
                        ingested_iso,
                        searchable,
                        payload_json,
                    ),
                )
                cur.execute(
                    """
                    INSERT INTO record_versions (
                        record_id, source_version, content_sha256, source_sha256,
                        ingested_at, ingestion_run_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.record_id,
                        record.source_version,
                        content_sha,
                        source_sha,
                        ingested_iso,
                        run_id,
                    ),
                )
                changed.append(record)
            conn.commit()

        return (
            UpsertSummary(
                inserted=inserted,
                updated=updated,
                skipped=skipped,
                record_ids=record_ids,
            ),
            changed,
        )

    def get_by_record_id(self, record_id: str) -> KnowledgeRecord | None:
        conn = self._ensure_conn()
        with self._lock:
            row = conn.execute(
                "SELECT record_json FROM records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
        if row is None:
            return None
        return KnowledgeRecord.model_validate_json(row["record_json"])

    def get_by_source_id(
        self, source_type: str, source_id: str
    ) -> KnowledgeRecord | None:
        conn = self._ensure_conn()
        with self._lock:
            row = conn.execute(
                "SELECT record_json FROM records WHERE source_type = ? AND UPPER(source_id) = UPPER(?)",
                (source_type, source_id.strip()),
            ).fetchone()
        if row is None:
            return None
        return KnowledgeRecord.model_validate_json(row["record_json"])

    def get_many_by_record_ids(
        self, record_ids: list[str]
    ) -> dict[str, KnowledgeRecord]:
        if not record_ids:
            return {}
        conn = self._ensure_conn()
        placeholders = ",".join("?" for _ in record_ids)
        with self._lock:
            rows = conn.execute(
                f"SELECT record_id, record_json FROM records WHERE record_id IN ({placeholders})",
                record_ids,
            ).fetchall()
        return {
            row["record_id"]: KnowledgeRecord.model_validate_json(row["record_json"])
            for row in rows
        }

    def get_related(self, record: KnowledgeRecord) -> list[KnowledgeRecord]:
        target_ids = list(
            dict.fromkeys(rel.target_source_id for rel in record.relationships)
        )
        if not target_ids:
            return []
        conn = self._ensure_conn()
        placeholders = ",".join("?" for _ in target_ids)
        with self._lock:
            rows = conn.execute(
                f"SELECT record_json FROM records WHERE UPPER(source_id) IN ({placeholders})",
                [t.upper() for t in target_ids],
            ).fetchall()
        related: list[KnowledgeRecord] = []
        seen: set[str] = set()
        for row in rows:
            rec = KnowledgeRecord.model_validate_json(row["record_json"])
            if rec.record_id not in seen and rec.record_id != record.record_id:
                seen.add(rec.record_id)
                related.append(rec)
        return related

    def get_by_node_uuids(self, node_uuids: list[str]) -> dict[str, KnowledgeRecord]:
        """Resolve Cognee DataPoint UUIDs back to validated KnowledgeRecords."""
        if not node_uuids:
            return {}
        conn = self._ensure_conn()
        clean = list(dict.fromkeys(str(u) for u in node_uuids if u))
        placeholders = ",".join("?" for _ in clean)
        with self._lock:
            rows = conn.execute(
                f"SELECT node_uuid, record_json FROM records WHERE node_uuid IN ({placeholders})",
                clean,
            ).fetchall()
        return {
            row["node_uuid"]: KnowledgeRecord.model_validate_json(row["record_json"])
            for row in rows
        }

    def find_existing_source_records(
        self, source_ids: list[str]
    ) -> dict[str, KnowledgeRecord]:
        """Resolve stored records keyed by uppercase source_id."""
        if not source_ids:
            return {}
        conn = self._ensure_conn()
        upper_ids = list(dict.fromkeys(sid.strip().upper() for sid in source_ids if sid))
        placeholders = ",".join("?" for _ in upper_ids)
        with self._lock:
            rows = conn.execute(
                f"SELECT record_json FROM records WHERE UPPER(source_id) IN ({placeholders})",
                upper_ids,
            ).fetchall()
        result: dict[str, KnowledgeRecord] = {}
        for row in rows:
            rec = KnowledgeRecord.model_validate_json(row["record_json"])
            result[rec.source_id.upper()] = rec
        return result

    def find_incoming_links(
        self, target_source_ids: list[str]
    ) -> list[tuple[KnowledgeRecord, str, str, str]]:
        """Find stored records that have relationships targeting target_source_ids."""
        targets = {sid.strip().upper() for sid in target_source_ids if sid}
        if not targets:
            return []
        conn = self._ensure_conn()
        with self._lock:
            rows = conn.execute("SELECT record_json FROM records").fetchall()
        links: list[tuple[KnowledgeRecord, str, str, str]] = []
        for row in rows:
            rec = KnowledgeRecord.model_validate_json(row["record_json"])
            for rel in rec.relationships:
                t_up = rel.target_source_id.strip().upper()
                if t_up in targets:
                    links.append((rec, t_up, rel.relationship_type, rel.source))
        return links

    def get_version_history(self, record_id: str) -> list[dict[str, Any]]:
        conn = self._ensure_conn()
        with self._lock:
            rows = conn.execute(
                """
                SELECT source_version, content_sha256, source_sha256, ingested_at, ingestion_run_id
                FROM record_versions
                WHERE record_id = ?
                ORDER BY id ASC
                """,
                (record_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_exact_id_matches(
        self, query: KnowledgeSearchQuery
    ) -> list[KnowledgeSearchHit]:
        candidates = extract_source_id_candidates(query.query)
        if not candidates:
            return []
        conn = self._ensure_conn()
        placeholders = ",".join("?" for _ in candidates)
        with self._lock:
            rows = conn.execute(
                f"SELECT record_json FROM records WHERE UPPER(source_id) IN ({placeholders})",
                candidates,
            ).fetchall()
        hits: list[KnowledgeSearchHit] = []
        for row in rows:
            rec = KnowledgeRecord.model_validate_json(row["record_json"])
            if matches_filters(rec, query):
                hits.append(
                    KnowledgeSearchHit(
                        record=rec,
                        score=1.0,
                        retrieval_mode="exact_id",
                        matched_via=f"source_id:{rec.source_id}",
                    )
                )
        return hits

    def lexical_search(self, query: KnowledgeSearchQuery) -> list[KnowledgeSearchHit]:
        conn = self._ensure_conn()
        sql = "SELECT record_json, searchable_text FROM records"
        params: list[Any] = []
        clauses: list[str] = []
        if query.source_type:
            clauses.append("source_type = ?")
            params.append(query.source_type)
        if query.kind:
            clauses.append("LOWER(kind) = LOWER(?)")
            params.append(query.kind)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        with self._lock:
            rows = conn.execute(sql, params).fetchall()

        scored: list[KnowledgeSearchHit] = []
        for row in rows:
            rec = KnowledgeRecord.model_validate_json(row["record_json"])
            if not matches_filters(rec, query):
                continue
            score = lexical_score(query.query, rec, row["searchable_text"])
            if score > 0:
                scored.append(
                    KnowledgeSearchHit(
                        record=rec,
                        score=score,
                        retrieval_mode="lexical",
                        matched_via="manifest_tokens",
                    )
                )

        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[: query.top_k]

    def stats(self, backend_name: str) -> KnowledgeStoreStats:
        conn = self._ensure_conn()
        with self._lock:
            total = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            by_source = {
                row["source_type"]: row["cnt"]
                for row in conn.execute(
                    "SELECT source_type, COUNT(*) AS cnt FROM records GROUP BY source_type"
                ).fetchall()
            }
            by_kind = {
                row["kind"]: row["cnt"]
                for row in conn.execute(
                    "SELECT kind, COUNT(*) AS cnt FROM records GROUP BY kind"
                ).fetchall()
            }
            versions: dict[str, list[str]] = {}
            for row in conn.execute(
                "SELECT DISTINCT source_type, source_version FROM records ORDER BY source_version"
            ).fetchall():
                versions.setdefault(row["source_type"], []).append(row["source_version"])
            runs_count = conn.execute("SELECT COUNT(*) FROM ingestion_runs").fetchone()[0]
            last_row = conn.execute(
                "SELECT MAX(ingested_at) AS latest FROM records"
            ).fetchone()

        latest_dt = None
        if last_row and last_row["latest"]:
            latest_dt = datetime.fromisoformat(last_row["latest"])

        return KnowledgeStoreStats(
            backend=backend_name,
            total_records=total,
            counts_by_source_type=by_source,
            counts_by_kind=by_kind,
            active_versions=versions,
            total_ingestion_runs=runs_count,
            last_ingested_at=latest_dt,
        )

    def save_ingestion_run(self, run: IngestionRunStatus) -> None:
        conn = self._ensure_conn()
        with self._lock:
            conn.execute(
                """
                INSERT INTO ingestion_runs (
                    run_id, source_type, status, started_at, completed_at, run_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    run_json = excluded.run_json
                """,
                (
                    run.run_id,
                    run.source_type,
                    run.status,
                    run.started_at.isoformat(),
                    run.completed_at.isoformat() if run.completed_at else None,
                    run.model_dump_json(),
                ),
            )
            conn.commit()

    def get_ingestion_run(self, run_id: str) -> IngestionRunStatus | None:
        conn = self._ensure_conn()
        with self._lock:
            row = conn.execute(
                "SELECT run_json FROM ingestion_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return IngestionRunStatus.model_validate_json(row["run_json"])

    def list_ingestion_runs(self, limit: int = 20) -> list[IngestionRunStatus]:
        conn = self._ensure_conn()
        with self._lock:
            rows = conn.execute(
                "SELECT run_json FROM ingestion_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [IngestionRunStatus.model_validate_json(r["run_json"]) for r in rows]

