"""End-to-end KCP orchestration for MITRE ATT&CK and CVE ingestion."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from contracts import KnowledgeRecord
from services.knowledge.config import KnowledgeSettings
from services.knowledge.kcp.compressor import compress_item
from services.knowledge.kcp.normalizer import normalize_item
from services.knowledge.kcp.okf_builder import build_knowledge_record
from services.knowledge.models import CompressionAudit, IngestionRunStatus
from services.knowledge.parsers import (
    CveParseError,
    iter_cve_files,
    parse_cve_file,
    parse_mitre_stix_file,
)
from services.knowledge.storage.base import KnowledgeStore


logger = logging.getLogger(__name__)


class _CompressionAccumulator:
    """Tracks aggregate compression metrics across an ingestion run."""

    def __init__(self) -> None:
        self.raw_chars = 0
        self.compressed_chars = 0
        self.stripped_citations = 0
        self.stripped_html_tags = 0

    def add(self, audit: CompressionAudit) -> None:
        self.raw_chars += audit.raw_chars
        self.compressed_chars += audit.compressed_chars
        self.stripped_citations += audit.stripped_citations
        self.stripped_html_tags += audit.stripped_html_tags

    def summary(self) -> dict[str, Any]:
        ratio = (
            round(self.compressed_chars / self.raw_chars, 4)
            if self.raw_chars > 0
            else 1.0
        )
        return {
            "total_raw_chars": self.raw_chars,
            "total_compressed_chars": self.compressed_chars,
            "overall_compression_ratio": ratio,
            "total_stripped_citations": self.stripped_citations,
            "total_stripped_html_tags": self.stripped_html_tags,
        }


class KCPPipeline:
    """Executes Parse -> Normalize -> Compress -> OKF -> Store for security datasets."""

    def __init__(self, settings: KnowledgeSettings, store: KnowledgeStore) -> None:
        self.settings = settings
        self.store = store

    async def ingest_mitre(
        self,
        path: Path | None = None,
        entity_types: set[str] | None = None,
        include_deprecated: bool = False,
        limit: int | None = None,
        dry_run: bool = False,
        batch_size: int = 100,
    ) -> IngestionRunStatus:
        """Ingest a MITRE Enterprise ATT&CK STIX 2.1 bundle into the store."""
        target_path = Path(path) if path is not None else self.settings.mitre_default_path
        run_id = f"run-mitre-{uuid.uuid4().hex[:10]}"
        started_at = datetime.now(timezone.utc)
        acc = _CompressionAccumulator()

        run = IngestionRunStatus(
            run_id=run_id,
            source_type="mitre_attack",
            status="running",
            started_at=started_at,
            source_path=str(target_path),
            dry_run=dry_run,
        )

        try:
            await self.store.initialize()
            items, meta = parse_mitre_stix_file(
                path=target_path,
                entity_types=entity_types,
                include_deprecated=include_deprecated,
                limit=limit,
            )
            run.source_version = str(meta.get("source_version") or "")
            run.rejected_or_filtered = int(meta.get("filtered_count") or 0)

            records: list[KnowledgeRecord] = []
            for item in items:
                norm = normalize_item(item)
                comp, audit = compress_item(norm)
                acc.add(audit)
                records.append(
                    build_knowledge_record(
                        item=comp,
                        audit=audit,
                        kcp_version=self.settings.kcp_version,
                        run_id=run_id,
                        ingested_at=started_at,
                    )
                )

            run.parsed = len(records)
            if not dry_run and records:
                for start in range(0, len(records), batch_size):
                    summary = await self.store.upsert_records(
                        records[start : start + batch_size]
                    )
                    run.inserted += summary.inserted
                    run.updated += summary.updated
                    run.skipped += summary.skipped

            run.status = "completed"
        except Exception as exc:
            logger.exception("MITRE ingestion failed for %s", target_path)
            run.failed += 1
            run.errors.append(str(exc))
            run.status = "failed"
        finally:
            run.completed_at = datetime.now(timezone.utc)
            run.compression_summary = acc.summary()
            try:
                await self.store.save_ingestion_run(run)
            except Exception:
                logger.exception("Failed saving MITRE ingestion run status")

        return run

    async def ingest_cve(
        self,
        path: Path | None = None,
        years: list[int] | None = None,
        cve_ids: list[str] | None = None,
        delta_file: Path | None = None,
        include_rejected: bool = False,
        limit: int | None = None,
        dry_run: bool = False,
        batch_size: int = 50,
    ) -> IngestionRunStatus:
        """Stream CVE List v5 JSON files through KCP and upsert in batches."""
        target_path = Path(path) if path is not None else self.settings.cve_default_dir
        run_id = f"run-cve-{uuid.uuid4().hex[:10]}"
        started_at = datetime.now(timezone.utc)
        acc = _CompressionAccumulator()

        run = IngestionRunStatus(
            run_id=run_id,
            source_type="cve",
            status="running",
            started_at=started_at,
            source_path=str(target_path),
            dry_run=dry_run,
        )

        versions_seen: set[str] = set()
        batch: list[KnowledgeRecord] = []

        async def _flush() -> None:
            if not batch or dry_run:
                batch.clear()
                return
            summary = await self.store.upsert_records(list(batch))
            run.inserted += summary.inserted
            run.updated += summary.updated
            run.skipped += summary.skipped
            batch.clear()

        try:
            await self.store.initialize()
            if not target_path.exists():
                raise FileNotFoundError(f"CVE source path does not exist: {target_path}")

            for cve_file in iter_cve_files(
                path=target_path,
                years=years,
                cve_ids=cve_ids,
                delta_file=delta_file,
            ):
                if limit is not None and run.parsed >= limit:
                    break
                try:
                    parsed = parse_cve_file(cve_file, include_rejected=include_rejected)
                except CveParseError as exc:
                    run.failed += 1
                    if len(run.errors) < 50:
                        run.errors.append(str(exc))
                    continue
                except Exception as exc:
                    run.failed += 1
                    if len(run.errors) < 50:
                        run.errors.append(f"{cve_file}: {exc}")
                    continue

                if parsed is None:
                    run.rejected_or_filtered += 1
                    continue

                norm = normalize_item(parsed)
                comp, audit = compress_item(norm)
                acc.add(audit)
                versions_seen.add(comp.source_format)
                record = build_knowledge_record(
                    item=comp,
                    audit=audit,
                    kcp_version=self.settings.kcp_version,
                    run_id=run_id,
                    ingested_at=started_at,
                )
                run.parsed += 1
                batch.append(record)
                if len(batch) >= batch_size:
                    await _flush()

            await _flush()
            run.source_version = ",".join(sorted(versions_seen)) or "cve-json-5"
            if run.failed > 0:
                run.status = "completed_with_errors" if run.parsed > 0 else "failed"
            else:
                run.status = "completed"
        except Exception as exc:
            logger.exception("CVE ingestion failed for %s", target_path)
            run.failed += 1
            run.errors.append(str(exc))
            run.status = "failed"
        finally:
            run.completed_at = datetime.now(timezone.utc)
            run.compression_summary = acc.summary()
            try:
                await self.store.save_ingestion_run(run)
            except Exception:
                logger.exception("Failed saving CVE ingestion run status")

        return run

