"""Storage protocol and shared search/filter helpers for knowledge stores."""

from __future__ import annotations

import re
import uuid
from typing import Protocol, runtime_checkable

from contracts import KnowledgeRecord
from services.knowledge.models import (
    IngestionRunStatus,
    KnowledgeSearchHit,
    KnowledgeSearchQuery,
    KnowledgeStoreStats,
    UpsertSummary,
)


_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*", re.IGNORECASE)
_ID_CANDIDATE_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|(?:TA|DS)\d{4}|[TMGS]\d{4}(?:\.\d{3})?)\b",
    re.IGNORECASE,
)


def node_uuid_for_record(record_id: str) -> uuid.UUID:
    """Return the deterministic Cognee DataPoint UUID5 for an OKF record_id."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"forensiq:okf:{record_id}")


def node_uuid_for_concept(concept_id: str) -> uuid.UUID:
    """Return the deterministic Cognee DataPoint UUID5 for an external concept."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"forensiq:concept:{concept_id.strip().upper()}")


def build_searchable_text(record: KnowledgeRecord) -> str:
    """Create a dense, provenance-preserving text projection for indexing."""
    content = record.content
    parts: list[str] = [record.source_id]
    title = content.get("name") or content.get("title") or ""
    if title:
        parts.append(str(title))
    kind = content.get("kind") or ""
    if kind:
        parts.append(str(kind))
    tactics = content.get("tactics") or []
    if tactics:
        parts.append("tactics: " + ", ".join(str(t) for t in tactics))
    platforms = content.get("platforms") or []
    if platforms:
        parts.append("platforms: " + ", ".join(str(p) for p in platforms))
    products = content.get("affected_products_normalized") or []
    if products:
        parts.append("products: " + ", ".join(str(p) for p in products))
    cwes = content.get("cwe_ids") or []
    if cwes:
        parts.append("cwes: " + ", ".join(str(c) for c in cwes))
    severity = content.get("severity")
    if isinstance(severity, dict) and severity.get("base_score") is not None:
        parts.append(
            f"cvss {severity.get('base_score')} {severity.get('base_severity') or ''}".strip()
        )
    summary = content.get("summary") or ""
    if summary:
        parts.append(str(summary))
    desc = content.get("description") or ""
    if desc and desc != summary:
        parts.append(str(desc))
    detection = content.get("detection") or ""
    if detection:
        parts.append("detection: " + str(detection))
    return " | ".join(part for part in parts if part)


def extract_source_id_candidates(query_text: str) -> list[str]:
    """Extract canonical ATT&CK / CVE / CWE identifiers referenced in query text."""
    seen: set[str] = set()
    ids: list[str] = []
    for match in _ID_CANDIDATE_RE.findall(query_text or ""):
        upper = match.upper()
        if upper not in seen:
            seen.add(upper)
            ids.append(upper)
    return ids


def matches_filters(record: KnowledgeRecord, query: KnowledgeSearchQuery) -> bool:
    """Apply structured metadata filters cleanly without mutating records."""
    if query.source_type and record.source_type != query.source_type:
        return False

    content = record.content
    if query.kind and str(content.get("kind", "")).lower() != query.kind.lower():
        return False

    if query.tactic:
        target_tactic = query.tactic.strip().lower()
        tactics = [str(t).lower() for t in content.get("tactics", [])]
        tactic_ids = [str(t).lower() for t in content.get("tactic_ids", [])]
        if target_tactic not in tactics and target_tactic not in tactic_ids:
            return False

    if query.platform:
        target_platform = query.platform.strip().lower()
        platforms = [str(p).lower() for p in content.get("platforms", [])]
        if not any(target_platform in p for p in platforms):
            return False

    if query.min_cvss is not None:
        severity = content.get("severity")
        score = severity.get("base_score") if isinstance(severity, dict) else None
        if score is None or float(score) < query.min_cvss:
            return False

    return True


def lexical_score(
    query_text: str, record: KnowledgeRecord, searchable_text: str
) -> float:
    """Compute a deterministic [0.0, 1.0] lexical relevance score."""
    q_lower = (query_text or "").strip().lower()
    if not q_lower:
        return 0.0

    src_lower = record.source_id.lower()
    if q_lower == src_lower or q_lower == record.record_id.lower():
        return 1.0

    title = str(record.content.get("name") or record.content.get("title") or "").lower()
    if q_lower in title:
        return 0.92

    q_tokens = set(_TOKEN_RE.findall(q_lower))
    if not q_tokens:
        return 0.0

    doc_tokens = set(_TOKEN_RE.findall(searchable_text.lower()))
    title_tokens = set(_TOKEN_RE.findall(title))

    overlap = len(q_tokens & doc_tokens)
    if overlap == 0:
        return 0.0

    base = overlap / len(q_tokens)
    title_boost = 0.15 * (len(q_tokens & title_tokens) / len(q_tokens))
    phrase_boost = 0.1 if q_lower in searchable_text.lower() else 0.0
    id_boost = 0.25 if src_lower in q_tokens else 0.0

    return round(min(0.99, 0.7 * base + title_boost + phrase_boost + id_boost), 4)


@runtime_checkable
class KnowledgeStore(Protocol):
    """Storage abstraction implemented by CogneeKnowledgeStore and InMemoryKnowledgeStore."""

    async def initialize(self) -> None: ...

    async def close(self) -> None: ...

    async def upsert_records(self, records: list[KnowledgeRecord]) -> UpsertSummary: ...

    async def get_by_record_id(self, record_id: str) -> KnowledgeRecord | None: ...

    async def get_by_source_id(
        self, source_type: str, source_id: str
    ) -> KnowledgeRecord | None: ...

    async def get_related(self, record: KnowledgeRecord) -> list[KnowledgeRecord]: ...

    async def search(self, query: KnowledgeSearchQuery) -> list[KnowledgeSearchHit]: ...

    async def list_records(
        self,
        source_type: str | None = None,
        kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[KnowledgeRecord]: ...

    async def stats(self) -> KnowledgeStoreStats: ...

    async def save_ingestion_run(self, run: IngestionRunStatus) -> None: ...

    async def get_ingestion_run(self, run_id: str) -> IngestionRunStatus | None: ...

    async def list_ingestion_runs(self, limit: int = 20) -> list[IngestionRunStatus]: ...

