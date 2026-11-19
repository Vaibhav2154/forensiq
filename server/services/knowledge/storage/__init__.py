"""Knowledge storage backends and provenance manifest."""

from .base import (
    KnowledgeStore,
    build_searchable_text,
    extract_source_id_candidates,
    lexical_score,
    matches_filters,
    node_uuid_for_concept,
    node_uuid_for_record,
)
from .cognee_adapter import CogneeKnowledgeStore
from .manifest_store import ManifestStore
from .memory_store import InMemoryKnowledgeStore

__all__ = [
    "CogneeKnowledgeStore",
    "InMemoryKnowledgeStore",
    "KnowledgeStore",
    "ManifestStore",
    "build_searchable_text",
    "extract_source_id_candidates",
    "lexical_score",
    "matches_filters",
    "node_uuid_for_concept",
    "node_uuid_for_record",
]
