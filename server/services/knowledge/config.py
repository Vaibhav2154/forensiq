"""Self-contained configuration for the ForensIQ knowledge pipeline."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


SERVER_ROOT = Path(__file__).resolve().parents[2]


class KnowledgeSettings(BaseSettings):
    """Configuration for KCP, OKF, and Cognee knowledge services.

    Deliberately decoupled from ``core.config`` so Developer 1 modules can run
    and be tested independently without MongoDB or cloud LLM credentials.
    """

    model_config = SettingsConfigDict(env_prefix="KNOWLEDGE_", extra="ignore")

    data_dir: Path = Field(default_factory=lambda: SERVER_ROOT / ".forensiq_knowledge")
    mitre_default_path: Path = Field(
        default_factory=lambda: (
            SERVER_ROOT
            / "frameworks"
            / "mitre-enterprise-attack"
            / "enterprise-attack-17.1.json"
        )
    )
    cve_default_dir: Path = Field(
        default_factory=lambda: SERVER_ROOT / "frameworks" / "cve"
    )

    store_backend: Literal["cognee", "memory"] = "cognee"
    cognee_vector_db: str = "lancedb"
    cognee_graph_db: str = "kuzu"
    cognee_embedding_provider: str = Field(
        default_factory=lambda: os.getenv("EMBEDDING_PROVIDER", "fastembed")
    )
    cognee_embedding_model: str = Field(
        default_factory=lambda: os.getenv(
            "EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5"
        )
    )
    cognee_embedding_dimensions: int = Field(
        default_factory=lambda: int(os.getenv("EMBEDDING_DIMENSIONS", "384"))
    )
    cognee_embedding_api_key: str | None = Field(
        default_factory=lambda: os.getenv("EMBEDDING_API_KEY")
    )
    cognee_llm_provider: str | None = Field(
        default_factory=lambda: os.getenv("LLM_PROVIDER")
    )
    cognee_llm_model: str | None = Field(
        default_factory=lambda: os.getenv("LLM_MODEL")
    )
    cognee_llm_api_key: str | None = Field(
        default_factory=lambda: os.getenv("LLM_API_KEY")
    )

    kcp_version: str = "1.0.0"
    dataset_name: str = "forensiq_okf"

