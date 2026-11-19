"""Self-contained configuration for the ForensIQ multi-agent investigation system."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


SERVER_ROOT = Path(__file__).resolve().parents[2]
_ENV_FILE = SERVER_ROOT / ".env"
if _ENV_FILE.is_file():
    load_dotenv(_ENV_FILE, override=False)


AgentRole = Literal[
    "orchestrator",
    "event_analyst",
    "knowledge_enricher",
    "sequence_analyst",
    "correlation_timeline",
    "attack_path_analyst",
    "recommendation_drafter",
]

ALL_AGENT_ROLES: tuple[AgentRole, ...] = (
    "orchestrator",
    "event_analyst",
    "knowledge_enricher",
    "sequence_analyst",
    "correlation_timeline",
    "attack_path_analyst",
    "recommendation_drafter",
)

_ROLE_KEY_ATTR: dict[AgentRole, str] = {
    "orchestrator": "gemini_api_key_orchestrator",
    "event_analyst": "gemini_api_key_event_analyst",
    "knowledge_enricher": "gemini_api_key_knowledge_enricher",
    "sequence_analyst": "gemini_api_key_sequence_analyst",
    "correlation_timeline": "gemini_api_key_correlation_timeline",
    "attack_path_analyst": "gemini_api_key_attack_path",
    "recommendation_drafter": "gemini_api_key_recommendation",
}

_ROLE_MODEL_ATTR: dict[AgentRole, str] = {
    "orchestrator": "gemini_model_orchestrator",
    "event_analyst": "gemini_model_event_analyst",
    "knowledge_enricher": "gemini_model_knowledge_enricher",
    "sequence_analyst": "gemini_model_sequence_analyst",
    "correlation_timeline": "gemini_model_correlation_timeline",
    "attack_path_analyst": "gemini_model_attack_path",
    "recommendation_drafter": "gemini_model_recommendation",
}


@dataclass(frozen=True)
class AgentCredentials:
    """Resolved non-secret metadata + API key for a single sub-agent role."""

    role: AgentRole
    api_key: str
    model_name: str
    key_slot_label: str


class InvestigationSettings(BaseSettings):
    """Configuration for the LangGraph multi-agent investigation orchestrator.

    Deliberately decoupled from ``core.config`` so Developer 4 modules can run
    and be tested independently without MongoDB.
    """

    model_config = SettingsConfigDict(
        env_prefix="INVESTIGATION_",
        env_file=str(_ENV_FILE) if _ENV_FILE.is_file() else None,
        extra="ignore",
    )

    # Global fallback key (reads GEMINI_API_KEY when INVESTIGATION_DEFAULT_GEMINI_API_KEY is unset)
    default_gemini_api_key: str = Field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "")
    )
    # Comma-separated pool of Gemini API keys distributed across sub-agents
    gemini_api_keys: str = Field(default="")

    # Per-agent Gemini API key overrides
    gemini_api_key_orchestrator: str | None = Field(default=None)
    gemini_api_key_event_analyst: str | None = Field(default=None)
    gemini_api_key_knowledge_enricher: str | None = Field(default=None)
    gemini_api_key_sequence_analyst: str | None = Field(default=None)
    gemini_api_key_correlation_timeline: str | None = Field(default=None)
    gemini_api_key_attack_path: str | None = Field(default=None)
    gemini_api_key_recommendation: str | None = Field(default=None)

    # Model configuration (default gemini-2.5-flash across all roles)
    gemini_model: str = Field(default="gemini-3.1-flash-lite")
    gemini_model_orchestrator: str | None = Field(default=None)
    gemini_model_event_analyst: str | None = Field(default=None)
    gemini_model_knowledge_enricher: str | None = Field(default=None)
    gemini_model_sequence_analyst: str | None = Field(default=None)
    gemini_model_correlation_timeline: str | None = Field(default=None)
    gemini_model_attack_path: str | None = Field(default=None)
    gemini_model_recommendation: str | None = Field(default=None)

    # Workflow & generation parameters
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    max_refinement_rounds: int = Field(default=1, ge=0, le=3)
    max_followup_queries: int = Field(default=4, ge=0, le=10)
    top_k_knowledge: int = Field(default=6, ge=1, le=20)
    request_timeout_seconds: float = Field(default=45.0, ge=5.0, le=180.0)
    max_retries: int = Field(default=2, ge=0, le=5)

    def parsed_key_pool(self) -> list[str]:
        """Return deduplicated non-empty keys from ``INVESTIGATION_GEMINI_API_KEYS``."""
        seen: set[str] = set()
        keys: list[str] = []
        for raw in self.gemini_api_keys.split(","):
            cleaned = raw.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                keys.append(cleaned)
        return keys

    def resolve_agent_credentials(self, role: AgentRole) -> AgentCredentials:
        """Resolve API key, model name, and safe slot label for ``role``.

        Precedence:
        1. Per-agent env var (``INVESTIGATION_GEMINI_API_KEY_<ROLE>``)
        2. Key pool (``INVESTIGATION_GEMINI_API_KEYS``), indexed deterministically by role
        3. Fallback to ``GEMINI_API_KEY`` (``default_gemini_api_key``)
        """
        model_override = getattr(self, _ROLE_MODEL_ATTR[role], None)
        model_name = (model_override or self.gemini_model).strip() or "gemini-2.5-flash"

        per_agent_key = getattr(self, _ROLE_KEY_ATTR[role], None)
        if per_agent_key and per_agent_key.strip():
            return AgentCredentials(
                role=role,
                api_key=per_agent_key.strip(),
                model_name=model_name,
                key_slot_label=f"env:{role}",
            )

        pool = self.parsed_key_pool()
        if pool:
            idx = ALL_AGENT_ROLES.index(role) % len(pool)
            return AgentCredentials(
                role=role,
                api_key=pool[idx],
                model_name=model_name,
                key_slot_label=f"pool[{idx}]",
            )

        fallback_key = (self.default_gemini_api_key or os.getenv("GEMINI_API_KEY", "")).strip()
        return AgentCredentials(
            role=role,
            api_key=fallback_key,
            model_name=model_name,
            key_slot_label="default:GEMINI_API_KEY" if fallback_key else "unconfigured",
        )

    def fallback_key_candidates(self, primary_key: str) -> list[tuple[str, str]]:
        """Return alternative ``(api_key, key_slot_label)`` pairs for transient retry rotation."""
        candidates: list[tuple[str, str]] = []
        seen: set[str] = {primary_key} if primary_key else set()
        for idx, key in enumerate(self.parsed_key_pool()):
            if key not in seen:
                seen.add(key)
                candidates.append((key, f"pool[{idx}]"))
        fallback_key = (self.default_gemini_api_key or os.getenv("GEMINI_API_KEY", "")).strip()
        if fallback_key and fallback_key not in seen:
            candidates.append((fallback_key, "default:GEMINI_API_KEY"))
        return candidates

    def sanitized_summary(self, lstm_connected: bool = False) -> dict[str, Any]:
        """Return a safe, secret-free configuration snapshot for diagnostics/API."""
        agents: dict[str, dict[str, Any]] = {}
        for role in ALL_AGENT_ROLES:
            creds = self.resolve_agent_credentials(role)
            agents[role] = {
                "model": creds.model_name,
                "key_slot": creds.key_slot_label,
                "key_configured": bool(creds.api_key),
            }
        return {
            "default_model": self.gemini_model,
            "key_pool_size": len(self.parsed_key_pool()),
            "max_refinement_rounds": self.max_refinement_rounds,
            "max_followup_queries": self.max_followup_queries,
            "top_k_knowledge": self.top_k_knowledge,
            "temperature": self.temperature,
            "lstm_connected": lstm_connected,
            "agents": agents,
        }
