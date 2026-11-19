"""Unit tests for InvestigationSettings key resolution and GeminiAgentFactory."""

from __future__ import annotations

import asyncio

from services.investigation.config import ALL_AGENT_ROLES, InvestigationSettings
from services.investigation.llm_factory import GeminiAgentFactory
from services.investigation.models import EventAnalysisOutput


def test_per_agent_key_and_pool_and_fallback_precedence() -> None:
    settings = InvestigationSettings(
        _env_file=None,
        default_gemini_api_key="fallback-default-key",
        gemini_api_keys="pool-key-0, pool-key-1",
        gemini_api_key_event_analyst="dedicated-event-key",
        gemini_model="gemini-2.5-flash",
        gemini_model_orchestrator="gemini-2.5-pro",
    )

    # 1. Per-agent override takes top precedence
    ev_creds = settings.resolve_agent_credentials("event_analyst")
    assert ev_creds.api_key == "dedicated-event-key"
    assert ev_creds.key_slot_label == "env:event_analyst"
    assert ev_creds.model_name == "gemini-2.5-flash"

    # 2. Pool keys distribute deterministically across roles without overrides
    orch_creds = settings.resolve_agent_credentials("orchestrator")
    assert orch_creds.api_key == "pool-key-0"
    assert orch_creds.key_slot_label == "pool[0]"
    assert orch_creds.model_name == "gemini-2.5-pro"

    kn_creds = settings.resolve_agent_credentials("knowledge_enricher")
    assert kn_creds.api_key == "pool-key-0"
    assert kn_creds.key_slot_label == "pool[0]"

    seq_creds = settings.resolve_agent_credentials("sequence_analyst")
    assert seq_creds.api_key == "pool-key-1"
    assert seq_creds.key_slot_label == "pool[1]"

    # 3. Fallback candidates never include primary key and never duplicate
    fallbacks = settings.fallback_key_candidates("pool-key-0")
    fallback_keys = [k for k, _ in fallbacks]
    assert "pool-key-0" not in fallback_keys
    assert "pool-key-1" in fallback_keys
    assert "fallback-default-key" in fallback_keys

    # 4. Sanitized summary never leaks any secret API key
    summary = settings.sanitized_summary(lstm_connected=False)
    serialized = str(summary)
    assert "dedicated-event-key" not in serialized
    assert "pool-key-0" not in serialized
    assert "pool-key-1" not in serialized
    assert "fallback-default-key" not in serialized
    assert summary["lstm_connected"] is False
    assert set(summary["agents"].keys()) == set(ALL_AGENT_ROLES)


def test_default_fallback_key_when_pool_empty() -> None:
    settings = InvestigationSettings(
        _env_file=None,
        default_gemini_api_key="single-gemini-key",
        gemini_api_keys="",
    )
    for role in ALL_AGENT_ROLES:
        creds = settings.resolve_agent_credentials(role)
        assert creds.api_key == "single-gemini-key"
        assert creds.key_slot_label == "default:GEMINI_API_KEY"


def test_factory_custom_runner_returns_validated_schema() -> None:
    settings = InvestigationSettings(
        _env_file=None,
        default_gemini_api_key="test-key",
        gemini_model="gemini-2.5-flash",
    )

    async def fake_runner(role, schema, system_prompt, user_prompt):
        assert role == "event_analyst"
        assert schema is EventAnalysisOutput
        return {
            "observations": [],
            "iocs": [],
            "noteworthy_event_ids": ["evt-001"],
            "observed_behaviors": ["ssh failed login"],
            "entities_summary": ["account:alex"],
            "telemetry_gaps": ["exit code missing"],
        }

    factory = GeminiAgentFactory(settings=settings, custom_runner=fake_runner)
    result, model_name, slot = asyncio.run(
        factory.invoke_structured(
            role="event_analyst",
            schema=EventAnalysisOutput,
            system_prompt="sys",
            user_prompt="usr",
        )
    )
    assert isinstance(result, EventAnalysisOutput)
    assert result.noteworthy_event_ids == ["evt-001"]
    assert model_name == "gemini-2.5-flash"
    assert slot.startswith("mock:")
