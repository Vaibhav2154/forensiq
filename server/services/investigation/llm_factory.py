"""Gemini LLM factory providing per-agent API keys and structured Pydantic outputs."""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any, Callable, TypeVar

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel

from services.investigation.config import AgentCredentials, AgentRole, InvestigationSettings


logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

StructuredRunner = Callable[[AgentRole, type[BaseModel], str, str], Any]


def _is_transient_gemini_error(exc: Exception) -> bool:
    """Return True when an exception looks like a rate-limit or transient API failure."""
    msg = str(exc).lower()
    transient_markers = (
        "429",
        "resourceexhausted",
        "resource_exhausted",
        "quota",
        "rate limit",
        "too many requests",
        "503",
        "unavailable",
        "deadline exceeded",
        "timeout",
    )
    return any(marker in msg for marker in transient_markers)


class GeminiAgentFactory:
    """Builds structured-output Gemini chat runnables keyed per sub-agent role."""

    def __init__(
        self,
        settings: InvestigationSettings | None = None,
        custom_runner: StructuredRunner | None = None,
    ) -> None:
        self.settings = settings or InvestigationSettings()
        self._custom_runner = custom_runner
        self._client_cache: dict[tuple[str, str, float], ChatGoogleGenerativeAI] = {}

    def get_credentials(self, role: AgentRole) -> AgentCredentials:
        return self.settings.resolve_agent_credentials(role)

    def _get_chat_model(self, api_key: str, model_name: str) -> ChatGoogleGenerativeAI:
        cache_key = (api_key, model_name, self.settings.temperature)
        client = self._client_cache.get(cache_key)
        if client is None:
            client = ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=api_key,
                temperature=self.settings.temperature,
                timeout=self.settings.request_timeout_seconds,
                max_retries=0,
            )
            self._client_cache[cache_key] = client
        return client

    async def invoke_structured(
        self,
        role: AgentRole,
        schema: type[T],
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[T, str, str]:
        """Invoke the configured Gemini sub-agent and validate its response against ``schema``.

        Returns:
            ``(validated_result, model_name, key_slot_label)``
        """
        creds = self.get_credentials(role)

        if self._custom_runner is not None:
            raw = self._custom_runner(role, schema, system_prompt, user_prompt)
            if inspect.isawaitable(raw):
                raw = await raw
            if isinstance(raw, schema):
                return raw, creds.model_name, f"mock:{creds.key_slot_label}"
            return schema.model_validate(raw), creds.model_name, f"mock:{creds.key_slot_label}"

        if not creds.api_key:
            raise RuntimeError(
                f"No Gemini API key configured for agent role {role!r}. "
                "Set GEMINI_API_KEY, INVESTIGATION_GEMINI_API_KEYS, or "
                f"INVESTIGATION_GEMINI_API_KEY_{role.upper()}."
            )

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]

        # Build attempt sequence: primary key + optional key-pool rotation candidates
        attempts: list[tuple[str, str]] = [(creds.api_key, creds.key_slot_label)]
        fallbacks = self.settings.fallback_key_candidates(creds.api_key)
        attempts.extend(fallbacks)

        max_total_attempts = max(1, self.settings.max_retries + 1)
        last_exc: Exception | None = None

        for attempt_idx in range(max_total_attempts):
            api_key, slot_label = attempts[attempt_idx % len(attempts)]
            try:
                llm = self._get_chat_model(api_key=api_key, model_name=creds.model_name)
                structured_llm = llm.with_structured_output(schema)
                response = await structured_llm.ainvoke(messages)
                if response is None:
                    raise ValueError(f"Empty structured response from Gemini for role {role!r}")
                if isinstance(response, schema):
                    return response, creds.model_name, slot_label
                return schema.model_validate(response), creds.model_name, slot_label
            except Exception as exc:
                last_exc = exc
                should_retry = attempt_idx + 1 < max_total_attempts and _is_transient_gemini_error(exc)
                if should_retry:
                    backoff = min(4.0, 0.75 * (2**attempt_idx))
                    logger.warning(
                        "Gemini transient error for role=%s slot=%s (attempt %d/%d): %s; retrying in %.2fs",
                        role,
                        slot_label,
                        attempt_idx + 1,
                        max_total_attempts,
                        exc,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise

        assert last_exc is not None
        raise last_exc
