"""Sequence workstream FastAPI endpoints and contract boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from contracts import NormalizedEvent, SequenceCue
from services.sequence import BatchResult, SequenceEngine, SequenceError, StateCorruptionError

router = APIRouter(prefix="/api/v1/sequence", tags=["Sequential Context"])

_sequence_engine: SequenceEngine | None = None


class SequenceEvaluateRequest(BaseModel):
    """Batch of normalized events submitted for sequential LSTM scoring."""

    events: list[NormalizedEvent] = Field(default_factory=list)


class SequenceEvaluateResponse(BaseModel):
    """Structured response mirroring :class:`BatchResult`."""

    cues: list[SequenceCue] = Field(default_factory=list)
    processed_event_ids: list[str] = Field(default_factory=list)
    skipped_event_ids: list[str] = Field(default_factory=list)
    duplicate_event_ids: list[str] = Field(default_factory=list)
    expired_scope_keys: list[str] = Field(default_factory=list)
    reset_scope_keys: list[str] = Field(default_factory=list)
    replay_incomplete_scope_keys: list[str] = Field(default_factory=list)


def set_sequence_engine(engine: SequenceEngine | None) -> None:
    """Inject the configured sequence engine (application startup or tests)."""
    global _sequence_engine
    _sequence_engine = engine


def get_sequence_engine() -> SequenceEngine:
    """Return the injected engine.

    Raises:
        RuntimeError: when no engine has been injected.
    """
    if _sequence_engine is None:
        raise RuntimeError(
            "No SequenceEngine is configured. Inject an engine built from approved "
            "values with routers.sequence.set_sequence_engine() during startup."
        )
    return _sequence_engine


def _require_sequence_engine() -> SequenceEngine:
    try:
        return get_sequence_engine()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def process_normalized_events(
    events: Sequence[NormalizedEvent], *, engine: SequenceEngine | None = None
) -> BatchResult:
    """Process a batch of ``NormalizedEvent`` objects for an optional engine."""
    active = engine if engine is not None else get_sequence_engine()
    return active.process_batch(list(events))


def sequence_cues(
    events: Sequence[NormalizedEvent], *, engine: SequenceEngine | None = None
) -> list[SequenceCue]:
    """Return only the cues produced for a batch."""
    return process_normalized_events(events, engine=engine).cues


@router.get("/status", response_model=dict[str, Any])
async def get_sequence_status(
    engine: SequenceEngine = Depends(_require_sequence_engine),
) -> dict[str, Any]:
    """Return sequence LSTM engine configuration and active scope count."""
    scope_keys = await asyncio.to_thread(lambda: list(engine.store.scope_keys()))
    return {
        "lstm_ready": True,
        "model_version": engine.config.model_version,
        "window_events": engine.config.window_events,
        "threshold": engine.config.threshold,
        "state_ttl_seconds": engine.config.state_ttl_seconds,
        "store_backend": type(engine.store).__name__,
        "active_scopes_count": len(scope_keys),
    }


@router.post("/evaluate", response_model=SequenceEvaluateResponse)
async def evaluate_sequence_events(
    payload: SequenceEvaluateRequest,
    engine: SequenceEngine = Depends(_require_sequence_engine),
) -> SequenceEvaluateResponse:
    """Evaluate normalized events with persistent per-scope LSTM context."""
    try:
        batch_result = await asyncio.to_thread(
            process_normalized_events, payload.events, engine=engine
        )
    except SequenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return SequenceEvaluateResponse(
        cues=batch_result.cues,
        processed_event_ids=batch_result.processed_event_ids,
        skipped_event_ids=batch_result.skipped_event_ids,
        duplicate_event_ids=batch_result.duplicate_event_ids,
        expired_scope_keys=batch_result.expired_scope_keys,
        reset_scope_keys=batch_result.reset_scope_keys,
        replay_incomplete_scope_keys=batch_result.replay_incomplete_scope_keys,
    )


@router.get("/scopes/{scope_key:path}", response_model=dict[str, Any])
async def inspect_scope_state(
    scope_key: str,
    engine: SequenceEngine = Depends(_require_sequence_engine),
) -> dict[str, Any]:
    """Inspect retained bounded event window metadata for a scope."""
    try:
        state = await asyncio.to_thread(engine.state_for, scope_key)
    except StateCorruptionError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if state is None:
        raise HTTPException(status_code=404, detail=f"Scope {scope_key!r} not found")

    latest_score = state.entries[-1].score if state.entries else None
    return {
        "scope_key": state.scope_key,
        "model_version": state.model_version,
        "window_size": state.window_size,
        "event_ids": state.event_ids,
        "last_event_time": (
            state.last_event_time.isoformat() if state.last_event_time is not None else None
        ),
        "trimmed": state.trimmed,
        "replay_incomplete": state.replay_incomplete,
        "reset_reason": state.reset_reason,
        "evidence_references": state.evidence_references,
        "latest_score": latest_score,
    }


@router.post("/expire", response_model=dict[str, Any])
async def expire_stale_scopes(
    engine: SequenceEngine = Depends(_require_sequence_engine),
) -> dict[str, Any]:
    """Sweep and expire inactive scopes past ``state_ttl_seconds``."""
    expired = await asyncio.to_thread(engine.expire, datetime.now(timezone.utc))
    return {"expired_scope_keys": expired}


__all__ = [
    "SequenceEvaluateRequest",
    "SequenceEvaluateResponse",
    "get_sequence_engine",
    "process_normalized_events",
    "router",
    "sequence_cues",
    "set_sequence_engine",
]
