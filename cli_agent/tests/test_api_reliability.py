"""Bounded, cancellable retries and HTTP failure classification."""

from __future__ import annotations

import asyncio

import pytest

from cli_agent.services.api_client import ApiClient
from cli_agent.services.errors import (
    RateLimitError,
    ServerError,
    TransportError,
    ValidationError,
)

from .conftest import FakeTransport

BASE = "http://localhost:8000"


async def _no_sleep(_seconds: float) -> None:
    return None


def client(transport: FakeTransport, **kwargs) -> ApiClient:
    return ApiClient(
        BASE,
        transport=transport,
        token_provider=lambda: "token",
        sleep=_no_sleep,
        **kwargs,
    )


async def test_retry_after_header_controls_the_delay() -> None:
    delays: list[float] = []

    async def record_sleep(seconds: float) -> None:
        delays.append(seconds)

    transport = FakeTransport().queue(
        (429, {"detail": "slow down"}, {"Retry-After": "2"}),
        {"ok": True},
    )
    api = ApiClient(
        BASE,
        transport=transport,
        token_provider=lambda: "token",
        sleep=record_sleep,
    )
    assert await api.request("POST", "/api/v1/analyze", json_body={}, retry_transient=True) == {"ok": True}
    assert len(transport.requests) == 2
    assert delays and delays[0] == pytest.approx(2.0)


async def test_retry_after_is_capped() -> None:
    delays: list[float] = []

    async def record_sleep(seconds: float) -> None:
        delays.append(seconds)

    transport = FakeTransport().queue(
        (503, {}, {"Retry-After": "3600"}),
        {"ok": True},
    )
    api = ApiClient(BASE, transport=transport, sleep=record_sleep)
    await api.request("POST", "/api/v1/analyze", json_body={}, retry_transient=True)
    assert delays[0] <= 10.0


async def test_transient_post_failure_is_retried_then_succeeds() -> None:
    transport = FakeTransport().queue(
        (503, {"detail": "starting"}),
        {"summary": "ok", "matched_techniques": []},
    )
    api = client(transport)
    payload = await api.request(
        "POST", "/api/v1/analyze", json_body={"logs": "x"}, retry_transient=True
    )
    assert payload["summary"] == "ok"
    assert len(transport.requests) == 2


async def test_transport_failure_is_retried_for_transient_posts() -> None:
    transport = FakeTransport([TransportError("connection refused"), {"ok": True}])
    api = client(transport)
    assert await api.request("POST", "/x", json_body={}, retry_transient=True) == {"ok": True}
    assert len(transport.requests) == 2


async def test_non_retryable_validation_is_not_retried() -> None:
    transport = FakeTransport().queue((422, {"detail": "logs too long"}))
    api = client(transport)
    with pytest.raises(ValidationError):
        await api.request("POST", "/api/v1/analyze", json_body={}, retry_transient=True)
    assert len(transport.requests) == 1


async def test_unauthorized_is_never_retried() -> None:
    transport = FakeTransport().queue((401, {"detail": "expired"}))
    api = client(transport)
    with pytest.raises(Exception):
        await api.request("POST", "/api/v1/analyze", json_body={}, retry_transient=True)
    assert len(transport.requests) == 1


async def test_retries_are_bounded() -> None:
    transport = FakeTransport().queue(
        (503, {}),
        (503, {}),
        (503, {}),
        (503, {}),
        (503, {}),
    )
    api = client(transport)
    with pytest.raises(ServerError):
        await api.request(
            "POST", "/api/v1/analyze", json_body={}, retry_transient=True, retry_attempts=3
        )
    assert len(transport.requests) == 3


async def test_ratelimit_error_carries_retry_after() -> None:
    transport = FakeTransport().queue((429, {"detail": "slow"}, {"Retry-After": "4"}))
    api = client(transport, max_retries=0)
    with pytest.raises(RateLimitError) as excinfo:
        await api.request("GET", "/health")
    assert excinfo.value.retry_after == 4.0


async def test_backoff_is_cancellable() -> None:
    blocked = asyncio.Event()

    async def hanging_sleep(_seconds: float) -> None:
        # Sleep until cancelled; the event is never set.
        await blocked.wait()

    transport = FakeTransport(error=TransportError("down"))
    api = ApiClient(BASE, transport=transport, sleep=hanging_sleep)
    task = asyncio.create_task(
        api.request("POST", "/x", json_body={}, retry_transient=True, retry_attempts=3)
    )
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(transport.requests) == 1, "a cancelled retry must stop sending"


async def test_get_retry_still_uses_conservative_statuses() -> None:
    transport = FakeTransport().queue((500, {}), {"ok": True})
    api = client(transport, max_retries=2)
    with pytest.raises(ServerError):
        await api.request("GET", "/health")
    assert len(transport.requests) == 1, "500 is not retried"
