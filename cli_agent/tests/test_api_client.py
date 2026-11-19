"""Checkpoint 3: API client headers, payloads, errors and retry safety."""

from __future__ import annotations

import asyncio

import pytest

from cli_agent.services.api_client import ApiClient
from cli_agent.services.errors import (
    ForbiddenError,
    MalformedResponseError,
    RateLimitError,
    ServerError,
    TransportError,
    UnauthorizedError,
    ValidationError,
)
from cli_agent.services.response_adapter import adapt_analysis

from .conftest import FakeTransport

BASE = "http://localhost:8000"


def _client(transport, token="abc123", **kwargs) -> ApiClient:
    return ApiClient(BASE, transport=transport, token_provider=lambda: token, **kwargs)


async def test_bearer_header_is_attached() -> None:
    transport = FakeTransport().queue({"ok": True})
    client = _client(transport)
    await client.request("GET", "/users/me")
    assert transport.last["headers"]["Authorization"] == "Bearer abc123"
    assert transport.last["url"] == f"{BASE}/users/me"


async def test_no_bearer_header_without_token() -> None:
    transport = FakeTransport().queue({"ok": True})
    client = _client(transport, token=None)
    await client.request("GET", "/users/me")
    assert "Authorization" not in transport.last["headers"]


async def test_login_request_is_unauthenticated_and_serialized() -> None:
    transport = FakeTransport().queue({"access_token": "t", "token_type": "bearer"})
    client = _client(transport)
    payload = await client.request(
        "POST",
        "/login",
        json_body={"username": "analyst", "password": "secret"},
        authenticated=False,
    )
    assert payload["access_token"] == "t"
    assert transport.last["json"] == {"username": "analyst", "password": "secret"}
    assert "Authorization" not in transport.last["headers"]


async def test_successful_json_response_is_parsed() -> None:
    transport = FakeTransport().queue({"summary": "ok", "matched_techniques": []})
    client = _client(transport)
    assert await client.request("POST", "/api/v1/analyze", json_body={"logs": "x"}) == {
        "summary": "ok",
        "matched_techniques": [],
    }


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, UnauthorizedError),
        (403, ForbiddenError),
        (422, ValidationError),
        (429, RateLimitError),
        (500, ServerError),
        (503, ServerError),
    ],
)
async def test_error_statuses_map_to_typed_errors(status: int, error: type[Exception]) -> None:
    transport = FakeTransport().queue((status, {"detail": "boom"}))
    client = _client(transport, max_retries=0)
    with pytest.raises(error) as excinfo:
        await client.request("POST", "/api/v1/analyze", json_body={"logs": "x"})
    assert excinfo.value.status == status
    assert "boom" in str(excinfo.value)


async def test_validation_detail_is_readable() -> None:
    transport = FakeTransport().queue((422, {"detail": [{"msg": "logs too long"}]}))
    client = _client(transport, max_retries=0)
    with pytest.raises(ValidationError) as excinfo:
        await client.request("POST", "/api/v1/analyze", json_body={"logs": "x"})
    assert "logs too long" in str(excinfo.value)


async def test_malformed_json_on_success_raises() -> None:
    transport = FakeTransport().queue((200, "<html>not json</html>"))
    client = _client(transport)
    with pytest.raises(MalformedResponseError):
        await client.request("GET", "/users/me")


async def test_empty_body_returns_none() -> None:
    transport = FakeTransport().queue((200, ""))
    client = _client(transport)
    assert await client.request("POST", "/api/v1/monitoring/sessions/1/stop") is None


async def test_timeout_becomes_transport_error() -> None:
    transport = FakeTransport(error=asyncio.TimeoutError())
    client = _client(transport, max_retries=0)
    with pytest.raises(TransportError):
        await client.request("POST", "/api/v1/analyze", json_body={"logs": "x"})


async def test_connection_failure_becomes_transport_error() -> None:
    transport = FakeTransport(error=ConnectionRefusedError("refused"))
    client = _client(transport, max_retries=0)
    with pytest.raises(TransportError):
        await client.request("GET", "/users/me")


async def test_get_is_retried_on_retryable_status() -> None:
    transport = FakeTransport().queue((503, {"detail": "starting"}), {"status": "ok"})
    client = _client(transport, max_retries=1)
    assert await client.request("GET", "/health") == {"status": "ok"}
    assert len(transport.requests) == 2


async def test_post_is_never_retried() -> None:
    """A retried POST after an ambiguous failure could duplicate analysis."""
    transport = FakeTransport().queue((503, {"detail": "unavailable"}))
    client = _client(transport, max_retries=2)
    with pytest.raises(ServerError):
        await client.request("POST", "/api/v1/analyze", json_body={"logs": "x"})
    assert len(transport.requests) == 1


async def test_post_timeout_is_not_retried() -> None:
    transport = FakeTransport(error=asyncio.TimeoutError())
    client = _client(transport, max_retries=2)
    with pytest.raises(TransportError):
        await client.request("POST", "/api/v1/analyze", json_body={"logs": "x"})
    assert len(transport.requests) == 1


async def test_get_gives_up_after_bounded_retries() -> None:
    transport = FakeTransport().queue((503, {}), (503, {}), (503, {}))
    client = _client(transport, max_retries=2)
    with pytest.raises(ServerError):
        await client.request("GET", "/health")
    assert len(transport.requests) == 3


async def test_close_delegates_to_transport() -> None:
    transport = FakeTransport()
    client = _client(transport)
    await client.close()
    assert transport.closed is True


async def test_base_url_trailing_slash_is_normalized() -> None:
    transport = FakeTransport().queue({"ok": True})
    client = ApiClient("http://localhost:8000/", transport=transport)
    await client.request("GET", "/health")
    assert transport.last["url"] == "http://localhost:8000/health"


async def test_analyze_payload_matches_backend_model() -> None:
    """The request body keeps the legacy keys the current endpoint accepts."""
    transport = FakeTransport().queue(
        {"summary": "s", "matched_techniques": [], "processing_time_ms": 1.5}
    )
    client = _client(transport)
    response = await client.request(
        "POST",
        "/api/v1/analyze",
        json_body={"logs": "line", "enhance_with_ai": True, "max_results": 5},
    )
    sent = transport.last["json"]
    assert set(sent) == {"logs", "enhance_with_ai", "max_results"}
    view = adapt_analysis(response)
    assert view.summary == "s"
    assert view.processing_time_ms == 1.5
