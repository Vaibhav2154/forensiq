"""Typed errors raised by the ForensIQ client service layer.

Rules enforced throughout the client layer:

* messages never contain access tokens or passwords;
* backend error bodies are surfaced as short ``detail`` text, not dumped raw;
* "no data" is never modelled as an error (see ``response_adapter``).
"""

from __future__ import annotations

from typing import Any


class ForensIQError(Exception):
    """Base class for every client-layer failure."""


class ConfigurationError(ForensIQError):
    """Configuration is missing, unreadable, or out of range."""


class AuthError(ForensIQError):
    """Authentication failed, or an authenticated session is required."""

    def __init__(self, message: str, *, reauthentication_required: bool = False) -> None:
        super().__init__(message)
        self.reauthentication_required = reauthentication_required


class ApiError(ForensIQError):
    """The backend was reached and answered with an error status."""

    def __init__(
        self,
        status: int,
        message: str,
        *,
        detail: str | None = None,
        payload: Any = None,
    ) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.detail = detail
        self.payload = payload
        # Populated for 429/503 responses that carry a Retry-After header.
        self.retry_after: float | None = None


class UnauthorizedError(ApiError):
    """HTTP 401 - the token is missing, expired, or invalid."""


class ForbiddenError(ApiError):
    """HTTP 403 - authenticated but not permitted."""


class ValidationError(ApiError):
    """HTTP 422 - the backend rejected the request body."""


class RateLimitError(ApiError):
    """HTTP 429 - the backend asked us to slow down."""


class ServerError(ApiError):
    """HTTP 5xx - the backend failed."""


class StatePersistenceError(ForensIQError):
    """A durable checkpoint or queue write failed."""


class TransportError(ForensIQError):
    """No usable HTTP response (timeout, connection refused, DNS, TLS)."""


class MalformedResponseError(ForensIQError):
    """The backend answered with a body that could not be interpreted."""


def error_from_status(
    status: int,
    *,
    detail: str | None = None,
    payload: Any = None,
) -> ApiError:
    """Map an HTTP status onto the most specific error class."""
    message = detail or _default_message(status)
    if status == 401:
        return UnauthorizedError(status, message, detail=detail, payload=payload)
    if status == 403:
        return ForbiddenError(status, message, detail=detail, payload=payload)
    if status == 422:
        return ValidationError(status, message, detail=detail, payload=payload)
    if status == 429:
        return RateLimitError(status, message, detail=detail, payload=payload)
    if 500 <= status <= 599:
        return ServerError(status, message, detail=detail, payload=payload)
    return ApiError(status, message, detail=detail, payload=payload)


def _default_message(status: int) -> str:
    return {
        400: "bad request",
        401: "authentication required or token expired",
        403: "access denied",
        404: "not found",
        409: "conflict",
        422: "validation error",
        429: "rate limited",
    }.get(status, "unexpected response")
