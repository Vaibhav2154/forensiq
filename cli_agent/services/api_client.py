"""HTTP access to the ForensIQ backend.

The transport is a plain async callable so tests can supply a fake and the
real implementation can stay a thin ``aiohttp`` wrapper:

    transport(method, url, headers, json_body, timeout) -> HttpResponse

Retry policy (deliberately conservative):

* only GET/HEAD are retried automatically;
* only on 502/503/504 or a transport failure;
* at most ``max_retries`` extra attempts with a short capped backoff.

``POST`` is never retried blindly: ``/api/v1/analyze`` is not idempotent and a
retry after an ambiguous timeout could duplicate analysis work.
"""

from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Mapping

from .errors import MalformedResponseError, TransportError, error_from_status

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_POST_RETRY_ATTEMPTS = 3
# GET/HEAD keep the conservative Phase 3 set.
RETRYABLE_STATUS = frozenset({502, 503, 504})
# An explicitly retryable POST (log-batch delivery) additionally tolerates
# throttling and ambiguous upstream failures.  HTTP 500 is *not* retried: the
# backend already answered, and the same payload is likely to fail again.
TRANSIENT_POST_STATUS = frozenset({408, 425, 429, 502, 503, 504})
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD"})
MAX_RETRY_DELAY = 10.0


@dataclass(frozen=True)
class HttpResponse:
    """Minimal HTTP response shape used by the transport boundary."""

    status: int
    text: str
    headers: Mapping[str, str] = None  # type: ignore[assignment]

    def header(self, name: str) -> str | None:
        if not self.headers:
            return None
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


Transport = Callable[
    [str, str, Mapping[str, str], Any, float], Awaitable[HttpResponse]
]


class AiohttpTransport:
    """Default transport backed by a lazily created ``aiohttp`` session."""

    def __init__(self) -> None:
        self._session: Any = None
        self._loop: Any = None

    async def _get_session(self) -> Any:
        loop = asyncio.get_running_loop()
        if self._session is None or self._session.closed or self._loop is not loop:
            import aiohttp  # imported lazily: keeps package import dependency-free

            self._session = aiohttp.ClientSession()
            self._loop = loop
        return self._session

    async def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json_body: Any,
        timeout: float,
    ) -> HttpResponse:
        import aiohttp

        session = await self._get_session()
        try:
            async with session.request(
                method,
                url,
                headers=dict(headers),
                json=json_body,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                return HttpResponse(status=response.status, text=await response.text())
        except asyncio.TimeoutError as exc:
            raise TransportError(f"timeout after {timeout:g}s") from exc
        except aiohttp.ClientError as exc:
            raise TransportError(f"connection failed: {type(exc).__name__}") from exc
        except OSError as exc:
            raise TransportError(f"connection failed: {type(exc).__name__}") from exc

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None
        self._loop = None


class ApiClient:
    """JSON client for the existing ForensIQ routes (no invented endpoints)."""

    def __init__(
        self,
        base_url: str,
        *,
        transport: Transport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        token_provider: Callable[[], str | None] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        if not base_url or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL")
        self.base_url = base_url.strip().rstrip("/")
        self.transport: Transport = transport or AiohttpTransport()
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self._token_provider = token_provider
        self._sleep = sleep or asyncio.sleep

    # -- helpers ---------------------------------------------------------
    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _headers(self, authenticated: bool) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if authenticated and self._token_provider is not None:
            token = self._token_provider()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def _backoff(self, attempt: int) -> float:
        """Capped exponential backoff with jitter (never a tight loop)."""
        base = min(0.5 * (2**attempt), MAX_RETRY_DELAY)
        return base * random.uniform(0.5, 1.0)

    @staticmethod
    def _retry_after(response: HttpResponse) -> float | None:
        """Parse ``Retry-After`` seconds or HTTP-date, capped for UI sanity."""
        value = response.header("Retry-After")
        if not value:
            return None
        value = value.strip()
        try:
            seconds = float(value)
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return None
            import time as _time

            seconds = when.timestamp() - _time.time()
        if seconds < 0:
            return 0.0
        return min(seconds, MAX_RETRY_DELAY)

    # -- request core ----------------------------------------------------
    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        authenticated: bool = True,
        idempotent: bool | None = None,
        retry_transient: bool = False,
        retry_attempts: int | None = None,
    ) -> Any:
        """Perform one request.

        ``retry_transient`` opts a non-idempotent call (batch delivery) into
        bounded retries for throttling and ambiguous upstream failures.  The
        caller accepts that a retry after an ambiguous timeout may duplicate
        analysis work; the backend has no idempotency key.
        """
        method = method.upper()
        if idempotent is None:
            idempotent = method in IDEMPOTENT_METHODS
        if idempotent:
            attempts = self.max_retries + 1
            retry_status = RETRYABLE_STATUS
        elif retry_transient:
            attempts = max(1, int(retry_attempts or DEFAULT_POST_RETRY_ATTEMPTS))
            retry_status = TRANSIENT_POST_STATUS
        else:
            attempts = 1
            retry_status = frozenset()

        last_error: TransportError | None = None

        for attempt in range(attempts):
            try:
                response = await self.transport(
                    method,
                    self.url(path),
                    self._headers(authenticated),
                    json_body,
                    self.timeout,
                )
            except (TransportError, asyncio.TimeoutError, OSError) as exc:
                last_error = (
                    exc if isinstance(exc, TransportError) else TransportError(str(exc))
                )
                if retry_transient and attempt + 1 < attempts:
                    await self._sleep(self._backoff(attempt))
                    continue
                if idempotent and attempt + 1 < attempts:
                    await self._sleep(self._backoff(attempt))
                    continue
                raise last_error

            if response.status in retry_status and attempt + 1 < attempts:
                delay = self._retry_after(response)
                await self._sleep(delay if delay is not None else self._backoff(attempt))
                continue
            return self._handle(path, response)

        raise last_error or TransportError("request failed")  # pragma: no cover

    def _handle(self, path: str, response: HttpResponse) -> Any:
        payload = _try_json(response.text)

        if response.status >= 400:
            detail = _error_detail(payload) or (response.text or "").strip()[:200] or None
            error = error_from_status(response.status, detail=detail, payload=payload)
            error.retry_after = self._retry_after(response)
            raise error

        if payload is _UNPARSEABLE:
            # A 2xx with a body we cannot read is a protocol violation, but an
            # empty body is a legitimate "no content" answer.
            if (response.text or "").strip():
                raise MalformedResponseError(
                    f"response from {path} was not valid JSON"
                )
            return None
        return payload

    # -- lifecycle -------------------------------------------------------
    async def close(self) -> None:
        closer = getattr(self.transport, "close", None)
        if closer is not None:
            await closer()


_UNPARSEABLE = object()


def _try_json(text: str | None) -> Any:
    if text is None or not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError:
        return _UNPARSEABLE


def _error_detail(payload: Any) -> str | None:
    if isinstance(payload, dict):
        for key in ("detail", "error", "message"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:200]
        detail = payload.get("detail")
        if isinstance(detail, list) and detail:
            # FastAPI validation errors: keep it short and human readable.
            first = detail[0]
            if isinstance(first, dict) and first.get("msg"):
                return str(first["msg"])[:200]
    return None
