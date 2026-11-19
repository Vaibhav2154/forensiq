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
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from .errors import MalformedResponseError, TransportError, error_from_status

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
RETRYABLE_STATUS = frozenset({502, 503, 504})
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD"})


@dataclass(frozen=True)
class HttpResponse:
    """Minimal HTTP response shape used by the transport boundary."""

    status: int
    text: str


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
    ) -> None:
        if not base_url or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL")
        self.base_url = base_url.strip().rstrip("/")
        self.transport: Transport = transport or AiohttpTransport()
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self._token_provider = token_provider

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
        return min(0.25 * (2**attempt), 2.0)

    # -- request core ----------------------------------------------------
    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        authenticated: bool = True,
        idempotent: bool | None = None,
    ) -> Any:
        method = method.upper()
        if idempotent is None:
            idempotent = method in IDEMPOTENT_METHODS
        attempts = self.max_retries + 1 if idempotent else 1
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
                if attempt + 1 < attempts:
                    await asyncio.sleep(self._backoff(attempt))
                    continue
                raise last_error

            if response.status in RETRYABLE_STATUS and attempt + 1 < attempts:
                await asyncio.sleep(self._backoff(attempt))
                continue
            return self._handle(path, response)

        raise last_error or TransportError("request failed")  # pragma: no cover

    def _handle(self, path: str, response: HttpResponse) -> Any:
        payload = _try_json(response.text)

        if response.status >= 400:
            detail = _error_detail(payload) or (response.text or "").strip()[:200] or None
            raise error_from_status(response.status, detail=detail, payload=payload)

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
