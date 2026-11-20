"""Shared fakes and helpers.

Everything here is offline: a fake transport replaces HTTP, a fake extractor
replaces system log access, and every path is a ``tmp_path``.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import pytest

from cli_agent.services.api_client import HttpResponse


class FakeTransport:
    """Queued-response HTTP transport with request capture."""

    def __init__(
        self,
        responses: list[Any] | None = None,
        *,
        error: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.responses = list(responses or [])
        self.error = error
        self.delay = delay
        self.requests: list[dict[str, Any]] = []
        self.closed = False

    def queue(self, *responses: Any) -> "FakeTransport":
        self.responses.extend(responses)
        return self

    async def __call__(
        self,
        method: str,
        url: str,
        headers,
        json_body,
        timeout: float,
    ) -> HttpResponse:
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "json": json_body,
                "timeout": timeout,
            }
        )
        if self.delay:
            import asyncio

            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        if not self.responses:
            raise AssertionError(f"unexpected request: {method} {url}")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        headers = None
        if isinstance(item, tuple):
            if len(item) == 3:
                status, body, headers = item
            else:
                status, body = item
        else:
            status, body = 200, item
        text = body if isinstance(body, str) else json.dumps(body)
        return HttpResponse(status=status, text=text, headers=headers)

    async def close(self) -> None:
        self.closed = True

    @property
    def last(self) -> dict[str, Any]:
        return self.requests[-1]


class FakeExtractor:
    """Stand-in for ``legacy.dynamic_log_extractor.DynamicLogExtractor``."""

    def __init__(
        self,
        batches: list[dict[str, list[dict[str, Any]]]] | None = None,
        *,
        sources: list[dict[str, Any]] | None = None,
        error: Exception | None = None,
        format_error: Exception | None = None,
    ) -> None:
        self.batches = list(batches or [])
        self.sources = sources if sources is not None else [
            {"id": "auth_logs", "type": "file", "description": "Authentication logs"},
            {"id": "process_monitor", "type": "process_monitor", "description": "Processes"},
        ]
        self.error = error
        self.format_error = format_error
        self.calls: list[tuple[list[str], int]] = []

    def get_available_sources(self) -> list[dict[str, Any]]:
        return list(self.sources)

    def extract_logs(self, sources=None, time_range_minutes: int = 5):
        if self.error is not None:
            raise self.error
        self.calls.append((list(sources or []), time_range_minutes))
        if self.batches:
            return self.batches.pop(0)
        return {source: [] for source in (sources or [])}

    def format_logs_for_analysis(self, extracted) -> str:
        if self.format_error is not None:
            raise self.format_error
        lines = []
        for source, entries in extracted.items():
            for entry in entries:
                lines.append(f"{entry.get('timestamp', '')} [{source}] {entry.get('message', '')}".strip())
        return "\n".join(lines)

    def get_system_summary(self) -> dict[str, Any]:
        return {"system": "Fake", "available_sources": len(self.sources)}


def make_jwt(*, expires_in: float = 3600, subject: str = "analyst") -> str:
    """Build an unsigned JWT-shaped token so ``exp`` can be decoded locally."""

    def _segment(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = _segment({"alg": "HS256", "typ": "JWT"})
    body = _segment({"sub": subject, "exp": time.time() + expires_in})
    return f"{header}.{body}.signature-not-verified"


async def wait_for(predicate, *, timeout: float = 2.0) -> bool:
    """Poll ``predicate`` until true or the deadline passes (test helper)."""
    import asyncio

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


@pytest.fixture
def token_file(tmp_path):
    return tmp_path / "session.json"


@pytest.fixture
def config_file(tmp_path):
    return tmp_path / "config.json"
