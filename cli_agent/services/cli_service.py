"""Facade the CLI (and later the Textual app) talks to.

This is the only object the presentation layer needs. It owns wiring, not
policy: authentication, configuration, collection and monitoring each stay in
their own module so they can be tested in isolation.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .api_client import ApiClient, Transport
from .auth_service import AuthService, Session, TokenStore
from .collector_service import (
    DEFAULT_COLLECTOR_STATE_PATH,
    CollectionResult,
    CollectorService,
)
from .config_service import ClientConfig, ConfigService
from .errors import ConfigurationError, ForensIQError
from .monitoring_service import MonitoringService, MonitoringState
from .response_adapter import AnalysisView, adapt_analysis

ANALYZE_ENDPOINT = "/api/v1/analyze"
MAX_LOG_CHARS = 50_000  # mirrors server/model/logs_model.py: logs max_length


class CliService:
    """Reusable application services, free of terminal rendering."""

    def __init__(
        self,
        *,
        config_service: ConfigService | None = None,
        token_store: TokenStore | None = None,
        transport: Transport | None = None,
        collector: CollectorService | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        self.config_service = config_service or ConfigService()
        self.config = config or self.config_service.load()
        self.auth = AuthService(store=token_store or TokenStore())
        self.api = ApiClient(
            self.config.base_url,
            transport=transport,
            token_provider=lambda: self.auth.token,
        )
        self.auth.bind_client(self.api)
        # Persisting byte offsets across restarts keeps a restarted collector
        # from replaying (or stalling on) a rotation it has already passed.
        self.collector = collector or CollectorService(
            state_path=DEFAULT_COLLECTOR_STATE_PATH
        )
        self._monitoring: MonitoringService | None = None

    # -- session ---------------------------------------------------------
    def restore_session(self) -> Session | None:
        return self.auth.load_session()

    async def login(self, username: str, password: str, *, base_url: str | None = None) -> Session:
        if base_url and base_url.rstrip("/") != self.config.base_url:
            self.config = self.config_service.update(base_url=base_url.rstrip("/"))
            self.api.base_url = self.config.base_url
        return await self.auth.login(username, password)

    def logout(self) -> None:
        """Clear the local session; monitoring is stopped separately."""
        self.auth.logout()

    async def profile(self) -> dict[str, Any]:
        return await self.auth.profile()

    async def register(self, username: str, email: str, password: str) -> dict[str, Any]:
        return await self.auth.register(username, email, password)

    @property
    def is_authenticated(self) -> bool:
        return self.auth.is_authenticated

    # -- analysis --------------------------------------------------------
    async def analyze_text(
        self,
        logs: str,
        *,
        enhance_with_ai: bool | None = None,
        max_results: int | None = None,
    ) -> AnalysisView:
        if not isinstance(logs, str) or not logs.strip():
            raise ConfigurationError("no log content to analyze")
        if len(logs) > MAX_LOG_CHARS:
            raise ConfigurationError(
                f"log content exceeds the backend limit of {MAX_LOG_CHARS} characters"
            )
        self.auth.require_session()
        payload = {
            "logs": logs,
            "enhance_with_ai": self.config.enhance_with_ai if enhance_with_ai is None else bool(enhance_with_ai),
            "max_results": int(max_results or self.config.max_results),
        }
        response = await self.api.request("POST", ANALYZE_ENDPOINT, json_body=payload)
        return adapt_analysis(response)

    async def analyze_file(self, path: str | Path, **kwargs: Any) -> AnalysisView:
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            raise ConfigurationError(f"log file not found: {file_path}")
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {file_path}: {exc}") from exc
        return await self.analyze_text(content, **kwargs)

    # -- monitoring ------------------------------------------------------
    def configure_monitoring(self, **changes: Any) -> ClientConfig:
        self.config = self.config_service.update(**changes)
        self.api.base_url = self.config.base_url
        return self.config

    def available_sources(self) -> list[dict[str, Any]]:
        return self.collector.available_sources()

    def collect_once(self, sources: list[str] | None = None) -> CollectionResult:
        return self.collector.collect(sources)

    def _build_monitoring(self, **callbacks: Any) -> MonitoringService:
        return MonitoringService(
            collector=self.collector,
            api_client=self.api,
            auth=self.auth,
            config=self.config,
            **callbacks,
        )

    async def start_monitoring(
        self,
        *,
        interval: int | None = None,
        sources: list[str] | None = None,
        **callbacks: Any,
    ) -> MonitoringService:
        if self._monitoring is not None and self._monitoring.is_running:
            return self._monitoring
        self._monitoring = self._build_monitoring(**callbacks)
        await self._monitoring.start(interval=interval, sources=sources)
        return self._monitoring

    async def stop_monitoring(self) -> None:
        if self._monitoring is None:
            return
        await self._monitoring.stop()
        self._monitoring = None

    async def force_cycle(self):
        """Run one collection/submission now, if monitoring is running."""
        if self._monitoring is None:
            return None
        return await self._monitoring.force_cycle()

    @property
    def monitoring(self) -> MonitoringService | None:
        return self._monitoring

    # -- status ----------------------------------------------------------
    def status(self) -> dict[str, Any]:
        monitoring = self._monitoring
        return {
            "authenticated": self.is_authenticated,
            "username": (self.auth.session.username if self.auth.session else None),
            "base_url": self.config.base_url,
            "monitoring_state": (
                monitoring.state.value if monitoring is not None else MonitoringState.STOPPED.value
            ),
            "monitoring": (
                {
                    "cycles": monitoring.stats.cycles,
                    "submitted": monitoring.stats.submitted,
                    "failures": monitoring.stats.failures,
                    "session_id": monitoring.stats.session_id,
                    "last_error": monitoring.stats.last_error,
                }
                if monitoring is not None
                else None
            ),
            "config": asdict(self.config),
        }

    # -- lifecycle -------------------------------------------------------
    async def close(self) -> None:
        try:
            await self.stop_monitoring()
        finally:
            await self.api.close()

    async def __aenter__(self) -> "CliService":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()
