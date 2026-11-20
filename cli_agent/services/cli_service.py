"""Facade the CLI (and later the Textual app) talks to.

This is the only object the presentation layer needs. It owns wiring, not
policy: authentication, configuration, collection and monitoring each stay in
their own module so they can be tested in isolation.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from ..remediation import RemediationEngine
from .api_client import ApiClient, Transport
from .auth_service import AuthService, Session, TokenStore
from .collector_service import (
    DEFAULT_COLLECTOR_STATE_PATH,
    CollectionResult,
    CollectorService,
)
from .config_service import ClientConfig, ConfigService
from .errors import ConfigurationError, ForensIQError
from .limits import MAX_LOG_CHARS
from .monitoring_service import MonitoringService, MonitoringState
from .outbox import Outbox
from .response_adapter import AnalysisView, adapt_analysis

ANALYZE_ENDPOINT = "/api/v1/analyze"
HEALTH_ENDPOINT = "/health"
SESSIONS_ENDPOINT = "/api/v1/monitoring/sessions"
KNOWLEDGE_STATS_ENDPOINT = "/api/v1/knowledge/stats"
KNOWLEDGE_SEARCH_ENDPOINT = "/api/v1/knowledge/search"
LATEST_ANALYSIS_ENDPOINT = "/api/v1/latest"
HISTORY_ENDPOINT = "/api/v1/history"
INVESTIGATIONS_ENDPOINT = "/api/v1/investigations"


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
        outbox: Outbox | None = None,
        remediation: RemediationEngine | None = None,
    ) -> None:
        self.config_service = config_service or ConfigService()
        self.config_error: str | None = None
        if config is not None:
            self.config = config
        else:
            # A corrupt config must not prevent the app from starting; surface
            # the problem instead of silently rewriting the user's file.
            try:
                self.config = self.config_service.load()
            except ConfigurationError as exc:
                self.config = ClientConfig()
                self.config_error = str(exc)
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
        # The pending-delivery journal shares the collector's state directory.
        # Tests that pass a collector without persistence stay file-free.
        if outbox is None:
            state_path = self.collector.state_path
            outbox = (
                Outbox(state_path.with_name("pending_delivery.json"))
                if state_path is not None
                else None
            )
        self.outbox = outbox
        self.remediation = remediation or RemediationEngine(
            backend_base_url=self.config.base_url
        )
        self._monitoring: MonitoringService | None = None

    # -- session ---------------------------------------------------------
    def restore_session(self) -> Session | None:
        return self.auth.load_session()

    async def login(self, username: str, password: str, *, base_url: str | None = None) -> Session:
        if self._monitoring_active():
            raise ConfigurationError("stop monitoring before signing in")
        if base_url and base_url.rstrip("/") != self.config.base_url:
            self.config = self.config_service.update(base_url=base_url.rstrip("/"))
            self.api.base_url = self.config.base_url
            self.remediation.set_backend_url(self.config.base_url)
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

    # -- read-only backend views (Phase 6) --------------------------------
    async def backend_health(self) -> dict[str, Any]:
        """``GET /health`` - exists in the backend and needs no authentication."""
        payload = await self.api.request("GET", HEALTH_ENDPOINT, authenticated=False)
        return payload if isinstance(payload, dict) else {}

    async def list_sessions(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        """``GET /api/v1/monitoring/sessions`` for the authenticated user.

        The backend supports full history via ``active_only=false``; both
        active and stopped rows are returned by the same route.
        """
        self.auth.require_session()
        query = urlencode({"active_only": "true" if active_only else "false"})
        payload = await self.api.request("GET", f"{SESSIONS_ENDPOINT}?{query}")
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []

    async def get_session(self, session_id: str) -> dict[str, Any]:
        self.auth.require_session()
        payload = await self.api.request("GET", f"{SESSIONS_ENDPOINT}/{session_id}")
        return payload if isinstance(payload, dict) else {}

    async def knowledge_stats(self) -> dict[str, Any]:
        """``GET /api/v1/knowledge/stats`` - the only knowledge read the CLI needs."""
        payload = await self.api.request("GET", KNOWLEDGE_STATS_ENDPOINT)
        return payload if isinstance(payload, dict) else {}

    async def search_knowledge(self, query: str, *, top_k: int = 10) -> dict[str, Any]:
        """``GET /api/v1/knowledge/search`` with server-side result limits."""
        if not query or not query.strip():
            return {"query": query, "total_hits": 0, "hits": []}
        query_string = urlencode({"q": query.strip(), "top_k": max(1, min(50, int(top_k)))})
        payload = await self.api.request(
            "GET", f"{KNOWLEDGE_SEARCH_ENDPOINT}?{query_string}"
        )
        return payload if isinstance(payload, dict) else {}

    async def latest_analysis(self) -> dict[str, Any] | None:
        """``GET /api/v1/latest`` - most recent stored analysis, if any."""
        self.auth.require_session()
        payload = await self.api.request("GET", LATEST_ANALYSIS_ENDPOINT)
        if isinstance(payload, dict):
            analysis = payload.get("analysis")
            return analysis if isinstance(analysis, dict) else None
        return None

    async def analysis_history(self, *, limit: int = 10) -> list[dict[str, Any]]:
        self.auth.require_session()
        query = urlencode({"limit": max(1, min(50, int(limit)))})
        payload = await self.api.request("GET", f"{HISTORY_ENDPOINT}?{query}")
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []

    async def sync_remediation_status(
        self,
        recommendation_id: str,
        execution_status: str,
        *,
        analysis_id: str | None = None,
        investigation_id: str | None = None,
        receipt_id: str | None = None,
        executed_by: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        """Report local HITL execution/rejection/rollback status back to the backend."""
        if not self.is_authenticated:
            return None
        if analysis_id:
            path = f"{HISTORY_ENDPOINT}/{analysis_id}/remediation-status"
        elif investigation_id:
            path = f"{INVESTIGATIONS_ENDPOINT}/{investigation_id}/remediation-status"
        else:
            return None
        body: dict[str, Any] = {
            "recommendation_id": recommendation_id,
            "execution_status": execution_status,
        }
        if receipt_id:
            body["receipt_id"] = receipt_id
        if executed_by:
            body["executed_by"] = executed_by
        if notes:
            body["notes"] = notes
        if analysis_id:
            body["analysis_id"] = analysis_id
        payload = await self.api.request("POST", path, json_body=body)
        return payload if isinstance(payload, dict) else None

    # -- collector -------------------------------------------------------
    def collector_summary(self) -> dict[str, Any]:
        """Platform summary plus configured sources, without raising at the UI."""
        summary: dict[str, Any] = {"sources": [], "system": {}, "error": None}
        try:
            summary["sources"] = self.collector.available_sources()
        except ForensIQError as exc:
            summary["error"] = str(exc)
        summary["system"] = self.collector.system_summary()
        return summary

    # -- monitoring ------------------------------------------------------
    def configure_monitoring(self, **changes: Any) -> ClientConfig:
        """Validate and persist configuration, refusing unsafe live changes.

        The polling loop snapshots its endpoint, interval and sources at start.
        Changing them mid-session would silently desynchronise the backend
        session from the client, so a controlled stop is required.
        """
        if self._monitoring_active():
            raise ConfigurationError(
                "stop monitoring before changing configuration"
            )
        updated = self.config_service.update(**changes)
        self.config = updated
        self.config_error = None
        self.api.base_url = updated.base_url
        self.remediation.set_backend_url(updated.base_url)
        return updated

    def _monitoring_active(self) -> bool:
        monitoring = self._monitoring
        return monitoring is not None and monitoring.state in (
            MonitoringState.STARTING,
            MonitoringState.RUNNING,
            MonitoringState.STOPPING,
        )

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
            outbox=self.outbox,
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
                    "session_close": monitoring.stats.session_close,
                    "pending_batches": monitoring.stats.batches_pending,
                    "pending_bytes": monitoring.stats.pending_bytes,
                    "last_error": monitoring.stats.last_error,
                }
                if monitoring is not None
                else None
            ),
            "config": asdict(self.config),
            "config_error": self.config_error,
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
