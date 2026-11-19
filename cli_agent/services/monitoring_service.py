"""Client-owned monitoring loop with an explicit, cancellable lifecycle.

Monitoring stays client-side because the backend only stores session metadata
(``server/services/analysis_storage_service.py:203-237``).

Lifecycle::

    STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED
                   |          |
                   +----------+--> ERROR

Guarantees:

* :meth:`MonitoringService.start` is idempotent: a second call while starting or
  running returns ``False`` and never creates a second loop;
* the loop is an ``asyncio.Task`` written as ``while not stop_event`` so it is
  always cancellable -- there is no bare ``while True``;
* :meth:`stop` cancels, joins the task, then best-effort closes the backend
  session;
* a failed or unreachable backend records an error and retries on the next
  scheduled cycle instead of freezing the app;
* if the session disappears (logout/expiry) the loop stops itself;
* no ``sys.exit`` and no terminal I/O live here.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable

from .api_client import ApiClient
from .auth_service import AuthService
from .collector_service import CollectorService
from .config_service import ClientConfig
from .errors import AuthError
from .limits import fit_logs_to_backend
from .response_adapter import AnalysisView, adapt_analysis, next_interval

ANALYZE_ENDPOINT = "/api/v1/analyze"
SESSIONS_ENDPOINT = "/api/v1/monitoring/sessions"


class MonitoringState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class MonitoringStats:
    cycles: int = 0
    submitted: int = 0
    empty_cycles: int = 0
    failures: int = 0
    last_error: str | None = None
    last_summary: str | None = None
    last_technique_count: int = 0
    session_id: str | None = None
    started_at: datetime | None = None
    last_cycle_at: datetime | None = None
    # Phase 6: the dashboard/monitoring pages report real submission timing and
    # volume instead of guessing from the cycle counter.
    last_success_at: datetime | None = None
    last_cycle_entries: int = 0
    submitted_entries: int = 0
    truncated_cycles: int = 0
    last_truncated_chars: int = 0


@dataclass(frozen=True)
class CycleOutcome:
    """One loop iteration, useful for tests and for the future TUI table."""

    cycle: int
    collected_entries: int
    submitted: bool
    view: AnalysisView | None = None
    error: str | None = None


StateCallback = Callable[[MonitoringState], None]
ResultCallback = Callable[[AnalysisView, CycleOutcome], None]
ErrorCallback = Callable[[Exception, CycleOutcome | None], None]
CycleCallback = Callable[[CycleOutcome], None]


class MonitoringService:
    """Owns the polling loop, its intervals and its backend session."""

    def __init__(
        self,
        collector: CollectorService,
        api_client: ApiClient,
        auth: AuthService,
        config: ClientConfig,
        *,
        on_result: ResultCallback | None = None,
        on_error: ErrorCallback | None = None,
        on_state_change: StateCallback | None = None,
        on_cycle: CycleCallback | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._collector = collector
        self._api = api_client
        self._auth = auth
        self._config = config
        self._on_result = on_result
        self._on_error = on_error
        self._on_state_change = on_state_change
        self._on_cycle = on_cycle
        self._sleep = sleep or self._interruptible_sleep
        self._now = now or (lambda: datetime.now(timezone.utc))

        self._state = MonitoringState.STOPPED
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        # Serialises the scheduled loop and on-demand cycles, so a manual cycle
        # can never overlap a scheduled one or double-submit a batch.
        self._cycle_lock = asyncio.Lock()
        self._stats = MonitoringStats()
        self._interval = int(config.interval_seconds)
        self._sources: tuple[str, ...] = tuple(config.sources)

    # -- read-only view --------------------------------------------------
    @property
    def state(self) -> MonitoringState:
        return self._state

    @property
    def stats(self) -> MonitoringStats:
        return self._stats

    @property
    def interval_seconds(self) -> int:
        return self._interval

    @property
    def sources(self) -> tuple[str, ...]:
        """The validated source ids this loop is collecting from."""
        return self._sources

    @property
    def is_running(self) -> bool:
        return self._state is MonitoringState.RUNNING and self._task is not None

    # -- lifecycle -------------------------------------------------------
    async def start(self, *, interval: int | None = None, sources: list[str] | None = None) -> bool:
        """Start the loop. Returns ``False`` if one is already active."""
        if self._state in (MonitoringState.STARTING, MonitoringState.RUNNING):
            return False

        if not self._auth.is_authenticated:
            raise AuthError("monitoring requires an authenticated session", reauthentication_required=True)

        if interval is not None:
            self._interval = max(10, int(interval))
        if sources is not None:
            self._sources = self._collector.validate_sources(sources)

        self._stop_event.clear()
        self._stats = MonitoringStats(started_at=self._now())
        self._set_state(MonitoringState.STARTING)

        try:
            self._stats.session_id = await self._register_session()
        except AuthError:
            self._set_state(MonitoringState.STOPPED)
            raise
        except Exception as exc:
            # Offline backend must not prevent local polling from starting; the
            # session row is an audit trail, not the monitoring engine.
            self._record_failure(exc, outcome=None)

        self._set_state(MonitoringState.RUNNING)
        self._task = asyncio.create_task(self._run(), name="forensique-monitoring")
        return True

    async def force_cycle(self) -> CycleOutcome | None:
        """Run one collection/submission now (the TUI's "force cycle")."""
        if self._state is not MonitoringState.RUNNING:
            return None
        async with self._cycle_lock:
            if self._stop_event.is_set() or self._state is not MonitoringState.RUNNING:
                return None
            return await self._run_cycle(self._stats.cycles + 1)

    async def stop(self) -> None:
        """Cancel the loop, join it, and close the backend session."""
        if self._state is MonitoringState.STOPPED and self._task is None:
            return
        self._set_state(MonitoringState.STOPPING)
        self._stop_event.set()

        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        await self._close_session()
        self._set_state(MonitoringState.STOPPED)

    async def __aenter__(self) -> "MonitoringService":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()

    # -- internals -------------------------------------------------------
    async def _run(self) -> None:
        cycle = 0
        try:
            while not self._stop_event.is_set():
                if not self._auth.is_authenticated:
                    await self._abort("session ended; monitoring stopped")
                    return
                cycle += 1
                async with self._cycle_lock:
                    outcome = await self._run_cycle(cycle)
                if outcome.error is not None:
                    await self._sleep(self._interval)
                    continue
                if outcome.view is not None:
                    self._interval = next_interval(outcome.view, int(self._config.interval_seconds))
                await self._sleep(self._interval)
        except asyncio.CancelledError:
            raise

    async def _run_cycle(self, cycle: int) -> CycleOutcome:
        try:
            result = self._collector.collect(
                list(self._sources) or None,
                time_range_minutes=_time_range(self._config),
            )
        except Exception as exc:
            self._record_failure(exc, outcome=None)
            return CycleOutcome(cycle=cycle, collected_entries=0, submitted=False, error=str(exc))

        self._stats.cycles += 1
        self._stats.last_cycle_at = self._now()
        self._stats.last_cycle_entries = result.total_entries

        if result.is_empty:
            self._stats.empty_cycles += 1
            return self._emit_cycle(
                CycleOutcome(cycle=cycle, collected_entries=0, submitted=False)
            )

        if not result.formatted_text.strip():
            self._stats.empty_cycles += 1
            return self._emit_cycle(
                CycleOutcome(
                    cycle=cycle, collected_entries=result.total_entries, submitted=False
                )
            )

        # The backend rejects ``logs`` longer than 50,000 characters with a
        # 422. Real collection batches routinely exceed that, so keep the most
        # recent tail and say so inside the payload.
        logs, dropped = fit_logs_to_backend(result.formatted_text)
        if dropped:
            self._stats.truncated_cycles += 1
            self._stats.last_truncated_chars = dropped
        payload = {
            "logs": logs,
            "enhance_with_ai": bool(self._config.enhance_with_ai),
            "max_results": int(self._config.max_results),
        }
        try:
            response = await self._api.request("POST", ANALYZE_ENDPOINT, json_body=payload)
            view = adapt_analysis(response)
        except AuthError as exc:
            self._record_failure(exc, outcome=None)
            await self._abort("session expired; monitoring stopped")
            return CycleOutcome(
                cycle=cycle,
                collected_entries=result.total_entries,
                submitted=False,
                error=str(exc),
            )
        except Exception as exc:
            self._record_failure(exc, outcome=None)
            return CycleOutcome(
                cycle=cycle,
                collected_entries=result.total_entries,
                submitted=False,
                error=str(exc),
            )

        self._stats.submitted += 1
        self._stats.submitted_entries += result.total_entries
        self._stats.last_success_at = self._now()
        self._stats.last_summary = view.summary or None
        self._stats.last_technique_count = view.technique_count
        outcome = CycleOutcome(
            cycle=cycle,
            collected_entries=result.total_entries,
            submitted=True,
            view=view,
        )
        if self._on_result is not None:
            self._on_result(view, outcome)
        return self._emit_cycle(outcome)

    def _emit_cycle(self, outcome: CycleOutcome) -> CycleOutcome:
        """Report every cycle (including empty ones) to the UI, if listening."""
        if self._on_cycle is not None:
            self._on_cycle(outcome)
        return outcome

    async def _abort(self, message: str) -> None:
        self._stop_event.set()
        self._stats.last_error = message
        self._set_state(MonitoringState.ERROR)

    def _record_failure(self, exc: Exception, outcome: CycleOutcome | None) -> None:
        self._stats.failures += 1
        self._stats.last_error = str(exc) or type(exc).__name__
        if self._on_error is not None:
            self._on_error(exc, outcome)

    async def _register_session(self) -> str | None:
        body: dict[str, Any] = {
            "interval_seconds": int(self._interval),
            "ai_agent_enabled": True,
        }
        if self._config.monitoring_type == "file" and self._config.log_path:
            body["log_path"] = self._config.log_path
        else:
            body["log_path"] = "dynamic:" + (",".join(self._sources) or "all")
        payload = await self._api.request("POST", SESSIONS_ENDPOINT, json_body=body)
        if isinstance(payload, dict):
            session_id = payload.get("session_id")
            return str(session_id) if session_id else None
        return None

    async def _close_session(self) -> None:
        session_id = self._stats.session_id
        if not session_id or not self._auth.is_authenticated:
            return
        try:
            await self._api.request(
                "POST", f"{SESSIONS_ENDPOINT}/{session_id}/stop"
            )
        except Exception:  # noqa: BLE001 - cleanup is best effort by design
            # The local loop has already stopped; a backend that is offline or
            # misbehaving must never surface as a failed shutdown.
            pass

    async def _interruptible_sleep(self, seconds: float) -> None:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stop_event.wait(), timeout=max(0.0, seconds))

    def _set_state(self, state: MonitoringState) -> None:
        if self._state is state:
            return
        self._state = state
        if self._on_state_change is not None:
            self._on_state_change(state)


def _time_range(config: ClientConfig) -> int:
    """Legacy behaviour: each dynamic cycle looks back over a short window."""
    return int(getattr(config, "extraction_time_range_minutes", 5) or 5)
