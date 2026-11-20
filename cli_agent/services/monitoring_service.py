"""Client-owned monitoring loop with lossless, acknowledgement-gated delivery.

Monitoring stays client-side because the backend only stores session metadata
(``server/services/analysis_storage_service.py:203-237``).

Lifecycle::

    STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED
                   |          |
                   +----------+--> ERROR

Phase 7 delivery rules
----------------------

* Collected text is split into requests that respect the backend's 50,000
  character ``logs`` limit.  Nothing is truncated; ordering is preserved and a
  single oversized event is cut across batches rather than dropped.
* Each cycle becomes a :class:`~cli_agent.services.outbox.PendingDelivery`,
  written to a private, bounded journal *before* the first request.  The
  collector checkpoint is committed only after every batch was acknowledged.
* A crash between acknowledgement and checkpoint commit can resend a batch.
  The backend has no idempotency key, so this is explicitly **at-least-once**,
  not exactly-once.
* While a delivery is pending, new logs are not collected: this bounds memory
  and disk use to one collection cycle and prevents the queue from growing
  without limit.  If the journal is full or unwritable, monitoring enters
  ``ERROR`` with a clear message instead of discarding data.

Lifecycle guarantees
--------------------

* ``start`` is idempotent and a generation token prevents a slow session
  registration from resurrecting a loop that was stopped meanwhile.
* ``stop`` cancels the loop, waits for it with a bound, then closes the backend
  session with a short timeout.  A failed/unknown session close is recorded as
  such; it is never reported as closed.
* A failed or unreachable backend records an error and retries on the next
  scheduled cycle instead of freezing the app.  Authentication loss aborts the
  loop while preserving pending batches.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable

from .api_client import ApiClient
from .auth_service import AuthService
from .collector_service import CollectorService
from .config_service import ClientConfig
from .errors import (
    AuthError,
    ForensIQError,
    StatePersistenceError,
    UnauthorizedError,
)
from .limits import split_logs_lossless
from .outbox import (
    Outbox,
    OutboxError,
    OutboxFullError,
    PendingBatch,
    PendingDelivery,
)
from .response_adapter import AnalysisView, adapt_analysis, next_interval

ANALYZE_ENDPOINT = "/api/v1/analyze"
SESSIONS_ENDPOINT = "/api/v1/monitoring/sessions"

DEFAULT_STOP_TIMEOUT = 10.0
DEFAULT_SESSION_CLOSE_TIMEOUT = 5.0
DEFAULT_BATCH_RETRY_ATTEMPTS = 3


class MonitoringState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class MonitoringStats:
    cycles: int = 0
    # ``submitted`` counts acknowledged batches (one batch for small cycles).
    submitted: int = 0
    empty_cycles: int = 0
    failures: int = 0
    last_error: str | None = None
    last_summary: str | None = None
    last_technique_count: int = 0
    session_id: str | None = None
    started_at: datetime | None = None
    last_cycle_at: datetime | None = None
    last_success_at: datetime | None = None
    last_cycle_entries: int = 0
    submitted_entries: int = 0
    # Phase 7 delivery observability.
    batches_submitted: int = 0
    batches_pending: int = 0
    pending_entries: int = 0
    pending_bytes: int = 0
    delivery_attempts: int = 0
    split_batches: int = 0
    oversized_batches: int = 0
    last_batch_error: str | None = None
    # "not-created" | "open" | "closed" | "unknown (...)".
    session_close: str = "not-created"
    # Retained for compatibility with Phase 6 display code; always zero now.
    truncated_cycles: int = 0
    last_truncated_chars: int = 0


@dataclass(frozen=True)
class CycleOutcome:
    """One loop iteration, useful for tests and for the TUI table."""

    cycle: int
    collected_entries: int
    submitted: bool
    view: AnalysisView | None = None
    error: str | None = None
    batches: int = 0
    pending_batches: int = 0
    pending_entries: int = 0


StateCallback = Callable[[MonitoringState], None]
ResultCallback = Callable[[AnalysisView, CycleOutcome], None]
ErrorCallback = Callable[[Exception, CycleOutcome | None], None]
CycleCallback = Callable[[CycleOutcome], None]


class MonitoringService:
    """Owns the polling loop, its intervals, batches and backend session."""

    def __init__(
        self,
        collector: CollectorService,
        api_client: ApiClient,
        auth: AuthService,
        config: ClientConfig,
        *,
        outbox: Outbox | None = None,
        on_result: ResultCallback | None = None,
        on_error: ErrorCallback | None = None,
        on_state_change: StateCallback | None = None,
        on_cycle: CycleCallback | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        now: Callable[[], datetime] | None = None,
        batch_retry_attempts: int = DEFAULT_BATCH_RETRY_ATTEMPTS,
        stop_timeout: float = DEFAULT_STOP_TIMEOUT,
        session_close_timeout: float = DEFAULT_SESSION_CLOSE_TIMEOUT,
    ) -> None:
        self._collector = collector
        self._api = api_client
        self._auth = auth
        self._config = config
        self._outbox = outbox
        self._on_result = on_result
        self._on_error = on_error
        self._on_state_change = on_state_change
        self._on_cycle = on_cycle
        self._sleep = sleep or self._interruptible_sleep
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._batch_retry_attempts = max(1, int(batch_retry_attempts))
        self._stop_timeout = max(0.1, float(stop_timeout))
        self._session_close_timeout = max(0.1, float(session_close_timeout))

        self._state = MonitoringState.STOPPED
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        # Serialises scheduled and on-demand cycles so a manual cycle can never
        # overlap a scheduled one or submit the same batch twice.
        self._cycle_lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()
        self._generation = 0
        self._stats = MonitoringStats()
        self._interval = int(config.interval_seconds)
        self._sources: tuple[str, ...] = tuple(config.sources)
        self._storage_paused = False

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
        async with self._lifecycle_lock:
            if self._state in (
                MonitoringState.STARTING,
                MonitoringState.RUNNING,
                MonitoringState.STOPPING,
            ):
                return False
            if not self._auth.is_authenticated:
                raise AuthError(
                    "monitoring requires an authenticated session",
                    reauthentication_required=True,
                )
            if interval is not None:
                self._interval = max(10, int(interval))
            if sources is not None:
                self._sources = self._collector.validate_sources(sources)

            # A previous ERROR loop may still be unwinding.  Clear it before
            # resetting the stop event, otherwise it could observe the cleared
            # event and keep polling alongside the new loop.
            previous = self._task
            self._task = None
            if previous is not None and not previous.done():
                previous.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await asyncio.wait_for(previous, timeout=self._stop_timeout)

            self._generation += 1
            generation = self._generation
            self._stop_event.clear()
            self._storage_paused = False
            self._stats = MonitoringStats(started_at=self._now())
            self._set_state(MonitoringState.STARTING)

        session_id: str | None = None
        session_error: Exception | None = None
        try:
            session_id = await self._register_session()
        except AuthError:
            async with self._lifecycle_lock:
                if generation == self._generation:
                    self._set_state(MonitoringState.STOPPED)
            raise
        except Exception as exc:  # noqa: BLE001 - offline backend must not block polling
            session_error = exc
            self._record_failure(exc, outcome=None)

        async with self._lifecycle_lock:
            if generation != self._generation or self._stop_event.is_set():
                # stop() won the race while the session POST was in flight.
                stale_session = session_id
                self._set_state(MonitoringState.STOPPED)
            else:
                stale_session = None

        if stale_session:
            # Do not leak a backend session created for a loop that was stopped.
            await self._stop_remote_session(stale_session)
            return False
        if generation != self._generation:
            return False

        self._stats.session_id = session_id
        if session_id:
            self._stats.session_close = "open"
        else:
            self._stats.session_close = "unknown (session not created)"
        if session_error is not None:
            self._stats.last_error = _short(session_error)

        self._set_state(MonitoringState.RUNNING)
        self._task = asyncio.create_task(self._run(), name="forensique-monitoring")
        return True

    async def force_cycle(self) -> CycleOutcome | None:
        """Run one delivery/collection cycle now (the TUI's "force cycle")."""
        if self._state is not MonitoringState.RUNNING:
            return None
        async with self._cycle_lock:
            if self._stop_event.is_set() or self._state is not MonitoringState.RUNNING:
                return None
            return await self._run_cycle(self._stats.cycles + 1)

    async def stop(self) -> None:
        """Cancel the loop with a bound, then close the backend session."""
        async with self._lifecycle_lock:
            if self._state is MonitoringState.STOPPED and self._task is None:
                return
            self._generation += 1
            self._set_state(MonitoringState.STOPPING)
            self._stop_event.set()
            task, self._task = self._task, None

        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, timeout=self._stop_timeout)

        await self._close_session()
        self._set_state(MonitoringState.STOPPED)

    async def update_runtime_limits(self, *, enhance_with_ai: bool, max_results: int) -> None:
        """Apply safe, non-structural settings to future batches."""
        self._config = replace(
            self._config,
            enhance_with_ai=bool(enhance_with_ai),
            max_results=int(max_results),
        )

    async def __aenter__(self) -> "MonitoringService":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()

    # -- loop ------------------------------------------------------------
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
                if self._stop_event.is_set():
                    return
                if outcome.error is not None:
                    await self._sleep(self._interval)
                    continue
                if outcome.view is not None:
                    self._interval = next_interval(
                        outcome.view, int(self._config.interval_seconds)
                    )
                await self._sleep(self._interval)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - never lose the loop silently
            self._record_failure(exc, outcome=None)
            await self._abort(f"monitoring stopped: {_short(exc)}")

    async def _run_cycle(self, cycle: int) -> CycleOutcome:
        # 1. Deliver anything the backend has not acknowledged yet.  No new
        #    logs are collected while a delivery is pending (bounded queue).
        delivery, load_error = self._load_pending()
        if load_error is not None:
            self._record_failure(load_error, outcome=None)
            self._pause_for_storage(load_error)
            return CycleOutcome(
                cycle=cycle,
                collected_entries=0,
                submitted=False,
                error=_short(load_error),
                pending_batches=self._stats.batches_pending,
            )

        delivered_view: AnalysisView | None = None
        if delivery is not None:
            delivered_view, ok, error = await self._deliver(delivery)
            if not ok:
                return CycleOutcome(
                    cycle=cycle,
                    collected_entries=delivery.entries,
                    submitted=False,
                    view=delivered_view,
                    error=error,
                    batches=self._stats.batches_submitted,
                    pending_batches=self._stats.batches_pending,
                    pending_entries=self._stats.pending_entries,
                )

        # 2. Collect new events.  The durable checkpoint is withheld when an
        #    outbox exists: it advances only after acknowledgement.
        try:
            result = self._collector.collect(
                list(self._sources) or None,
                time_range_minutes=_time_range(self._config),
                persist=self._outbox is None,
            )
        except Exception as exc:
            self._record_failure(exc, outcome=None)
            return CycleOutcome(cycle=cycle, collected_entries=0, submitted=False, error=_short(exc))

        self._stats.cycles += 1
        self._stats.last_cycle_at = self._now()
        self._stats.last_cycle_entries = result.total_entries

        if result.is_empty or not result.formatted_text.strip():
            self._stats.empty_cycles += 1
            return self._emit_cycle(
                CycleOutcome(
                    cycle=cycle,
                    collected_entries=result.total_entries,
                    submitted=False,
                    view=delivered_view,
                    batches=self._stats.batches_submitted,
                    pending_batches=self._stats.batches_pending,
                    pending_entries=self._stats.pending_entries,
                )
            )

        split = split_logs_lossless(result.formatted_text)
        self._stats.split_batches = split.count
        self._stats.oversized_batches = split.oversized
        if split.count == 0:  # pragma: no cover - whitespace-only extractor output
            self._stats.empty_cycles += 1
            return self._emit_cycle(
                CycleOutcome(
                    cycle=cycle,
                    collected_entries=result.total_entries,
                    submitted=False,
                    error="collected text contained no records",
                )
            )

        offsets, files = self._collector.snapshot_state()
        delivery = PendingDelivery(
            batches=tuple(PendingBatch(text=text) for text in split.batches),
            checkpoint=offsets,
            checkpoint_files=files,
            entries=result.total_entries,
            enhance_with_ai=bool(self._config.enhance_with_ai),
            max_results=int(self._config.max_results),
        )
        self._publish_pending(delivery)

        if self._outbox is not None:
            try:
                self._outbox.save(delivery)
            except OutboxFullError as exc:
                # Never discard: pause collection with a clear error; offsets
                # were not committed, so a later restart re-reads this data.
                self._record_failure(exc, outcome=None)
                self._pause_for_storage(exc)
                self._stats.batches_pending = 0
                self._stats.pending_entries = 0
                self._stats.pending_bytes = 0
                return CycleOutcome(
                    cycle=cycle,
                    collected_entries=result.total_entries,
                    submitted=False,
                    error=_short(exc),
                    pending_batches=0,
                )
            except OutboxError as exc:
                self._record_failure(exc, outcome=None)
                self._pause_for_storage(exc)
                self._stats.batches_pending = 0
                self._stats.pending_entries = 0
                self._stats.pending_bytes = 0
                return CycleOutcome(
                    cycle=cycle,
                    collected_entries=result.total_entries,
                    submitted=False,
                    error=_short(exc),
                )

        view, ok, error = await self._deliver(delivery)
        if not ok:
            return CycleOutcome(
                cycle=cycle,
                collected_entries=result.total_entries,
                submitted=False,
                view=view,
                error=error,
                batches=self._stats.batches_submitted,
                pending_batches=self._stats.batches_pending,
                pending_entries=self._stats.pending_entries,
            )

        self._stats.last_summary = (view.summary if view else None) or None
        self._stats.last_technique_count = view.technique_count if view else 0
        final_view = view or delivered_view
        outcome = CycleOutcome(
            cycle=cycle,
            collected_entries=result.total_entries,
            submitted=True,
            view=final_view,
            batches=self._stats.batches_submitted,
            pending_batches=self._stats.batches_pending,
            pending_entries=self._stats.pending_entries,
        )
        if final_view is not None and self._on_result is not None:
            self._on_result(final_view, outcome)
        return self._emit_cycle(outcome)

    # -- pending delivery -------------------------------------------------
    def _load_pending(self) -> tuple[PendingDelivery | None, Exception | None]:
        if self._outbox is None:
            return None, None
        try:
            delivery = self._outbox.load()
        except OutboxError as exc:
            return None, exc
        if delivery is not None and not delivery.is_empty:
            self._publish_pending(delivery)
        return delivery, None

    async def _deliver(
        self, delivery: PendingDelivery
    ) -> tuple[AnalysisView | None, bool, str | None]:
        """Send every batch once; remove only acknowledged ones from the journal."""
        pending = list(delivery.batches)
        view: AnalysisView | None = None

        while pending:
            batch = pending[0]
            self._stats.delivery_attempts += 1
            payload = {
                "logs": batch.text,
                "enhance_with_ai": delivery.enhance_with_ai,
                "max_results": delivery.max_results,
            }
            try:
                response = await self._api.request(
                    "POST",
                    ANALYZE_ENDPOINT,
                    json_body=payload,
                    retry_transient=True,
                    retry_attempts=self._batch_retry_attempts,
                )
                view = adapt_analysis(response)
            except (AuthError, UnauthorizedError) as exc:
                self._record_failure(exc, outcome=None)
                self._persist_pending(delivery)
                # The backend rejected the bearer token; drop it so the UI
                # demands a fresh login instead of presenting a false session.
                try:
                    self._auth.logout()
                except ForensIQError:  # pragma: no cover - permission edge case
                    pass
                await self._abort("authentication expired; pending batches preserved")
                return view, False, "authentication expired; pending batches preserved"
            except Exception as exc:  # noqa: BLE001 - classified by the API client
                self._record_failure(exc, outcome=None)
                failed = replace(
                    batch,
                    attempts=batch.attempts + 1,
                    last_error=_short(exc),
                )
                delivery = delivery.with_batches([failed, *pending[1:]])
                self._persist_pending(delivery)
                self._stats.last_batch_error = _short(exc)
                return view, False, _short(exc)

            # Acknowledged by the backend: remove it from the journal before
            # moving on.  A crash here resends the remainder, never loses it.
            pending.pop(0)
            delivery = delivery.with_batches(pending)
            self._stats.submitted += 1
            self._stats.batches_submitted += 1
            self._publish_pending(delivery)
            if pending:
                self._persist_pending(delivery)

        # Every batch acknowledged: commit the checkpoint they cover, then let
        # the journal go.  Ordering favours no-loss (duplicates on a crash
        # between the two writes are acceptable and documented).
        try:
            if delivery.checkpoint:
                self._collector.commit_state(delivery.checkpoint, delivery.checkpoint_files)
        except (StatePersistenceError, ForensIQError) as exc:
            self._record_failure(exc, outcome=None)
            self._pause_for_storage(exc)
            return view, False, _short(exc)

        if self._outbox is not None:
            try:
                self._outbox.clear()
            except OutboxError as exc:
                # The data is delivered and checkpointed.  Leaving the journal
                # behind only risks duplicates, so warn without failing.
                self._stats.last_batch_error = _short(exc)

        self._stats.submitted_entries += delivery.entries
        self._stats.last_success_at = self._now()
        self._stats.last_batch_error = None
        self._stats.batches_pending = 0
        self._stats.pending_entries = 0
        self._stats.pending_bytes = 0
        return view, True, None

    def _persist_pending(self, delivery: PendingDelivery) -> None:
        if self._outbox is None:
            return
        try:
            self._outbox.save(delivery)
        except OutboxError as exc:
            # The old journal on disk still holds the full delivery, so no
            # loss; surface the storage problem and stop collecting.
            self._record_failure(exc, outcome=None)
            self._pause_for_storage(exc)

    def _publish_pending(self, delivery: PendingDelivery) -> None:
        self._stats.batches_pending = len(delivery.batches)
        self._stats.pending_entries = delivery.entries if delivery.batches else 0
        self._stats.pending_bytes = delivery.total_bytes

    # -- failure handling -------------------------------------------------
    async def _abort(self, message: str) -> None:
        self._stop_event.set()
        self._stats.last_error = message
        self._set_state(MonitoringState.ERROR)

    def _pause_for_storage(self, exc: Exception) -> None:
        self._storage_paused = True
        self._stats.last_error = f"delivery storage paused: {_short(exc)}"
        self._stop_event.set()
        self._set_state(MonitoringState.ERROR)

    def _record_failure(self, exc: Exception, outcome: CycleOutcome | None) -> None:
        self._stats.failures += 1
        self._stats.last_error = _short(exc)
        if self._on_error is not None:
            self._on_error(exc, outcome)

    def _emit_cycle(self, outcome: CycleOutcome) -> CycleOutcome:
        if self._on_cycle is not None:
            self._on_cycle(outcome)
        return outcome

    # -- backend session --------------------------------------------------
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
        """Close the backend session, recording the true outcome."""
        session_id = self._stats.session_id
        if not session_id:
            self._stats.session_close = "not-created"
            return
        if not self._auth.is_authenticated:
            self._stats.session_close = "unknown (signed out before stop)"
            return
        try:
            await asyncio.wait_for(
                self._api.request("POST", f"{SESSIONS_ENDPOINT}/{session_id}/stop"),
                timeout=self._session_close_timeout,
            )
        except Exception as exc:  # noqa: BLE001 - session close is best effort
            self._stats.session_close = f"unknown ({_short(exc)})"
        else:
            self._stats.session_close = "closed"

    async def _stop_remote_session(self, session_id: str) -> None:
        if not self._auth.is_authenticated:
            return
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                self._api.request("POST", f"{SESSIONS_ENDPOINT}/{session_id}/stop"),
                timeout=self._session_close_timeout,
            )

    async def _interruptible_sleep(self, seconds: float) -> None:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stop_event.wait(), timeout=max(0.0, seconds))

    def _set_state(self, state: MonitoringState) -> None:
        if self._state is state:
            return
        self._state = state
        if self._on_state_change is not None:
            self._on_state_change(state)


def _short(exc: BaseException, limit: int = 160) -> str:
    text = str(exc).strip() or type(exc).__name__
    return text[:limit]


def _time_range(config: ClientConfig) -> int:
    """Legacy behaviour: each dynamic cycle looks back over a short window."""
    return int(getattr(config, "extraction_time_range_minutes", 5) or 5)


__all__ = [
    "CycleOutcome",
    "MonitoringService",
    "MonitoringState",
    "MonitoringStats",
]
