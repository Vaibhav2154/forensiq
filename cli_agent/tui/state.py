"""Single source of truth for what the TUI displays.

Phase 6 replaced per-widget counters with one :class:`AppState` that every page
renders from.  The app mutates it only from

* completed service calls (login, monitoring cycle, backend refresh), and
* bounded callbacks delivered with ``App.call_later`` from the monitoring loop.

Nothing here invents a metric: every field is either read from a service,
copied from a backend response, or left at ``None``/empty to be rendered as
``Unknown``/``No data``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque

from ..remediation.models import (
    CommandOrDiffPreview,
    ExecutionReceipt,
    PreflightReport,
    RemediationItemView,
)
from ..services.response_adapter import AnalysisView

MAX_EVENTS = 200
MAX_CYCLES = 50


@dataclass
class BackendStatus:
    """Result of the last ``GET /health`` probe (or of any failed request)."""

    state: str = "unknown"  # unknown | online | degraded | offline
    detail: str = "not probed yet"
    services: dict[str, str] = field(default_factory=dict)
    latency_ms: float | None = None
    checked_at: datetime | None = None

    @property
    def label(self) -> str:
        return {
            "online": "Online",
            "degraded": "Degraded",
            "offline": "Offline",
            "unknown": "Unknown",
        }.get(self.state, "Unknown")


@dataclass(frozen=True)
class CycleRecord:
    """One collection/submission cycle, for the Monitoring page table."""

    cycle: int
    entries: int
    submitted: bool
    error: str | None
    at: datetime


@dataclass(frozen=True)
class EventRecord:
    """A bounded operational event, mirrored into the live stream."""

    at: datetime
    message: str
    role: str = "info"


@dataclass
class AppState:
    """Everything the pages read.  Mutated only through explicit helpers."""

    authenticated: bool = False
    username: str | None = None
    profile: dict[str, Any] = field(default_factory=dict)
    profile_error: str | None = None

    backend: BackendStatus = field(default_factory=BackendStatus)

    monitoring_state: str = "stopped"
    session_id: str | None = None
    interval_seconds: int = 300
    sources: tuple[str, ...] = ()
    collector_catalogue: list[dict[str, Any]] = field(default_factory=list)
    collector_error: str | None = None
    platform: str | None = None

    cycles: int = 0
    submitted: int = 0
    empty_cycles: int = 0
    failures: int = 0
    collected_entries: int = 0
    submitted_entries: int = 0
    last_cycle_entries: int = 0
    truncated_cycles: int = 0
    last_truncated_chars: int = 0
    last_success_at: datetime | None = None
    last_error: str | None = None
    last_summary: str | None = None
    # Phase 7 delivery state.
    batches_submitted: int = 0
    pending_batches: int = 0
    pending_entries: int = 0
    pending_bytes: int = 0
    oversized_batches: int = 0
    session_close: str = "not-created"

    latest_analysis: AnalysisView | None = None
    analysis_status: str = "empty"  # empty | loaded | unavailable
    analysis_error: str | None = None

    remediation_items: list[RemediationItemView] = field(default_factory=list)
    selected_remediation_index: int = 0
    remediation_preflight: dict[str, PreflightReport] = field(default_factory=dict)
    remediation_previews: dict[str, CommandOrDiffPreview] = field(default_factory=dict)
    remediation_journal: list[ExecutionReceipt] = field(default_factory=list)
    remediation_status: str = "empty"  # empty | loaded | unavailable
    remediation_error: str | None = None

    sessions: list[dict[str, Any]] = field(default_factory=list)
    sessions_status: str = "unknown"  # unknown | loaded | error
    sessions_error: str | None = None

    knowledge_stats: dict[str, Any] = field(default_factory=dict)
    knowledge_status: str = "unknown"  # unknown | loaded | error
    knowledge_error: str | None = None
    knowledge_hits: list[dict[str, Any]] = field(default_factory=list)
    knowledge_query: str = ""
    knowledge_search_status: str = "idle"  # idle | searching | loaded | error
    knowledge_search_error: str | None = None
    knowledge_search_notice: str | None = None

    events: Deque[EventRecord] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    cycle_log: Deque[CycleRecord] = field(default_factory=lambda: deque(maxlen=MAX_CYCLES))
    loading: set[str] = field(default_factory=set)

    # -- helpers ---------------------------------------------------------
    def note(self, message: str, role: str = "info") -> None:
        self.events.append(EventRecord(datetime.now(), message, role))

    def apply_monitoring(self, monitoring: Any) -> None:
        """Copy a ``MonitoringService`` snapshot into the shared state."""
        if monitoring is None:
            self.monitoring_state = "stopped"
            self.session_id = None
            return
        stats = monitoring.stats
        self.monitoring_state = monitoring.state.value
        self.interval_seconds = monitoring.interval_seconds
        self.sources = tuple(monitoring.sources)
        self.session_id = stats.session_id
        self.cycles = stats.cycles
        self.submitted = stats.submitted
        self.empty_cycles = stats.empty_cycles
        self.failures = stats.failures
        self.collected_entries = stats.submitted_entries
        self.submitted_entries = stats.submitted_entries
        self.last_cycle_entries = stats.last_cycle_entries
        self.last_success_at = stats.last_success_at
        self.last_error = stats.last_error
        self.last_summary = stats.last_summary
        self.truncated_cycles = stats.truncated_cycles
        self.last_truncated_chars = stats.last_truncated_chars
        self.batches_submitted = stats.batches_submitted
        self.pending_batches = stats.batches_pending
        self.pending_entries = stats.pending_entries
        self.pending_bytes = stats.pending_bytes
        self.oversized_batches = stats.oversized_batches
        self.session_close = stats.session_close

    def record_cycle(self, record: CycleRecord) -> None:
        self.cycle_log.append(record)
        if record.error:
            self.failures += 1
            self.last_error = record.error
        if record.submitted:
            self.submitted += 1

    @property
    def pending_fixable_count(self) -> int:
        return sum(
            1
            for item in self.remediation_items
            if item.is_executable_locally and item.execution_status == "pending_approval"
        )

    def clear_analysis(self) -> None:
        self.latest_analysis = None
        self.analysis_status = "empty"
        self.analysis_error = None
        self.remediation_items = []
        self.selected_remediation_index = 0
        self.remediation_preflight.clear()
        self.remediation_previews.clear()
        self.remediation_status = "empty"
        self.remediation_error = None

    def reset_for_logout(self) -> None:
        self.authenticated = False
        self.username = None
        self.profile = {}
        self.profile_error = None
        self.monitoring_state = "stopped"
        self.session_id = None
        self.cycles = self.submitted = self.empty_cycles = self.failures = 0
        self.collected_entries = self.submitted_entries = 0
        self.last_cycle_entries = 0
        self.last_success_at = None
        self.last_error = None
        self.last_summary = None
        self.batches_submitted = 0
        self.pending_batches = 0
        self.pending_entries = 0
        self.pending_bytes = 0
        self.oversized_batches = 0
        self.session_close = "not-created"
        self.sessions = []
        self.sessions_status = "unknown"
        self.sessions_error = None
        self.knowledge_hits = []
        self.knowledge_search_status = "idle"
        self.knowledge_search_error = None
        self.knowledge_search_notice = None
        self.cycle_log.clear()
        self.clear_analysis()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
