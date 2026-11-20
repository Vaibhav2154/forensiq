"""ForensIQ Textual application - Phase 6 functional pages.

The approved preview shell is preserved: header, sidebar navigation, the four
status cards, the monitoring panel with its three controls, the matched
techniques panel and the live event stream.  Phase 6 fills each navigation
destination with real data from :class:`~cli_agent.services.cli_service.CliService`
instead of repeating one placeholder:

===========================  =============================================
destination                  real content
===========================  =============================================
Dashboard                    auth, ``/health`` probe, monitoring counters,
                             collector sources, last success/error
Monitoring                   controls, interval, sources, submission path,
                             bounded recent-cycle table
Analysis                     ``GET /api/v1/latest`` (or the last live cycle):
                             summary, techniques, enhanced report,
                             investigation and processing time
Knowledge                    ``GET /api/v1/knowledge/stats`` and
                             ``GET /api/v1/knowledge/search``
Sessions                     ``GET /api/v1/monitoring/sessions`` history
Settings                     validated, persisted client configuration and
                             the authenticated account
===========================  =============================================

Deliberate layout additions (all inside the existing regions, recorded in
``PHASE_6_REPORT.md``):

1. a sign-in modal (Phase 4 + 5) because the dashboard has no credential
   widgets;
2. ``l``/``o`` shortcuts next to the untouched preview bindings;
3. page-specific content mounted inside the existing ``#monitor-panel`` and
   ``#technique-panel`` regions (``#page-detail``, ``#settings-form``,
   ``#knowledge-form``, ``#detail-view``).  Panel positions, sizes, borders,
   navigation and shortcuts are unchanged.
"""

from __future__ import annotations

import asyncio
import os
import platform as platform_module
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlsplit

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

from ..services.cli_service import CliService
from ..services.config_service import ClientConfig
from ..services.errors import ConfigurationError, ForensIQError
from ..services.monitoring_service import CycleOutcome, MonitoringState
from ..services.response_adapter import AnalysisView, adapt_analysis
from .state import AppState, BackendStatus, CycleRecord
from .theme import FORENSIQ_THEME, THEME_NAME, rich_colour, theme_variable_defaults

NAV_ITEMS = [
    ("dashboard", "Dashboard", "Operational overview"),
    ("monitoring", "Monitoring", "Collection and submission"),
    ("analysis", "Analysis", "Latest investigation report"),
    ("knowledge", "Knowledge", "ATT&CK / CVE store"),
    ("sessions", "Sessions", "Backend monitoring sessions"),
    ("settings", "Settings", "Profile and endpoint"),
]

VIEW_DESCRIPTIONS = {
    "dashboard": "live status from the service layer",
    "monitoring": "automatic Windows/Linux log collection",
    "analysis": "latest stored analysis",
    "knowledge": "backend knowledge store",
    "sessions": "backend session history",
    "settings": "configuration and account",
}

# Panel headings per destination: (monitor panel, technique panel).
PANEL_HEADINGS = {
    "dashboard": ("MONITORING SESSION", "MATCHED TECHNIQUES"),
    "monitoring": ("COLLECTION STATUS", "RECENT CYCLES"),
    "analysis": ("ANALYSIS", "MATCHED TECHNIQUES"),
    "knowledge": ("KNOWLEDGE STORE", "SEARCH RESULTS"),
    "sessions": ("CURRENT SESSION", "SESSION HISTORY"),
    "settings": ("CONFIGURATION", "ACCOUNT"),
}

TECHNIQUE_ROWS = 25
ROW_LIMIT = 50


class LoginScreen(ModalScreen[bool]):
    """Minimal sign-in modal: username, password, submit, cancel."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, service: CliService) -> None:
        super().__init__()
        self._service = service

    def compose(self) -> ComposeResult:
        with Vertical(id="login-box"):
            yield Label("SIGN IN", classes="panel-title")
            yield Label(f"endpoint  {escape(self._service.config.base_url)}", classes="kv")
            yield Label("username", classes="kv")
            yield Input(placeholder="username", id="login-username")
            yield Label("password", classes="kv")
            yield Input(placeholder="password", password=True, id="login-password")
            yield Label("", id="login-error")
            with Horizontal(id="login-actions"):
                yield Button("Sign in", id="btn-login", variant="success")
                yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        session = self._service.auth.session
        self.query_one("#login-username", Input).value = (session.username or "") if session else ""
        self.query_one("#login-username", Input).focus()

    # -- actions ---------------------------------------------------------
    async def _submit(self) -> None:
        username = self.query_one("#login-username", Input).value.strip()
        password = self.query_one("#login-password", Input).value
        error = self.query_one("#login-error", Label)
        if not username or not password:
            error.update("username and password are required")
            return
        error.update("")
        try:
            await self._service.login(username, password)
        except ForensIQError as exc:
            error.update(escape(str(exc)))
            return
        except Exception as exc:  # noqa: BLE001 - never leak a traceback into the UI
            error.update(f"login failed: {escape(type(exc).__name__)}")
            return
        finally:
            # Never keep the password in a widget after the attempt.
            self.query_one("#login-password", Input).value = ""
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-login":
            self.run_worker(self._submit(), exclusive=True)
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.run_worker(self._submit(), exclusive=True)


class ForensIQApp(App):
    """Functional ForensIQ console with the approved preview layout."""

    TITLE = "ForensIQ"
    SUB_TITLE = "security operations console"
    CSS_PATH = "styles.tcss"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("1", "goto('dashboard')", "Dashboard"),
        ("2", "goto('monitoring')", "Monitoring"),
        ("3", "goto('analysis')", "Analysis"),
        ("4", "goto('knowledge')", "Knowledge"),
        ("5", "goto('sessions')", "Sessions"),
        ("6", "goto('settings')", "Settings"),
        ("s", "start_monitoring", "Start"),
        ("x", "stop_monitoring", "Stop"),
        ("t", "tick", "Force cycle"),
        ("l", "login", "Sign in"),
        ("o", "logout", "Sign out"),
    ]

    def __init__(
        self,
        service: CliService | None = None,
        *,
        restore_session: bool = True,
        auto_probe: bool = True,
    ) -> None:
        super().__init__()
        self.service = service or CliService()
        self._restore_on_start = restore_session
        # Tests disable the periodic ``/health`` probe so their fake transport
        # scripts stay deterministic. Real launches keep it on.
        self._auto_probe = auto_probe
        self.state = AppState()
        self.view = "dashboard"

        # Legacy counters kept in sync for backwards compatibility with the
        # Phase 5 behavioural tests; the state object is authoritative.
        self.events = 0
        self.submitted = 0
        self.techniques_found = 0
        self.cycles = 0

        self._latest: AnalysisView | None = None
        self._table_shape: tuple[str, ...] | None = None
        self._settings_loaded = False
        self._settings_dirty = False
        self._probe_inflight = False
        self._compact = False
        self._closing = False
        self._stream_history: deque[tuple[tuple[str, str], ...]] = deque(maxlen=200)

    # -- layout (approved preview shell, content regions filled per page) --
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Label("FORENSIQ", id="brand")
                yield Label("security operations", id="brand-sub")
                yield ListView(
                    *[
                        ListItem(Label(f"{index + 1}  {label}"), id=f"nav-{key}")
                        for index, (key, label, _desc) in enumerate(NAV_ITEMS)
                    ]
                )
            with Vertical(id="main"):
                yield Label("", id="view-note")
                with Horizontal(id="cards"):
                    yield Static("AUTH\nsigned out", classes="card", id="card-auth")
                    yield Static("BACKEND\nunknown", classes="card", id="card-backend")
                    yield Static("MONITORING\nstopped", classes="card", id="card-mon")
                    yield Static("BATCHES\n0 submitted", classes="card", id="card-batches")
                with Horizontal(id="panels"):
                    with Vertical(id="monitor-panel"):
                        yield Label("MONITORING SESSION", id="monitor-heading", classes="panel-title")
                        yield Static("", id="monitor-detail", classes="kv")
                        with Horizontal(id="controls"):
                            yield Button("Start", id="btn-start", variant="success")
                            yield Button("Stop", id="btn-stop", variant="error")
                            yield Button("Force cycle", id="btn-tick")
                        yield Static(
                            "Client-owned polling. The backend only stores the session row.",
                            id="controls-note",
                            classes="kv",
                        )
                        with VerticalScroll(id="page-detail"):
                            yield Static("", id="page-detail-text", classes="kv")
                            with Vertical(id="settings-form"):
                                yield Label("backend url", classes="field-label")
                                yield Input(placeholder="http://localhost:8000", id="settings-url")
                                yield Label("interval (seconds)", classes="field-label")
                                yield Input(placeholder="300", id="settings-interval")
                                yield Label("max results (1-20)", classes="field-label")
                                yield Input(placeholder="5", id="settings-max-results")
                                yield Label("sources (comma separated, empty = all)", classes="field-label")
                                yield Input(placeholder="auth_logs, syslog", id="settings-sources")
                                yield Checkbox("AI enhancement", id="settings-enhance")
                                yield Button("Save configuration", id="btn-save-settings")
                            with Horizontal(id="knowledge-form"):
                                yield Input(placeholder="search ATT&CK / CVE", id="knowledge-query")
                                yield Button("Search", id="btn-knowledge-search")
                            yield Label("", id="form-error")
                    with Vertical(id="technique-panel"):
                        yield Label("MATCHED TECHNIQUES", id="technique-heading", classes="panel-title")
                        yield DataTable(id="techniques")
                        yield RichLog(id="detail-view", markup=False, wrap=True)
                with Vertical(id="stream-panel"):
                    yield Label("LIVE EVENT STREAM", classes="panel-title")
                    yield RichLog(id="stream", markup=True, wrap=True, max_lines=200)
        yield Footer()

    # -- startup ----------------------------------------------------------
    def on_mount(self) -> None:
        # Register the approved reference palette, then make it the default.
        # An explicit persisted preference (FORENSIQ_THEME or Textual's own
        # TEXTUAL_THEME) wins; otherwise the black theme is applied before the
        # first paint and every widget derives from it.
        self.register_theme(FORENSIQ_THEME)
        self.theme_changed_signal.subscribe(self, self._theme_changed)
        preferred = os.environ.get("FORENSIQ_THEME") or os.environ.get("TEXTUAL_THEME")
        self.theme = preferred if preferred in self.available_themes else THEME_NAME

        table = self.query_one("#techniques", DataTable)
        table.add_columns("ID", "Technique", "Score")
        self._table_shape = ("ID", "Technique", "Score")
        table.cursor_type = "row"
        table.zebra_stripes = True

        self.state.platform = f"{platform_module.system()} {platform_module.release()}"
        self.state.interval_seconds = self.service.config.interval_seconds
        self.state.sources = tuple(self.service.config.sources)

        self._write_stream(("muted", f"forensiq {escape(self.service.config.base_url)}"))
        if self._restore_on_start:
            self._restore_session()
        else:
            self.state.note("not signed in - press l to sign in", "warn")
            self._write_stream(("warn", "not signed in - press l to sign in"))
        self._sync_state()
        self._render_page()

        list_view = self.query_one(ListView)
        list_view.focus()
        list_view.index = 0

        self.set_interval(1.0, self._clock_tick)
        if self._auto_probe:
            self.run_worker(self._refresh_dashboard(), group="view-load", exclusive=True)
            self.set_interval(20.0, self._periodic_probe)

    def _restore_session(self) -> None:
        try:
            session = self.service.restore_session()
        except ForensIQError as exc:
            self._notify(f"cannot restore session: {exc}", "bad")
            self.state.authenticated = False
            return
        if session is None:
            self.state.authenticated = False
            self._notify("not signed in - press l to sign in", "warn")
            return
        self.state.authenticated = True
        self.state.username = session.username
        self._notify(f"session restored as {session.username or 'unknown'}", "ok")

    # -- data loading -----------------------------------------------------
    def _periodic_probe(self) -> None:
        if not self._probe_inflight:
            self.run_worker(self._refresh_dashboard(), group="probe")

    async def _refresh_dashboard(self) -> None:
        await self._probe_backend()
        if self.service.is_authenticated:
            await self._load_profile()
        await self._load_collector_info()
        self._sync_state()
        self._render_page()

    async def _probe_backend(self) -> None:
        if self._probe_inflight:
            return
        self._probe_inflight = True
        started = time.perf_counter()
        try:
            health = await asyncio.wait_for(self.service.backend_health(), timeout=10)
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise
        except Exception as exc:  # noqa: BLE001 - offline is a normal state
            self.state.backend = BackendStatus(
                state="offline",
                detail=self._short_error(exc),
                checked_at=datetime.now(timezone.utc),
            )
        else:
            status = str(health.get("status") or "unknown")
            services = health.get("services") or {}
            self.state.backend = BackendStatus(
                state="degraded" if status == "degraded" else "online",
                detail=f"health {status}",
                services={str(k): str(v) for k, v in services.items()} if isinstance(services, dict) else {},
                latency_ms=(time.perf_counter() - started) * 1000,
                checked_at=datetime.now(timezone.utc),
            )
        finally:
            self._probe_inflight = False
        # An expired token is discovered by the next authenticated call; do not
        # silently mark the user signed in when the service dropped the session.
        self.state.authenticated = self.service.is_authenticated

    async def _load_profile(self) -> None:
        try:
            profile = await self.service.profile()
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:  # noqa: BLE001 - page must render regardless
            self.state.profile_error = self._short_error(exc)
            self.state.authenticated = self.service.is_authenticated
            return
        self.state.profile = profile
        self.state.profile_error = None
        self.state.authenticated = True
        self.state.username = str(profile.get("username") or self.state.username or "")

    async def _load_collector_info(self) -> None:
        try:
            summary = await asyncio.to_thread(self.service.collector_summary)
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:  # noqa: BLE001
            self.state.collector_error = self._short_error(exc)
            return
        self.state.collector_catalogue = list(summary.get("sources") or [])
        self.state.collector_error = summary.get("error")

    async def _load_view(self, key: str) -> None:
        self.state.loading.add(key)
        try:
            if key in ("dashboard", "monitoring", "analysis", "sessions", "settings"):
                await self._probe_backend()
            if key in ("dashboard", "monitoring"):
                await self._load_collector_info()
            if key == "analysis":
                await self._load_analysis()
            elif key == "sessions":
                await self._load_sessions()
            elif key == "knowledge":
                await self._load_knowledge()
            elif key == "settings" and self.service.is_authenticated:
                await self._load_profile()
        finally:
            self.state.loading.discard(key)
            self._sync_state()
            self._render_page()

    async def _load_analysis(self) -> None:
        if not self.service.is_authenticated:
            self.state.analysis_status = "empty"
            self.state.analysis_error = "not authenticated - press l to sign in"
            return
        try:
            payload = await self.service.latest_analysis()
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:  # noqa: BLE001
            self.state.analysis_status = "unavailable"
            self.state.analysis_error = self._short_error(exc)
            return
        if payload is None:
            self.state.analysis_status = "empty"
            self.state.analysis_error = None
            return
        try:
            view = adapt_analysis(payload)
        except ForensIQError as exc:
            self.state.analysis_status = "unavailable"
            self.state.analysis_error = str(exc)
            return
        self._latest = view
        self.state.latest_analysis = view
        self.state.analysis_status = "loaded"
        self.state.analysis_error = None
        self.techniques_found = view.technique_count

    async def _load_sessions(self) -> None:
        if not self.service.is_authenticated:
            self.state.sessions_status = "error"
            self.state.sessions_error = "not authenticated - press l to sign in"
            return
        try:
            rows = await self.service.list_sessions(active_only=False)
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:  # noqa: BLE001
            self.state.sessions_status = "error"
            self.state.sessions_error = self._short_error(exc)
            return
        self.state.sessions = rows
        self.state.sessions_status = "loaded"
        self.state.sessions_error = None

    async def _load_knowledge(self) -> None:
        try:
            stats = await self.service.knowledge_stats()
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:  # noqa: BLE001
            self.state.knowledge_status = "error"
            self.state.knowledge_error = self._short_error(exc)
            return
        self.state.knowledge_stats = stats
        self.state.knowledge_status = "loaded"
        self.state.knowledge_error = None

    async def _run_knowledge_search(self) -> None:
        query = self.query_one("#knowledge-query", Input).value.strip()
        self.query_one("#form-error", Label).update("")
        if not query:
            self.query_one("#form-error", Label).update("enter a search query")
            return
        self.state.knowledge_query = query
        self.state.knowledge_search_status = "searching"
        self._render_page()
        try:
            payload = await self.service.search_knowledge(query, top_k=ROW_LIMIT)
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:  # noqa: BLE001
            self.state.knowledge_search_status = "error"
            self.state.knowledge_search_error = self._short_error(exc)
            self.state.knowledge_hits = []
        else:
            hits = payload.get("hits")
            self.state.knowledge_hits = [row for row in hits if isinstance(row, dict)] if isinstance(hits, list) else []
            self.state.knowledge_search_status = "loaded"
            self.state.knowledge_search_error = None
            self.state.knowledge_search_notice = payload.get("notice") if isinstance(payload.get("notice"), str) else None
        self._render_page()

    # -- state helpers ----------------------------------------------------
    def _sync_state(self) -> None:
        monitoring = self.service.monitoring
        if monitoring is not None:
            self.state.apply_monitoring(monitoring)
            self.cycles = self.state.cycles
            self.submitted = self.state.submitted
            self.events = self.state.collected_entries
        else:
            self.state.apply_monitoring(None)
        self.state.authenticated = self.service.is_authenticated
        self.state.username = self.state.username or (
            self.service.auth.session.username if self.service.auth.session else None
        )
        self.state.interval_seconds = (
            monitoring.interval_seconds
            if monitoring is not None
            else self.service.config.interval_seconds
        )
        self.state.sources = (
            tuple(monitoring.sources)
            if monitoring is not None
            else tuple(self.service.config.sources)
        )

    @staticmethod
    def _short_error(exc: BaseException) -> str:
        text = str(exc).strip()
        return text[:120] if text else type(exc).__name__

    @staticmethod
    def _fmt_time(value: datetime | str | None) -> str:
        if value is None:
            return "No data"
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return value[:19]
        return value.astimezone().strftime("%H:%M:%S")

    def get_theme_variable_defaults(self) -> dict[str, str]:
        """CSS/Markup fallbacks for every theme, including Textual's built-ins.

        Textual calls this whenever it rebuilds the variable table, so the
        `fq-*` variables used by styles.tcss always resolve. FORENSIQ_THEME's
        explicit values still win.
        """
        return theme_variable_defaults(self.current_theme)

    def _colour(self, role: str) -> str:
        """Concrete colour for a Rich markup role in the active theme."""
        return rich_colour(self.current_theme, role)

    def _write_stream(self, *segments: tuple[str, str]) -> None:
        """Append a themed stream line.

        A line is a sequence of ``(role, text)`` segments. Keeping roles rather
        than baked-in colours lets a theme switch recolor the whole backlog.
        """
        self._stream_history.append(tuple(segments))
        self._write_segments(segments)

    def _write_segments(self, segments: tuple[tuple[str, str], ...]) -> None:
        try:
            log = self.query_one("#stream", RichLog)
        except Exception:  # pragma: no cover - during teardown
            return
        markup = " ".join(
            f"[{self._colour(role)}]{text}[/{self._colour(role)}]"
            for role, text in segments
            if text
        )
        if markup:
            log.write(markup)

    def _redraw_stream(self) -> None:
        """Re-render the stream backlog with the active theme's colours."""
        try:
            log = self.query_one("#stream", RichLog)
        except Exception:  # pragma: no cover - during teardown
            return
        log.clear()
        for segments in self._stream_history:
            self._write_segments(segments)

    def _theme_changed(self, _theme) -> None:
        """Textual signal: the whole application must adopt the new theme."""
        if getattr(self, "_closing", False) or not self.is_mounted:
            return
        # The signal is published right after Textual reparses the CSS, so the
        # new variables are ready for Rich markup by the time this runs.
        self.call_after_refresh(self._apply_theme_refresh)

    def _apply_theme_refresh(self) -> None:
        if getattr(self, "_closing", False):
            return
        self._render_page()
        self._redraw_stream()

    def _notify(self, message: str, colour_role: str = "info") -> None:
        """Operational feedback: shared state + the existing event stream."""
        self.state.note(message, colour_role)
        role = colour_role if colour_role in ("ok", "warn", "bad", "info") else "info"
        stamp = datetime.now().strftime("%H:%M:%S")
        self._write_stream(("muted", stamp), (role, escape(message)))

    # -- rendering --------------------------------------------------------
    def _render_page(self) -> None:
        if self._closing:
            return
        st = self.state
        try:
            self.query_one("#view-note", Label).update(self._view_note())
            monitor_heading, technique_heading = PANEL_HEADINGS.get(
                self.view, PANEL_HEADINGS["dashboard"]
            )
            self.query_one("#monitor-heading", Label).update(monitor_heading)
            self.query_one("#technique-heading", Label).update(technique_heading)
            self._render_cards()
            self.query_one("#monitor-detail", Static).update(self._monitor_markup())
            self.query_one("#page-detail-text", Static).update(self._detail_markup())
            self.query_one("#stream-panel").display = self.view in ("dashboard", "monitoring") and not self._compact
            self.query_one("#settings-form").display = self.view == "settings"
            self.query_one("#knowledge-form").display = self.view == "knowledge"
            self._fill_forms()
            self._render_table()
            self._render_detail_view()
            self._update_buttons()
        except Exception:  # pragma: no cover - widgets missing only during teardown
            pass

    def _render_cards(self) -> None:
        st = self.state
        backend = st.backend
        backend_colour = {"online": self._colour('ok'), "degraded": self._colour('warn'), "offline": self._colour('bad')}.get(backend.state, self._colour('muted'))
        host = urlsplit(self.service.config.base_url).netloc or self.service.config.base_url
        latency = f" ({backend.latency_ms:.0f}ms)" if backend.latency_ms is not None else ""
        auth_text = escape(st.username) if st.username else "signed out"
        auth_colour = self._colour('ok') if st.authenticated else self._colour('warn')
        state_colour = {
            "running": self._colour('ok'),
            "starting": self._colour('info'),
            "stopping": self._colour('warn'),
            "error": self._colour('bad'),
        }.get(st.monitoring_state, self._colour('warn'))

        self.query_one("#card-auth", Static).update(
            f"[{self._colour('muted')}]AUTH[/{self._colour('muted')}]\n[{auth_colour}]{auth_text}[/{auth_colour}]"
        )
        self.query_one("#card-backend", Static).update(
            f"[{self._colour('muted')}]BACKEND[/{self._colour('muted')}]\n[{backend_colour}]{backend.label}{latency}[/{backend_colour}] {escape(host)}"
        )
        self.query_one("#card-mon", Static).update(
            f"[{self._colour('muted')}]MONITORING[/{self._colour('muted')}]\n[{state_colour}]{st.monitoring_state}[/{state_colour}]"
        )
        self.query_one("#card-batches", Static).update(
            f"[{self._colour('muted')}]BATCHES[/{self._colour('muted')}]\n{st.submitted} submitted"
        )

    def _source_label(self) -> str:
        if self.state.sources:
            return f"{len(self.state.sources)} selected: " + ", ".join(self.state.sources[:3]) + (
                "..." if len(self.state.sources) > 3 else ""
            )
        catalogue = [str(source.get("id")) for source in self.state.collector_catalogue]
        if catalogue:
            return f"all {len(catalogue)}: " + ", ".join(catalogue[:3]) + (
                "..." if len(catalogue) > 3 else ""
            )
        return "Unknown"

    def _submission_label(self) -> str:
        if not self.state.authenticated:
            return "not authenticated - local only"
        if self.state.backend.state == "offline":
            return "backend offline - not submitting"
        if self.state.backend.state in ("online", "degraded"):
            return f"submitting to {urlsplit(self.service.config.base_url).netloc or 'backend'}"
        return "Unknown - backend not probed"

    def _monitor_markup(self) -> str:
        st = self.state
        state_colour = {
            "running": self._colour('ok'),
            "starting": self._colour('info'),
            "stopping": self._colour('warn'),
            "error": self._colour('bad'),
        }.get(st.monitoring_state, self._colour('warn'))
        lines = [
            f"state        [{state_colour}]{st.monitoring_state}[/{state_colour}]",
            f"session id   {escape(st.session_id) if st.session_id else 'No data'}",
            f"interval     {st.interval_seconds}s",
        ]
        if self.view == "dashboard":
            lines += [
                f"backend      {st.backend.label}",
                f"sources      {escape(self._source_label())}",
                f"cycles       {st.cycles} ({st.submitted} submitted, {st.empty_cycles} empty)",
                f"batches      {st.batches_submitted} sent, {st.pending_batches} pending",
                f"failures     {st.failures}",
                f"last success {self._fmt_time(st.last_success_at)}",
                f"last error   {escape(st.last_error[:40]) if st.last_error else '-'}",
            ]
        elif self.view == "monitoring":
            pending = (
                f"{st.pending_batches} batch(es), {st.pending_entries} event(s)"
                if st.pending_batches
                else "none"
            )
            lines += [
                f"submission   {escape(self._submission_label())}",
                f"sources      {escape(self._source_label())}",
                f"cycles       {st.cycles}",
                f"empty        {st.empty_cycles}",
                f"failures     {st.failures}",
                f"last cycle   {st.last_cycle_entries} event(s)",
                f"pending      {escape(pending)}",
                f"session stop {escape(st.session_close)}",
                f"oversized    {st.oversized_batches} batch(es) cut mid-event",
                f"last error   {escape(st.last_error[:40]) if st.last_error else '-'}",
            ]
        elif self.view == "analysis":
            view = st.latest_analysis
            lines += [
                f"status       {escape(st.analysis_status)}",
                f"techniques   {view.technique_count if view else 'No data'}",
                f"processing   {f'{view.processing_time_ms:.0f}ms' if view and view.processing_time_ms is not None else 'No data'}",
                f"investigation {'available' if view and view.has_investigation else ('absent' if view else 'No data')}",
                f"metrics      {len(view.visualization_metrics or {}) if view else 'No data'} key(s)",
            ]
        elif self.view == "knowledge":
            stats = st.knowledge_stats
            kinds = stats.get("counts_by_kind") or {}
            kind_text = ", ".join(f"{k} {v}" for k, v in list(kinds.items())[:2]) or "No data"
            lines += [
                f"status       {escape(st.knowledge_status)}",
                f"backend      {escape(str(stats.get('backend') or 'Unknown'))}",
                f"records      {stats.get('total_records', 'No data')}",
                f"kinds        {escape(kind_text)}",
                f"last ingest  {self._fmt_time(stats.get('last_ingested_at'))}",
            ]
        elif self.view == "sessions":
            lines += [
                f"backend rows {len(st.sessions)}",
                f"history      {escape(st.sessions_status)}",
                f"monitoring   {st.monitoring_state}",
            ]
        else:  # settings
            profile = st.profile
            lines += [
                f"endpoint     {escape(self.service.config.base_url)}",
                f"account      {escape(str(profile.get('username') or st.username or 'not authenticated'))}",
                f"email        {escape(str(profile.get('email') or '-'))}",
                f"max results  {self.service.config.max_results}",
                f"ai enhance   {'on' if self.service.config.enhance_with_ai else 'off'}",
            ]
        if st.loading:
            lines.append(f"[{self._colour('info')}]loading {escape(', '.join(sorted(st.loading)))}...[/{self._colour('info')}]")
        return "\n".join(lines)

    def _detail_markup(self) -> str:
        st = self.state
        if self.view == "dashboard":
            services = st.backend.services
            summary = (
                ", ".join(f"{k}: {v}" for k, v in list(services.items())[:4])
                if services
                else "No data"
            )
            lines = [
                f"[{self._colour('muted')}]health[/{self._colour('muted')}]       {escape(summary)}",
                f"[{self._colour('muted')}]platform[/{self._colour('muted')}]     {escape(st.platform or 'Unknown')}",
                f"[{self._colour('muted')}]collected[/{self._colour('muted')}]    {st.collected_entries} event(s)",
                f"[{self._colour('muted')}]submitted[/{self._colour('muted')}]    {st.submitted_entries} event(s)",
            ]
            if st.collector_error:
                lines.append(f"[{self._colour('bad')}]collector: {escape(st.collector_error[:60])}[/{self._colour('bad')}]")
            return "\n".join(lines)
        if self.view == "monitoring":
            recent = list(st.events)[-3:]
            lines = [f"[{self._colour('muted')}]next cycle in {st.interval_seconds}s while running[/{self._colour('muted')}]"]
            for event in recent:
                lines.append(
                    f"[{self._colour('muted')}]{event.at.strftime('%H:%M:%S')}[/{self._colour('muted')}] {escape(event.message[:52])}"
                )
            return "\n".join(lines)
        if self.view == "analysis":
            if st.analysis_error:
                return f"[{self._colour('bad')}]{escape(st.analysis_error)}[/{self._colour('bad')}]"
            if st.latest_analysis is None:
                return (
                    "No analysis available.\n\n"
                    "Start monitoring (s) to submit a batch, or place a stored\n"
                    "analysis on the backend. Nothing is fabricated here."
                )
            stamp = st.latest_analysis.raw.get("analysis_timestamp") if st.latest_analysis.raw else None
            captured = self._fmt_time(stamp if isinstance(stamp, str) else None)
            return f"[{self._colour('muted')}]source[/{self._colour('muted')}] backend /api/v1/latest\n[{self._colour('muted')}]captured[/{self._colour('muted')}] {escape(captured)}"
        if self.view == "knowledge":
            if st.knowledge_error:
                return f"[{self._colour('bad')}]{escape(st.knowledge_error)}[/{self._colour('bad')}]"
            return (
                "Search the backend knowledge store. The CLI never invents\n"
                "records: an empty store returns zero hits."
            )
        if self.view == "sessions":
            if st.sessions_error:
                return f"[{self._colour('bad')}]{escape(st.sessions_error)}[/{self._colour('bad')}]"
            return (
                "Session rows are owned by the backend. Started/stopped times\n"
                "come from the API response; no local history is kept."
            )
        return "Edit the fields below and save. Values are validated before\nany file is written; the token store is never touched."

    def _view_note(self) -> str:
        st = self.state
        base = VIEW_DESCRIPTIONS.get(self.view, "")
        detail = ""
        if self.view == "dashboard":
            detail = f"backend {st.backend.label} - monitoring {st.monitoring_state}"
        elif self.view == "monitoring":
            detail = self._submission_label()
        elif self.view == "analysis":
            detail = f"{st.analysis_status}"
        elif self.view == "knowledge":
            total = st.knowledge_stats.get("total_records")
            detail = f"{total} record(s)" if total is not None else st.knowledge_status
        elif self.view == "sessions":
            detail = f"{len(st.sessions)} row(s)"
        elif self.view == "settings":
            sources = ", ".join(self.service.config.sources) or "all available"
            detail = (
                f"interval {self.service.config.interval_seconds}s - "
                f"max results {self.service.config.max_results} - "
                f"ai {'on' if self.service.config.enhance_with_ai else 'off'} - "
                f"sources: {sources}"
            )
        return (
            f"[b]{self.view.capitalize()}[/b]  [dim]{escape(base)}"
            + (f" - {escape(detail)}" if detail else "")
            + "[/dim]"
        )

    # -- tables -----------------------------------------------------------
    def _set_columns(self, table: DataTable, columns: tuple[str, ...]) -> None:
        if self._table_shape == columns:
            return
        table.clear(columns=True)
        table.add_columns(*columns)
        self._table_shape = columns

    def _render_table(self) -> None:
        table = self.query_one("#techniques", DataTable)
        if self.view in ("dashboard", "analysis"):
            self._set_columns(table, ("ID", "Technique", "Score"))
            table.clear(columns=False)
            view = self.state.latest_analysis
            if view is None or not view.techniques:
                table.add_row("-", "no techniques in the latest batch", "-")
            else:
                for technique in view.techniques[:TECHNIQUE_ROWS]:
                    score = (
                        f"{technique.relevance_score:.2f}"
                        if isinstance(technique.relevance_score, float)
                        else "-"
                    )
                    table.add_row(
                        escape(technique.technique_id or "-"),
                        escape(technique.name or "-"),
                        score,
                    )
        elif self.view == "monitoring":
            self._set_columns(table, ("Cycle", "Events", "Result", "Time"))
            table.clear(columns=False)
            if not self.state.cycle_log:
                table.add_row("-", "-", "no cycles yet", "-")
            else:
                for record in list(self.state.cycle_log)[-ROW_LIMIT:][::-1]:
                    result = "submitted" if record.submitted else (record.error or "empty")
                    table.add_row(
                        str(record.cycle),
                        str(record.entries),
                        escape(result[:28]),
                        record.at.strftime("%H:%M:%S"),
                    )
        elif self.view == "knowledge":
            self._set_columns(table, ("ID", "Name", "Score"))
            table.clear(columns=False)
            if self.state.knowledge_search_status == "error":
                table.add_row(
                    "-",
                    escape((self.state.knowledge_search_error or "search failed")[:40]),
                    "-",
                )
            elif not self.state.knowledge_hits:
                table.add_row("-", "no knowledge records returned", "-")
            else:
                for hit in self.state.knowledge_hits[:ROW_LIMIT]:
                    record = hit.get("record") if isinstance(hit.get("record"), dict) else {}
                    content = record.get("content") if isinstance(record.get("content"), dict) else {}
                    name = content.get("name") or content.get("title") or record.get("source_id")
                    score = hit.get("score")
                    table.add_row(
                        escape(str(record.get("source_id") or "-")[:20]),
                        escape(str(name or "-")[:40]),
                        f"{float(score):.2f}" if isinstance(score, (int, float)) else "-",
                    )
        elif self.view == "sessions":
            self._set_columns(table, ("Session", "Status", "Started", "Stopped"))
            table.clear(columns=False)
            if self.state.sessions_status == "error":
                table.add_row("-", escape((self.state.sessions_error or "error")[:30]), "-", "-")
            elif not self.state.sessions:
                table.add_row("-", "no sessions returned", "-", "-")
            else:
                for row in self.state.sessions[:ROW_LIMIT]:
                    table.add_row(
                        escape(str(row.get("session_id") or "-")[:12]),
                        escape(str(row.get("status") or "-")),
                        self._fmt_time(row.get("created_at")),
                        self._fmt_time(row.get("stopped_at")) if row.get("stopped_at") else "-",
                    )
        else:  # settings
            self._set_columns(table, ("Setting", "Value"))
            table.clear(columns=False)
            config = self.service.config
            for key, value in (
                ("backend url", config.base_url),
                ("interval", f"{config.interval_seconds}s"),
                ("max results", str(config.max_results)),
                ("ai enhancement", "on" if config.enhance_with_ai else "off"),
                ("monitoring type", config.monitoring_type),
                ("sources", ", ".join(config.sources) or "all available"),
                ("account", self.state.username or "not authenticated"),
            ):
                table.add_row(escape(key), escape(str(value)))

    def _render_detail_view(self) -> None:
        detail = self.query_one("#detail-view", RichLog)
        table = self.query_one("#techniques", DataTable)
        text = self._long_text()
        if text is None:
            detail.display = False
            table.styles.height = "1fr"
            return
        detail.display = True
        table.styles.height = 12
        detail.clear()
        detail.write(text)

    def _long_text(self) -> str | None:
        st = self.state
        if self.view == "analysis":
            if st.analysis_error:
                return f"ANALYSIS UNAVAILABLE\n\n{st.analysis_error}\n"
            view = st.latest_analysis
            if view is None:
                return None
            blocks = ["SUMMARY", view.summary or "(backend returned no summary)", ""]
            if view.enhanced_analysis:
                blocks += ["ENHANCED ANALYSIS", view.enhanced_analysis, ""]
            else:
                blocks += [
                    "ENHANCED ANALYSIS",
                    "Not provided. The backend only fills this when AI enhancement "
                    "is enabled and a Gemini credential is configured.",
                    "",
                ]
            investigation = view.investigation
            if isinstance(investigation, dict) and investigation:
                blocks.append("INVESTIGATION")
                for key in ("executive_summary", "rendered_summary", "summary"):
                    value = investigation.get(key)
                    if isinstance(value, str) and value.strip():
                        blocks.append(value.strip())
                        break
                findings = investigation.get("findings")
                if isinstance(findings, list):
                    blocks.append(f"{len(findings)} finding(s) recorded.")
                blocks.append("")
            if view.visualization_metrics:
                blocks.append(
                    "VISUALIZATION METRICS\n"
                    + ", ".join(sorted(view.visualization_metrics.keys()))
                )
            return "\n".join(blocks)
        if self.view == "knowledge":
            stats = st.knowledge_stats
            if st.knowledge_error:
                return f"KNOWLEDGE STORE UNAVAILABLE\n\n{st.knowledge_error}\n"
            lines = [
                "BACKEND KNOWLEDGE STORE",
                "",
                f"backend          {stats.get('backend', 'Unknown')}",
                f"total records    {stats.get('total_records', 'No data')}",
                f"ingestion runs   {stats.get('total_ingestion_runs', 'No data')}",
                f"last ingested    {stats.get('last_ingested_at') or 'No data'}",
                "",
                "WHAT IS AVAILABLE",
                "The backend exposes /api/v1/knowledge/{stats,search,ingest/*}.",
                "Search results are retrieved ATT&CK/CVE context only - never",
                "proof of compromise. Ingestion from the CLI is not implemented",
                "and is not faked here.",
            ]
            notice = getattr(st, "knowledge_search_notice", None)
            if notice:
                lines += ["", str(notice)]
            return "\n".join(lines)
        if self.view == "monitoring" and st.last_error:
            return f"LAST ERROR\n\n{st.last_error}\n"
        return None

    def _fill_forms(self) -> None:
        config = self.service.config
        form = self.query_one("#settings-form")
        if self.view == "settings" and not self._settings_dirty and not self._settings_loaded:
            self.query_one("#settings-url", Input).value = config.base_url
            self.query_one("#settings-interval", Input).value = str(config.interval_seconds)
            self.query_one("#settings-max-results", Input).value = str(config.max_results)
            self.query_one("#settings-sources", Input).value = ", ".join(config.sources)
            self.query_one("#settings-enhance", Checkbox).value = config.enhance_with_ai
            self._settings_loaded = True
        elif self.view != "settings":
            self._settings_loaded = False
            self._settings_dirty = False
        form.display = self.view == "settings"

    def _update_buttons(self) -> None:
        state = self.state.monitoring_state
        running = state in ("running", "starting")
        self.query_one("#btn-start", Button).disabled = running
        self.query_one("#btn-stop", Button).disabled = state == "stopped"

    # -- monitoring callbacks (delivered from the service loop task) ------
    def _on_state_change(self, state: MonitoringState) -> None:
        self.call_later(self._render_state, state)

    def _render_state(self, state: MonitoringState) -> None:
        self._notify(
            f"monitoring {state.value}", "ok" if state is MonitoringState.RUNNING else "warn"
        )
        self._sync_state()
        self._render_page()

    def _on_cycle(self, outcome: CycleOutcome) -> None:
        self.call_later(self._apply_cycle, outcome)

    def _apply_cycle(self, outcome: CycleOutcome) -> None:
        self.state.record_cycle(
            CycleRecord(
                cycle=outcome.cycle,
                entries=outcome.collected_entries,
                submitted=outcome.submitted,
                error=outcome.error,
                at=datetime.now(),
            )
        )
        self._sync_state()
        self._refresh_live()

    def _on_result(self, view: AnalysisView, outcome: CycleOutcome) -> None:
        self.call_later(self._apply_result, view, outcome)

    def _apply_result(self, view: AnalysisView, outcome: CycleOutcome) -> None:
        self._latest = view
        self.state.latest_analysis = view
        self.state.analysis_status = "loaded"
        self.state.analysis_error = None
        self.techniques_found = view.technique_count
        self._sync_state()
        self._refresh_live()

        stamp = datetime.now().strftime("%H:%M:%S")
        summary = (view.summary or "").strip().replace("\n", " ")
        detail = f" - {escape(summary)[:70]}" if summary else ""
        self._write_stream(
            ("muted", stamp),
            ("info", f"cycle {outcome.cycle}"),
            ("text", f"{outcome.collected_entries} event(s) submitted{detail}"),
        )
        for technique in view.techniques[:3]:
            label = technique.technique_id or "?"
            name = technique.name or "unnamed"
            score = (
                f" ({technique.relevance_score:.2f})"
                if isinstance(technique.relevance_score, float)
                else ""
            )
            self._write_stream(("muted", f"             {escape(label)} {escape(name)}{score}"))
        if view.summary:
            self._notify(f"analysis: {view.summary.strip()[:90]}", "info")

    def _on_error(self, exc: Exception, outcome: CycleOutcome | None) -> None:
        self.call_later(self._render_error, exc, outcome)

    def _render_error(self, exc: Exception, outcome: CycleOutcome | None) -> None:
        self._notify(f"backend error: {self._short_error(exc)}", "bad")
        self._sync_state()
        self._refresh_live()

    def _refresh_live(self) -> None:
        """Update live values without disturbing text inputs."""
        if self._closing:
            return
        try:
            self._render_cards()
            self.query_one("#monitor-detail", Static).update(self._monitor_markup())
            self.query_one("#page-detail-text", Static).update(self._detail_markup())
            self._update_buttons()
            if self.view in ("dashboard", "monitoring", "analysis"):
                self._render_table()
                self._render_detail_view()
            self.query_one("#view-note", Label).update(self._view_note())
        except Exception:  # pragma: no cover - teardown
            pass

    # -- terminal size ----------------------------------------------------
    def on_resize(self, event) -> None:
        """Keep the shell usable on short terminals without moving anything.

        Below 30 rows the 12-row event stream is hidden so the panels keep a
        scrollable height; below 100 columns the fixed 44-column monitor panel
        narrows to 34. Neither change touches the approved 120x40 layout.
        """
        self._compact = event.size.height < 30 or event.size.width < 90
        try:
            self.query_one("#monitor-panel").styles.width = 34 if event.size.width < 100 else 44
            self.query_one("#stream-panel").display = (
                self.view in ("dashboard", "monitoring") and not self._compact
            )
        except Exception:  # pragma: no cover - during mount/teardown
            pass

    # -- clock ------------------------------------------------------------
    def _clock_tick(self) -> None:
        if self.service.monitoring is not None or self.state.monitoring_state != "stopped":
            self._sync_state()
            self._refresh_live()

    # -- actions ----------------------------------------------------------
    def action_goto(self, key: str) -> None:
        self.view = key
        list_view = self.query_one(ListView)
        for index, (nav_key, _label, _desc) in enumerate(NAV_ITEMS):
            if nav_key == key:
                list_view.index = index
                break
        self._sync_state()
        self._render_page()
        self.run_worker(self._load_view(key), group="view-load", exclusive=True)

    def action_login(self) -> None:
        if self.service.is_authenticated:
            self._notify("already signed in", "warn")
            return
        self.push_screen(LoginScreen(self.service), self._login_finished)

    def _login_finished(self, success: bool | None) -> None:
        if not success:
            self._notify("login cancelled", "warn")
            self._sync_state()
            self._render_page()
            return
        self.state.authenticated = True
        self.state.username = self.service.auth.session.username if self.service.auth.session else None
        self._notify(f"signed in as {self.state.username or 'unknown'}", "ok")
        self._sync_state()
        self._render_page()
        self.run_worker(self._refresh_dashboard(), group="view-load", exclusive=True)

    async def action_logout(self) -> None:
        if self.service.monitoring is not None:
            try:
                await asyncio.wait_for(self.service.stop_monitoring(), timeout=15)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001 - logout must not block
                pass
        self.service.logout()
        self.state.reset_for_logout()
        self._latest = None
        self._notify("signed out; local token discarded", "warn")
        self._sync_state()
        self._render_page()

    async def action_start_monitoring(self) -> None:
        monitoring = self.service.monitoring
        if monitoring is not None and monitoring.state in (
            MonitoringState.STARTING,
            MonitoringState.RUNNING,
        ):
            self._notify("monitoring is already running", "warn")
            return
        if not self.service.is_authenticated:
            self._notify("authentication required - press l to sign in", "bad")
            return

        config = self.service.config
        try:
            await self.service.start_monitoring(
                interval=config.interval_seconds,
                sources=list(config.sources) or None,
                on_state_change=self._on_state_change,
                on_result=self._on_result,
                on_error=self._on_error,
                on_cycle=self._on_cycle,
            )
        except ForensIQError as exc:
            self._notify(f"cannot start monitoring: {exc}", "bad")
            return
        except Exception as exc:  # noqa: BLE001 - UI must survive anything here
            self._notify(f"cannot start monitoring: {type(exc).__name__}", "bad")
            return

        self.cycles = 0
        self.events = 0
        self.submitted = 0
        self.techniques_found = 0
        self.state.cycle_log.clear()
        self._sync_state()
        self._notify("monitoring started", "ok")
        self._render_page()

    async def action_stop_monitoring(self) -> None:
        if self.service.monitoring is None:
            self._notify("monitoring is not running", "warn")
            return
        try:
            await asyncio.wait_for(self.service.stop_monitoring(), timeout=15)
        except asyncio.TimeoutError:
            self._notify("monitoring stop timed out; backend session may still be open", "bad")
        except Exception as exc:  # noqa: BLE001 - a failed stop must not crash the app
            self._notify(f"monitoring stop failed: {exc}", "bad")
        else:
            self._notify("monitoring stopped", "warn")
        self._sync_state()
        self._render_page()

    async def action_tick(self) -> None:
        monitoring = self.service.monitoring
        if monitoring is None or monitoring.state is not MonitoringState.RUNNING:
            self._notify("start monitoring first (press s)", "warn")
            return
        try:
            outcome = await monitoring.force_cycle()
        except Exception as exc:  # noqa: BLE001 - manual cycle is best effort
            self._notify(f"force cycle failed: {exc}", "bad")
            return
        if outcome is None:
            self._notify("monitoring is not running", "warn")

    # -- settings ---------------------------------------------------------
    def _save_settings(self) -> None:
        error_label = self.query_one("#form-error", Label)
        error_label.update("")
        try:
            url = self.query_one("#settings-url", Input).value.strip().rstrip("/")
            if not url.lower().startswith(("http://", "https://")):
                raise ConfigurationError("backend url must start with http:// or https://")
            try:
                interval = int(self.query_one("#settings-interval", Input).value.strip())
                max_results = int(self.query_one("#settings-max-results", Input).value.strip())
            except ValueError as exc:
                raise ConfigurationError("interval and max results must be whole numbers") from exc
            raw_sources = [
                part.strip()
                for part in self.query_one("#settings-sources", Input).value.split(",")
                if part.strip()
            ]
            sources = self.service.collector.validate_sources(raw_sources) if raw_sources else ()
            enhance = self.query_one("#settings-enhance", Checkbox).value
            config: ClientConfig = self.service.configure_monitoring(
                base_url=url,
                interval_seconds=interval,
                max_results=max_results,
                sources=tuple(sources),
                enhance_with_ai=bool(enhance),
            )
        except ForensIQError as exc:
            error_label.update(escape(str(exc)))
            return
        except Exception as exc:  # noqa: BLE001 - validation must never crash the UI
            error_label.update(escape(f"cannot save: {type(exc).__name__}"))
            return
        self._settings_loaded = False
        self._settings_dirty = False
        self._notify(
            f"configuration saved: {config.base_url} every {config.interval_seconds}s",
            "ok",
        )
        self._sync_state()
        self._render_page()
        self.run_worker(self._refresh_dashboard(), group="view-load", exclusive=True)

    # -- shutdown ---------------------------------------------------------
    async def _close_service(self) -> None:
        """Cancel monitoring and close HTTP, bounded so exit cannot hang.

        Deliberately *not* named ``_shutdown``: that is a Textual ``App``
        internal, and overriding it skips the framework's own teardown.
        """
        if self._closing:
            return
        self._closing = True
        self._write_stream(("muted", "shutting down..."))
        try:
            await asyncio.wait_for(self.service.close(), timeout=15)
        except asyncio.TimeoutError:
            pass
        except Exception:  # noqa: BLE001 - shutdown is best effort by design
            pass

    async def on_unmount(self) -> None:
        await self._close_service()

    # -- events -----------------------------------------------------------
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("nav-"):
            self.action_goto(item_id.removeprefix("nav-"))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id and event.input.id.startswith("settings-"):
            self._settings_dirty = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-start":
            self.run_worker(self.action_start_monitoring(), exclusive=True)
        elif button_id == "btn-stop":
            self.run_worker(self.action_stop_monitoring(), exclusive=True)
        elif button_id == "btn-tick":
            self.run_worker(self.action_tick(), exclusive=True)
        elif button_id == "btn-save-settings":
            self._save_settings()
        elif button_id == "btn-knowledge-search":
            self.run_worker(self._run_knowledge_search(), exclusive=True)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "knowledge-query":
            self.run_worker(self._run_knowledge_search(), exclusive=True)


def main() -> None:
    ForensIQApp().run()


if __name__ == "__main__":
    main()
