"""ForensIQ Textual application (Phase 4 + 5).

The compose tree is the approved preview layout, unchanged: header, sidebar,
four status cards, the monitoring panel with its three controls, the matched
techniques table and the live event stream. Only colours (``styles.tcss``) and
behaviour (real services) differ.

Deliberate exceptions to "do not change the layout", all required for
functionality and recorded in ``COMBINED_PHASE_4_5_REPORT.md``:

1. a modal sign-in screen (Textual ``ModalScreen``) because the backend issues
   JWTs through ``POST /login`` and the dashboard has no credential widgets;
2. ``l`` (sign in) and ``o`` (sign out) key bindings, added alongside the
   existing shortcuts, which are otherwise untouched.

Analysis, knowledge and sessions remain placeholders: selecting them only
updates the existing view-note label.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from urllib.parse import urlsplit

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
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
from ..services.errors import ForensIQError
from ..services.monitoring_service import CycleOutcome, MonitoringState
from ..services.response_adapter import AnalysisView

NAV_ITEMS = [
    ("dashboard", "Dashboard", "Operational overview"),
    ("monitoring", "Monitoring", "Collection and submission"),
    ("analysis", "Analysis", "Latest investigation report"),
    ("knowledge", "Knowledge", "ATT&CK / CVE store"),
    ("sessions", "Sessions", "Backend monitoring sessions"),
    ("settings", "Settings", "Profile and endpoint"),
]

VIEW_DESCRIPTIONS = {
    "analysis": "placeholder - reporting arrives in a later phase",
    "knowledge": "placeholder - ATT&CK / CVE browsing arrives in a later phase",
    "sessions": "placeholder - backend session history arrives in a later phase",
}

# Colour roles, mirrored in styles.tcss. Kept here because RichLog markup
# cannot use the Textual CSS variables.
OK = "#39FF88"
WARN = "#E5B94B"
BAD = "#F06464"
INFO = "#5CC8D7"
MUTED = "#91A598"
TECHNIQUE_ROWS = 25


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
    """Functional ForensIQ dashboard with the approved preview layout."""

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
    ) -> None:
        super().__init__()
        self.service = service or CliService()
        self._restore_on_start = restore_session
        self.view = "dashboard"
        self.events = 0
        self.submitted = 0
        self.techniques_found = 0
        self.cycles = 0
        self._latest: AnalysisView | None = None
        self._closing = False

    # -- layout (unchanged from the approved preview) ---------------------
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
                with Horizontal():
                    yield Static("AUTH\nsigned out", classes="card")
                    yield Static("BACKEND\n-", classes="card")
                    yield Static("MONITORING\nstopped", classes="card", id="card-mon")
                    yield Static("BATCHES\n0 submitted", classes="card", id="card-batches")
                with Horizontal(id="panels"):
                    with Vertical(id="monitor-panel"):
                        yield Label("MONITORING SESSION", classes="panel-title")
                        yield Static("", id="monitor-detail", classes="kv")
                        with Horizontal(id="controls"):
                            yield Button("Start", id="btn-start", variant="success")
                            yield Button("Stop", id="btn-stop", variant="error")
                            yield Button("Force cycle", id="btn-tick")
                        yield Static(
                            "Client-owned polling. The backend only stores the session row.",
                            classes="kv",
                        )
                    with Vertical(id="technique-panel"):
                        yield Label("MATCHED TECHNIQUES", classes="panel-title")
                        yield DataTable(id="techniques")
                with Vertical(id="stream-panel"):
                    yield Label("LIVE EVENT STREAM", classes="panel-title")
                    yield RichLog(id="stream", markup=True, wrap=True, max_lines=200)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#techniques", DataTable)
        table.add_columns("ID", "Technique", "Score")
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_row("-", "no analysis yet", "-")

        self._write_stream(f"[{MUTED}]forensiq {escape(self.service.config.base_url)}[/{MUTED}]")
        if self._restore_on_start:
            self._restore_session()
        else:
            self._write_stream(f"[{WARN}]not signed in - press l to sign in[/{WARN}]")
        self._refresh_panels()

        list_view = self.query_one(ListView)
        list_view.focus()
        list_view.index = 0

        self.set_interval(1.0, self._clock_tick)

    # -- session ----------------------------------------------------------
    def _restore_session(self) -> None:
        try:
            session = self.service.restore_session()
        except ForensIQError as exc:
            self._write_stream(f"[{BAD}]cannot restore session: {escape(str(exc))}[/{BAD}]")
            return
        if session is None:
            self._write_stream(f"[{WARN}]not signed in - press l to sign in[/{WARN}]")
            return
        self._write_stream(
            f"[{OK}]session restored[/{OK}] as {escape(session.username or 'unknown')}"
        )

    def _current_username(self) -> str | None:
        session = self.service.auth.session
        return session.username if session else None

    # -- rendering --------------------------------------------------------
    def _write_stream(self, markup: str) -> None:
        try:
            self.query_one("#stream", RichLog).write(markup)
        except Exception:  # pragma: no cover - during teardown
            pass

    def _notify(self, message: str, colour_role: str = "info") -> None:
        """Operational feedback in the existing event stream."""
        colour = {"ok": OK, "warn": WARN, "bad": BAD, "info": INFO}.get(colour_role, INFO)
        stamp = datetime.now().strftime("%H:%M:%S")
        self._write_stream(f"[{MUTED}]{stamp}[/{MUTED}] [{colour}]{escape(message)}[/{colour}]")

    def _refresh_panels(self) -> None:
        monitoring = self.service.monitoring
        state = monitoring.state if monitoring is not None else MonitoringState.STOPPED
        state_colour = {
            MonitoringState.RUNNING: OK,
            MonitoringState.STARTING: INFO,
            MonitoringState.STOPPING: WARN,
            MonitoringState.ERROR: BAD,
        }.get(state, WARN)

        username = self._current_username()
        auth_text = escape(username) if username else "signed out"
        auth_colour = OK if username else WARN
        host = urlsplit(self.service.config.base_url).netloc or self.service.config.base_url

        cards = self.query(".card")
        if len(cards) >= 2:
            cards[0].update(f"[{MUTED}]AUTH[/{MUTED}]\n[{auth_colour}]{auth_text}[/{auth_colour}]")
            cards[1].update(f"[{MUTED}]BACKEND[/{MUTED}]\n{escape(host)}")
        self.query_one("#card-mon", Static).update(
            f"[{MUTED}]MONITORING[/{MUTED}]\n[{state_colour}]{state.value}[/{state_colour}]"
        )
        self.query_one("#card-batches", Static).update(
            f"[{MUTED}]BATCHES[/{MUTED}]\n{self.submitted} submitted"
        )

        session_id = monitoring.stats.session_id if monitoring is not None else None
        interval = monitoring.interval_seconds if monitoring is not None else self.service.config.interval_seconds
        last_error = monitoring.stats.last_error if monitoring is not None else None

        detail = (
            f"state        [{state_colour}]{state.value}[/{state_colour}]\n"
            f"session id   {escape(session_id) if session_id else '-'}\n"
            f"interval     {interval}s\n"
            f"cycles       {self.cycles}\n"
            f"events       {self.events}\n"
            f"techniques   {self.techniques_found}"
        )
        if last_error:
            detail += f"\n[{BAD}]last error   {escape(last_error)[:60]}[/{BAD}]"
        self.query_one("#monitor-detail", Static).update(detail)

        running = state in (MonitoringState.RUNNING, MonitoringState.STARTING)
        self.query_one("#btn-start", Button).disabled = running
        self.query_one("#btn-stop", Button).disabled = state is MonitoringState.STOPPED

        self.query_one("#view-note", Label).update(self._view_note())

    def _view_note(self) -> str:
        if self.view == "settings":
            config = self.service.config
            sources = ", ".join(config.sources) or "all available"
            return (
                "[b]Settings[/b]  "
                f"[dim]interval {config.interval_seconds}s - max results {config.max_results} - "
                f"ai {'on' if config.enhance_with_ai else 'off'} - sources: {escape(sources)}[/dim]"
            )
        description = VIEW_DESCRIPTIONS.get(self.view)
        if description is None:
            description = next(
                (desc for key, _label, desc in NAV_ITEMS if key == self.view), ""
            )
        return f"[b]{self.view.capitalize()}[/b]  [dim]{escape(description)}[/dim]"

    def _fill_techniques(self, view: AnalysisView) -> None:
        table = self.query_one("#techniques", DataTable)
        table.clear(columns=False)
        if not view.techniques:
            table.add_row("-", "no techniques in the latest batch", "-")
            return
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

    # -- monitoring callbacks (run from the service's loop task) ----------
    def _on_state_change(self, state: MonitoringState) -> None:
        self.call_later(self._render_state, state)

    def _render_state(self, state: MonitoringState) -> None:
        self._notify(f"monitoring {state.value}", "ok" if state is MonitoringState.RUNNING else "warn")
        self._refresh_panels()

    def _on_result(self, view: AnalysisView, outcome: CycleOutcome) -> None:
        self.call_later(self._apply_result, view, outcome)

    def _apply_result(self, view: AnalysisView, outcome: CycleOutcome) -> None:
        self.cycles = outcome.cycle
        self.submitted += 1
        self.events += outcome.collected_entries
        self.techniques_found = view.technique_count
        self._latest = view
        self._fill_techniques(view)

        stamp = datetime.now().strftime("%H:%M:%S")
        summary = (view.summary or "").strip().replace("\n", " ")
        detail = f" - {escape(summary)[:70]}" if summary else ""
        self._write_stream(
            f"[{MUTED}]{stamp}[/{MUTED}] [{INFO}]cycle {outcome.cycle}[/{INFO}] "
            f"{outcome.collected_entries} event(s) submitted{detail}"
        )
        for technique in view.techniques[:3]:
            label = technique.technique_id or "?"
            name = technique.name or "unnamed"
            score = (
                f" ({technique.relevance_score:.2f})"
                if isinstance(technique.relevance_score, float)
                else ""
            )
            self._write_stream(f"[{MUTED}]             {escape(label)} {escape(name)}{score}[/{MUTED}]")
        if view.summary:
            self._notify(f"analysis: {view.summary.strip()[:90]}", "info")
        self._refresh_panels()

    def _on_error(self, exc: Exception, outcome: CycleOutcome | None) -> None:
        self.call_later(self._render_error, exc, outcome)

    def _render_error(self, exc: Exception, outcome: CycleOutcome | None) -> None:
        message = str(exc) or type(exc).__name__
        self._notify(f"backend error: {message}", "bad")
        self._refresh_panels()

    # -- clock
    def _clock_tick(self) -> None:
        """Refresh live counters; the service owns all state."""
        if self.service.monitoring is not None:
            self._refresh_panels()

    # -- actions ----------------------------------------------------------
    def action_goto(self, key: str) -> None:
        self.view = key
        list_view = self.query_one(ListView)
        for index, (nav_key, _label, _desc) in enumerate(NAV_ITEMS):
            if nav_key == key:
                list_view.index = index
                break
        self._refresh_panels()

    def action_login(self) -> None:
        if self.service.is_authenticated:
            self._notify("already signed in", "warn")
            return
        self.push_screen(LoginScreen(self.service), self._login_finished)

    def _login_finished(self, success: bool | None) -> None:
        if not success:
            self._notify("login cancelled", "warn")
            self._refresh_panels()
            return
        self._notify(f"signed in as {self._current_username() or 'unknown'}", "ok")
        self._refresh_panels()

    async def action_logout(self) -> None:
        if self.service.monitoring is not None:
            try:
                await asyncio.wait_for(self.service.stop_monitoring(), timeout=15)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001 - logout must not block
                pass
        self.service.logout()
        self.query_one("#techniques", DataTable).clear(columns=False)
        self.query_one("#techniques", DataTable).add_row("-", "no analysis yet", "-")
        self._notify("signed out; local token discarded", "warn")
        self._refresh_panels()

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
        self._notify("monitoring started", "ok")
        self._refresh_panels()

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
        self._refresh_panels()

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

    # -- shutdown ---------------------------------------------------------
    # ``q``/Ctrl+C use Textual's own ``quit`` action, which is asynchronous and
    # only calls ``exit()``. Shutdown work happens in ``on_unmount`` so the
    # framework's own teardown is never blocked mid-keypress.
    async def _close_service(self) -> None:
        """Cancel monitoring and close HTTP, bounded so exit cannot hang.

        Deliberately *not* named ``_shutdown``: that is a Textual ``App``
        internal, and overriding it skips the framework's own teardown.
        """
        if self._closing:
            return
        self._closing = True
        self._write_stream(f"[{MUTED}]shutting down...[/{MUTED}]")
        try:
            await asyncio.wait_for(self.service.close(), timeout=15)
        except asyncio.TimeoutError:
            pass
        except Exception:  # noqa: BLE001 - shutdown is best effort by design
            pass

    async def on_unmount(self) -> None:
        """Stop monitoring and close HTTP on every exit path (q, Ctrl+C, stop)."""
        await self._close_service()

    # -- events -----------------------------------------------------------
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("nav-"):
            self.view = item_id.removeprefix("nav-")
            self._refresh_panels()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.run_worker(self.action_start_monitoring(), exclusive=True)
        elif event.button.id == "btn-stop":
            self.run_worker(self.action_stop_monitoring(), exclusive=True)
        elif event.button.id == "btn-tick":
            self.run_worker(self.action_tick(), exclusive=True)


def main() -> None:
    ForensIQApp().run()


if __name__ == "__main__":
    main()
