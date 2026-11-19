"""ForensIQ TUI - visual preview (mock data only).

This is a throwaway-looking but representative shell: sidebar navigation,
status cards, a monitoring panel, technique list and a live log stream. Every
value is fake. No authentication, no collectors, no HTTP.

Run:  python -m cli_agent.tui.preview
Exit: q  (or Ctrl+C)
"""

from __future__ import annotations

import random
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Label, ListItem, ListView, RichLog, Static

NAV_ITEMS = [
    ("dashboard", "Dashboard", "Operational overview"),
    ("monitoring", "Monitoring", "Collection and submission"),
    ("analysis", "Analysis", "Latest investigation report"),
    ("knowledge", "Knowledge", "ATT&CK / CVE store"),
    ("sessions", "Sessions", "Backend monitoring sessions"),
    ("settings", "Settings", "Profile and endpoint"),
]

MOCK_EVENTS = [
    ("14:02:11", "auth_logs", "Failed password for root from 10.0.4.19", "medium"),
    ("14:02:19", "auth_logs", "Accepted publickey for deploy from 10.0.4.7", "low"),
    ("14:03:02", "process_monitor", "powershell.exe -enc SQBFAFgA", "high"),
    ("14:03:44", "network_connections", "ESTABLISHED 10.0.4.19:443 -> 45.9.148.11", "high"),
    ("14:04:05", "syslog", "systemd[1]: Started Session 42 of user analyst", "low"),
    ("14:04:31", "file_system_activity", "/etc/cron.d/.hidden created by www-data", "medium"),
]

MOCK_TECHNIQUES = [
    ("T1110", "Brute Force", "0.87"),
    ("T1059.001", "PowerShell", "0.81"),
    ("T1071.001", "Web Protocols", "0.74"),
    ("T1546.003", "WMI Event Subscription", "0.62"),
]


class ForensIQPreview(App):
    """Visual-only preview of the planned ForensIQ terminal interface."""

    TITLE = "ForensIQ"
    SUB_TITLE = "preview build - mock data only"
    CSS = """
    Screen { background: #0b1020; color: #d7e0f4; }
    Header { background: #131a2e; color: #9fb4d8; }
    Footer { background: #131a2e; color: #7f8fb3; }

    #body { height: 1fr; }

    #sidebar {
        width: 28;
        background: #0f1526;
        border-right: solid #22304d;
        padding: 1 0;
    }
    #brand { padding: 0 2; color: #7fe3c0; text-style: bold; }
    #brand-sub { padding: 0 2 1 2; color: #5c6c8f; }
    ListView { background: #0f1526; }
    ListItem { padding: 0 1; color: #b9c7e2; }
    ListItem.--highlight { background: #1d2a47; color: #ffffff; }

    #main { padding: 1 2; }

    .card {
        width: 1fr;
        height: 5;
        border: round #22304d;
        background: #101830;
        padding: 0 1;
        margin-right: 1;
    }
    .card-title { color: #6f82a8; }
    .card-value { color: #eaf1ff; text-style: bold; }
    .ok { color: #7fe3c0; }
    .warn { color: #ffcf6b; }
    .bad { color: #ff7a7a; }

    #panels { height: 1fr; }
    #monitor-panel {
        width: 44;
        border: round #22304d;
        background: #101830;
        padding: 1;
        margin-right: 1;
    }
    #technique-panel {
        width: 1fr;
        border: round #22304d;
        background: #101830;
        padding: 1;
    }
    .panel-title { color: #7fe3c0; text-style: bold; }
    .kv { color: #b9c7e2; }
    #controls { height: 3; margin-top: 1; }
    Button { margin-right: 1; }
    #stream-panel {
        height: 12;
        border: round #22304d;
        background: #0d1424;
        padding: 0 1;
        margin-top: 1;
    }
    #view-note { color: #5c6c8f; padding: 0 0 1 0; }
    """

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
    ]

    def __init__(self) -> None:
        super().__init__()
        self.monitoring = False
        self.submitted = 0
        self.events = 0
        self.techniques_found = 0
        self.cycles = 0
        self.view = "dashboard"

    # -- layout ----------------------------------------------------------
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
                    yield Static("AUTH\nmock session", classes="card")
                    yield Static("BACKEND\nlocalhost:8000", classes="card")
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
        for row in MOCK_TECHNIQUES:
            table.add_row(*row)
        table.cursor_type = "row"
        table.zebra_stripes = True

        self._write_stream("[dim]connected to http://localhost:8000 (mock)[/dim]")
        for timestamp, source, message, severity in MOCK_EVENTS:
            self._write_event(timestamp, source, message, severity)
        self.events = len(MOCK_EVENTS)
        self._refresh_panels()

        list_view = self.query_one(ListView)
        list_view.focus()
        list_view.index = 0

        self.set_interval(1.0, self._clock_tick)

    # -- rendering -------------------------------------------------------
    def _write_event(self, timestamp: str, source: str, message: str, severity: str) -> None:
        colour = {"high": "red", "medium": "yellow", "low": "green"}.get(severity, "white")
        self.query_one("#stream", RichLog).write(
            f"[dim]{timestamp}[/dim] [{colour}]{source:<20}[/{colour}] {message}"
        )

    def _write_stream(self, markup: str) -> None:
        self.query_one("#stream", RichLog).write(markup)

    def _refresh_panels(self) -> None:
        state = "running" if self.monitoring else "stopped"
        state_colour = "ok" if self.monitoring else "warn"
        session = "sess-mock-7f3a" if self.monitoring else "-"
        interval = "300s (adaptive)" if self.monitoring else "-"
        self.query_one("#card-mon", Static).update(
            f"[dim]MONITORING[/dim]\n[{state_colour}]{state}[/{state_colour}]"
        )
        self.query_one("#card-batches", Static).update(
            f"[dim]BATCHES[/dim]\n{self.submitted} submitted"
        )
        self.query_one("#monitor-detail", Static).update(
            f"state        [{state_colour}]{state}[/{state_colour}]\n"
            f"session id   {session}\n"
            f"interval     {interval}\n"
            f"cycles       {self.cycles}\n"
            f"events       {self.events}\n"
            f"techniques   {self.techniques_found}"
        )
        self.query_one("#btn-start", Button).disabled = self.monitoring
        self.query_one("#btn-stop", Button).disabled = not self.monitoring

        key = self.view
        description = next((desc for nav_key, _label, desc in NAV_ITEMS if nav_key == key), "")
        self.query_one("#view-note", Label).update(
            f"[b]{key.capitalize()}[/b]  [dim]{description} - preview content is mock only[/dim]"
        )

    # -- behaviour -------------------------------------------------------
    def _clock_tick(self) -> None:
        if self.monitoring and random.random() < 0.35:
            self._run_cycle()

    def _run_cycle(self) -> None:
        self.cycles += 1
        new_events = random.randint(1, 4)
        self.events += new_events
        self.submitted += 1
        self.techniques_found += random.randint(0, 2)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._write_event(timestamp, "collector", f"cycle {self.cycles}: {new_events} new event(s)", "low")
        self._write_stream(
            f"[dim]{timestamp}[/dim] [cyan]batch submitted[/cyan] "
            f"{random.randint(400, 9000)} chars -> 200 OK"
        )
        self._refresh_panels()

    def action_goto(self, key: str) -> None:
        self.view = key
        list_view = self.query_one(ListView)
        for index, (nav_key, _label, _desc) in enumerate(NAV_ITEMS):
            if nav_key == key:
                list_view.index = index
                break
        self._refresh_panels()

    def action_start_monitoring(self) -> None:
        if self.monitoring:
            return
        self.monitoring = True
        self._write_stream("[green]monitoring started[/green] (mock session sess-mock-7f3a)")
        self._refresh_panels()

    def action_stop_monitoring(self) -> None:
        if not self.monitoring:
            return
        self.monitoring = False
        self._write_stream("[yellow]monitoring stopped[/yellow] (session closed)")
        self._refresh_panels()

    def action_tick(self) -> None:
        if not self.monitoring:
            self._write_stream("[dim]start monitoring first (press s)[/dim]")
            return
        self._run_cycle()

    # -- events ----------------------------------------------------------
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("nav-"):
            self.view = item_id.removeprefix("nav-")
            self._refresh_panels()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.action_start_monitoring()
        elif event.button.id == "btn-stop":
            self.action_stop_monitoring()
        elif event.button.id == "btn-tick":
            self.action_tick()


def main() -> None:
    ForensIQPreview().run()


if __name__ == "__main__":
    main()
