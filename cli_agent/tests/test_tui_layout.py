"""Visual regression: the functional TUI must keep the approved preview shell.

Phase 6 adds real content inside the existing regions, so the Phase 5 rule
("the whole widget tree is byte-identical") no longer holds.  The invariant
that does hold, and that this module enforces, is:

* every container of the approved preview (by id, type and parent) still
  exists, in the same place - no panel moved, no card dropped, no navigation
  restructured;
* the four cards, six navigation items and the preview's shortcuts are
  preserved (shortcuts only extended by ``l``/``o``);
* the palette is centralised and complete;
* the layout still mounts at 120x40 and 80x24.

Additional content widgets inside a preserved region are allowed and listed in
``PHASE_6_REPORT.md``.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from textual.widgets import ListItem

from cli_agent.services.auth_service import TokenStore
from cli_agent.services.cli_service import CliService
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ConfigService
from cli_agent.tui.app import ForensIQApp

from .conftest import FakeExtractor, FakeTransport

REPO_ROOT = Path(__file__).resolve().parents[2]
TUI_DIR = Path(__file__).resolve().parents[1] / "tui"
MARKER = "__SHELL__"

# The preview is measured in its own interpreter: two Textual apps cannot be
# driven back-to-back in one event loop (the second never reports ready).
PREVIEW_SCRIPT = f"""
import json
from textual.containers import Horizontal, Vertical
from textual.widgets import ListItem, ListView
from cli_agent.tui.preview import ForensIQPreview


def shell(widget, parent=None):
    rows = []
    if isinstance(widget, (Horizontal, Vertical)):
        if widget.id:
            rows.append([type(widget).__name__, widget.id, parent])
        child_parent = widget.id or parent
        for child in widget.children:
            rows.extend(shell(child, child_parent))
    elif isinstance(widget, ListView):
        rows.append(["ListView", widget.id or "list", parent])
    return rows


async def main():
    app = ForensIQPreview()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        print("{MARKER}" + json.dumps(shell(app.screen)))


import asyncio
asyncio.run(main())
"""

REQUIRED_PALETTE = {
    "#080C0A",  # main background
    "#101713",  # panel background
    "#00C853",  # primary green
    "#39FF88",  # bright green
    "#4B8061",  # muted green
    "#176B3A",  # selection
    "#E0E8E2",  # main text
    "#91A598",  # secondary text
    "#E5B94B",  # warning
    "#F06464",  # error
    "#5CC8D7",  # information
}
PREVIEW_ONLY_COLOURS = ("#0b1020", "#131a2e", "#7fe3c0", "#101830", "#1d2a47")


def shell(widget, parent=None) -> list:
    """Shell fingerprint: containers by id/type/parent, plus the nav list."""
    from textual.containers import Horizontal, Vertical
    from textual.widgets import ListView

    rows: list = []
    if isinstance(widget, (Horizontal, Vertical)):
        if widget.id:
            rows.append([type(widget).__name__, widget.id, parent])
        child_parent = widget.id or parent
        for child in widget.children:
            rows.extend(shell(child, child_parent))
    elif isinstance(widget, ListView):
        rows.append(["ListView", widget.id or "list", parent])
    return rows


def build_app(tmp_path) -> ForensIQApp:
    service = CliService(
        config_service=ConfigService(tmp_path / "config.json"),
        token_store=TokenStore(tmp_path / "session.json"),
        transport=FakeTransport(),
        collector=CollectorService(extractor=FakeExtractor()),
    )
    return ForensIQApp(service=service, restore_session=False, auto_probe=False)


def preview_shell() -> list:
    result = subprocess.run(
        [sys.executable, "-c", PREVIEW_SCRIPT],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    lines = [line for line in result.stdout.splitlines() if line.startswith(MARKER)]
    assert lines, result.stdout
    return json.loads(lines[-1][len(MARKER) :])


async def test_preview_shell_is_preserved(tmp_path) -> None:
    expected = preview_shell()
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        current = shell(app.screen)

    # Every preview container still exists with the same parent.
    app_map = {(row[1], row[0]): row[2] for row in current}
    for _kind, widget_id, parent in expected:
        key = (widget_id, dict((row[1], row[0]) for row in expected).get(widget_id))
        assert key in app_map, f"preview region {widget_id} is missing or changed type"
        assert app_map[key] == parent, f"region {widget_id} moved out of {parent}"


async def test_layout_survives_120x40_and_80x24(tmp_path) -> None:
    for size in ((120, 40), (80, 24)):
        app = build_app(tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            for selector in ("#body", "#sidebar", "#main", "#panels", "#monitor-panel", "#technique-panel"):
                widget = app.query_one(selector)
                assert widget.size.width > 0 and widget.size.height > 0, f"{selector} collapsed at {size}"
            # Content must remain reachable through scrolling, not clipped away.
            assert app.query_one("#page-detail").size.height >= 1


async def test_layout_ids_survive(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        for selector in (
            "#body",
            "#sidebar",
            "#main",
            "#cards",
            "#panels",
            "#monitor-panel",
            "#technique-panel",
            "#controls",
            "#stream-panel",
            "#btn-start",
            "#btn-stop",
            "#btn-tick",
            "#techniques",
            "#stream",
            "#card-auth",
            "#card-backend",
            "#card-mon",
            "#card-batches",
            "#view-note",
            # Phase 6 additions, inside the regions above.
            "#page-detail",
            "#page-detail-text",
            "#settings-form",
            "#knowledge-form",
            "#detail-view",
            "#monitor-heading",
            "#technique-heading",
        ):
            assert app.query(selector), f"missing {selector}"
        assert len(app.query(".card")) == 4
        assert len(app.query(ListItem)) == 6
        assert len(app.query("ListView ListItem")) == 6


def test_shortcuts_are_preserved_and_only_extended() -> None:
    from cli_agent.tui.preview import ForensIQPreview

    preview_keys = {binding[0] for binding in ForensIQPreview.BINDINGS}
    app_keys = {binding[0] for binding in ForensIQApp.BINDINGS}
    assert preview_keys <= app_keys
    assert app_keys - preview_keys == {"l", "o"}, "unexpected extra shortcut"


def test_preview_baseline_is_still_the_mock_shell() -> None:
    """Guard against "fixing" the layout by editing the baseline itself."""
    source = (TUI_DIR / "preview.py").read_text(encoding="utf-8")
    assert "mock" in source.lower()
    assert "cli_agent.services" not in source


def test_palette_is_centralised_and_complete() -> None:
    stylesheet = (TUI_DIR / "styles.tcss").read_text(encoding="utf-8")
    upper = stylesheet.upper()
    for colour in REQUIRED_PALETTE:
        assert colour in upper, f"palette colour {colour} missing from styles.tcss"
    assert ForensIQApp.CSS_PATH == "styles.tcss"

    # The preview's navy dev-theme colours must not survive in the app.
    for colour in PREVIEW_ONLY_COLOURS:
        assert colour.upper() not in upper


def test_app_module_holds_no_layout_styling_beyond_structure() -> None:
    """Sizes/borders belong to styles.tcss; app.py should not inline CSS."""
    source = (TUI_DIR / "app.py").read_text(encoding="utf-8")
    assert "DEFAULT_CSS" not in source
    assert not re.search(r"^\s*CSS\s*=", source, re.MULTILINE)
