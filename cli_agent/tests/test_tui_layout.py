"""Visual regression: the functional TUI must keep the approved preview layout.

The check compares the mounted widget tree of :class:`ForensIQApp` with the
tree of the frozen :class:`ForensIQPreview` (same ids, same classes, same
containment, same order) and verifies that the only stylesheet change is the
palette. Any accidental redesign - a moved panel, a new column layout, a
dropped card - fails here.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from textual.widgets import ListItem

from cli_agent.services.cli_service import CliService
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ConfigService
from cli_agent.services.auth_service import TokenStore
from cli_agent.tui.app import ForensIQApp

from .conftest import FakeExtractor, FakeTransport

REPO_ROOT = Path(__file__).resolve().parents[2]
TUI_DIR = Path(__file__).resolve().parents[1] / "tui"
MARKER = "__FINGERPRINT__"

# The preview is measured in its own interpreter: two Textual apps cannot be
# driven back-to-back in one event loop (the second never reports ready).
PREVIEW_SCRIPT = f"""
import json
from textual.containers import Horizontal, Vertical
from textual.widgets import ListItem, ListView
from cli_agent.tui.preview import ForensIQPreview


def structure(widget):
    node = [type(widget).__name__, widget.id, sorted(widget.classes)]
    if isinstance(widget, (Horizontal, Vertical)):
        node.append([structure(child) for child in widget.children])
    elif isinstance(widget, ListView):
        node.append([child.id for child in widget.children if isinstance(child, ListItem)])
    return node


async def main():
    app = ForensIQPreview()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        print("{MARKER}" + json.dumps(structure(app.screen)))


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


def structure(widget) -> list:
    """Structural fingerprint: type, id, classes and declared children only.

    Leaf widgets are compared without descending, because their internal
    children (scrollbars, rendered rows) depend on data, not layout.
    """
    from textual.containers import Horizontal, Vertical
    from textual.widgets import ListItem, ListView

    node: list = [type(widget).__name__, widget.id, sorted(widget.classes)]
    if isinstance(widget, (Horizontal, Vertical)):
        node.append([structure(child) for child in widget.children])
    elif isinstance(widget, ListView):
        node.append([child.id for child in widget.children if isinstance(child, ListItem)])
    return node


def build_app(tmp_path) -> ForensIQApp:
    service = CliService(
        config_service=ConfigService(tmp_path / "config.json"),
        token_store=TokenStore(tmp_path / "session.json"),
        transport=FakeTransport(),
        collector=CollectorService(extractor=FakeExtractor()),
    )
    return ForensIQApp(service=service, restore_session=False)


def preview_fingerprint() -> list:
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
    return json.loads(lines[-1][len(MARKER):])


async def test_widget_tree_is_identical_to_the_preview(tmp_path) -> None:
    preview = preview_fingerprint()
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        current = structure(app.screen)
    assert current == preview


async def test_layout_ids_survive(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        for selector in (
            "#body",
            "#sidebar",
            "#main",
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
            "#card-mon",
            "#card-batches",
            "#view-note",
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
