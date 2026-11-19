"""Global theme architecture: switching must repaint the whole application.

These tests read computed widget styles, not CSS text: Textual's own theme
change path (``App.theme`` -> reparse CSS -> ``theme_changed_signal``) must
reach every screen, container, component class and Rich backlog.
"""

from __future__ import annotations

import re
from pathlib import Path

from textual.widgets import DataTable

from cli_agent.tui.app import ForensIQApp, LoginScreen
from cli_agent.tui.theme import (
    FORENSIQ_THEME,
    SEMANTIC_VARIABLES,
    THEME_NAME,
    theme_variable_defaults,
)

from .conftest import wait_for
from .test_tui_layout import TUI_DIR, build_app

# Concrete expectations from Textual's own nord theme, used to prove a switch
# really adopts the new theme rather than returning the old palette.
NORD_CANVAS = "#2E3440"
NORD_SURFACE = "#3B4252"
NORD_CHROME = "#434C5E"
NORD_PRIMARY = "#88C0D0"

PAGE_KEYS = {
    "1": "dashboard",
    "2": "monitoring",
    "3": "analysis",
    "4": "knowledge",
    "5": "sessions",
    "6": "settings",
}


def background(widget) -> str:
    return widget.styles.background.hex.upper()


def foreground(widget) -> str:
    return widget.styles.color.hex.upper()


def border_colour(widget) -> str:
    return widget.styles.border_top[1].hex.upper()


def rich_hex(colour) -> str:
    """Normalise a Rich colour (as returned by component styles) to hex."""
    return colour.get_truecolor().hex.upper()


async def switch(app: ForensIQApp, pilot, name: str) -> None:
    """Switch theme and wait for the new palette to be applied."""
    app.theme = name
    expected = theme_variable_defaults(app.current_theme)["fq-chrome"].upper()
    assert await wait_for(
        lambda: app.current_theme.name == name
        and f"-theme-{name}" in app.classes
        and background(app.query_one("Header")) == expected,
        timeout=5,
    ), f"theme {name} did not reach the screen"
    await pilot.pause()


async def test_default_theme_is_approved_black(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.theme == THEME_NAME
        assert app.current_theme is FORENSIQ_THEME or app.current_theme.name == THEME_NAME

        # The approved palette is the resolved theme, not a leftover default.
        resolved = theme_variable_defaults(app.current_theme)
        assert resolved["fq-canvas"] == "#000000"
        assert resolved["fq-chrome"] == "#101010"
        assert resolved["fq-sidebar"] == "#1A1A1A"
        assert resolved["fq-border"] == "#4B6550"
        assert resolved["fq-cursor-bg"] == "#0B4F4F"

        assert background(app.screen) == "#000000"
        assert background(app.query_one("Header")) == "#101010"
        assert background(app.query_one("Footer")) == "#101010"
        assert background(app.query_one("#sidebar")) == "#1A1A1A"
        assert background(app.query_one("#card-mon")) == "#000000"
        assert background(app.query_one("#monitor-panel")) == "#000000"
        assert background(app.query_one("#technique-panel")) == "#000000"
        assert background(app.query_one("#stream-panel")) == "#000000"
        assert border_colour(app.query_one("#monitor-panel")) == "#4B6550"
        assert foreground(app.query_one("#technique-heading")) == "#00C853"
        assert foreground(app.query_one("#monitor-detail")) == "#808080"

        # Every semantic variable exists for CSS even before a switch.
        for variable in SEMANTIC_VARIABLES:
            assert variable in app.theme_variables, variable


async def test_theme_switch_repaints_every_region(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await switch(app, pilot, "nord")

        resolved = theme_variable_defaults(app.current_theme)
        assert resolved["fq-canvas"].upper() == NORD_CANVAS
        assert resolved["fq-surface"].upper() == NORD_SURFACE
        assert resolved["fq-chrome"].upper() == NORD_CHROME
        assert resolved["fq-heading"].upper() == NORD_PRIMARY

        # Shell regions, all the way down to leaves.
        assert background(app.screen) == NORD_CANVAS
        assert background(app.query_one("Header")) == NORD_CHROME
        assert background(app.query_one("Footer")) == NORD_CHROME
        assert background(app.query_one("#sidebar")) == NORD_CHROME
        assert background(app.query_one("#card-auth")) == NORD_SURFACE
        assert background(app.query_one("#monitor-panel")) == NORD_SURFACE
        assert background(app.query_one("#technique-panel")) == NORD_SURFACE
        assert background(app.query_one("#stream-panel")) == NORD_SURFACE
        assert border_colour(app.query_one("#monitor-panel")) == resolved["fq-border"].upper()
        assert foreground(app.query_one("#technique-heading")) == NORD_PRIMARY

        # Navigation is part of the active theme too.
        selected = app.query_one("#nav-dashboard")
        assert background(selected) == resolved["fq-nav-selected"].upper()
        assert foreground(selected) == resolved["fq-nav-selected-text"].upper()

        # Neutral buttons derive from the active surface/primary pair.
        for selector in ("#btn-start", "#btn-stop", "#btn-tick"):
            assert background(app.query_one(selector)) == NORD_SURFACE, selector

        # Switching back restores the approved palette exactly.
        await switch(app, pilot, THEME_NAME)
        assert background(app.screen) == "#000000"
        assert background(app.query_one("Header")) == "#101010"
        assert background(app.query_one("#sidebar")) == "#1A1A1A"
        assert background(app.query_one("#card-auth")) == "#000000"
        assert background(app.query_one("#stream-panel")) == "#000000"
        assert border_colour(app.query_one("#monitor-panel")) == "#4B6550"
        assert background(app.query_one("#nav-dashboard")) == "#0078D4"
        assert foreground(app.query_one("#nav-dashboard")) == "#FFFFFF"


async def test_theme_switch_covers_all_six_pages(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()

        async def visit_all(expected_canvas: str, expected_surface: str) -> None:
            for key, view in PAGE_KEYS.items():
                await pilot.press(key)
                assert await wait_for(lambda: app.view == view, timeout=5), view
                await pilot.pause()
                assert app.theme in (THEME_NAME, "nord")
                assert background(app.screen) == expected_canvas, view
                assert background(app.query_one("#monitor-panel")) == expected_surface, view
                assert background(app.query_one("#card-batches")) == expected_surface, view
                assert background(app.query_one("#sidebar")) in ("#1A1A1A", NORD_CHROME), view

        await visit_all("#000000", "#000000")
        await switch(app, pilot, "nord")
        await visit_all(NORD_CANVAS, NORD_SURFACE)
        await switch(app, pilot, THEME_NAME)
        await visit_all("#000000", "#000000")


async def test_table_component_classes_follow_theme(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        table = app.query_one("#techniques", DataTable)

        resolved = theme_variable_defaults(app.current_theme)
        header = table.get_component_rich_style("datatable--header")
        assert rich_hex(header.bgcolor) == resolved["fq-surface"].upper()
        assert rich_hex(header.color) == resolved["fq-heading"].upper()

        # Blurred cursor is subdued; actively selected row uses the theme teal.
        cursor = table.get_component_rich_style("datatable--cursor")
        assert rich_hex(cursor.bgcolor) == resolved["fq-cursor-blurred-bg"].upper()
        table.focus()
        await pilot.pause()
        cursor = table.get_component_rich_style("datatable--cursor")
        assert rich_hex(cursor.bgcolor) == resolved["fq-cursor-bg"].upper()

        # Switch: header, rows and cursor all come from nord now.
        await switch(app, pilot, "nord")
        resolved = theme_variable_defaults(app.current_theme)
        header = table.get_component_rich_style("datatable--header")
        assert rich_hex(header.bgcolor) == NORD_SURFACE
        assert rich_hex(header.color) == NORD_PRIMARY
        cursor = table.get_component_rich_style("datatable--cursor")
        assert rich_hex(cursor.bgcolor) == resolved["fq-cursor-bg"].upper()
        odd = table.get_component_rich_style("datatable--odd-row")
        assert rich_hex(odd.bgcolor) == resolved["fq-row-alt"].upper()


async def test_button_focus_and_disabled_follow_theme(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        start = app.query_one("#btn-start")
        stop = app.query_one("#btn-stop")

        assert stop.disabled
        assert foreground(stop) == "#808080"

        start.focus()
        await pilot.pause()
        assert border_colour(start) == "#00C853"

        await switch(app, pilot, "nord")
        resolved = theme_variable_defaults(app.current_theme)
        assert foreground(stop) == resolved["fq-button-disabled-text"].upper()
        assert border_colour(start) == resolved["fq-button-focus-border"].upper()


async def test_stream_backlog_and_roles_recolour_on_switch(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app._stream_history, "startup stream lines must be recorded"

        before_muted = app._colour("muted")
        before_heading = app._colour("heading")
        await switch(app, pilot, "nord")
        resolved = theme_variable_defaults(app.current_theme)

        assert app._colour("muted") == resolved["fq-muted"]
        assert app._colour("heading") == resolved["fq-heading"]
        assert app._colour("muted") != before_muted
        assert app._colour("heading") != before_heading

        # Backlog text is preserved, only its colours change.
        log = app.query_one("#stream")
        assert len(log.lines) >= 1

        await switch(app, pilot, THEME_NAME)
        assert app._colour("muted") == "#808080"
        assert app._colour("heading") == "#00C853"
        assert app._colour("bad") == "#F06464"
        assert app._colour("warning") == "#E5B94B"
        assert app._colour("info") == "#5CC8D7"


async def test_login_modal_follows_global_theme(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.push_screen(LoginScreen(app.service))
        assert await wait_for(lambda: isinstance(app.screen, LoginScreen), timeout=5)
        await pilot.pause()

        box = app.screen.query_one("#login-box")
        assert background(box) == "#000000"
        assert border_colour(box) == "#4B6550"

        await switch(app, pilot, "nord")
        box = app.screen.query_one("#login-box")
        assert background(box) == NORD_SURFACE
        assert border_colour(box) == theme_variable_defaults(app.current_theme)["fq-border"].upper()

        await switch(app, pilot, THEME_NAME)
        box = app.screen.query_one("#login-box")
        assert background(box) == "#000000"
        assert border_colour(box) == "#4B6550"


async def test_repeated_switching_leaves_no_stale_styles(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        sequence = ("nord", "gruvbox", "textual-light", THEME_NAME, "nord", THEME_NAME)
        for name in sequence:
            await switch(app, pilot, name)
            classes = [class_ for class_ in app.classes if class_.startswith("-theme-")]
            assert classes == [f"-theme-{name}"], classes
            for variable in SEMANTIC_VARIABLES:
                assert variable in app.theme_variables, variable

        assert app.current_theme.name == THEME_NAME
        assert background(app.screen) == "#000000"
        assert background(app.query_one("#sidebar")) == "#1A1A1A"
        assert border_colour(app.query_one("#monitor-panel")) == "#4B6550"
        assert background(app.query_one("#nav-dashboard")) == "#0078D4"
        assert foreground(app.query_one("#nav-dashboard")) == "#FFFFFF"


async def test_theme_switch_works_at_80x24(tmp_path) -> None:
    app = build_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.theme == THEME_NAME
        assert background(app.screen) == "#000000"
        assert background(app.query_one("#sidebar")) == "#1A1A1A"

        await switch(app, pilot, "nord")
        assert background(app.screen) == NORD_CANVAS
        assert background(app.query_one("#sidebar")) == NORD_CHROME
        assert background(app.query_one("#card-auth")) == NORD_SURFACE

        await switch(app, pilot, THEME_NAME)
        assert background(app.screen) == "#000000"
        assert border_colour(app.query_one("#technique-panel")) == "#4B6550"


async def test_theme_preference_is_honoured_on_startup(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("FORENSIQ_THEME", "nord")
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.theme == "nord"
        assert background(app.screen) == NORD_CANVAS

    monkeypatch.setenv("FORENSIQ_THEME", "not-a-registered-theme")
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.theme == THEME_NAME
        assert background(app.screen) == "#000000"


def test_palette_has_a_single_source_of_truth() -> None:
    """No widget source may carry literal colours of its own."""
    app_source = (TUI_DIR / "app.py").read_text(encoding="utf-8")
    assert not re.search(r"#[0-9A-Fa-f]{6}\b", app_source), "app.py must not hard-code colours"

    stylesheet = (TUI_DIR / "styles.tcss").read_text(encoding="utf-8")
    assert not re.search(r"#[0-9A-Fa-f]{6}\b", stylesheet), "styles.tcss must not hard-code colours"

    # The approved palette lives in exactly one place.
    assert FORENSIQ_THEME.name == THEME_NAME
    palette = Path(TUI_DIR / "theme.py").read_text(encoding="utf-8")
    assert palette.count("#000000") > 0


async def test_ctrl_p_theme_palette_switches_globally(tmp_path) -> None:
    """The existing Ctrl+P palette path must apply the theme globally."""
    app = build_app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.theme == THEME_NAME

        async def pick(name: str) -> None:
            await pilot.press("ctrl+p")
            assert await wait_for(
                lambda: type(app.screen).__name__ == "CommandPalette", timeout=5
            )
            await pilot.pause()
            await pilot.press(*"theme")
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press(*name)
            await pilot.press("enter")
            assert await wait_for(lambda: app.theme == name, timeout=5), app.theme
            await pilot.pause()

        await pick("nord")
        assert background(app.screen) == NORD_CANVAS
        assert background(app.query_one("#sidebar")) == NORD_CHROME
        assert background(app.query_one("#card-auth")) == NORD_SURFACE

        await pick(THEME_NAME)
        assert app.screen.styles.background.hex.upper() == "#000000"
        assert background(app.query_one("#sidebar")) == "#1A1A1A"
        assert border_colour(app.query_one("#monitor-panel")) == "#4B6550"
        assert background(app.query_one("#nav-dashboard")) == "#0078D4"
