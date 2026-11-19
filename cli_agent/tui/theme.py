"""ForensIQ theme architecture.

Single source of truth for the TUI palette.

Every colour used by the interface is defined here as a *semantic* CSS
variable (``$fq-canvas``, ``$fq-border``, ...).  ``styles.tcss`` and the Rich
markup written into the event stream reference those variables instead of
literal hex values, so switching ``App.theme`` repaints the whole application.

Two layers cooperate:

1. :data:`FORENSIQ_THEME` -- the approved mostly-black, htop-inspired theme.
   It sets the Textual theme fields *and* every ``fq-*`` variable explicitly.
2. :func:`theme_variable_defaults` -- fallbacks for Textual's built-in themes
   (nord, gruvbox, textual-light, ...).  Textual calls
   ``App.get_theme_variable_defaults`` whenever it rebuilds the CSS variable
   table, so the ``fq-*`` variables always resolve, even for a theme that has
   never heard of ForensIQ.

Values returned here are concrete colours (never ``auto`` or a colour plus
alpha) because the same values are also interpolated into Rich markup, where
Textual's CSS colour syntax is not understood.
"""

from __future__ import annotations

from textual.color import Color
from textual.theme import Theme

THEME_NAME = "forensiq"

# Rich markup roles -> semantic CSS variables.  Call sites use role names
# ("ok", "warn", ...) rather than colours, so a theme switch can recolour the
# event stream and every Static/RichLog body.
RICH_ROLE_VARIABLES: dict[str, str] = {
    "text": "fq-text",
    "muted": "fq-muted",
    "heading": "fq-heading",
    "ok": "fq-ok",
    "warn": "fq-warning",
    "bad": "fq-error",
    "error": "fq-error",
    "warning": "fq-warning",
    "info": "fq-info",
}

# Every variable styles.tcss may reference.  Defined explicitly by
# FORENSIQ_THEME and derived from the active theme by the defaults below.
SEMANTIC_VARIABLES: tuple[str, ...] = (
    "fq-canvas",
    "fq-surface",
    "fq-chrome",
    "fq-sidebar",
    "fq-border",
    "fq-border-dim",
    "fq-heading",
    "fq-text",
    "fq-muted",
    "fq-ok",
    "fq-warning",
    "fq-error",
    "fq-info",
    "fq-nav-selected",
    "fq-nav-selected-text",
    "fq-row-alt",
    "fq-cursor-bg",
    "fq-cursor-text",
    "fq-cursor-blurred-bg",
    "fq-cursor-blurred-text",
    "fq-button-bg",
    "fq-button-hover-bg",
    "fq-button-active-bg",
    "fq-button-text",
    "fq-button-focus-border",
    "fq-button-disabled-text",
    "fq-button-disabled-border",
    "fq-scrollbar",
    "fq-scrollbar-hover",
    "fq-scrollbar-active",
    "fq-scrollbar-track",
    "fq-overlay",
    "fq-selection",
    "fq-header-text",
    "fq-footer-key",
    "fq-footer-desc",
)


def _blend(base: str | Color, overlay: str | Color, amount: float) -> str:
    """Opaque blend of ``overlay`` over ``base`` as ``#RRGGBB``."""
    base_colour = base if isinstance(base, Color) else Color.parse(base)
    overlay_colour = overlay if isinstance(overlay, Color) else Color.parse(overlay)
    return base_colour.blend(overlay_colour, amount).hex


def _mix_towards(base: str, other: str, amount: float) -> str:
    return _blend(base, other, amount)


def theme_variable_defaults(theme: Theme) -> dict[str, str]:
    """Resolve ``fq-*`` variables for *theme*.

    Used two ways:

    * ``App.get_theme_variable_defaults`` so CSS always has a value for every
      ``fq-*`` variable, including while a built-in theme is active;
    * :func:`rich_colour` for markup colours, which need concrete values.

    Explicit values in ``theme.variables`` win, so FORENSIQ_THEME's palette is
    authoritative for the approved appearance.
    """
    colours = theme.to_color_system().generate()
    background = Color.parse(colours["background"])
    surface = Color.parse(colours["surface"])
    panel = Color.parse(colours["panel"])
    foreground = Color.parse(colours["foreground"])
    primary = Color.parse(colours["primary"])
    secondary = Color.parse(colours["secondary"])
    success = Color.parse(colours["success"])
    warning = Color.parse(colours["warning"])
    error = Color.parse(colours["error"])
    accent = Color.parse(colours["accent"])

    dark = theme.dark
    muted = _blend(background, foreground, 0.62)
    disabled_text = _blend(background, foreground, 0.38)
    row_alt = surface.lighten(0.05).hex if dark else surface.darken(0.05).hex
    button_hover = surface.lighten(0.07).hex if dark else surface.darken(0.07).hex
    cursor_bg = _blend(surface, primary, 0.38)
    nav_text = secondary.get_contrast_text().hex
    selection = _blend(background, primary, 0.45)
    border = _blend(background, primary, 0.55)

    defaults = {
        "fq-canvas": background.hex,
        "fq-surface": surface.hex,
        "fq-chrome": panel.hex,
        "fq-sidebar": panel.hex,
        "fq-border": border,
        "fq-border-dim": _blend(surface, foreground, 0.18),
        "fq-heading": primary.hex,
        "fq-text": foreground.hex,
        "fq-muted": muted,
        "fq-ok": success.hex,
        "fq-warning": warning.hex,
        "fq-error": error.hex,
        "fq-info": accent.hex,
        "fq-nav-selected": secondary.hex,
        "fq-nav-selected-text": nav_text,
        "fq-row-alt": row_alt,
        "fq-cursor-bg": cursor_bg,
        "fq-cursor-text": foreground.hex,
        "fq-cursor-blurred-bg": row_alt,
        "fq-cursor-blurred-text": muted,
        "fq-button-bg": surface.hex,
        "fq-button-hover-bg": button_hover,
        "fq-button-active-bg": panel.hex,
        "fq-button-text": foreground.hex,
        "fq-button-focus-border": primary.hex,
        "fq-button-disabled-text": disabled_text,
        "fq-button-disabled-border": _blend(surface, foreground, 0.22),
        "fq-scrollbar": colours.get("scrollbar", primary.hex),
        "fq-scrollbar-hover": colours.get("scrollbar-hover", primary.hex),
        "fq-scrollbar-active": colours.get("scrollbar-active", primary.hex),
        "fq-scrollbar-track": colours.get("scrollbar-background", panel.hex),
        "fq-overlay": f"{background.hex} 70%",
        "fq-selection": selection,
        "fq-header-text": foreground.hex,
        "fq-footer-key": primary.hex,
        "fq-footer-desc": muted,
    }
    # An explicitly registered theme may override any semantic variable.
    defaults.update(
        {
            key: str(value)
            for key, value in theme.variables.items()
            if key in SEMANTIC_VARIABLES
        }
    )
    return defaults


def rich_colour(theme: Theme, role: str) -> str:
    """Concrete colour for *role* in *theme* (safe inside Rich markup)."""
    variables = theme_variable_defaults(theme)
    return variables[RICH_ROLE_VARIABLES.get(role, "fq-text")]


# The approved reference appearance: black surfaces, charcoal chrome,
# thin sage borders, bright-green headings, blue selection, restrained teal
# table cursor.  These values are also the palette asserted by the tests.
FORENSIQ_THEME = Theme(
    name=THEME_NAME,
    primary="#00C853",
    secondary="#0078D4",
    accent="#5CC8D7",
    warning="#E5B94B",
    error="#F06464",
    success="#00C853",
    foreground="#C5C5C5",
    background="#000000",
    surface="#000000",
    panel="#101010",
    boost="#1A1A1A",
    dark=True,
    variables={
        # Semantic variables consumed by styles.tcss and Rich markup.
        "fq-canvas": "#000000",
        "fq-surface": "#000000",
        "fq-chrome": "#101010",
        "fq-sidebar": "#1A1A1A",
        "fq-border": "#4B6550",
        "fq-border-dim": "#2A2A2A",
        "fq-heading": "#00C853",
        "fq-text": "#C5C5C5",
        "fq-muted": "#808080",
        "fq-ok": "#00C853",
        "fq-warning": "#E5B94B",
        "fq-error": "#F06464",
        "fq-info": "#5CC8D7",
        "fq-nav-selected": "#0078D4",
        "fq-nav-selected-text": "#FFFFFF",
        "fq-row-alt": "#070707",
        "fq-cursor-bg": "#0B4F4F",
        "fq-cursor-text": "#D6F5F5",
        "fq-cursor-blurred-bg": "#101A1A",
        "fq-cursor-blurred-text": "#C5C5C5",
        "fq-button-bg": "#000000",
        "fq-button-hover-bg": "#1A1A1A",
        "fq-button-active-bg": "#101010",
        "fq-button-text": "#C5C5C5",
        "fq-button-focus-border": "#00C853",
        "fq-button-disabled-text": "#808080",
        "fq-button-disabled-border": "#2A2A2A",
        "fq-scrollbar": "#4B6550",
        "fq-scrollbar-hover": "#5C7D62",
        "fq-scrollbar-active": "#00C853",
        "fq-scrollbar-track": "#101010",
        "fq-overlay": "#000000 70%",
        "fq-selection": "#0078D4 45%",
        "fq-header-text": "#C5C5C5",
        "fq-footer-key": "#00C853",
        "fq-footer-desc": "#808080",
        # Textual component variables (widgets Textual styles internally).
        "block-cursor-background": "#0B4F4F",
        "block-cursor-foreground": "#D6F5F5",
        "block-cursor-blurred-background": "#0B4F4F",
        "block-cursor-blurred-foreground": "#D6F5F5",
        "button-foreground": "#C5C5C5",
        "button-color-foreground": "#C5C5C5",
        "button-focus-text-style": "bold",
        "footer-item-background": "#101010",
        "footer-key-background": "#101010",
        "footer-key-foreground": "#00C853",
        "footer-description-background": "#101010",
        "footer-description-foreground": "#808080",
        "block-hover-background": "#1A1A1A",
        "input-selection-background": "#0078D4 45%",
        "scrollbar": "#4B6550",
        "scrollbar-hover": "#5C7D62",
        "scrollbar-active": "#00C853",
        "scrollbar-background": "#101010",
        "scrollbar-background-hover": "#101010",
        "scrollbar-background-active": "#101010",
        "scrollbar-corner-color": "#000000",
    },
)

__all__ = [
    "FORENSIQ_THEME",
    "RICH_ROLE_VARIABLES",
    "SEMANTIC_VARIABLES",
    "THEME_NAME",
    "rich_colour",
    "theme_variable_defaults",
]
