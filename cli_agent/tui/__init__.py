"""ForensIQ terminal UI.

* :mod:`cli_agent.tui.app` -- the functional Textual application (Phase 4 + 5):
  real authentication, configuration and monitoring, with the approved preview
  layout and an htop-inspired palette in ``styles.tcss``.
* :mod:`cli_agent.tui.preview` -- the original mock-only preview, kept as the
  frozen visual baseline for the layout regression test.

Launch: ``python -m cli_agent.tui`` (or ``forensiq tui``).
"""

from .app import ForensIQApp

__all__ = ["ForensIQApp"]
