"""ForensIQ command-line client.

Layout:

* :mod:`cli_agent.services` -- reusable application services (no terminal I/O)
* :mod:`cli_agent.legacy`   -- the migrated LogIQ CLI, kept behaviourally intact
* :mod:`cli_agent.tui`      -- the Textual application

Only :mod:`cli_agent.services` is intended to be imported by the TUI.
"""

__version__ = "0.1.0"
