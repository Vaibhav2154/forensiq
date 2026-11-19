"""ForensIQ command-line client.

Layout:

* :mod:`cli_agent.client` -- reusable application services (no terminal I/O)
* :mod:`cli_agent.legacy` -- the migrated LogIQ CLI, kept behaviourally intact
* ``cli_agent.tui``       -- reserved for the Textual application (later phase)

Only :mod:`cli_agent.client` is intended to be imported by the future TUI.
"""

__version__ = "0.1.0"
