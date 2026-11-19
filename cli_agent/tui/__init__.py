"""ForensIQ terminal UI (preview only).

Only :mod:`cli_agent.tui.preview` exists today: a self-contained mock dashboard
used to review the look and feel. It does not import ``cli_agent.client``, does
not authenticate, does not collect logs and never contacts the backend.

The real Phase 4 + 5 implementation will replace it with screens backed by
:class:`cli_agent.client.cli_service.CliService`.
"""
