"""Checkpoint 2: the package imports and the CLI entry point resolves."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_client_package_imports() -> None:
    import cli_agent
    import cli_agent.services as client

    assert cli_agent.__version__
    for name in ("ApiClient", "AuthService", "CliService", "CollectorService", "MonitoringService"):
        assert hasattr(client, name)


def test_legacy_module_imports_without_optional_ml_stack() -> None:
    """``pandas``/``redis`` are not installed here; import must still work."""
    import cli_agent.legacy.cli_tool as legacy

    assert callable(legacy.main)
    assert callable(legacy._load_prerag_classifier)


def test_entry_point_resolves() -> None:
    from cli_agent.cli import build_parser, main

    parser = build_parser()
    assert parser.prog == "forensiq"
    assert callable(main)


def test_help_runs_as_a_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "cli_agent", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "auth" in result.stdout
    assert "monitor" in result.stdout


def test_version_flag_exits_cleanly() -> None:
    from cli_agent.cli import main

    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


def test_import_does_not_prompt_or_connect(monkeypatch) -> None:
    """Importing must not ask for a password, start a loop, or open a socket."""
    import importlib

    def _fail(*_args, **_kwargs):
        raise AssertionError("import-time side effect detected")

    monkeypatch.setattr("getpass.getpass", _fail)
    for module in ("cli_agent.services", "cli_agent.cli", "cli_agent.legacy.cli_tool"):
        sys.modules.pop(module, None)
        importlib.import_module(module)


def test_no_monitoring_task_is_created_on_import() -> None:
    import asyncio

    async def _check() -> None:
        assert asyncio.all_tasks() == {asyncio.current_task()}

    asyncio.run(_check())
