"""Checkpoint 7: the renamed ``cli_agent.services`` package and repo hygiene."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_DIR = REPO_ROOT / "cli_agent"


def test_services_package_exposes_the_same_surface() -> None:
    import cli_agent.services as services

    for name in (
        "ApiClient",
        "AuthService",
        "CliService",
        "CollectorService",
        "ConfigService",
        "MonitoringService",
        "MonitoringState",
        "adapt_analysis",
        "next_interval",
    ):
        assert hasattr(services, name), f"{name} missing from cli_agent.services"
    assert services.__doc__


def test_old_client_package_is_gone() -> None:
    assert importlib.util.find_spec("cli_agent.client") is None
    assert not (CLI_DIR / "client").exists()
    assert (CLI_DIR / "services").is_dir()


def test_no_source_file_still_imports_the_old_package() -> None:
    offenders = []
    for path in CLI_DIR.rglob("*.py"):
        relative = path.relative_to(CLI_DIR)
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        # Local virtualenvs / runtime data live inside cli_agent and are
        # ignored by git; they are not project source.
        if any(part.startswith(".") or part.endswith(".egg-info") for part in relative.parts):
            continue
        text = path.read_text(encoding="utf-8")
        if "cli_agent.client" in text or "from .client" in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_pyproject_declares_the_console_scripts() -> None:
    text = (CLI_DIR / "pyproject.toml").read_text(encoding="utf-8")
    assert 'forensiq = "cli_agent.cli:main"' in text
    assert 'forensiq-legacy = "cli_agent.legacy.cli_tool:main"' in text
    assert 'textual>=0.80' in text


def test_tui_entry_point_exists() -> None:
    from cli_agent.tui.__main__ import main as tui_main  # noqa: F401
    from cli_agent.cli import build_parser

    args = build_parser().parse_args(["tui"])
    assert args.command == "tui"


@pytest.mark.skipif(not (REPO_ROOT / ".git").exists(), reason="not a git checkout")
def test_gitignore_tracks_cli_agent_and_ignores_root_client() -> None:
    def ignored(path: str) -> bool:
        result = subprocess.run(
            ["git", "check-ignore", "-q", path], cwd=REPO_ROOT
        )
        return result.returncode == 0

    assert not ignored("cli_agent/services/cli_service.py")
    assert not ignored("cli_agent/docs/CLI_USER_GUIDE.md")
    assert not ignored("cli_agent/tui/app.py")
    # Root ``client/`` is already tracked in this repository, so git never
    # ignores the directory itself; the anchored rule protects newly created
    # files there (checked with paths that are guaranteed untracked).
    assert ignored("client/untracked_probe.py")
    assert ignored("docs/untracked_probe.md")


def test_gitignore_contains_no_cli_agent_rule() -> None:
    lines = [
        line.strip()
        for line in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    ]
    assert "cli_agent/" not in lines
    assert "cli_agent" not in lines
