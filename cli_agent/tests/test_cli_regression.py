"""Checkpoint 6: CLI surface regression and the facade flow."""

from __future__ import annotations

import pytest

from cli_agent.cli import build_parser
from cli_agent.client.auth_service import TokenStore
from cli_agent.client.cli_service import CliService
from cli_agent.client.config_service import ConfigService
from cli_agent.client.errors import AuthError, ConfigurationError

from .conftest import FakeTransport, make_jwt

BASE = "http://localhost:8000"


# -- argument parsing (legacy compatibility) -----------------------------
def test_auth_login_shape() -> None:
    args = build_parser().parse_args(["auth", "login", "--username", "analyst", "--password", "pw"])
    assert args.command == "auth"
    assert args.auth_command == "login"
    assert args.username == "analyst"


def test_auth_register_shape() -> None:
    args = build_parser().parse_args(
        ["auth", "register", "--username", "a", "--email", "a@example.com"]
    )
    assert args.auth_command == "register"
    assert args.email == "a@example.com"


def test_profile_setup_shape() -> None:
    args = build_parser().parse_args(
        ["profile", "setup", "--log-path", "/var/log/auth.log", "--interval", "120"]
    )
    assert args.profile_command == "setup"
    assert args.log_path == "/var/log/auth.log"
    assert args.interval == 120


def test_profile_setup_dynamic_shape() -> None:
    args = build_parser().parse_args(
        [
            "profile",
            "setup-dynamic",
            "--sources",
            "auth_logs",
            "process_monitor",
            "--interval",
            "300",
            "--list-sources",
        ]
    )
    assert args.sources == ["auth_logs", "process_monitor"]
    assert args.list_sources is True


def test_monitor_shapes() -> None:
    dynamic = build_parser().parse_args(["monitor", "--dynamic"])
    file_mode = build_parser().parse_args(["monitor", "--start", "--interval", "60"])
    assert dynamic.dynamic is True
    assert file_mode.start is True
    assert file_mode.interval == 60


def test_analyze_shape() -> None:
    args = build_parser().parse_args(["analyze", "--file", "sample.log", "--output", "out.json"])
    assert args.file == "sample.log"
    assert args.output == "out.json"


def test_monitor_requires_a_mode() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["monitor"])


def test_help_lists_legacy_commands() -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["--help"])
    assert excinfo.value.code == 0


# -- facade flow ---------------------------------------------------------
def build_service(tmp_path, transport: FakeTransport) -> CliService:
    return CliService(
        config_service=ConfigService(tmp_path / "config.json"),
        token_store=TokenStore(tmp_path / "session.json"),
        transport=transport,
    )


async def test_login_then_analyze_uses_bearer_and_legacy_payload(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"access_token": make_jwt(), "token_type": "bearer"},
        {"summary": "one", "matched_techniques": [{"technique_id": "T1110", "name": "Brute Force"}]},
    )
    service = build_service(tmp_path, transport)

    await service.login("analyst", "pw")
    view = await service.analyze_text("Jan 1 sshd: Failed password for root")
    await service.close()

    assert view.technique_count == 1
    analyze = [r for r in transport.requests if r["url"].endswith("/api/v1/analyze")][0]
    assert analyze["headers"]["Authorization"].startswith("Bearer ")
    assert set(analyze["json"]) == {"logs", "enhance_with_ai", "max_results"}
    assert "Failed password" in analyze["json"]["logs"]


async def test_analyze_requires_a_session(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport())
    with pytest.raises(AuthError):
        await service.analyze_text("line")
    await service.close()


async def test_logout_prevents_further_analysis(tmp_path) -> None:
    transport = FakeTransport().queue({"access_token": make_jwt()})
    service = build_service(tmp_path, transport)
    await service.login("analyst", "pw")
    service.logout()

    with pytest.raises(AuthError):
        await service.analyze_text("line")
    await service.close()


async def test_oversized_logs_are_rejected_locally(tmp_path) -> None:
    transport = FakeTransport().queue({"access_token": make_jwt()})
    service = build_service(tmp_path, transport)
    await service.login("analyst", "pw")

    with pytest.raises(ConfigurationError):
        await service.analyze_text("x" * 50_001)
    await service.close()


async def test_empty_logs_are_rejected(tmp_path) -> None:
    transport = FakeTransport().queue({"access_token": make_jwt()})
    service = build_service(tmp_path, transport)
    await service.login("analyst", "pw")

    with pytest.raises(ConfigurationError):
        await service.analyze_text("   ")
    await service.close()


async def test_missing_log_file_is_reported(tmp_path) -> None:
    transport = FakeTransport().queue({"access_token": make_jwt()})
    service = build_service(tmp_path, transport)
    await service.login("analyst", "pw")

    with pytest.raises(ConfigurationError):
        await service.analyze_file(tmp_path / "nope.log")
    await service.close()


async def test_analyze_file_reads_and_submits(tmp_path) -> None:
    log_file = tmp_path / "sample.log"
    log_file.write_text("sshd: Failed password\n", encoding="utf-8")
    transport = FakeTransport().queue(
        {"access_token": make_jwt()},
        {"summary": "ok", "matched_techniques": []},
    )
    service = build_service(tmp_path, transport)
    await service.login("analyst", "pw")

    view = await service.analyze_file(log_file)
    await service.close()

    assert view.summary == "ok"
    analyze = [r for r in transport.requests if r["url"].endswith("/api/v1/analyze")][0]
    assert "Failed password" in analyze["json"]["logs"]


def test_profile_configuration_is_persisted(tmp_path) -> None:
    transport = FakeTransport()
    service = build_service(tmp_path, transport)
    config = service.configure_monitoring(
        monitoring_type="dynamic",
        interval_seconds=120,
        max_results=3,
    )
    assert config.interval_seconds == 120
    reloaded = ConfigService(tmp_path / "config.json").load()
    assert reloaded.interval_seconds == 120
    assert reloaded.max_results == 3


def test_invalid_interval_is_rejected(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport())
    with pytest.raises(ConfigurationError):
        service.configure_monitoring(interval_seconds=1)


def test_status_reports_state(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport())
    status = service.status()
    assert status["authenticated"] is False
    assert status["monitoring_state"] == "stopped"
    assert status["base_url"] == BASE
