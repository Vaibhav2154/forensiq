"""Configuration safety: corrupt files, live-change guards, atomic private saves."""

from __future__ import annotations

import json
import os
import stat

import pytest

from cli_agent.services.auth_service import Session, TokenStore
from cli_agent.services.cli_service import CliService
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ClientConfig, ConfigService
from cli_agent.services.errors import ConfigurationError

from .conftest import FakeExtractor, FakeTransport, make_jwt


def build_service(tmp_path, transport) -> CliService:
    store = TokenStore(tmp_path / "session.json")
    store.save(Session(access_token=make_jwt(), expires_at=10**12))
    service = CliService(
        config_service=ConfigService(tmp_path / "config.json"),
        token_store=store,
        transport=transport,
        collector=CollectorService(extractor=FakeExtractor()),
    )
    service.auth.load_session()
    return service


def test_corrupt_config_does_not_prevent_startup(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{broken", encoding="utf-8")
    service = CliService(
        config_service=ConfigService(path),
        token_store=TokenStore(tmp_path / "session.json"),
        collector=CollectorService(extractor=FakeExtractor()),
    )
    assert service.config.base_url == "http://localhost:8000"
    assert service.config_error


def test_invalid_base_url_is_rejected() -> None:
    with pytest.raises(ConfigurationError):
        ClientConfig(base_url="not-a-url").validated()


def test_saved_config_is_private_and_atomic(tmp_path) -> None:
    path = tmp_path / "config.json"
    ConfigService(path).save(ClientConfig(interval_seconds=120))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text(encoding="utf-8"))["interval_seconds"] == 120
    assert [p.name for p in tmp_path.iterdir()] == ["config.json"]


async def test_configuration_cannot_change_during_monitoring(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-1"}, {"status": "stopped"})
    service = build_service(tmp_path, transport)
    await service.start_monitoring(interval=10, sources=None)
    try:
        with pytest.raises(ConfigurationError):
            service.configure_monitoring(interval_seconds=60)
    finally:
        await service.stop_monitoring()

    # Once stopped, the same change is accepted and persisted.
    updated = service.configure_monitoring(interval_seconds=60)
    assert updated.interval_seconds == 60
    await service.close()


def test_unwritable_config_directory_is_reported(tmp_path, monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("cli_agent.services.config_service.tempfile.mkstemp", refuse)
    with pytest.raises(ConfigurationError):
        ConfigService(tmp_path / "config.json").save(ClientConfig())
