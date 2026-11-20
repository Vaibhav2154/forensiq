"""Tests for CLI batch char limits, split-batch pacing delay, and log noise filtering."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from textual.widgets import Button, Checkbox, Input

from cli_agent.cli import build_parser
from cli_agent.services.api_client import ApiClient
from cli_agent.services.auth_service import AuthService, Session, TokenStore
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import (
    ClientConfig,
    ConfigService,
    DEFAULT_AI_BATCH_CHARS,
    DEFAULT_BATCH_DELAY,
)
from cli_agent.services.errors import ConfigurationError
from cli_agent.services.limits import filter_log_noise
from cli_agent.services.monitoring_service import MonitoringService
from cli_agent.tui.app import ForensIQApp

from .conftest import FakeExtractor, FakeTransport, make_jwt, wait_for
from .test_tui_pages import HEALTH, PROFILE, SIZE, build_service, goto

BASE = "http://localhost:8000"


# -- noise filter --------------------------------------------------------
def test_filter_log_noise_drops_benign_chatter_and_dupes_keeps_security() -> None:
    raw = "\n".join(
        [
            "systemd[1]: Started Session 42 of User vaibhi.",
            "CRON[101]: pam_unix(cron:session): session opened for user root",
            "app[9]: [DEBUG] heartbeat ok",
            "sshd[900]: Failed password for invalid user admin from 10.0.0.5 port 5521 ssh2",
            "sshd[900]: Failed password for invalid user admin from 10.0.0.5 port 5521 ssh2",
            "systemd[1]: Started sshd.service - Failed with result 'exit-code'",
            "sudo[901]: vaibhi : TTY=pts/0 ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        ]
    )
    filtered, dropped = filter_log_noise(raw)
    lines = filtered.splitlines()

    assert dropped == 4  # 3 benign lines + 1 exact duplicate
    assert len(lines) == 3
    assert any("Failed password" in line for line in lines)
    assert any("Failed with result" in line for line in lines)
    assert any("/etc/shadow" in line for line in lines)


def test_filter_log_noise_never_empties_all_benign_batch() -> None:
    raw = "\n".join(
        [
            "systemd[1]: Started Session 1 of User alice.",
            "systemd[1]: Started Session 1 of User alice.",
            "systemd[1]: Finished Clean php session files.",
        ]
    )
    filtered, dropped = filter_log_noise(raw)
    assert filtered.strip()
    assert len(filtered.splitlines()) == 2
    assert dropped == 1


# -- config defaults & validation ----------------------------------------
def test_config_defaults_and_legacy_file_upgrade(tmp_path) -> None:
    cfg = ClientConfig()
    assert cfg.max_batch_chars == DEFAULT_AI_BATCH_CHARS == 10_000
    assert cfg.batch_delay_seconds == DEFAULT_BATCH_DELAY == 2.0
    assert cfg.filter_noise is True

    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(
        json.dumps({"base_url": BASE, "interval_seconds": 60, "max_results": 5}),
        encoding="utf-8",
    )
    loaded = ConfigService(legacy_path).load()
    assert loaded.max_batch_chars == DEFAULT_AI_BATCH_CHARS
    assert loaded.batch_delay_seconds == DEFAULT_BATCH_DELAY
    assert loaded.filter_noise is True


def test_config_validation_bounds() -> None:
    with pytest.raises(ConfigurationError):
        ClientConfig(max_batch_chars=500).validated()
    with pytest.raises(ConfigurationError):
        ClientConfig(max_batch_chars=50_001).validated()
    with pytest.raises(ConfigurationError):
        ClientConfig(batch_delay_seconds=-0.5).validated()
    with pytest.raises(ConfigurationError):
        ClientConfig(batch_delay_seconds=61.0).validated()


# -- monitoring batch limit + pacing delay -------------------------------
async def test_monitoring_enforces_max_batch_chars_and_paces_split_batches(tmp_path) -> None:
    store = TokenStore(tmp_path / "session.json")
    store.save(Session(access_token=make_jwt(), username="analyst", expires_at=time.time() + 3600))
    auth = AuthService(store=store)
    auth.load_session()

    sleep_calls: list[float] = []

    async def record_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        await asyncio.sleep(0.01)

    async def no_sleep(_seconds: float) -> None:
        return None

    # ~5,200 chars -> with max_batch_chars=2_000 this splits into 3 batches.
    lines = [f"2026-01-01T00:00:{i % 60:02d} sshd: Failed password attempt {i} " + "a" * 35 for i in range(60)]
    payload_text = "\n".join(lines)
    assert len(payload_text) > 4_000

    transport = FakeTransport().queue(
        {"session_id": "s-pace"},
        {"summary": "b1", "matched_techniques": []},
        {"summary": "b2", "matched_techniques": []},
        {"summary": "b3", "matched_techniques": []},
        {"status": "stopped"},
    )
    client = ApiClient(BASE, transport=transport, token_provider=lambda: auth.token, sleep=no_sleep)
    auth.bind_client(client)
    collector = CollectorService(extractor=FakeExtractor(batches=[{"auth_logs": [{"message": payload_text}]}]))
    config = ClientConfig(
        interval_seconds=30,
        sources=("auth_logs",),
        max_batch_chars=2_000,
        batch_delay_seconds=3.5,
        filter_noise=True,
    )
    service = MonitoringService(
        collector,
        client,
        auth,
        config,
        sleep=record_sleep,
    )

    await service.start()
    assert await wait_for(lambda: service.stats.submitted == 3, timeout=5)
    await service.stop()

    sent = [r["json"]["logs"] for r in transport.requests if r["url"].endswith("/api/v1/analyze")]
    assert len(sent) == 3
    assert all(len(chunk) <= 2_000 for chunk in sent)
    # 3 split batches -> 2 pacing sleeps of 3.5s between consecutive batches.
    assert sleep_calls[:2] == [3.5, 3.5]


# -- CLI parser flags ----------------------------------------------------
def test_cli_parser_exposes_batch_limit_delay_and_noise_filter_flags() -> None:
    parser = build_parser()

    dyn = parser.parse_args(
        [
            "profile",
            "setup-dynamic",
            "--interval",
            "120",
            "--max-batch-chars",
            "8000",
            "--batch-delay",
            "3.5",
            "--no-noise-filter",
        ]
    )
    assert dyn.max_batch_chars == 8000
    assert dyn.batch_delay == 3.5
    assert dyn.no_noise_filter is True

    mon = parser.parse_args(
        [
            "monitor",
            "--dynamic",
            "--max-batch-chars",
            "9000",
            "--batch-delay",
            "1.5",
            "--no-noise-filter",
        ]
    )
    assert mon.max_batch_chars == 9000
    assert mon.batch_delay == 1.5
    assert mon.no_noise_filter is True


# -- TUI settings round-trip ---------------------------------------------
async def test_tui_settings_round_trips_batch_chars_delay_and_noise_filter(tmp_path) -> None:
    config = ClientConfig(
        interval_seconds=120,
        max_results=3,
        max_batch_chars=12_000,
        batch_delay_seconds=2.5,
        filter_noise=True,
        sources=("auth_logs",),
    )
    transport = FakeTransport().queue(HEALTH, PROFILE, HEALTH, PROFILE)
    service = build_service(tmp_path, transport, config=config)
    app = ForensIQApp(service=service, auto_probe=False)

    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "6")
        await pilot.pause()

        assert app.query_one("#settings-batch-chars", Input).value == "12000"
        assert app.query_one("#settings-batch-delay", Input).value == "2.5"
        assert app.query_one("#settings-filter-noise", Checkbox).value is True

        app.query_one("#settings-batch-chars", Input).value = "8000"
        app.query_one("#settings-batch-delay", Input).value = "4"
        app.query_one("#settings-filter-noise", Checkbox).value = False
        await pilot.pause()
        app.query_one("#btn-save-settings", Button).press()
        await pilot.pause()

        saved = ConfigService(tmp_path / "config.json").load()
        assert saved.max_batch_chars == 8000
        assert saved.batch_delay_seconds == 4.0
        assert saved.filter_noise is False

