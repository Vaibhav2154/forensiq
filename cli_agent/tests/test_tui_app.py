"""Phase 4 + 5: functional Textual app against the real service layer.

Every test runs headless (``run_test``) with the fake transport/extractor from
``conftest``: no network, no real log files, no writes outside ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from textual.widgets import DataTable, Input, Label, RichLog, Static

from cli_agent.services.auth_service import Session, TokenStore
from cli_agent.services.cli_service import CliService
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ClientConfig, ConfigService
from cli_agent.tui.app import ForensIQApp, LoginScreen

from .conftest import FakeExtractor, FakeTransport, make_jwt, wait_for

SIZE = (120, 40)


def build_service(
    tmp_path,
    transport: FakeTransport,
    *,
    batches=None,
    session: bool = True,
    config: ClientConfig | None = None,
) -> CliService:
    config_service = ConfigService(tmp_path / "config.json")
    if config is not None:
        config_service.save(config)
    store = TokenStore(tmp_path / "session.json")
    if session:
        store.save(
            Session(
                access_token=make_jwt(),
                username="analyst",
                expires_at=time.time() + 3600,
            )
        )
    return CliService(
        config_service=config_service,
        token_store=store,
        transport=transport,
        collector=CollectorService(extractor=FakeExtractor(batches=batches or [])),
    )


def card(app: ForensIQApp, index: int) -> str:
    return app.query(".card")[index].content


def stream_text(app: ForensIQApp) -> str:
    log = app.query_one("#stream", RichLog)
    return "\n".join(line.text for line in log.lines)


def note_text(app: ForensIQApp) -> str:
    return str(app.query_one("#view-note", Label).content)


# -- authentication ------------------------------------------------------
async def test_signed_out_app_blocks_monitoring(tmp_path) -> None:
    transport = FakeTransport()
    service = build_service(tmp_path, transport, session=False)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert "signed out" in card(app, 0)

        await pilot.press("s")
        await pilot.pause()

        assert app.service.monitoring is None
        assert transport.requests == []
        assert "authentication required" in stream_text(app)


async def test_restored_session_is_shown(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport())
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert "analyst" in card(app, 0)
        assert "session restored" in stream_text(app)


async def test_login_modal_authenticates_and_dismisses(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport().queue({"access_token": make_jwt()}), session=False)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, LoginScreen)

        app.screen.query_one("#login-username", Input).value = "analyst"
        app.screen.query_one("#login-password", Input).value = "secret"
        await pilot.click("#btn-login")
        assert await wait_for(lambda: app.service.is_authenticated)

        await pilot.pause()
        assert not isinstance(app.screen, LoginScreen)
        assert "analyst" in card(app, 0)
        assert "signed in as analyst" in stream_text(app)


async def test_failed_login_reports_error_without_leaking_password(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport().queue((401, {"detail": "bad credentials"})), session=False)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("l")
        await pilot.pause()
        app.screen.query_one("#login-username", Input).value = "analyst"
        app.screen.query_one("#login-password", Input).value = "hunter2"
        await pilot.click("#btn-login")
        assert await wait_for(
            lambda: "incorrect username or password"
            in str(app.screen.query_one("#login-error", Label).content)
        )
        assert not app.service.is_authenticated
        assert "hunter2" not in str(app.screen.query_one("#login-error", Label).content)
        assert "bad credentials" not in str(app.screen.query_one("#login-error", Label).content)
        assert app.screen.query_one("#login-password", Input).value == ""


async def test_logout_stops_monitoring_and_clears_token(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-1"})
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("s")
        assert await wait_for(lambda: service.monitoring is not None)

        await pilot.press("o")
        assert await wait_for(lambda: not service.is_authenticated)

        assert service.monitoring is None
        assert "signed out" in card(app, 0)
        assert (tmp_path / "session.json").exists() is False


# -- configuration -------------------------------------------------------
async def test_configuration_is_loaded_and_applied(tmp_path) -> None:
    config = ClientConfig(
        base_url="http://10.0.0.5:9000",
        interval_seconds=120,
        max_results=3,
        sources=("auth_logs",),
    )
    transport = FakeTransport().queue({"session_id": "s-1"})
    service = build_service(tmp_path, transport, config=config)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert "10.0.0.5:9000" in card(app, 1)
        assert app.service.config.interval_seconds == 120

        await pilot.press("s")
        assert await wait_for(lambda: service.monitoring is not None)
        assert service.monitoring.interval_seconds == 120
        await pilot.press("x")


async def test_settings_view_reports_live_configuration(tmp_path) -> None:
    config = ClientConfig(interval_seconds=120, max_results=3, sources=("auth_logs",))
    service = build_service(tmp_path, FakeTransport(), config=config)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("6")
        await pilot.pause()
        assert app.view == "settings"
        note = note_text(app)
        assert "interval 120s" in note
        assert "max results 3" in note
        assert "auth_logs" in note


async def test_each_view_has_its_own_heading_and_content(tmp_path) -> None:
    """Phase 6 + HITL Remediation: destinations no longer share one placeholder view-note."""
    service = build_service(tmp_path, FakeTransport())
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        seen = set()
        for key in ("1", "2", "3", "4", "5", "6", "7"):
            await pilot.press(key)
            await pilot.pause()
            note = note_text(app)
            assert "placeholder" not in note
            seen.add(note)
        assert len(seen) == 7


# -- monitoring lifecycle ------------------------------------------------
async def test_start_runs_a_cycle_and_fills_the_existing_widgets(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "sess-7"},
        {
            "summary": "brute force against sshd",
            "matched_techniques": [{"technique_id": "T1110", "name": "Brute Force", "relevance_score": 0.87}],
        },
    )
    service = build_service(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "Failed password"}, {"message": "Failed password"}]}],
    )
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("s")
        assert await wait_for(lambda: app.submitted >= 1)
        await pilot.pause()

        assert "running" in card(app, 2)
        assert "1 submitted" in card(app, 3)
        table = app.query_one("#techniques", DataTable)
        assert table.row_count == 1
        assert "cycle 1" in stream_text(app)
        assert "brute force against sshd" in stream_text(app)

        await pilot.press("x")
        assert await wait_for(lambda: service.monitoring is None)
        await pilot.pause()
        assert "stopped" in card(app, 2)
        assert transport.requests[-1]["url"].endswith("/monitoring/sessions/sess-7/stop")


async def test_force_cycle_submits_an_extra_batch(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        {"summary": "one", "matched_techniques": []},
        {"summary": "two", "matched_techniques": []},
    )
    service = build_service(
        tmp_path,
        transport,
        batches=[
            {"auth_logs": [{"message": "a"}]},
            {"auth_logs": [{"message": "b"}]},
        ],
    )
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("s")
        assert await wait_for(lambda: app.submitted >= 1)

        await pilot.press("t")
        assert await wait_for(lambda: app.submitted >= 2)
        await pilot.press("x")
        assert await wait_for(lambda: service.monitoring is None)


async def test_force_cycle_before_start_only_reports(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport())
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("t")
        await pilot.pause()
        assert "start monitoring first" in stream_text(app)


async def test_backend_failure_is_reported_and_loop_survives(tmp_path) -> None:
    transport = FakeTransport().queue(
        (503, {"detail": "database offline"}),
        (500, {"detail": "analysis exploded"}),
    )
    service = build_service(tmp_path, transport, batches=[{"auth_logs": [{"message": "x"}]}])
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("s")
        assert await wait_for(lambda: "backend error" in stream_text(app))
        assert await wait_for(lambda: "analysis exploded" in stream_text(app))

        await pilot.pause()
        assert service.monitoring is not None
        assert service.monitoring.state.value == "running"
        await pilot.press("x")
        assert await wait_for(lambda: service.monitoring is None)


async def test_start_button_and_monitoring_guard_are_consistent(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-1"})
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        assert app.query_one("#btn-start").disabled is False
        assert app.query_one("#btn-stop").disabled is True

        await pilot.press("s")
        assert await wait_for(lambda: service.monitoring is not None)
        await pilot.pause()
        assert app.query_one("#btn-start").disabled is True
        assert app.query_one("#btn-stop").disabled is False

        await pilot.press("x")
        assert await wait_for(lambda: service.monitoring is None)
        await pilot.pause()
        assert app.query_one("#btn-start").disabled is False


# -- shutdown ------------------------------------------------------------
async def test_quit_stops_monitoring_and_closes_the_transport(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-3"}, {"status": "stopped"})
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("s")
        assert await wait_for(lambda: service.monitoring is not None)

        await pilot.press("q")

    assert service.monitoring is None
    assert transport.closed is True
    assert transport.requests[-1]["url"].endswith("/monitoring/sessions/s-3/stop")


async def test_shutdown_without_monitoring_is_clean(tmp_path) -> None:
    transport = FakeTransport()
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        await pilot.press("q")

    assert transport.closed is True
    assert asyncio.all_tasks() == {asyncio.current_task()} or all(
        task.done() for task in asyncio.all_tasks() if task is not asyncio.current_task()
    )
