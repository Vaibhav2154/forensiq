"""Phase 6: distinct, data-driven pages against the service layer.

All offline: the fake transport scripts the verified backend contracts
(``/health``, ``/api/v1/latest``, ``/api/v1/monitoring/sessions``,
``/api/v1/knowledge/*``).  Real-backend coverage lives in
``tests/integration/test_backend_e2e.py`` and is labelled separately.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from textual.widgets import Button, Checkbox, DataTable, Input, Label, RichLog

from cli_agent.services.api_client import ApiClient
from cli_agent.services.auth_service import Session, TokenStore
from cli_agent.services.cli_service import CliService
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ClientConfig, ConfigService
from cli_agent.services.errors import AuthError, TransportError
from cli_agent.tui.app import ForensIQApp

from .conftest import FakeExtractor, FakeTransport, make_jwt, wait_for

SIZE = (120, 40)
HEALTH = {"status": "healthy", "services": {"gemini_ai": "healthy", "knowledge": "healthy"}}
PROFILE = {"username": "analyst", "email": "analyst@example.com", "cli_active": True}

ANALYSIS = {
    "summary": "KCP normalized 3 events; one failed SSH login burst.",
    "matched_techniques": [
        {"technique_id": "T1110", "name": "Brute Force", "relevance_score": 0.87},
        {"technique_id": "T1078", "name": "Valid Accounts", "relevance_score": 0.41},
    ],
    "enhanced_analysis": "Multi-agent report text.",
    "investigation": {"executive_summary": "Short investigation summary.", "findings": [{"id": "f1"}]},
    "visualization_metrics": {"severity_breakdown": {"high": 1}},
    "processing_time_ms": 12.5,
    "analysis_timestamp": "2026-01-01T10:00:00",
}

SESSIONS = [
    {
        "session_id": "sess-aaaa",
        "status": "active",
        "created_at": "2026-01-01T09:00:00",
        "stopped_at": None,
        "interval_seconds": 300,
        "log_path": "dynamic:auth_logs",
        "ai_agent_enabled": False,
    },
    {
        "session_id": "sess-bbbb",
        "status": "stopped",
        "created_at": "2026-01-01T08:00:00",
        "stopped_at": "2026-01-01T08:30:00",
        "interval_seconds": 120,
        "log_path": "dynamic:syslog",
        "ai_agent_enabled": False,
    },
]

KNOWLEDGE_STATS = {
    "backend": "cognee",
    "total_records": 42,
    "counts_by_kind": {"attack-pattern": 40, "cve": 2},
    "counts_by_source_type": {"mitre_attack": 40, "cve": 2},
    "active_versions": {"mitre_attack": ["17.1"]},
    "total_ingestion_runs": 3,
    "last_ingested_at": "2026-01-01T07:00:00+00:00",
}

KNOWLEDGE_SEARCH = {
    "query": "brute force",
    "total_hits": 1,
    "retrieval_mode": "auto",
    "hits": [
        {
            "record": {"record_id": "r1", "source_id": "T1110", "content": {"name": "Brute Force"}},
            "score": 0.91,
            "retrieval_mode": "auto",
            "matched_via": "lexical",
        }
    ],
    "notice": "Context only, not proof of compromise.",
}


def build_service(
    tmp_path,
    transport,
    *,
    session: bool = True,
    config: ClientConfig | None = None,
    batches: list[dict[str, Any]] | None = None,
) -> CliService:
    config_service = ConfigService(tmp_path / "config.json")
    if config is not None:
        config_service.save(config)
    store = TokenStore(tmp_path / "session.json")
    if session:
        store.save(Session(access_token=make_jwt(), username="analyst", expires_at=time.time() + 3600))
    return CliService(
        config_service=config_service,
        token_store=store,
        transport=transport,
        collector=CollectorService(extractor=FakeExtractor(batches=batches or [])),
    )


def card(app: ForensIQApp, card_id: str) -> str:
    return str(app.query_one(f"#{card_id}").content)


def note(app: ForensIQApp) -> str:
    return str(app.query_one("#view-note", Label).content)


def detail_text(app: ForensIQApp) -> str:
    log = app.query_one("#detail-view", RichLog)
    return "\n".join(line.text for line in log.lines)


def table_cells(app: ForensIQApp) -> list[list[str]]:
    table = app.query_one("#techniques", DataTable)
    return [[str(cell) for cell in table.get_row_at(index)] for index in range(table.row_count)]


async def goto(app: ForensIQApp, pilot, key: str) -> None:
    await pilot.press(key)
    await pilot.pause()


# -- dashboard -----------------------------------------------------------
async def test_dashboard_reports_live_backend_health(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, PROFILE)
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=True)
    async with app.run_test(size=SIZE) as pilot:
        assert await wait_for(lambda: app.state.backend.state == "online")
        await pilot.pause()
        assert "Online" in card(app, "card-backend")
        assert "analyst" in card(app, "card-auth")
        assert "gemini_ai: healthy" in str(app.query_one("#page-detail-text").content)
        assert any(req["url"].endswith("/health") for req in transport.requests)


async def test_dashboard_shows_offline_without_fake_values(tmp_path) -> None:
    transport = FakeTransport(error=TransportError("connection refused"))
    service = build_service(tmp_path, transport, session=False)
    app = ForensIQApp(service=service, auto_probe=True)
    async with app.run_test(size=SIZE) as pilot:
        assert await wait_for(lambda: app.state.backend.state == "offline")
        await pilot.pause()
        assert "Offline" in card(app, "card-backend")
        assert "signed out" in card(app, "card-auth")
        assert "stopped" in card(app, "card-mon")


# -- analysis ------------------------------------------------------------
async def test_analysis_page_renders_backend_response(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, {"analysis": ANALYSIS})
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "3")
        assert await wait_for(lambda: app.state.analysis_status == "loaded")
        await pilot.pause()

        rows = table_cells(app)
        assert rows[0][0] == "T1110"
        assert app.query_one("#techniques", DataTable).row_count == 2
        text = detail_text(app)
        assert "SUMMARY" in text
        assert "failed SSH login burst" in text
        assert "Multi-agent report text." in text
        assert "1 finding(s)" in text
        assert "12ms" in str(app.query_one("#monitor-detail").content)


async def test_analysis_page_handles_missing_optional_fields(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, {"analysis": {"summary": "", "matched_techniques": []}})
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "3")
        assert await wait_for(lambda: app.state.analysis_status == "loaded")
        await pilot.pause()
        assert "no techniques in the latest batch" in table_cells(app)[0][1]
        text = detail_text(app)
        assert "backend returned no summary" in text
        assert "Not provided" in text
        assert "T1110" not in text


async def test_analysis_empty_state_when_nothing_stored(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, {"analysis": None})
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "3")
        assert await wait_for(lambda: app.state.analysis_status == "empty")
        await pilot.pause()
        assert "No analysis available" in str(app.query_one("#page-detail-text").content)


async def test_analysis_requires_authentication(tmp_path) -> None:
    service = build_service(tmp_path, FakeTransport(), session=False)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "3")
        await pilot.pause()
        assert app.state.analysis_status == "empty"
        assert "not authenticated" in str(app.query_one("#page-detail-text").content)


# -- sessions ------------------------------------------------------------
async def test_sessions_page_lists_backend_history(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, SESSIONS)
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "5")
        assert await wait_for(lambda: app.state.sessions_status == "loaded")
        await pilot.pause()
        rows = table_cells(app)
        assert len(rows) == 2
        assert rows[0][1] == "active"
        assert rows[1][1] == "stopped"
        assert "2 row(s)" in note(app)
        # The backend history route is queried with active_only=false.
        session_requests = [r for r in transport.requests if "/monitoring/sessions" in r["url"]]
        assert session_requests and "active_only=false" in session_requests[-1]["url"]


async def test_sessions_page_reports_backend_error(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, (500, {"detail": "session store offline"}))
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "5")
        assert await wait_for(lambda: app.state.sessions_status == "error")
        await pilot.pause()
        assert "session store offline" in str(app.query_one("#page-detail-text").content)


# -- knowledge -----------------------------------------------------------
async def test_knowledge_page_shows_store_stats(tmp_path) -> None:
    transport = FakeTransport().queue(KNOWLEDGE_STATS)
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "4")
        assert await wait_for(lambda: app.state.knowledge_status == "loaded")
        await pilot.pause()
        assert "cognee" in str(app.query_one("#monitor-detail").content)
        assert "42 record(s)" in note(app)
        assert "ATT&CK/CVE context only" in detail_text(app)


async def test_knowledge_search_renders_real_hits(tmp_path) -> None:
    transport = FakeTransport().queue(KNOWLEDGE_STATS, KNOWLEDGE_SEARCH)
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "4")
        assert await wait_for(lambda: app.state.knowledge_status == "loaded")
        app.query_one("#knowledge-query", Input).value = "brute force"
        app.query_one("#btn-knowledge-search", Button).press()
        assert await wait_for(lambda: app.state.knowledge_search_status == "loaded")
        await pilot.pause()
        assert table_cells(app)[0][0] == "T1110"
        assert app.state.knowledge_hits[0]["score"] == 0.91
        assert "Context only" in detail_text(app)
        assert "q=brute+force" in transport.requests[-1]["url"]


# -- settings ------------------------------------------------------------
async def test_settings_loads_and_saves_valid_configuration(tmp_path) -> None:
    config = ClientConfig(interval_seconds=120, max_results=3, sources=("auth_logs",))
    transport = FakeTransport().queue(HEALTH, PROFILE, HEALTH, PROFILE)
    service = build_service(tmp_path, transport, config=config)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "6")
        await pilot.pause()
        assert app.query_one("#settings-url", Input).value == "http://localhost:8000"
        assert app.query_one("#settings-interval", Input).value == "120"

        app.query_one("#settings-url", Input).value = "http://127.0.0.1:9000"
        app.query_one("#settings-interval", Input).value = "60"
        app.query_one("#settings-max-results", Input).value = "7"
        await pilot.pause()
        app.query_one("#btn-save-settings", Button).press()
        await pilot.pause()

        saved = ConfigService(tmp_path / "config.json").load()
        assert saved.base_url == "http://127.0.0.1:9000"
        assert saved.interval_seconds == 60
        assert saved.max_results == 7
        assert service.api.base_url == "http://127.0.0.1:9000"
        assert str(app.query_one("#form-error", Label).content) == ""


async def test_settings_rejects_invalid_values(tmp_path) -> None:
    transport = FakeTransport()
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "6")
        await pilot.pause()
        app.query_one("#settings-url", Input).value = "ftp://nope"
        app.query_one("#btn-save-settings", Button).press()
        await pilot.pause()
        assert "http" in str(app.query_one("#form-error", Label).content)
        assert service.config.base_url == "http://localhost:8000"

        app.query_one("#settings-url", Input).value = "http://localhost:8000"
        app.query_one("#settings-interval", Input).value = "5"
        app.query_one("#btn-save-settings", Button).press()
        await pilot.pause()
        assert "interval_seconds" in str(app.query_one("#form-error", Label).content)


async def test_settings_enhance_checkbox_round_trips(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, PROFILE)
    service = build_service(tmp_path, transport, config=ClientConfig(enhance_with_ai=True))
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "6")
        await pilot.pause()
        app.query_one("#settings-enhance", Checkbox).value = False
        app.query_one("#btn-save-settings", Button).press()
        await pilot.pause()
        assert ConfigService(tmp_path / "config.json").load().enhance_with_ai is False


# -- shared reactive state ----------------------------------------------
async def test_monitoring_updates_dashboard_and_monitoring_pages(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "sess-77"},
        {"summary": "two failures", "matched_techniques": []},
        HEALTH,
    )
    service = build_service(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "a"}, {"message": "b"}]}],
    )
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("s")
        assert await wait_for(lambda: app.state.submitted == 1)
        await pilot.pause()
        assert "running" in card(app, "card-mon")
        assert "1 submitted" in card(app, "card-batches")
        assert app.state.session_id == "sess-77"

        await goto(app, pilot, "2")
        assert await wait_for(lambda: app.view == "monitoring")
        rows = table_cells(app)
        assert rows and rows[0][2] == "submitted"

        await pilot.press("x")
        assert await wait_for(lambda: service.monitoring is None)
        await pilot.pause()
        assert "stopped" in card(app, "card-mon")


async def test_logout_clears_analysis_and_session_state(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, {"analysis": ANALYSIS})
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await goto(app, pilot, "3")
        assert await wait_for(lambda: app.state.analysis_status == "loaded")
        await pilot.press("o")
        assert await wait_for(lambda: not service.is_authenticated)
        await pilot.pause()
        assert app.state.latest_analysis is None
        assert app.state.session_id is None
        assert "signed out" in card(app, "card-auth")


async def test_each_page_has_a_distinct_layout(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH, {"analysis": None}, KNOWLEDGE_STATS, [])
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        headings = []
        for key in ("1", "5", "4", "6"):
            await goto(app, pilot, key)
            headings.append(str(app.query_one("#technique-heading", Label).content))
        assert len(set(headings)) == 4


# -- service-level contract checks (fake transport) ---------------------
async def test_service_backend_views_need_auth_where_the_backend_does(tmp_path) -> None:
    transport = FakeTransport()
    service = build_service(tmp_path, transport, session=False)
    with pytest.raises(AuthError):
        await service.list_sessions()
    with pytest.raises(AuthError):
        await service.latest_analysis()
    # ``/health`` and knowledge stats are deliberately unauthenticated.
    transport.queue(HEALTH, KNOWLEDGE_STATS)
    assert (await service.backend_health())["status"] == "healthy"
    assert (await service.knowledge_stats())["total_records"] == 42


async def test_api_client_sends_no_authorization_for_health(tmp_path) -> None:
    transport = FakeTransport().queue(HEALTH)
    service = build_service(tmp_path, transport)
    await service.backend_health()
    assert "Authorization" not in transport.requests[0]["headers"]


async def test_monitoring_splits_oversized_batches_without_loss(tmp_path) -> None:
    """60k characters are delivered as two ordered batches, not truncated."""
    oversized = "x" * 60_000
    transport = FakeTransport().queue(
        {"session_id": "sess-big"},
        {"summary": "first", "matched_techniques": []},
        {"summary": "second", "matched_techniques": []},
    )
    service = build_service(
        tmp_path,
        transport,
        config=ClientConfig(max_batch_chars=50_000, batch_delay_seconds=0.0, filter_noise=False),
        batches=[{"auth_logs": [{"message": oversized}]}],
    )
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("s")
        assert await wait_for(lambda: app.state.submitted == 2, timeout=5)
        analyze = [r for r in transport.requests if r["url"].endswith("/api/v1/analyze")]
        assert len(analyze) == 2, "the oversized event was not split into batches"
        payloads = [request["json"]["logs"] for request in analyze]
        assert all(len(payload) <= 50_000 for payload in payloads)
        # No marker, no dropped characters: concatenation is the full event.
        assert "client truncated" not in "".join(payloads)
        assert "".join(payloads).count("x") == 60_000
        assert app.state.pending_batches == 0
        assert app.state.oversized_batches == 1
        await pilot.press("x")
        assert await wait_for(lambda: service.monitoring is None)


@pytest.mark.parametrize("size", [(120, 40), (80, 24)])
async def test_all_six_pages_open_at_supported_terminal_sizes(tmp_path, size) -> None:
    """The approved six-page navigation works at both official terminal sizes."""
    transport = FakeTransport().queue(HEALTH, {"analysis": None}, KNOWLEDGE_STATS, [])
    service = build_service(tmp_path, transport)
    app = ForensIQApp(service=service, auto_probe=False)
    async with app.run_test(size=size) as pilot:
        for key, view in (
            ("1", "dashboard"),
            ("2", "monitoring"),
            ("3", "analysis"),
            ("4", "knowledge"),
            ("5", "sessions"),
            ("6", "settings"),
        ):
            await goto(app, pilot, key)
            assert app.view == view
        assert app.theme in app.available_themes
