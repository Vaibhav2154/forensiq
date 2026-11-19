"""Real-backend integration tests (Phase 6).

Skipped unless the local FastAPI server is reachable.  Run them explicitly::

    cli_agent/.venv/bin/python -m pytest cli_agent/tests/integration -q

They talk to a real server over HTTP through the real ``aiohttp`` transport -
no fake responses, no monkeypatched clients.  Credentials are created for the
test run and never printed.
"""

from __future__ import annotations

import os
import secrets
import time

import pytest

from cli_agent.services.auth_service import Session, TokenStore
from cli_agent.services.cli_service import CliService
from cli_agent.services.config_service import ClientConfig, ConfigService
from cli_agent.services.errors import AuthError, UnauthorizedError, ValidationError
from cli_agent.tui.app import ForensIQApp

from ..conftest import make_jwt, wait_for

BASE_URL = os.environ.get("FORENSIQ_E2E_URL", "http://127.0.0.1:8000")


def _reachable() -> bool:
    import socket
    from urllib.parse import urlsplit

    parts = urlsplit(BASE_URL)
    try:
        with socket.create_connection((parts.hostname or "127.0.0.1", parts.port or 80), timeout=1):
            return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _reachable(), reason=f"backend not reachable at {BASE_URL}"),
]


def build_service(tmp_path) -> CliService:
    config_service = ConfigService(tmp_path / "config.json")
    config_service.save(
        ClientConfig(base_url=BASE_URL, interval_seconds=60, max_results=3, enhance_with_ai=False)
    )
    return CliService(
        config_service=config_service,
        token_store=TokenStore(tmp_path / "session.json"),
    )


async def _new_account(service: CliService) -> tuple[str, str]:
    suffix = secrets.token_hex(5)
    username = f"phase6_e2e_{suffix}"
    email = f"{username}@example.com"
    password = f"E2e-{secrets.token_hex(8)}"
    await service.register(username, email, password)
    return username, password


async def test_registration_login_profile_and_logout(tmp_path) -> None:
    service = build_service(tmp_path)
    try:
        username, password = await _new_account(service)
        session = await service.login(username, password)
        assert session.access_token
        assert service.is_authenticated

        profile = await service.profile()
        assert profile["username"] == username
        assert profile["email"] == f"{username}@example.com"

        # Logout discards the token and the persisted file.
        service.logout()
        assert not service.is_authenticated
        assert not (tmp_path / "session.json").exists()
    finally:
        await service.close()


async def test_invalid_credentials_and_token(tmp_path) -> None:
    service = build_service(tmp_path)
    try:
        username, _password = await _new_account(service)
        with pytest.raises(AuthError):
            await service.login(username, "definitely-wrong")

        service.auth.store.save(
            Session(
                access_token=make_jwt(expires_in=3600, subject="ghost"),
                username="ghost",
                expires_at=time.time() + 3600,
            )
        )
        service.auth.load_session()
        with pytest.raises(AuthError):
            await service.profile()
        assert not service.is_authenticated
    finally:
        await service.close()


async def test_health_and_knowledge_contracts(tmp_path) -> None:
    service = build_service(tmp_path)
    try:
        health = await service.backend_health()
        assert health["status"] in {"healthy", "degraded"}
        stats = await service.knowledge_stats()
        assert "total_records" in stats
        search = await service.search_knowledge("brute force", top_k=3)
        assert "hits" in search and isinstance(search["hits"], list)
    finally:
        await service.close()


async def test_analysis_and_session_lifecycle(tmp_path) -> None:
    service = build_service(tmp_path)
    try:
        username, password = await _new_account(service)
        await service.login(username, password)

        view = await service.analyze_text(
            "2026-01-01T00:00:00Z sshd[1]: Failed password for root from 10.0.4.19 port 22 ssh2",
            enhance_with_ai=False,
            max_results=3,
        )
        assert view.summary
        assert view.processing_time_ms is not None
        assert view.technique_count == len(view.techniques)

        monitoring = await service.start_monitoring(interval=60, sources=None)
        assert monitoring.stats.session_id
        session_id = monitoring.stats.session_id
        rows = await service.list_sessions(active_only=False)
        assert any(row["session_id"] == session_id for row in rows)

        await service.stop_monitoring()
        rows = await service.list_sessions(active_only=False)
        stopped = next(row for row in rows if row["session_id"] == session_id)
        assert stopped["status"] == "stopped"

        latest = await service.latest_analysis()
        assert latest is None or "summary" in latest
        history = await service.analysis_history(limit=5)
        assert isinstance(history, list)
    finally:
        await service.close()


async def test_live_tui_against_the_real_backend(tmp_path) -> None:
    """Drive the real Textual app (not ``preview``) against the real server."""
    service = build_service(tmp_path)
    username, password = await _new_account(service)
    await service.login(username, password)
    service.config_service.save(
        ClientConfig(base_url=BASE_URL, interval_seconds=60, max_results=3, enhance_with_ai=False)
    )
    service.config = service.config_service.load()
    service.api.base_url = BASE_URL

    app = ForensIQApp(service=service, auto_probe=True)
    try:
        async with app.run_test(size=(120, 40)) as pilot:
            assert await wait_for(lambda: app.state.backend.state == "online", timeout=10)
            await pilot.pause()
            assert app.state.username == username

            await pilot.press("3")
            assert await wait_for(lambda: app.state.analysis_status in {"loaded", "empty"}, timeout=10)

            await pilot.press("5")
            assert await wait_for(lambda: app.state.sessions_status == "loaded", timeout=10)

            await pilot.press("4")
            assert await wait_for(lambda: app.state.knowledge_status == "loaded", timeout=10)
    finally:
        await service.close()
