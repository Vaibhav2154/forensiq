"""Checkpoint 4: monitoring lifecycle, cancellation and failure handling."""

from __future__ import annotations

import asyncio
import time

import pytest

from cli_agent.services.api_client import ApiClient
from cli_agent.services.auth_service import AuthService, Session, TokenStore
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ClientConfig
from cli_agent.services.errors import AuthError
from cli_agent.services.monitoring_service import MonitoringService, MonitoringState

from .conftest import FakeExtractor, FakeTransport, make_jwt, wait_for

BASE = "http://localhost:8000"


async def _fast_sleep(_seconds: float) -> None:
    """Keep loop tests responsive; intervals are asserted, not waited on."""
    await asyncio.sleep(0.01)


def make_service(
    tmp_path,
    transport: FakeTransport,
    *,
    batches=None,
    authenticated: bool = True,
    interval: int = 10,
    sources=("auth_logs",),
):
    store = TokenStore(tmp_path / "session.json")
    if authenticated:
        store.save(
            Session(
                access_token=make_jwt(),
                username="analyst",
                expires_at=time.time() + 3600,
            )
        )
    auth = AuthService(store=store)
    auth.load_session()
    client = ApiClient(BASE, transport=transport, token_provider=lambda: auth.token)
    auth.bind_client(client)
    collector = CollectorService(extractor=FakeExtractor(batches=batches))
    config = ClientConfig(interval_seconds=interval, sources=tuple(sources))
    service = MonitoringService(collector, client, auth, config, sleep=_fast_sleep)
    return service, auth, transport


async def test_start_registers_session_and_submits(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "sess-1", "status": "created"},
        {"summary": "ok", "matched_techniques": []},
    )
    service, _auth, _t = make_service(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"timestamp": "t", "message": "Failed password"}]}],
    )

    assert await service.start() is True
    assert service.state is MonitoringState.RUNNING
    assert await wait_for(lambda: service.stats.submitted == 1)
    await service.stop()

    urls = [request["url"] for request in transport.requests]
    assert urls[0].endswith("/api/v1/monitoring/sessions")
    assert any(url.endswith("/api/v1/analyze") for url in urls)
    assert service.stats.session_id == "sess-1"


async def test_start_twice_does_not_duplicate_the_loop(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "sess-1"})
    service, _auth, _t = make_service(tmp_path, transport)

    assert await service.start() is True
    assert await service.start() is False

    session_posts = [
        r for r in transport.requests if r["url"].endswith("/monitoring/sessions")
    ]
    assert len(session_posts) == 1
    await service.stop()


async def test_stop_cancels_task_and_closes_session(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "sess-9"},
        {"session_id": "sess-9", "status": "stopped"},
    )
    service, _auth, _t = make_service(tmp_path, transport)
    await service.start()

    await service.stop()

    assert service.state is MonitoringState.STOPPED
    assert service._task is None
    assert transport.requests[-1]["url"].endswith("/monitoring/sessions/sess-9/stop")


async def test_stop_leaves_no_pending_tasks(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-1"}, {"status": "stopped"})
    service, _auth, _t = make_service(tmp_path, transport)
    await service.start()
    await service.stop()

    others = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    assert others == [] or all(task.done() for task in others)


async def test_empty_cycle_does_not_submit(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-1"})
    service, _auth, _t = make_service(tmp_path, transport, batches=[{"auth_logs": []}])

    await service.start()
    assert await wait_for(lambda: service.stats.empty_cycles >= 1)
    await service.stop()

    assert service.stats.submitted == 0
    assert not any(r["url"].endswith("/api/v1/analyze") for r in transport.requests)


async def test_failed_submission_is_recorded_and_loop_survives(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        (500, {"detail": "analysis exploded"}),
    )
    service, _auth, _t = make_service(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "x"}]}],
    )

    await service.start()
    assert await wait_for(lambda: service.stats.failures >= 1)
    assert service.state is MonitoringState.RUNNING
    assert "analysis exploded" in (service.stats.last_error or "")
    await service.stop()


async def test_result_callback_receives_view(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        {"summary": "one technique", "matched_techniques": [{"technique_id": "T1110"}]},
    )
    received = []
    store = TokenStore(tmp_path / "session.json")
    store.save(Session(access_token=make_jwt(), expires_at=time.time() + 3600))
    auth = AuthService(store=store)
    auth.load_session()
    client = ApiClient(BASE, transport=transport, token_provider=lambda: auth.token)
    auth.bind_client(client)
    service = MonitoringService(
        CollectorService(
            extractor=FakeExtractor(batches=[{"auth_logs": [{"message": "x"}]}])
        ),
        client,
        auth,
        ClientConfig(interval_seconds=10, sources=("auth_logs",)),
        sleep=_fast_sleep,
        on_result=lambda view, outcome: received.append((view, outcome)),
    )

    await service.start()
    assert await wait_for(lambda: len(received) == 1)
    await service.stop()

    view, outcome = received[0]
    assert view.technique_count == 1
    assert outcome.submitted is True
    assert outcome.collected_entries == 1


async def test_logout_stops_monitoring(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-1"})
    service, auth, _t = make_service(tmp_path, transport)

    await service.start()
    assert await wait_for(lambda: service.stats.cycles >= 1)
    auth.logout()

    assert await wait_for(lambda: service.state is MonitoringState.ERROR)
    await service.stop()
    assert service.state is MonitoringState.STOPPED


async def test_start_requires_authentication(tmp_path) -> None:
    service, _auth, _t = make_service(tmp_path, FakeTransport(), authenticated=False)
    with pytest.raises(AuthError):
        await service.start()
    assert service.state is MonitoringState.STOPPED


async def test_stop_without_start_is_a_noop(tmp_path) -> None:
    service, _auth, _t = make_service(tmp_path, FakeTransport())
    await service.stop()
    assert service.state is MonitoringState.STOPPED


async def test_registration_failure_does_not_block_local_polling(tmp_path) -> None:
    transport = FakeTransport().queue(
        (503, {"detail": "database offline"}),
        {"summary": "still works", "matched_techniques": []},
    )
    service, _auth, _t = make_service(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "x"}]}],
    )

    await service.start()
    assert service.state is MonitoringState.RUNNING
    assert await wait_for(lambda: service.stats.submitted == 1)
    assert service.stats.session_id is None
    await service.stop()


async def test_adaptive_interval_uses_backend_threat_level(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        {"summary": "high risk", "threat_level": "high", "matched_techniques": []},
    )
    service, _auth, _t = make_service(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "x"}]}],
        interval=300,
    )

    await service.start()
    assert await wait_for(lambda: service.stats.submitted == 1)
    assert service.interval_seconds == 100
    await service.stop()


async def test_unknown_threat_level_keeps_base_interval(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        {"summary": "no level", "matched_techniques": []},
    )
    service, _auth, _t = make_service(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "x"}]}],
        interval=300,
    )

    await service.start()
    assert await wait_for(lambda: service.stats.submitted == 1)
    assert service.interval_seconds == 300
    await service.stop()
