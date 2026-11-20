"""Durable batch delivery, acknowledgement-gated checkpoints and restart replay."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from cli_agent.services.api_client import ApiClient
from cli_agent.services.auth_service import AuthService, Session, TokenStore
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ClientConfig
from cli_agent.services.monitoring_service import MonitoringService, MonitoringState
from cli_agent.services.outbox import Outbox

from .conftest import FakeExtractor, FakeTransport, make_jwt, wait_for
from .test_collector_state import OffsetsExtractor

BASE = "http://localhost:8000"


async def _fast_sleep(_seconds: float) -> None:
    await asyncio.sleep(0.01)


def make_auth(tmp_path) -> AuthService:
    store = TokenStore(tmp_path / "session.json")
    store.save(Session(access_token=make_jwt(), username="analyst", expires_at=time.time() + 3600))
    auth = AuthService(store=store)
    auth.load_session()
    return auth


def make_monitoring(
    tmp_path,
    transport: FakeTransport,
    *,
    batches=None,
    collector: CollectorService | None = None,
    outbox: Outbox | None = None,
    retry_attempts: int = 3,
) -> MonitoringService:
    auth = make_auth(tmp_path)
    client = ApiClient(BASE, transport=transport, token_provider=lambda: auth.token, sleep=_no_sleep)
    auth.bind_client(client)
    collector = collector or CollectorService(extractor=FakeExtractor(batches=batches))
    config = ClientConfig(interval_seconds=10, sources=("auth_logs",))
    return MonitoringService(
        collector,
        client,
        auth,
        config,
        outbox=outbox,
        sleep=_fast_sleep,
        batch_retry_attempts=retry_attempts,
    )


async def _no_sleep(_seconds: float) -> None:
    return None


def analyze_requests(transport: FakeTransport) -> list[dict]:
    return [r for r in transport.requests if r["url"].endswith("/api/v1/analyze")]


async def test_multiple_batches_are_delivered_in_order_without_loss(tmp_path) -> None:
    text = "x" * 60_000
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        {"summary": "one", "matched_techniques": []},
        {"summary": "two", "matched_techniques": []},
        {"status": "stopped"},
    )
    outbox = Outbox(tmp_path / "pending.json")
    service = make_monitoring(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": text}]}],
        outbox=outbox,
    )

    await service.start()
    assert await wait_for(lambda: service.stats.submitted == 2, timeout=5)
    await service.stop()

    payloads = [r["json"]["logs"] for r in analyze_requests(transport)]
    assert len(payloads) == 2
    assert all(len(payload) <= 50_000 for payload in payloads)
    assert "".join(payloads).count("x") == 60_000
    assert service.stats.batches_submitted == 2
    assert service.stats.batches_pending == 0
    assert not outbox.exists()


async def test_checkpoint_waits_for_acknowledgement(tmp_path) -> None:
    log = tmp_path / "auth.log"
    lines = [f"2026-01-01T00:0{i}: host sshd: event {i} " + "z" * 120 for i in range(600)]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    state = tmp_path / "collector_state.json"
    collector = CollectorService(extractor=OffsetsExtractor(log), state_path=state)
    outbox = Outbox(tmp_path / "pending.json")

    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        (422, {"detail": "simulated validation failure"}),
    )
    service = make_monitoring(tmp_path, transport, collector=collector, outbox=outbox)

    await service.start()
    assert await wait_for(lambda: service.stats.batches_pending >= 1, timeout=5)
    assert service.state is MonitoringState.RUNNING, "a batch failure must not kill the loop"
    assert not state.exists(), "checkpoint advanced before the backend acknowledged the data"
    pending = outbox.load()
    assert pending is not None and not pending.is_empty

    # Retry what is pending, then verify the checkpoint catches up.
    transport.queue(
        {"summary": "ok", "matched_techniques": []},
        {"summary": "ok", "matched_techniques": []},
        {"status": "stopped"},
    )
    await service.force_cycle()
    assert await wait_for(lambda: service.stats.batches_pending == 0, timeout=5)
    await service.stop()

    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved[str(log)] == log.stat().st_size
    assert not outbox.exists()

    # A restarted collector must not replay the acknowledged file.
    restarted = CollectorService(extractor=OffsetsExtractor(log), state_path=state)
    assert restarted.collect(["auth_logs"]).total_entries == 0


async def test_pending_delivery_survives_a_new_service_instance(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("\n".join(f"line {i} " + "q" * 100 for i in range(600)) + "\n", encoding="utf-8")
    state = tmp_path / "collector_state.json"
    outbox = Outbox(tmp_path / "pending.json")

    first = make_monitoring(
        tmp_path,
        FakeTransport().queue(
            {"session_id": "s-1"},
            (422, {"detail": "not now"}),
            {"status": "stopped"},
        ),
        collector=CollectorService(extractor=OffsetsExtractor(log), state_path=state),
        outbox=outbox,
    )
    await first.start()
    assert await wait_for(lambda: first.stats.batches_pending >= 1, timeout=5)
    await first.stop()
    assert outbox.exists()

    transport = FakeTransport().queue(
        {"session_id": "s-2"},
        {"summary": "ok", "matched_techniques": []},
        {"summary": "ok", "matched_techniques": []},
        {"status": "stopped"},
    )
    second = make_monitoring(
        tmp_path,
        transport,
        collector=CollectorService(extractor=OffsetsExtractor(log), state_path=state),
        outbox=outbox,
    )
    await second.start()
    assert await wait_for(
        lambda: second.stats.submitted >= 2 and second.stats.batches_pending == 0,
        timeout=5,
    )
    await second.stop()

    assert not outbox.exists()
    assert analyze_requests(transport), "pending batches were not replayed"
    assert json.loads(state.read_text(encoding="utf-8"))[str(log)] == log.stat().st_size


async def test_auth_expiry_preserves_pending_batches(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        (401, {"detail": "token expired"}),
        {"status": "stopped"},
    )
    outbox = Outbox(tmp_path / "pending.json")
    service = make_monitoring(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "unanswered"}]}],
        outbox=outbox,
    )

    await service.start()
    assert await wait_for(lambda: service.state is MonitoringState.ERROR, timeout=5)
    assert service.stats.batches_pending == 1
    saved = outbox.load()
    assert saved is not None and "unanswered" in saved.batches[0].text

    await service.stop()
    assert service.state is MonitoringState.STOPPED
    assert outbox.exists(), "authentication loss must not discard collected logs"


async def test_full_outbox_pauses_collection_instead_of_discarding(tmp_path) -> None:
    transport = FakeTransport().queue({"session_id": "s-1"}, {"status": "stopped"})
    outbox = Outbox(tmp_path / "pending.json", max_bytes=8)
    service = make_monitoring(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "more than eight bytes"}]}],
        outbox=outbox,
    )

    await service.start()
    assert await wait_for(lambda: service.state is MonitoringState.ERROR, timeout=5)
    assert service.stats.batches_pending == 0
    assert not analyze_requests(transport), "nothing may be sent when the journal is full"
    assert "storage" in (service.stats.last_error or "").lower()
    await service.stop()


async def test_session_close_reports_unknown_when_stop_fails(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-9"},
        (503, {"detail": "database offline"}),
    )
    service = make_monitoring(tmp_path, transport)
    await service.start()
    await wait_for(lambda: service.stats.cycles >= 1, timeout=5)
    await service.stop()

    assert service.stats.session_close.startswith("unknown")
    assert "closed" not in service.stats.session_close


async def test_session_close_is_confirmed_on_success(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-9"},
        {"session_id": "s-9", "status": "stopped"},
    )
    service = make_monitoring(tmp_path, transport)
    await service.start()
    await service.stop()
    assert service.stats.session_close == "closed"


async def test_stop_during_a_slow_submission_is_bounded(tmp_path) -> None:
    transport = FakeTransport(
        [
            {"session_id": "s-1"},
            {"summary": "slow", "matched_techniques": []},
            {"status": "stopped"},
        ],
        delay=0.5,
    )
    outbox = Outbox(tmp_path / "pending.json")
    service = make_monitoring(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "in flight"}]}],
        outbox=outbox,
    )

    await service.start()
    assert await wait_for(
        lambda: any(r["url"].endswith("/api/v1/analyze") for r in transport.requests),
        timeout=5,
    )
    await asyncio.wait_for(service.stop(), timeout=3)
    assert service.state is MonitoringState.STOPPED
    assert service._task is None
    # Any unacknowledged text remains durable (or was fully acknowledged).
    if outbox.exists():
        assert outbox.load().batches


async def test_stop_before_a_slow_session_registration_leaves_no_running_loop(tmp_path) -> None:
    transport = FakeTransport([{"session_id": "late"}], delay=0.2)
    service = make_monitoring(tmp_path, transport)

    start_task = asyncio.create_task(service.start())
    await asyncio.sleep(0.02)
    await asyncio.wait_for(service.stop(), timeout=3)
    await asyncio.wait_for(start_task, timeout=3)

    assert service.state is MonitoringState.STOPPED
    assert service._task is None
    assert not service.is_running


async def test_two_concurrent_force_cycles_do_not_double_submit(tmp_path) -> None:
    transport = FakeTransport().queue(
        {"session_id": "s-1"},
        {"summary": "ok", "matched_techniques": []},
        {"status": "stopped"},
    )
    service = make_monitoring(
        tmp_path,
        transport,
        batches=[{"auth_logs": [{"message": "only once"}]}],
    )
    await service.start()
    assert await wait_for(lambda: service.stats.submitted == 1, timeout=5)

    await asyncio.gather(service.force_cycle(), service.force_cycle())
    await service.stop()
    assert len(analyze_requests(transport)) == 1
