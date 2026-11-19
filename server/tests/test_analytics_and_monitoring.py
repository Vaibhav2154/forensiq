"""Tests for user analytics computation, GET /api/v1/analytics, and monitoring sessions."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers.analysis import router as analysis_router
from routers.auth import get_current_user
from routers.monitoring import router as monitoring_router, storage_service as monitoring_storage_service
from services.analysis_storage_service import AnalysisStorageService
from services.encryption_service import encryption_service


class _FakeAsyncCursor:
    def __init__(self, docs: list[dict]) -> None:
        self._docs = list(docs)
        self._idx = 0

    def sort(self, *_args, **_kwargs) -> "_FakeAsyncCursor":
        return self

    def __aiter__(self) -> "_FakeAsyncCursor":
        return self

    async def __anext__(self) -> dict:
        if self._idx >= len(self._docs):
            raise StopAsyncIteration
        item = self._docs[self._idx]
        self._idx += 1
        return item


class _FakeAnalysisCollection:
    def __init__(self, docs: list[dict]) -> None:
        self._docs = docs

    def find(self, _query: dict) -> _FakeAsyncCursor:
        return _FakeAsyncCursor(self._docs)


class _FakeUserCollection:
    def __init__(self, user_doc: dict | None) -> None:
        self._user_doc = user_doc

    async def find_one(self, _query: dict) -> dict | None:
        return self._user_doc


class _FakeDatabase:
    def __init__(self, user_doc: dict | None) -> None:
        self._user_doc = user_doc

    def get_collection(self, name: str) -> _FakeUserCollection:
        assert name == "user_collection"
        return _FakeUserCollection(self._user_doc)


def test_get_user_analytics_empty_and_populated(monkeypatch) -> None:
    svc = AnalysisStorageService()

    # 1. Empty user history
    monkeypatch.setattr(svc, "collection", _FakeAnalysisCollection([]))
    empty_stats = asyncio.run(svc.get_user_analytics("alice"))
    assert empty_stats == {
        "total_analyses": 0,
        "avg_processing_time": 0.0,
        "most_common_techniques": [],
        "analysis_timeline": [],
    }

    # 2. Populated user history with encrypted techniques
    hashed_pwd = "hashed-pwd-analytics-test"
    enc1, _ = encryption_service.encrypt_analysis_results(
        summary="Run 1",
        techniques=[
            {"technique_id": "T1110.001", "name": "Password Guessing"},
            {"technique_id": "T1548.003", "name": "Sudo and Sudo Caching"},
        ],
        enhanced_analysis=None,
        hashed_password=hashed_pwd,
    )
    enc2, _ = encryption_service.encrypt_analysis_results(
        summary="Run 2",
        techniques=[{"technique_id": "T1110.001", "name": "Password Guessing"}],
        enhanced_analysis=None,
        hashed_password=hashed_pwd,
    )

    docs = [
        {
            "user_id": "alice",
            "analysis_timestamp": datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc),
            "processing_time_ms": 1500.0,
            "techniques_count": 2,
            "encrypted_techniques": enc1["techniques"],
        },
        {
            "user_id": "alice",
            "analysis_timestamp": datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc),
            "processing_time_ms": 2500.0,
            "techniques_count": 1,
            "encrypted_techniques": enc2["techniques"],
        },
    ]

    monkeypatch.setattr(svc, "collection", _FakeAnalysisCollection(docs))
    import services.analysis_storage_service as storage_mod

    monkeypatch.setattr(storage_mod, "database", _FakeDatabase({"hashed_password": hashed_pwd}))

    stats = asyncio.run(svc.get_user_analytics("alice"))
    assert stats["total_analyses"] == 2
    assert stats["avg_processing_time"] == 2000.0
    assert stats["most_common_techniques"][0] == {
        "technique_id": "T1110.001",
        "name": "Password Guessing",
        "count": 2,
    }
    assert stats["most_common_techniques"][1]["technique_id"] == "T1548.003"
    assert stats["analysis_timeline"] == [
        {"date": "2026-11-19", "count": 2, "techniques_count": 3}
    ]


def test_analytics_and_monitoring_routes(monkeypatch) -> None:
    import routers.analysis as analysis_router_mod

    async def _fake_user_analytics(user_id: str):
        assert user_id == "vmn"
        return {
            "total_analyses": 3,
            "avg_processing_time": 1234.5,
            "most_common_techniques": [
                {"technique_id": "T1021.004", "name": "SSH", "count": 3}
            ],
            "analysis_timeline": [
                {"date": "2026-11-19", "count": 3, "techniques_count": 5}
            ],
        }

    async def _fake_get_user_sessions(username: str, active_only: bool = True):
        assert username == "vmn"
        all_sessions = [
            {"session_id": "s-1", "log_path": "/var/log/auth.log", "status": "active"},
            {"session_id": "s-2", "log_path": "/var/log/syslog", "status": "stopped"},
        ]
        return [s for s in all_sessions if s["status"] == "active"] if active_only else all_sessions

    monkeypatch.setattr(
        analysis_router_mod.analysis_storage_service,
        "get_user_analytics",
        _fake_user_analytics,
    )
    monkeypatch.setattr(
        monitoring_storage_service,
        "get_user_sessions",
        _fake_get_user_sessions,
    )

    app = FastAPI()
    app.include_router(analysis_router)
    app.include_router(monitoring_router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "vmn"}
    client = TestClient(app)

    analytics_resp = client.get("/api/v1/analytics")
    assert analytics_resp.status_code == 200
    assert analytics_resp.json()["total_analyses"] == 3
    assert analytics_resp.json()["most_common_techniques"][0]["technique_id"] == "T1021.004"

    active_sess_resp = client.get("/api/v1/monitoring/sessions?active_only=true")
    assert active_sess_resp.status_code == 200
    assert len(active_sess_resp.json()) == 1

    all_sess_resp = client.get("/api/v1/monitoring/sessions?active_only=false")
    assert all_sess_resp.status_code == 200
    assert len(all_sess_resp.json()) == 2

