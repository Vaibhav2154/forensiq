"""Isolated FastAPI TestClient tests for /api/v1/investigations and /api/v1/analyze."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers.investigations import router as investigations_router, set_investigation_service
from services.investigation import InvestigationService, InvestigationSettings
from services.knowledge import KnowledgeService, KnowledgeSettings
from tests.investigation.test_graph_workflow import (
    CVE_SAMPLE,
    FIXTURES_ROOT,
    MITRE_SAMPLE,
    _make_mock_runner,
)


def _build_client() -> TestClient:
    kn_svc = KnowledgeService(settings=KnowledgeSettings(store_backend="memory"))
    asyncio.run(kn_svc.initialize())
    asyncio.run(kn_svc.ingest_mitre(path=MITRE_SAMPLE))
    asyncio.run(kn_svc.ingest_cve(path=CVE_SAMPLE))

    runner, _ = _make_mock_runner()
    inv_svc = InvestigationService(
        knowledge_service=kn_svc,
        settings=InvestigationSettings(
            _env_file=None,
            default_gemini_api_key="test-secret-key-should-not-leak",
            gemini_api_keys="pool-secret-1,pool-secret-2",
        ),
        custom_runner=runner,
    )
    set_investigation_service(inv_svc)

    app = FastAPI()
    app.include_router(investigations_router)
    return TestClient(app)


def test_investigations_router_endpoints() -> None:
    client = _build_client()
    try:
        # 1. Config endpoint redacts secrets and shows LSTM hook status
        cfg_resp = client.get("/api/v1/investigations/config")
        assert cfg_resp.status_code == 200
        cfg = cfg_resp.json()
        assert cfg["lstm_connected"] is False
        assert cfg["key_pool_size"] == 2
        assert "test-secret-key" not in json.dumps(cfg)
        assert "pool-secret" not in json.dumps(cfg)

        # 2. Direct /run endpoint with golden InvestigationInput fixture
        inv_payload = json.loads(
            (FIXTURES_ROOT / "investigation_input.json").read_text(encoding="utf-8")
        )
        run_resp = client.post("/api/v1/investigations/run", json=inv_payload)
        assert run_resp.status_code == 200
        run_body = run_resp.json()
        assert run_body["investigation_id"] == "inv-0001"
        assert run_body["sequence_assessment"]["status"] == "analyzed"
        assert run_body["rendered_markdown_report"].startswith("# ForensIQ")

        # 3. /from-batch endpoint with golden BatchIngestRequest fixture (no LSTM cues)
        batch_payload = json.loads(
            (FIXTURES_ROOT / "batch_ingest_request.json").read_text(encoding="utf-8")
        )
        batch_resp = client.post(
            "/api/v1/investigations/from-batch",
            json=batch_payload,
            params={"top_k_knowledge": 5},
        )
        assert batch_resp.status_code == 200
        batch_body = batch_resp.json()
        assert batch_body["investigation_id"].startswith("inv-")
        assert batch_body["sequence_assessment"]["status"] == "skipped_no_cues"
        assert len(batch_body["observations"]) == 1
        assert batch_body["observations"][0]["event_id"] == "evt-0001"
        assert all(r["requires_human_approval"] is True for r in batch_body["recommendations"])
        assert all(r["auto_executable"] is False for r in batch_body["recommendations"])
    finally:
        set_investigation_service(None)


def test_analyze_router_and_encryption_backward_compatibility(monkeypatch) -> None:
    """Verify POST /api/v1/analyze uses the multi-agent workflow and encrypts investigation."""
    from routers.analysis import router as analysis_router, set_services
    from routers.auth import get_current_user
    from services.analysis_storage_service import analysis_storage_service
    from services.encryption_service import encryption_service
    from tests.investigation.test_graph_workflow import WORKSTATION_17_LOGS

    kn_svc = KnowledgeService(settings=KnowledgeSettings(store_backend="memory"))
    asyncio.run(kn_svc.initialize())
    asyncio.run(kn_svc.ingest_mitre(path=MITRE_SAMPLE))
    asyncio.run(kn_svc.ingest_cve(path=CVE_SAMPLE))

    runner, _ = _make_mock_runner()
    inv_svc = InvestigationService(
        knowledge_service=kn_svc,
        settings=InvestigationSettings(_env_file=None, default_gemini_api_key="test-key"),
        custom_runner=runner,
    )
    set_services(gemini=None, knowledge=kn_svc, investigation=inv_svc)

    async def _fake_store(user_id, request, response):
        return "mock-analysis-id"

    monkeypatch.setattr(analysis_storage_service, "store_analysis_result", _fake_store)

    app = FastAPI()
    app.include_router(analysis_router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "vmn"}
    client = TestClient(app)

    try:
        resp = client.post(
            "/api/v1/analyze",
            json={"logs": WORKSTATION_17_LOGS, "enhance_with_ai": True, "max_results": 5},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["summary"]
        assert body["enhanced_analysis"].startswith("# ForensIQ Multi-Agent Investigation Report")
        assert isinstance(body["matched_techniques"], list)
        assert len(body["matched_techniques"]) >= 1
        assert body["investigation"] is not None
        assert body["investigation"]["sequence_assessment"]["status"] == "skipped_no_cues"

        # Encryption round-trip with structured investigation payload
        enc, _ = encryption_service.encrypt_analysis_results(
            summary=body["summary"],
            techniques=body["matched_techniques"],
            enhanced_analysis=body["enhanced_analysis"],
            hashed_password="hashed-pwd-test-value",
            investigation=body["investigation"],
        )
        assert "investigation" in enc
        dec = encryption_service.decrypt_analysis_results(
            encrypted_data=enc,
            hashed_password="hashed-pwd-test-value",
        )
        assert dec["investigation"]["investigation_id"] == body["investigation"]["investigation_id"]

        # Legacy record without encrypted investigation still decrypts cleanly
        legacy_dec = encryption_service.decrypt_analysis_results(
            encrypted_data={
                "summary": enc["summary"],
                "techniques": enc["techniques"],
                "enhanced_analysis": enc["enhanced_analysis"],
            },
            hashed_password="hashed-pwd-test-value",
        )
        assert legacy_dec["investigation"] is None
    finally:
        set_services(None, None, None)
