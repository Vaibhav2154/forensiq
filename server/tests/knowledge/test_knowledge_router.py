"""API router tests for /api/v1/knowledge using an isolated FastAPI app."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers.knowledge import router, set_knowledge_service
from services.knowledge import KnowledgeService, KnowledgeSettings


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
MITRE_SAMPLE = FIXTURES_ROOT / "knowledge" / "mitre_sample_bundle.json"
CVE_SAMPLE = FIXTURES_ROOT / "knowledge" / "cve_sample"


def _build_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    service = KnowledgeService(
        settings=KnowledgeSettings(store_backend="memory")
    )
    set_knowledge_service(service)
    return TestClient(app)


def test_knowledge_router_full_lifecycle() -> None:
    client = _build_client()
    try:
        # 1. Ingest MITRE & CVE samples
        mitre_resp = client.post(
            "/api/v1/knowledge/ingest/mitre",
            json={"file_path": str(MITRE_SAMPLE)},
        )
        assert mitre_resp.status_code == 200
        mitre_run = mitre_resp.json()
        assert mitre_run["status"] == "completed"
        assert mitre_run["inserted"] > 0

        cve_resp = client.post(
            "/api/v1/knowledge/ingest/cve",
            json={"path": str(CVE_SAMPLE)},
        )
        assert cve_resp.status_code == 200
        cve_run = cve_resp.json()
        assert cve_run["status"] == "completed_with_errors"
        assert cve_run["inserted"] == 3
        assert cve_run["failed"] == 1

        # 2. Check ingestion status endpoints
        status_list = client.get("/api/v1/knowledge/ingestion/status")
        assert status_list.status_code == 200
        assert len(status_list.json()) == 2

        single_run = client.get(
            f"/api/v1/knowledge/ingestion/status/{mitre_run['run_id']}"
        )
        assert single_run.status_code == 200
        assert single_run.json()["run_id"] == mitre_run["run_id"]

        missing_run = client.get("/api/v1/knowledge/ingestion/status/does-not-exist")
        assert missing_run.status_code == 404

        # 3. Search POST and GET with filters
        post_search = client.post(
            "/api/v1/knowledge/search",
            json={
                "query": "brute force password guessing",
                "source_type": "mitre_attack",
                "top_k": 3,
            },
        )
        assert post_search.status_code == 200
        search_body = post_search.json()
        assert search_body["total_hits"] >= 1
        assert search_body["hits"][0]["is_evidence_proof"] is False

        get_search = client.get(
            "/api/v1/knowledge/search",
            params={"q": "CVE-2025-39447", "min_cvss": 7.0},
        )
        assert get_search.status_code == 200
        assert get_search.json()["hits"][0]["record"]["source_id"] == "CVE-2025-39447"

        # 4. Exact record & source lookup with related expansion
        rec_resp = client.get("/api/v1/knowledge/records/okf-mitre-t1110")
        assert rec_resp.status_code == 200
        assert rec_resp.json()["record"]["source_id"] == "T1110"

        src_resp = client.get(
            "/api/v1/knowledge/source/mitre_attack/T1110",
            params={"include_related": "true"},
        )
        assert src_resp.status_code == 200
        assert len(src_resp.json()["related_records"]) >= 1

        assert client.get("/api/v1/knowledge/records/missing").status_code == 404

        # 5. Stats endpoint
        stats_resp = client.get("/api/v1/knowledge/stats")
        assert stats_resp.status_code == 200
        assert stats_resp.json()["backend"] == "memory"
        assert stats_resp.json()["total_records"] == mitre_run["parsed"] + 3

        # 6. Log batch normalization endpoint against golden fixture
        batch_payload = json.loads(
            (FIXTURES_ROOT / "batch_ingest_request.json").read_text(encoding="utf-8")
        )
        norm_resp = client.post(
            "/api/v1/knowledge/normalize/batch",
            json=batch_payload,
        )
        assert norm_resp.status_code == 200
        events = norm_resp.json()
        assert len(events) == 1
        assert events[0]["event_id"] == "evt-0001"
        assert events[0]["scope_key"] == "host:workstation-17|account:alex"
        assert events[0]["event_type"] == "authentication_failure"

        # 6b. Prepare InvestigationInput (KCP + OKF retrieval handoff for multi-agent orchestrator)
        prep_resp = client.post(
            "/api/v1/knowledge/prepare-investigation",
            json=batch_payload,
            params={"top_k_knowledge": 5},
        )
        assert prep_resp.status_code == 200
        inv_input = prep_resp.json()
        assert inv_input["investigation_id"].startswith("inv-")
        assert len(inv_input["normalized_events"]) == 1
        assert inv_input["normalized_events"][0]["event_id"] == "evt-0001"
        assert inv_input["sequence_cues"] == []
        assert isinstance(inv_input["knowledge_records"], list)

        # 7. Validation checks
        bad_search = client.get("/api/v1/knowledge/search", params={"q": ""})
        assert bad_search.status_code == 422
    finally:
        set_knowledge_service(None)

