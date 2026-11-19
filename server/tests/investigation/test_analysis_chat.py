"""Unit and FastAPI router tests for the stored-analysis Gemini chatbot endpoints."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers.analysis import router as analysis_router, set_services
from routers.auth import get_current_user
from services.analysis_chat_service import AnalysisChatService
from services.analysis_storage_service import analysis_storage_service
from services.investigation.config import InvestigationSettings


SAMPLE_STORED_ANALYSIS_1 = {
    "id": "6aff0ea72d111f38a5bd37b0",
    "summary": "SSH password guessing followed by sudo /bin/cat /etc/shadow on workstation-17.",
    "matched_techniques": [
        {
            "technique_id": "T1021.004",
            "name": "SSH",
            "description": "Remote login via SSH",
            "kill_chain_phases": ["lateral-movement"],
            "platforms": ["Linux"],
            "relevance_score": 0.8839,
        },
        {
            "technique_id": "T1110.001",
            "name": "Password Guessing",
            "description": "Guessing passwords",
            "kill_chain_phases": ["credential-access"],
            "platforms": ["Linux"],
            "relevance_score": 0.856,
        },
    ],
    "enhanced_analysis": "# ForensIQ Multi-Agent Investigation Report",
    "investigation": {
        "investigation_id": "inv-abc123",
        "overall_threat_level": "critical",
        "overall_confidence": "high",
        "executive_summary": "Failed and accepted SSH logins for alex followed by sudo /bin/cat /etc/shadow.",
        "observations": [
            {
                "observation_id": "obs-001",
                "event_id": "evt-0001",
                "evidence_ref_id": "ev-0001",
                "timestamp_utc": "2026-11-19 14:40:01 UTC",
                "scope_key": "host:workstation-17|account:alex",
                "summary": "Failed password for alex from 203.0.113.25",
                "severity": "medium",
                "entities": ["host:workstation-17", "account:alex", "ip:203.0.113.25"],
                "is_anomalous": True,
            },
            {
                "observation_id": "obs-002",
                "event_id": "evt-0004",
                "evidence_ref_id": "ev-0004",
                "timestamp_utc": "2026-11-19 14:41:12 UTC",
                "scope_key": "host:workstation-17|account:alex",
                "summary": "sudo /bin/cat /etc/shadow executed by alex",
                "severity": "critical",
                "entities": ["host:workstation-17", "account:alex", "command:/bin/cat /etc/shadow"],
                "is_anomalous": True,
            },
        ],
        "findings": [
            {
                "finding_id": "find-001",
                "title": "SSH Compromise and Shadow File Access Attempt",
                "severity": "critical",
                "confidence": "high",
                "observed_facts": ["Failed SSH login and sudo /bin/cat /etc/shadow observed."],
                "inferences": ["Consistent with password guessing and credential dumping attempt."],
                "uncertainty": "Exit code of sudo command is not logged.",
                "supporting_event_ids": ["evt-0001", "evt-0004"],
                "evidence_ref_ids": ["ev-0001", "ev-0004"],
                "knowledge_source_ids": ["T1021.004", "T1110.001"],
            }
        ],
        "retrieved_knowledge": [
            {
                "record_id": "okf-mitre-t1021.004",
                "source_type": "mitre_attack",
                "source_id": "T1021.004",
                "name": "SSH",
                "related_mitigations": ["M1032: Multi-factor Authentication"],
            }
        ],
        "timeline": [],
        "relationships": [],
        "attack_path": {
            "hypothesis_title": "SSH -> Sudo",
            "nodes": [],
            "edges": [],
            "missing_evidence": ["Command exit status not recorded"],
        },
        "iocs": [{"ioc_type": "ip", "value": "203.0.113.25"}],
        "recommendations": [],
        "uncertainty_and_gaps": ["Command exit status not recorded"],
        "audit_trail": [],
    },
    "analysis_timestamp": "2026-11-19T14:58:27.917569",
    "processing_time_ms": 39432.75,
}

SAMPLE_STORED_ANALYSIS_2 = {
    "id": "6aff0ea72d111f38a5bd37b1",
    "summary": "Web application authorization bypass alert on web-02.",
    "matched_techniques": [],
    "enhanced_analysis": None,
    "investigation": {
        "investigation_id": "inv-def456",
        "overall_threat_level": "medium",
        "overall_confidence": "medium",
        "executive_summary": "Missing authorization check triggered by 198.51.100.42.",
        "observations": [],
        "findings": [],
        "retrieved_knowledge": [
            {
                "record_id": "okf-cve-2025-39447",
                "source_type": "cve",
                "source_id": "CVE-2025-39447",
                "name": "Missing Authorization in JetElements",
            }
        ],
        "iocs": [{"ioc_type": "ip", "value": "198.51.100.42"}],
        "uncertainty_and_gaps": [],
    },
    "analysis_timestamp": "2026-11-19T15:10:00.000000",
    "processing_time_ms": 12000.0,
}


def test_stored_analysis_chat_and_history_chat_endpoints(monkeypatch) -> None:
    captured_messages = []

    def fake_runner(messages):
        captured_messages.append(messages)
        return {
            "answer": (
                "Based on `evt-0001` and `evt-0004`, account `alex` experienced SSH failures "
                "from `203.0.113.25` followed by `sudo /bin/cat /etc/shadow`."
            ),
            # Include one hallucinated event_id and one hallucinated ATT&CK ID to verify filtering
            "referenced_event_ids": ["evt-0001", "evt-0004", "evt-hallucinated"],
            "referenced_knowledge_ids": ["T1021.004", "M1032", "T1078.004"],
            "follow_up_questions": [
                "Should I lock account alex immediately?",
                "What telemetry would confirm whether /etc/shadow was read?",
            ],
            "evidence_caveats": [
                "Exit status and stdout of `sudo /bin/cat /etc/shadow` are not present in logs."
            ],
        }

    chat_svc = AnalysisChatService(
        settings=InvestigationSettings(
            _env_file=None,
            default_gemini_api_key="test-key",
            gemini_model="gemini-2.5-flash",
        ),
        custom_runner=fake_runner,
    )
    set_services(gemini=None, knowledge=None, investigation=None, chat=chat_svc)

    stored_map = {
        SAMPLE_STORED_ANALYSIS_1["id"]: SAMPLE_STORED_ANALYSIS_1,
        SAMPLE_STORED_ANALYSIS_2["id"]: SAMPLE_STORED_ANALYSIS_2,
    }

    async def _fake_get_result(user_id: str, analysis_id: str):
        if user_id != "vmn":
            return None
        return stored_map.get(analysis_id)

    async def _fake_get_history(user_id: str, limit: int = 50, offset: int = 0):
        if user_id != "vmn":
            return []
        return [
            {"id": SAMPLE_STORED_ANALYSIS_1["id"]},
            {"id": SAMPLE_STORED_ANALYSIS_2["id"]},
        ][:limit]

    monkeypatch.setattr(analysis_storage_service, "get_analysis_result", _fake_get_result)
    monkeypatch.setattr(analysis_storage_service, "get_user_analysis_history", _fake_get_history)

    app = FastAPI()
    app.include_router(analysis_router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "vmn"}
    client = TestClient(app)

    try:
        # 1. Single stored analysis chat with conversation history & cross-history context
        resp = client.post(
            f"/api/v1/history/{SAMPLE_STORED_ANALYSIS_1['id']}/chat",
            json={
                "message": "Explain what happened on workstation-17 and whether /etc/shadow was exfiltrated.",
                "conversation_history": [
                    {"role": "user", "content": "What severity was this?"},
                    {"role": "assistant", "content": "Critical."},
                ],
                "include_recent_context": True,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["analysis_id"] == SAMPLE_STORED_ANALYSIS_1["id"]
        assert SAMPLE_STORED_ANALYSIS_1["id"] in body["analyses_consulted"]
        assert SAMPLE_STORED_ANALYSIS_2["id"] in body["analyses_consulted"]
        assert "203.0.113.25" in body["answer"]
        # Hallucinated event_id and T1078.004 must be filtered out
        assert body["referenced_event_ids"] == ["evt-0001", "evt-0004"]
        assert body["referenced_knowledge_ids"] == ["T1021.004", "M1032"]
        assert "T1078.004" not in body["referenced_knowledge_ids"]
        assert len(body["follow_up_questions"]) == 2
        assert len(body["evidence_caveats"]) == 1
        assert body["model_used"] == "gemini-2.5-flash"
        # Verify system + 2 history turns + 1 current user turn = 4 messages passed to Gemini
        assert len(captured_messages[-1]) == 4

        # 2. Missing analysis returns 404
        missing = client.post(
            "/api/v1/history/000000000000000000000000/chat",
            json={"message": "Tell me about this"},
        )
        assert missing.status_code == 404

        # 3. Cross-history chat endpoint
        hist_resp = client.post(
            "/api/v1/history/chat",
            json={"message": "Summarize my recent incidents", "limit": 5},
        )
        assert hist_resp.status_code == 200
        hist_body = hist_resp.json()
        assert hist_body["analysis_id"] is None
        assert len(hist_body["analyses_consulted"]) == 2
        assert "T1021.004" in hist_body["referenced_knowledge_ids"]
    finally:
        set_services(None, None, None)
