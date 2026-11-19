"""Unit and router tests for deterministic visualization metrics and GET /api/v1/latest."""

from __future__ import annotations

import math

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers.analysis import router as analysis_router
from routers.auth import get_current_user
from services.analysis_storage_service import analysis_storage_service
from services.visualization_metrics import compute_visualization_metrics


def test_compute_visualization_metrics_handles_empty_inputs() -> None:
    metrics = compute_visualization_metrics(
        matched_techniques=[],
        investigation=None,
        processing_time_ms=0,
    )

    assert metrics["overall_threat_level"] == "informational"
    assert metrics["overall_confidence_label"] == "low"
    assert metrics["overall_risk_score"] == 0
    assert metrics["max_confidence_pct"] == 0
    assert metrics["avg_confidence_pct"] == 0

    for item in metrics["sophistication_radar"]:
        assert math.isfinite(item["value"])
        assert 0 <= item["value"] <= 100
        assert item["value"] == 0

    for bar in metrics["threat_assessment_bars"]:
        assert math.isfinite(bar["value"])
        assert bar["value"] == 0

    assert metrics["phase_risk_distribution"] == []
    assert metrics["attack_progression"] == []
    assert metrics["attack_journey"] == []
    assert metrics["cve_matches"] == []
    assert metrics["summary_counts"]["techniques_detected"] == 0
    assert metrics["summary_counts"]["analysis_time_sec"] == 0.0


def test_compute_visualization_metrics_with_full_investigation() -> None:
    techniques = [
        {
            "technique_id": "T1110.001",
            "name": "Password Guessing",
            "description": "Guessing passwords against SSH.",
            "kill_chain_phases": ["credential-access"],
            "platforms": ["Linux"],
            "relevance_score": 0.88,
        },
        {
            "technique_id": "T1548.003",
            "name": "Sudo and Sudo Caching",
            "description": "Abusing sudo to elevate privileges.",
            "kill_chain_phases": ["defense-evasion", "privilege-escalation"],
            "platforms": ["Linux"],
            "relevance_score": 0.86,
        },
    ]

    investigation = {
        "overall_threat_level": "high",
        "overall_confidence": "medium",
        "retrieved_knowledge": [
            {
                "record_id": "okf-mitre-t1110.001",
                "source_type": "mitre_attack",
                "source_id": "T1110.001",
                "name": "Password Guessing",
                "relevance_score": 0.88,
            },
            {
                "record_id": "okf-cve-2025-39447",
                "source_type": "cve",
                "source_id": "CVE-2025-39447",
                "name": "OpenSSH Auth Bypass",
                "description_excerpt": "Improper auth handling.",
                "cvss_score": 8.1,
                "relevance_score": 0.72,
                "relevance_rationale": "SSH service exposed in logs.",
                "missing_confirmation_evidence": ["sshd package version"],
                "provenance_uri": "file:///frameworks/cve/CVE-2025-39447.json",
            },
        ],
        "timeline": [
            {
                "timestamp_utc": "2026-11-19 14:40:01 UTC",
                "timestamp_ist": "2026-11-19 20:10:01 IST",
                "event_id": "evt-0001",
                "summary": "Failed SSH login for alex",
                "significance": "medium",
            },
            {
                "timestamp_utc": "2026-11-19 14:41:12 UTC",
                "timestamp_ist": "2026-11-19 20:11:12 IST",
                "event_id": "evt-0002",
                "summary": "sudo cat /etc/shadow",
                "significance": "critical",
            },
        ],
        "iocs": [
            {"ioc_type": "ip", "value": "203.0.113.25", "context": "SSH source IP"},
        ],
        "findings": [
            {
                "finding_id": "find-001",
                "title": "SSH brute-force followed by sudo shadow read",
                "severity": "high",
                "confidence": "medium",
                "observed_facts": ["evt-0001 failed login", "evt-0002 sudo cat /etc/shadow"],
                "inferences": ["Possible compromised credentials"],
                "uncertainty": "No command exit code recorded.",
            }
        ],
        "recommendations": [
            {
                "recommendation_id": "rec-001",
                "priority": "immediate",
                "title": "Rotate credentials for alex",
                "target": "account:alex",
                "action": "Force password reset and inspect authorized_keys",
                "expected_effect": "Prevent reuse of compromised credentials",
                "requires_human_approval": True,
            }
        ],
        "attack_path": {
            "hypothesis_title": "Brute-force to local credential dump",
            "summary": "Observed SSH failures followed by sudo execution.",
            "nodes": [
                {
                    "node_id": "step_1",
                    "label": "Password Guessing via SSH",
                    "stage": "Credential Access",
                    "status": "observed",
                    "event_ids": ["evt-0001"],
                    "knowledge_source_ids": ["T1110.001"],
                    "confidence": "high",
                },
                {
                    "node_id": "step_2",
                    "label": "Privilege Escalation via Sudo",
                    "stage": "Privilege Escalation",
                    "status": "observed",
                    "event_ids": ["evt-0002"],
                    "knowledge_source_ids": ["T1548.003"],
                    "confidence": "high",
                },
            ],
            "edges": [],
            "missing_evidence": ["Command stdout/exit code"],
            "alternative_hypotheses": ["Legitimate admin maintenance"],
        },
        "uncertainty_and_gaps": ["Missing sshd version"],
        "guardrail_warnings": [],
    }

    metrics = compute_visualization_metrics(
        matched_techniques=techniques,
        investigation=investigation,
        processing_time_ms=12500.0,
    )

    assert metrics["overall_threat_level"] == "high"
    assert metrics["overall_confidence_label"] == "medium"
    assert metrics["overall_risk_score"] == 88
    assert metrics["max_confidence_pct"] == 88
    assert metrics["avg_confidence_pct"] == 87

    radar_by_subject = {item["subject"]: item["value"] for item in metrics["sophistication_radar"]}
    assert radar_by_subject["Evasion Capability"] == 86
    assert radar_by_subject["Persistence Level"] == 86
    assert radar_by_subject["Impact Potential"] == 88
    assert radar_by_subject["Lateral Movement"] == 0

    bars_by_label = {b["label"]: b["value"] for b in metrics["threat_assessment_bars"]}
    assert bars_by_label["Stealth Level"] == 86
    assert bars_by_label["Persistence Capability"] == 86
    assert bars_by_label["Lateral Movement Risk"] == 0

    phase_keys = [p["phase_key"] for p in metrics["phase_risk_distribution"]]
    assert phase_keys == ["privilege-escalation", "defense-evasion", "credential-access"]

    assert len(metrics["attack_progression"]) == 2
    assert metrics["attack_progression"][0]["status"] == "observed"
    assert metrics["attack_progression"][0]["timestamp"] == "2026-11-19 20:10:01 IST"
    assert metrics["attack_progression"][1]["timestamp"] == "2026-11-19 20:11:12 IST"

    assert len(metrics["cve_matches"]) == 1
    assert metrics["cve_matches"][0]["source_id"] == "CVE-2025-39447"
    assert metrics["cve_matches"][0]["cvss_score"] == 8.1

    assert metrics["summary_counts"] == {
        "techniques_detected": 2,
        "cve_count": 1,
        "attack_phases": 3,
        "findings_count": 1,
        "iocs_count": 1,
        "timeline_events_count": 2,
        "recommendations_count": 1,
        "analysis_time_sec": 12.5,
    }


def test_latest_endpoint_handles_dict_history_items(monkeypatch) -> None:
    expected_metrics = compute_visualization_metrics(
        matched_techniques=[],
        investigation=None,
        processing_time_ms=2500.0,
    )

    async def _fake_history(user_id: str, limit: int = 50, offset: int = 0):
        return [
            {
                "id": "6aff2f520bf8770bf20126ad",
                "analysis_timestamp": "2026-11-19T17:18:10.599000",
                "processing_time_ms": 2500.0,
                "techniques_count": 0,
                "logs_preview": "Preview unavailable",
            }
        ]

    async def _fake_get_result(user_id: str, analysis_id: str):
        assert user_id == "vmn"
        assert analysis_id == "6aff2f520bf8770bf20126ad"
        return {
            "summary": "Stored summary",
            "matched_techniques": [],
            "enhanced_analysis": None,
            "investigation": None,
            "visualization_metrics": expected_metrics,
            "analysis_timestamp": "2026-11-19T17:18:10.599000",
            "processing_time_ms": 2500.0,
        }

    monkeypatch.setattr(analysis_storage_service, "get_user_analysis_history", _fake_history)
    monkeypatch.setattr(analysis_storage_service, "get_analysis_result", _fake_get_result)

    app = FastAPI()
    app.include_router(analysis_router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "vmn"}
    client = TestClient(app)

    resp = client.get("/api/v1/latest")
    assert resp.status_code == 200
    body = resp.json()
    assert body["analysis"] is not None
    assert body["analysis"]["summary"] == "Stored summary"
    assert body["analysis"]["visualization_metrics"]["overall_risk_score"] == 0
    assert body["analysis"]["visualization_metrics"]["summary_counts"]["analysis_time_sec"] == 2.5

