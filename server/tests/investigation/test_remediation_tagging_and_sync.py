"""Unit and API tests for HITL remediation playbook tagging, guardrails, and status sync."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from contracts import EvidenceReference, NormalizedEvent
from routers.analysis import router as analysis_router
from routers.auth import get_current_user
from routers.investigations import router as investigations_router
from services.analysis_storage_service import AnalysisStorageService, analysis_storage_service
from services.encryption_service import encryption_service
from services.investigation.guardrails import sanitize_recommendations
from services.investigation.models import (
    EventAnalysisOutput,
    ObservedIOC,
    RecommendationItem,
    RecommendationOutput,
)
from services.investigation.playbook_tagger import tag_recommendations_for_tui


def _make_event(event_id: str, features: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        scope_key="workstation-17",
        event_time=datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
        event_type="auth_failure",
        source="auth_logs",
        features=features,
        evidence_ref=EvidenceReference(reference_id=f"ref-{event_id}", uri="file:///var/log/auth.log"),
    )


def _make_rec(
    rec_id: str,
    title: str,
    target: str,
    action: str,
    **extra: Any,
) -> RecommendationItem:
    return RecommendationItem(
        recommendation_id=rec_id,
        priority="immediate",
        title=title,
        target=target,
        action=action,
        expected_effect="Contain host compromise.",
        supporting_finding_ids=["f-001"],
        evidence_event_ids=["evt-001"],
        rollback_notes="Revert via local journal.",
        **extra,
    )


def test_deterministic_playbook_tagger_maps_tiers_and_blocks_fabrication() -> None:
    events = [
        _make_event(
            "evt-001",
            {
                "remote_ip": "185.220.101.4",
                "account": "alice",
                "pid": 4242,
                "command": "chmod 777 /etc/shadow && cp /tmp/x /etc/cron.d/backdoor",
                "package": "openssh-server",
            },
        ),
        _make_event(
            "evt-002",
            {
                "remote_ip": "127.0.0.1",
                "account": "root",
            },
        ),
    ]
    event_analysis = EventAnalysisOutput(
        iocs=[
            ObservedIOC(
                ioc_type="ip",
                value="185.220.101.4",
                event_ids=["evt-001"],
                evidence_ref_ids=["ref-evt-001"],
                context="SSH brute force source",
            ),
            ObservedIOC(
                ioc_type="account",
                value="alice",
                event_ids=["evt-001"],
                evidence_ref_ids=["ref-evt-001"],
                context="Compromised user account",
            ),
        ]
    )

    recs = [
        _make_rec("rec-001", "Block attacker IP", "185.220.101.4", "Deny inbound traffic from 185.220.101.4 via firewall"),
        _make_rec("rec-002", "Lock compromised account", "alice", "Lock account alice to stop SSH reuse"),
        _make_rec("rec-003", "Terminate active sessions", "alice", "Terminate user sessions for alice"),
        _make_rec("rec-004", "Restore shadow permissions", "/etc/shadow", "Fix file permission on /etc/shadow with chmod 0600"),
        _make_rec("rec-005", "Disable SSH password authentication", "/etc/ssh/sshd_config", "Harden sshd_config to disable password authentication"),
        _make_rec("rec-006", "Quarantine rogue cron job", "/etc/cron.d/backdoor", "Move unauthorized cron file /etc/cron.d/backdoor"),
        _make_rec("rec-007", "Rotate enterprise Kerberos keys", "Active Directory", "Coordinate with IAM team for full domain krbtgt rotation"),
        _make_rec("rec-008", "Block unverified IP", "203.0.113.99", "Block fabricated IP 203.0.113.99; rm -rf /"),
        _make_rec("rec-009", "Lock protected root account", "root", "Lock user root immediately"),
    ]

    tagged = tag_recommendations_for_tui(recs, events, event_analysis)
    by_id = {item.recommendation_id: item for item in tagged}

    assert by_id["rec-001"].fixable_via_tui is True
    assert by_id["rec-001"].fix_tier == "tier_1_playbook"
    assert by_id["rec-001"].playbook_id == "block_ip"
    assert by_id["rec-001"].playbook_params == {"ip": "185.220.101.4"}

    assert by_id["rec-002"].fixable_via_tui is True
    assert by_id["rec-002"].playbook_id == "lock_user"
    assert by_id["rec-002"].playbook_params == {"username": "alice"}

    assert by_id["rec-003"].fixable_via_tui is True
    assert by_id["rec-003"].playbook_id == "terminate_user_sessions"
    assert by_id["rec-003"].playbook_params == {"username": "alice"}

    assert by_id["rec-004"].fixable_via_tui is True
    assert by_id["rec-004"].playbook_id == "fix_file_permissions"
    assert by_id["rec-004"].playbook_params == {"path": "/etc/shadow", "mode": "0600"}

    assert by_id["rec-005"].fixable_via_tui is True
    assert by_id["rec-005"].fix_tier == "tier_2_config_diff"
    assert by_id["rec-005"].playbook_id == "harden_sshd_config"
    assert by_id["rec-005"].playbook_params == {"directive": "PasswordAuthentication", "value": "no"}

    assert by_id["rec-006"].fixable_via_tui is True
    assert by_id["rec-006"].fix_tier == "tier_2_config_diff"
    assert by_id["rec-006"].playbook_id == "quarantine_cron_file"
    assert by_id["rec-006"].playbook_params == {"path": "/etc/cron.d/backdoor"}

    # Tier 3 advisory remains non-executable
    assert by_id["rec-007"].fixable_via_tui is False
    assert by_id["rec-007"].fix_tier == "tier_3_advisory"
    assert by_id["rec-007"].playbook_id == "manual_only"
    assert by_id["rec-007"].playbook_params == {}

    # Unverified IP falls back to verified IP only if mentioned or stays safe;
    # here 203.0.113.99 is not in verified IPs, and no "rm -rf /" ever enters params!
    assert "rm -rf" not in str(by_id["rec-008"].playbook_params)
    assert by_id["rec-008"].playbook_params.get("ip") != "203.0.113.99"

    # Root is protected — never mapped to lock_user(username="root")
    assert by_id["rec-009"].playbook_params.get("username") != "root"

    # Hard HITL invariants on every single item
    for item in tagged:
        assert item.requires_human_approval is True
        assert item.auto_executable is False
        assert item.execution_status == "pending_approval"


def test_guardrails_enforce_hitl_invariants_on_recommendations() -> None:
    rec_bad = _make_rec(
        "rec-100",
        "Manual runbook marked fixable",
        "host",
        "Review firewall logs manually",
        fixable_via_tui=True,
        fix_tier="tier_1_playbook",
        playbook_id="manual_only",
        playbook_params={},
    )
    sanitized = sanitize_recommendations(
        RecommendationOutput(status="drafted", recommendations=[rec_bad]),
        valid_event_ids={"evt-001"},
        valid_finding_ids={"f-001"},
        valid_source_ids=set(),
    )
    assert len(sanitized) == 1
    assert sanitized[0].requires_human_approval is True
    assert sanitized[0].auto_executable is False
    assert sanitized[0].fixable_via_tui is False
    assert sanitized[0].fix_tier == "tier_3_advisory"
    assert sanitized[0].playbook_id == "manual_only"


def test_remediation_status_sync_storage_and_endpoints(monkeypatch) -> None:
    """Verify encrypted MongoDB read-modify-write and both status-sync endpoints."""
    from bson import ObjectId

    hashed_pwd = "hashed-user-secret"
    analysis_oid = ObjectId()
    investigation_payload = {
        "investigation_id": "inv-sync-001",
        "status": "completed",
        "recommendations": [
            {
                "recommendation_id": "rec-001",
                "priority": "immediate",
                "title": "Block attacker IP",
                "target": "185.220.101.4",
                "action": "Block 185.220.101.4",
                "expected_effect": "Stop brute force",
                "supporting_finding_ids": ["f-001"],
                "evidence_event_ids": ["evt-001"],
                "knowledge_mitigation_ids": [],
                "requires_human_approval": True,
                "auto_executable": False,
                "rollback_notes": "ufw delete deny from 185.220.101.4",
                "fixable_via_tui": True,
                "fix_tier": "tier_1_playbook",
                "playbook_id": "block_ip",
                "playbook_params": {"ip": "185.220.101.4"},
                "execution_status": "pending_approval",
            }
        ],
        "remediation_history": [],
    }
    enc, _ = encryption_service.encrypt_analysis_results(
        summary="SSH brute force detected",
        techniques=[],
        enhanced_analysis="Report",
        hashed_password=hashed_pwd,
        investigation=investigation_payload,
    )

    stored_doc: dict[str, Any] = {
        "_id": analysis_oid,
        "user_id": "vmn",
        "encrypted_summary": enc["summary"],
        "encrypted_techniques": enc["techniques"],
        "encrypted_enhanced_analysis": enc["enhanced_analysis"],
        "encrypted_investigation": enc["investigation"],
        "analysis_timestamp": datetime.now(timezone.utc),
    }

    class _FakeCursor:
        def __init__(self, docs: list[dict[str, Any]]) -> None:
            self._docs = docs

        def sort(self, *_args: Any, **_kwargs: Any) -> "_FakeCursor":
            return self

        def limit(self, *_args: Any, **_kwargs: Any) -> "_FakeCursor":
            return self

        def __aiter__(self):
            async def _gen():
                for doc in self._docs:
                    yield doc

            return _gen()

    class _FakeUserCollection:
        async def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
            if query.get("username") == "vmn":
                return {"username": "vmn", "hashed_password": hashed_pwd}
            return None

    class _FakeCollection:
        async def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
            if query.get("_id") == stored_doc["_id"] and query.get("user_id") == stored_doc["user_id"]:
                return stored_doc
            return None

        def find(self, query: dict[str, Any]) -> _FakeCursor:
            if query.get("user_id") == stored_doc["user_id"]:
                return _FakeCursor([stored_doc])
            return _FakeCursor([])

        async def update_one(self, flt: dict[str, Any], upd: dict[str, Any]) -> None:
            assert flt["_id"] == stored_doc["_id"]
            stored_doc.update(upd.get("$set", {}))

    import services.analysis_storage_service as storage_mod

    fake_analysis_col = _FakeCollection()
    fake_user_col = _FakeUserCollection()

    def _fake_get_collection(name: str):
        if name == "user_collection":
            return fake_user_col
        return fake_analysis_col

    monkeypatch.setattr(storage_mod.database, "get_collection", _fake_get_collection)
    svc = AnalysisStorageService()
    monkeypatch.setattr(svc, "collection", fake_analysis_col)

    # Patch singleton used by both routers
    monkeypatch.setattr(analysis_storage_service, "update_remediation_status", svc.update_remediation_status)

    app = FastAPI()
    app.include_router(analysis_router)
    app.include_router(investigations_router)
    app.dependency_overrides[get_current_user] = lambda: {"username": "vmn"}
    client = TestClient(app)

    # 1. Update via /api/v1/history/{analysis_id}/remediation-status
    resp1 = client.post(
        f"/api/v1/history/{analysis_oid}/remediation-status",
        json={
            "recommendation_id": "rec-001",
            "execution_status": "executed",
            "receipt_id": "rem-20260501-abc123",
            "executed_by": "analyst",
        },
    )
    assert resp1.status_code == 200, resp1.text
    body1 = resp1.json()
    assert body1["analysis_id"] == str(analysis_oid)
    assert body1["investigation_id"] == "inv-sync-001"
    assert body1["recommendation_id"] == "rec-001"
    assert body1["execution_status"] == "executed"
    assert body1["receipt_id"] == "rem-20260501-abc123"

    # 2. Update via /api/v1/investigations/{investigation_id}/remediation-status (rollback)
    resp2 = client.post(
        "/api/v1/investigations/inv-sync-001/remediation-status",
        json={
            "recommendation_id": "rec-001",
            "execution_status": "rolled_back",
            "receipt_id": "rem-20260501-abc123",
            "executed_by": "analyst",
            "notes": "Reverted after verification",
        },
    )
    assert resp2.status_code == 200, resp2.text
    assert resp2.json()["execution_status"] == "rolled_back"

    # Verify decrypted MongoDB document reflects latest status + 2 audit events
    dec = encryption_service.decrypt_analysis_results(
        encrypted_data={
            "summary": stored_doc["encrypted_summary"],
            "techniques": stored_doc["encrypted_techniques"],
            "enhanced_analysis": stored_doc["encrypted_enhanced_analysis"],
            "investigation": stored_doc["encrypted_investigation"],
        },
        hashed_password=hashed_pwd,
    )
    inv = dec["investigation"]
    assert inv["recommendations"][0]["execution_status"] == "rolled_back"
    assert len(inv["remediation_history"]) == 2
    assert inv["remediation_history"][0]["execution_status"] == "executed"
    assert inv["remediation_history"][1]["execution_status"] == "rolled_back"

    # 3. Unknown recommendation returns 404
    resp_missing = client.post(
        f"/api/v1/history/{analysis_oid}/remediation-status",
        json={"recommendation_id": "rec-999", "execution_status": "rejected"},
    )
    assert resp_missing.status_code == 404
