"""End-to-end LangGraph multi-agent workflow tests using InMemoryKnowledgeStore & mock Gemini."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from contracts import InvestigationInput
from services.investigation import (
    InvestigationService,
    InvestigationSettings,
    build_batch_from_raw_logs,
)
from services.investigation.models import (
    AttackPathEdge,
    AttackPathNode,
    AttackPathOutput,
    CorrelationTimelineOutput,
    EnrichedKnowledgeItem,
    EntityRelationship,
    EventAnalysisOutput,
    EvidenceObservation,
    FinalSynthesisDraft,
    FollowUpQueryPlan,
    InvestigationFinding,
    KnowledgeEnrichmentOutput,
    KnowledgeQuerySpec,
    ObservedIOC,
    OrchestratorReviewOutput,
    RecommendationItem,
    RecommendationOutput,
    SequenceAnalysisOutput,
    SequenceCueReview,
    TimelineEntry,
)
from services.knowledge import KnowledgeService, KnowledgeSettings


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
MITRE_SAMPLE = FIXTURES_ROOT / "knowledge" / "mitre_sample_bundle.json"
CVE_SAMPLE = FIXTURES_ROOT / "knowledge" / "cve_sample"

WORKSTATION_17_LOGS = """\
2026-11-19 20:10:01 IST workstation-17 sshd[4821]: Failed password for alex from 203.0.113.25 port 44120
2026-11-19 20:10:14 IST workstation-17 sshd[4822]: Failed password for alex from 203.0.113.25 port 44124
2026-11-19 20:10:49 IST workstation-17 sshd[4829]: Accepted password for alex from 203.0.113.25 port 44130
2026-11-19 20:11:12 IST workstation-17 sudo[5123]: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/bin/cat /etc/shadow
"""


async def _seeded_knowledge_service() -> KnowledgeService:
    svc = KnowledgeService(settings=KnowledgeSettings(store_backend="memory"))
    await svc.initialize()
    await svc.ingest_mitre(path=MITRE_SAMPLE)
    await svc.ingest_cve(path=CVE_SAMPLE)
    return svc


def _make_mock_runner(
    *,
    inject_hallucination_first_pass: bool = False,
    benign_mode: bool = False,
):
    """Build a deterministic mock Gemini structured-output runner for all sub-agent roles."""
    counters = {"attack_path_calls": 0, "review_calls": 0, "knowledge_calls": 0}

    def runner(role, schema, system_prompt, user_prompt):
        if schema is EventAnalysisOutput:
            # Extract real event_ids & evidence_ref_ids from prompt JSON
            import re

            ev_ids = re.findall(r'"event_id":\s*"([^"]+)"', user_prompt)
            ref_ids = re.findall(r'"reference_id":\s*"([^"]+)"', user_prompt)
            first_ev = ev_ids[0] if ev_ids else "evt-0001"
            first_ref = ref_ids[0] if ref_ids else "ev-0001"
            if benign_mode:
                return EventAnalysisOutput(
                    observations=[
                        EvidenceObservation(
                            observation_id="obs-001",
                            event_id=first_ev,
                            evidence_ref_id=first_ref,
                            timestamp_utc="2026-11-19 14:40:01 UTC",
                            scope_key="host:web-01",
                            summary="Routine health check logged with status 200.",
                            severity="informational",
                            is_anomalous=False,
                        )
                    ],
                    iocs=[],
                    noteworthy_event_ids=[],
                    observed_behaviors=["routine health check"],
                    entities_summary=["host:web-01"],
                    telemetry_gaps=[],
                )
            return EventAnalysisOutput(
                observations=[
                    EvidenceObservation(
                        observation_id=f"obs-{idx:03d}",
                        event_id=eid,
                        evidence_ref_id=ref_ids[idx - 1] if idx - 1 < len(ref_ids) else first_ref,
                        timestamp_utc="2026-11-19 14:40:01 UTC",
                        scope_key="host:workstation-17|account:alex",
                        summary=f"Observed security event {eid}",
                        severity="high" if idx == len(ev_ids) else "medium",
                        entities=["host:workstation-17", "account:alex", "ip:203.0.113.25"],
                        is_anomalous=True,
                    )
                    for idx, eid in enumerate(ev_ids, start=1)
                ],
                iocs=[
                    ObservedIOC(
                        ioc_type="ip",
                        value="203.0.113.25",
                        event_ids=ev_ids[:3],
                        evidence_ref_ids=ref_ids[:3],
                        context="Source IP of failed and accepted SSH password logins",
                    ),
                    ObservedIOC(
                        ioc_type="command",
                        value="/bin/cat /etc/shadow",
                        event_ids=ev_ids[-1:],
                        evidence_ref_ids=ref_ids[-1:],
                        context="Executed via sudo by account alex",
                    ),
                ],
                noteworthy_event_ids=ev_ids,
                observed_behaviors=["failed ssh password", "accepted ssh password", "sudo cat /etc/shadow"],
                entities_summary=["host:workstation-17", "account:alex", "ip:203.0.113.25"],
                telemetry_gaps=[
                    "Exit status and stdout of `sudo /bin/cat /etc/shadow` are not present in auth logs."
                ],
            )

        if schema is FollowUpQueryPlan:
            return FollowUpQueryPlan(
                queries=[
                    KnowledgeQuerySpec(
                        query="password guessing brute force credential access",
                        source_type="mitre_attack",
                        rationale="Match repeated failed SSH authentication attempts",
                    )
                ],
                should_check_cves=False,
            )

        if schema is KnowledgeEnrichmentOutput:
            counters["knowledge_calls"] += 1
            import re

            ev_ids = re.findall(r'"event_id":\s*"([^"]+)"', user_prompt)
            return KnowledgeEnrichmentOutput(
                enriched_records=[
                    EnrichedKnowledgeItem(
                        record_id="okf-mitre-t1110.001",
                        source_type="mitre_attack",
                        source_id="T1110.001",
                        name="Password Guessing",
                        tactics=["credential-access"],
                        platforms=["Linux"],
                        relevance_score=0.89,
                        is_evidence_proof=False,
                        supporting_event_ids=ev_ids[:2],
                        relevance_rationale="Two failed password attempts preceded a successful login from 203.0.113.25.",
                        missing_confirmation_evidence=["Check whether prior failed logins occurred from 203.0.113.25."],
                        related_mitigations=["M1032: Multi-factor Authentication"],
                    ),
                    EnrichedKnowledgeItem(
                        record_id="okf-mitre-t1110",
                        source_type="mitre_attack",
                        source_id="T1110",
                        name="Brute Force",
                        tactics=["credential-access"],
                        platforms=["Linux"],
                        relevance_score=0.84,
                        is_evidence_proof=False,
                        supporting_event_ids=ev_ids[:2],
                        relevance_rationale="Parent technique covering credential guessing attempts.",
                        missing_confirmation_evidence=["Confirm automated guessing rate across accounts."],
                    ),
                ],
                follow_up_queries_executed=["[mitre_attack] password guessing brute force"],
                unmapped_behaviors=[],
                cves_checked=False,
            )

        if schema is SequenceAnalysisOutput:
            return SequenceAnalysisOutput(
                status="analyzed",
                reviews=[
                    SequenceCueReview(
                        cue_id="cue-0001",
                        scope_key="host:workstation-17|account:alex",
                        risk_score=0.87,
                        threshold=0.75,
                        corroborated_by_events=True,
                        supporting_event_ids=["evt-0001"],
                        missing_event_ids=[],
                        assessment=(
                            "LSTM risk score 0.87 exceeds 0.75 and aligns with authentication_failure "
                            "on workstation-17|alex; treated as prioritization signal, not proof."
                        ),
                        confidence="medium",
                    )
                ],
                summary="LSTM cue cue-0001 corroborated as an investigative signal by evt-0001.",
            )

        if schema is CorrelationTimelineOutput:
            import re

            ev_ids = list(dict.fromkeys(re.findall(r'"event_id":\s*"([^"]+)"', user_prompt)))
            ref_ids = list(dict.fromkeys(re.findall(r'"reference_id":\s*"([^"]+)"', user_prompt)))
            timeline = [
                TimelineEntry(
                    timestamp_utc="2026-11-19 14:40:01 UTC",
                    timestamp_ist="2026-11-19 20:10:01 IST",
                    event_id=eid,
                    evidence_ref_id=ref_ids[idx] if idx < len(ref_ids) else "ev-0001",
                    scope_key="host:workstation-17|account:alex",
                    event_type="authentication_failure",
                    actor="alex",
                    source_ip="203.0.113.25",
                    host="workstation-17",
                    summary=f"Correlated event {eid}",
                    significance="medium",
                )
                for idx, eid in enumerate(ev_ids)
            ]
            return CorrelationTimelineOutput(
                timeline=timeline,
                relationships=[
                    EntityRelationship(
                        source_entity="ip:203.0.113.25",
                        relation="authenticated_as",
                        target_entity="account:alex",
                        evidence_type="observed",
                        supporting_event_ids=ev_ids[:3],
                        reasoning="Directly logged by sshd.",
                        confidence="high",
                    )
                ],
                correlated_scopes=["host:workstation-17|account:alex"],
                temporal_patterns=["2 failed logins -> accepted login -> sudo /etc/shadow within 71s"],
            )

        if schema is AttackPathOutput:
            counters["attack_path_calls"] += 1
            import re

            ev_ids = re.findall(r'"event_id":\s*"([^"]+)"', user_prompt)
            first_ev = ev_ids[0] if ev_ids else "evt-0001"
            last_ev = ev_ids[-1] if ev_ids else first_ev
            kids = (
                ["T1110.001", "T1078.004"]  # Inject hallucination on pass 1!
                if inject_hallucination_first_pass and counters["attack_path_calls"] == 1
                else ["T1110.001"]
            )
            return AttackPathOutput(
                hypothesis_title="SSH Password Guessing Followed by Sudo Shadow Access Attempt",
                summary="Observed failed/accepted SSH logins followed by sudo /bin/cat /etc/shadow.",
                nodes=[
                    AttackPathNode(
                        node_id="step_1",
                        label="Repeated SSH failed logins from 203.0.113.25",
                        stage="Credential Access",
                        status="observed",
                        event_ids=ev_ids[:2] or [first_ev],
                        knowledge_source_ids=kids,
                        confidence="high",
                    ),
                    AttackPathNode(
                        node_id="step_2",
                        label="Sudo invocation of /bin/cat /etc/shadow",
                        stage="Privilege Escalation",
                        status="observed",
                        event_ids=[last_ev],
                        knowledge_source_ids=[],
                        confidence="high",
                    ),
                    AttackPathNode(
                        node_id="step_3",
                        label="Offline credential cracking / lateral movement",
                        stage="Credential Access",
                        status="unconfirmed",
                        event_ids=[],
                        knowledge_source_ids=[],
                        confidence="low",
                    ),
                ],
                edges=[
                    AttackPathEdge(
                        source_node_id="step_1",
                        target_node_id="step_2",
                        label="session escalated via sudo",
                        status="inferred",
                        evidence_event_ids=[first_ev, last_ev],
                        reasoning="Same account and host within 71 seconds.",
                        confidence="high",
                    ),
                    AttackPathEdge(
                        source_node_id="step_2",
                        target_node_id="step_3",
                        label="possible hash exfiltration",
                        status="unconfirmed",
                        evidence_event_ids=[],
                        reasoning="No egress or file-read exit status observed.",
                        confidence="low",
                    ),
                ],
                missing_evidence=[
                    "Exit status and stdout of `sudo /bin/cat /etc/shadow` are not present.",
                    "No outbound network flow telemetry from workstation-17.",
                ],
                alternative_hypotheses=[
                    "Legitimate administrator alex mistyped their password twice before inspecting /etc/shadow."
                ],
            )

        if schema is OrchestratorReviewOutput:
            counters["review_calls"] += 1
            if benign_mode:
                return OrchestratorReviewOutput(
                    approved=True,
                    issues=[],
                    remediation_justified=False,
                    refinement_targets=[],
                    refinement_instructions="",
                    conflict_resolution_notes=["Benign activity; no remediation justified."],
                )
            return OrchestratorReviewOutput(
                approved=True,
                issues=[],
                remediation_justified=True,
                refinement_targets=[],
                refinement_instructions="",
                conflict_resolution_notes=["Sub-agent findings consistent and evidence-backed."],
            )

        if schema is RecommendationOutput:
            import re

            ev_ids = re.findall(r'"event_id":\s*"([^"]+)"', user_prompt)
            return RecommendationOutput(
                status="drafted",
                rationale="Supported high-severity authentication and sudo shadow-file access findings.",
                recommendations=[
                    RecommendationItem(
                        recommendation_id="rec-001",
                        priority="immediate",
                        title="Verify account alex activity and block 203.0.113.25 if unauthorized",
                        target="workstation-17 / account:alex / perimeter firewall",
                        action="Confirm with alex whether access from 203.0.113.25 was authorized; revoke sessions and rotate credentials if not.",
                        expected_effect="Contains potential unauthorized SSH access and credential exposure.",
                        supporting_finding_ids=["find-001"],
                        evidence_event_ids=ev_ids[:4],
                        knowledge_mitigation_ids=["M1032"],
                        requires_human_approval=True,
                        auto_executable=False,
                        rollback_notes="Re-enable account or remove firewall block if activity is confirmed benign.",
                    )
                ],
            )

        if schema is FinalSynthesisDraft:
            import re

            ev_ids = re.findall(r'"event_id":\s*"([^"]+)"', user_prompt)
            if benign_mode:
                return FinalSynthesisDraft(
                    overall_threat_level="informational",
                    overall_confidence="high",
                    executive_summary="Only routine benign system activity observed.",
                    findings=[],
                    potential_impact=[],
                    uncertainty_and_gaps=[],
                )
            return FinalSynthesisDraft(
                overall_threat_level="high",
                overall_confidence="high",
                executive_summary=(
                    "Observed two failed SSH logins followed by an accepted SSH login for alex from "
                    "203.0.113.25 and a subsequent `sudo /bin/cat /etc/shadow` invocation on workstation-17."
                ),
                findings=[
                    InvestigationFinding(
                        finding_id="find-001",
                        title="Suspected SSH Credential Compromise and Shadow File Access Attempt",
                        severity="high",
                        confidence="high",
                        observed_facts=[
                            "Failed SSH logins and accepted SSH login from 203.0.113.25 for alex.",
                            "Invocation of `sudo /bin/cat /etc/shadow` by alex on workstation-17.",
                        ],
                        inferences=[
                            "Sequence is consistent with credential guessing followed by credential dumping attempt."
                        ],
                        uncertainty="Command exit status and whether /etc/shadow contents were read/exfiltrated remain unconfirmed.",
                        supporting_event_ids=ev_ids[:4],
                        evidence_ref_ids=[],
                        knowledge_source_ids=["T1110.001"],
                    )
                ],
                potential_impact=["Offline password cracking if /etc/shadow hashes were obtained."],
                uncertainty_and_gaps=[
                    "Exit status of `sudo /bin/cat /etc/shadow` not recorded in auth logs."
                ],
            )

        raise AssertionError(f"Unexpected schema requested in mock runner: {schema}")

    return runner, counters


def test_raw_log_batch_parser_extracts_ist_timestamps_and_host() -> None:
    batch, excerpts = build_batch_from_raw_logs(WORKSTATION_17_LOGS, username="vmn")
    assert len(batch.records) == 4
    assert len(excerpts) == 4
    # 2026-11-19 20:10:01 IST == 2026-11-19 14:40:01 UTC
    assert batch.records[0].observed_at.hour == 14
    assert batch.records[0].observed_at.minute == 40
    assert batch.records[0].observed_at.second == 1
    assert batch.records[0].metadata["host"] == "workstation-17"
    assert batch.records[0].metadata["process"] == "sshd"
    assert batch.records[3].metadata["process"] == "sudo"


def test_full_workflow_workstation_17_without_lstm_cues() -> None:
    async def _run():
        kn_svc = await _seeded_knowledge_service()
        runner, _ = _make_mock_runner()
        inv_svc = InvestigationService(
            knowledge_service=kn_svc,
            settings=InvestigationSettings(_env_file=None, default_gemini_api_key="test-key"),
            custom_runner=runner,
        )
        result = await inv_svc.investigate_raw_logs(WORKSTATION_17_LOGS, username="vmn", max_results=5)

        assert result.investigation_id.startswith("inv-")
        assert result.overall_threat_level == "high"
        assert result.sequence_assessment.status == "skipped_no_cues"
        assert len(result.observations) == 4
        assert len(result.timeline) == 4
        assert result.timeline[0].timestamp_ist == "2026-11-19 20:10:01 IST"
        assert result.timeline[0].timestamp_utc == "2026-11-19 14:40:01 UTC"
        assert result.retrieved_knowledge
        assert all(item.is_evidence_proof is False for item in result.retrieved_knowledge)
        # Cognee 1-hop mitigation (M1032) should be available from mitre_sample_bundle.json
        assert any("M1032" in m for item in result.retrieved_knowledge for m in item.related_mitigations)
        assert result.recommendation_status == "drafted"
        assert len(result.recommendations) == 1
        assert result.recommendations[0].requires_human_approval is True
        assert result.recommendations[0].auto_executable is False
        assert "flowchart TD" in result.attack_path.mermaid_diagram
        assert "# ForensIQ Multi-Agent Investigation Report" in result.rendered_markdown_report
        assert result.rendered_summary
        # Verify audit trail includes skipped sequence_analyst and all specialist nodes
        node_names = [a.node_name for a in result.audit_trail]
        assert "orchestrator_plan" in node_names
        assert "event_analyst" in node_names
        assert "knowledge_enricher" in node_names
        assert "sequence_analyst" in node_names
        assert "correlation_timeline" in node_names
        assert "attack_path_analyst" in node_names
        assert "orchestrator_review" in node_names
        assert "recommendation_drafter" in node_names
        assert "orchestrator_synthesize" in node_names
        seq_entry = next(a for a in result.audit_trail if a.node_name == "sequence_analyst")
        assert seq_entry.status == "skipped"
        await kn_svc.close()

    asyncio.run(_run())


def test_golden_fixture_with_lstm_sequence_cue_activates_sequence_analyst() -> None:
    async def _run():
        kn_svc = await _seeded_knowledge_service()
        runner, _ = _make_mock_runner()
        inv_svc = InvestigationService(
            knowledge_service=kn_svc,
            settings=InvestigationSettings(_env_file=None, default_gemini_api_key="test-key"),
            custom_runner=runner,
        )
        inv_input = InvestigationInput.model_validate_json(
            (FIXTURES_ROOT / "investigation_input.json").read_text(encoding="utf-8")
        )
        result = await inv_svc.run_investigation(inv_input)

        assert result.investigation_id == "inv-0001"
        assert result.sequence_assessment.status == "analyzed"
        assert len(result.sequence_assessment.reviews) == 1
        assert result.sequence_assessment.reviews[0].cue_id == "cue-0001"
        assert result.sequence_assessment.reviews[0].supporting_event_ids == ["evt-0001"]
        seq_entry = next(a for a in result.audit_trail if a.node_name == "sequence_analyst")
        assert seq_entry.status == "completed"
        await kn_svc.close()

    asyncio.run(_run())


def test_hallucination_triggers_bounded_refinement_loop_and_resolves() -> None:
    async def _run():
        kn_svc = await _seeded_knowledge_service()
        runner, counters = _make_mock_runner(inject_hallucination_first_pass=True)
        inv_svc = InvestigationService(
            knowledge_service=kn_svc,
            settings=InvestigationSettings(
                _env_file=None,
                default_gemini_api_key="test-key",
                max_refinement_rounds=1,
            ),
            custom_runner=runner,
        )
        result = await inv_svc.investigate_raw_logs(WORKSTATION_17_LOGS, username="vmn")

        # Attack-path analyst ran twice (initial pass + 1 refinement pass) and review ran twice
        assert counters["attack_path_calls"] == 2
        assert counters["review_calls"] == 2
        assert result.refinement_rounds_executed == 1
        # Final result contains zero hallucinated T1078.004 references
        for node in result.attack_path.nodes:
            assert "T1078.004" not in node.knowledge_source_ids
        assert any("T1078.004" in w for w in result.guardrail_warnings)
        await kn_svc.close()

    asyncio.run(_run())


def test_benign_logs_skip_unjustified_recommendations() -> None:
    async def _run():
        kn_svc = await _seeded_knowledge_service()
        runner, _ = _make_mock_runner(benign_mode=True)
        inv_svc = InvestigationService(
            knowledge_service=kn_svc,
            settings=InvestigationSettings(_env_file=None, default_gemini_api_key="test-key"),
            custom_runner=runner,
        )
        result = await inv_svc.investigate_raw_logs(
            "2026-11-19 14:40:01 UTC web-01 nginx[100]: INFO health check status=200",
            username="vmn",
        )
        assert result.overall_threat_level == "informational"
        assert result.recommendation_status == "skipped_unjustified"
        assert result.recommendations == []
        assert "recommendation_drafter" not in [a.node_name for a in result.audit_trail]
        await kn_svc.close()

    asyncio.run(_run())
