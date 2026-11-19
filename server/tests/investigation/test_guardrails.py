"""Unit tests for deterministic anti-hallucination guardrails and Mermaid rendering."""

from __future__ import annotations

from datetime import datetime, timezone

from contracts import EvidenceReference, KnowledgeRecord, NormalizedEvent
from services.investigation.guardrails import (
    build_record_to_source_map,
    build_verified_source_ids,
    render_attack_path_mermaid,
    sanitize_attack_path,
    sanitize_enriched_knowledge,
    sanitize_findings,
    sanitize_recommendations,
    validate_subagent_outputs,
)
from services.investigation.models import (
    AttackPathEdge,
    AttackPathNode,
    AttackPathOutput,
    EnrichedKnowledgeItem,
    EventAnalysisOutput,
    EvidenceObservation,
    FinalSynthesisDraft,
    InvestigationFinding,
    KnowledgeEnrichmentOutput,
    RecommendationItem,
    RecommendationOutput,
)


def _sample_events() -> dict[str, NormalizedEvent]:
    now = datetime(2026, 11, 19, 14, 40, 1, tzinfo=timezone.utc)
    e1 = NormalizedEvent(
        event_id="evt-0001",
        scope_key="host:workstation-17|account:alex",
        event_time=now,
        event_type="authentication_failure",
        source="linux-auth",
        features={"host": "workstation-17", "account": "alex", "remote_ip": "203.0.113.25"},
        evidence_ref=EvidenceReference(
            reference_id="ev-0001",
            uri="api://analyze/vmn/batch-1",
            line_start=1,
            line_end=1,
        ),
    )
    e2 = NormalizedEvent(
        event_id="evt-0002",
        scope_key="host:workstation-17|account:alex",
        event_time=now,
        event_type="privilege_escalation",
        source="linux-auth",
        features={"host": "workstation-17", "account": "alex", "command": "/bin/cat /etc/shadow"},
        evidence_ref=EvidenceReference(
            reference_id="ev-0002",
            uri="api://analyze/vmn/batch-1",
            line_start=2,
            line_end=2,
        ),
    )
    return {e1.event_id: e1, e2.event_id: e2}


def _sample_catalog() -> dict[str, KnowledgeRecord]:
    now = datetime(2026, 11, 19, 9, 0, 0, tzinfo=timezone.utc)
    rec_ssh = KnowledgeRecord(
        record_id="okf-mitre-t1021.004",
        source_type="mitre_attack",
        source_id="T1021.004",
        source_version="17.1",
        content={"name": "SSH", "tactics": ["lateral-movement"], "platforms": ["Linux"]},
        relationships=[],
        provenance={"source_uri": "https://attack.mitre.org/techniques/T1021/004/"},
        ingested_at=now,
    )
    rec_sudo = KnowledgeRecord(
        record_id="okf-mitre-t1548.003",
        source_type="mitre_attack",
        source_id="T1548.003",
        source_version="17.1",
        content={"name": "Sudo and Sudo Caching", "tactics": ["privilege-escalation"], "platforms": ["Linux"]},
        relationships=[],
        provenance={"source_uri": "https://attack.mitre.org/techniques/T1548/003/"},
        ingested_at=now,
    )
    return {"T1021.004": rec_ssh, "T1548.003": rec_sudo}


def test_guardrails_catch_and_strip_hallucinated_t1078_004() -> None:
    """Reproduces the exact T1078.004 hallucination from the legacy single-LLM output."""
    events = _sample_events()
    catalog = _sample_catalog()
    valid_ids = build_verified_source_ids(catalog)

    ea = EventAnalysisOutput(
        observations=[
            EvidenceObservation(
                observation_id="obs-001",
                event_id="evt-0001",
                evidence_ref_id="ev-0001",
                timestamp_utc="2026-11-19 14:40:01 UTC",
                scope_key="host:workstation-17|account:alex",
                summary="Failed SSH password for alex from 203.0.113.25",
                severity="medium",
                is_anomalous=True,
            ),
            # Bad event_id check
            EvidenceObservation(
                observation_id="obs-999",
                event_id="evt-nonexistent",
                evidence_ref_id="ev-missing",
                timestamp_utc="2026-11-19 14:40:01 UTC",
                scope_key="host:workstation-17|account:alex",
                summary="Fabricated observation",
                severity="low",
            ),
        ]
    )

    ke = KnowledgeEnrichmentOutput(
        enriched_records=[
            EnrichedKnowledgeItem(
                record_id="okf-mitre-t1021.004",
                source_type="mitre_attack",
                source_id="T1021.004",
                name="SSH",
                supporting_event_ids=["evt-0001"],
                relevance_score=0.88,
            ),
            # Hallucinated technique not in catalog
            EnrichedKnowledgeItem(
                record_id="okf-mitre-t1078.004",
                source_type="mitre_attack",
                source_id="T1078.004",
                name="Valid Accounts (SSH)",
                supporting_event_ids=["evt-0001"],
                relevance_score=0.90,
            ),
        ]
    )

    ap = AttackPathOutput(
        hypothesis_title="SSH + Sudo Chain",
        nodes=[
            AttackPathNode(
                node_id="n1",
                label="SSH Access",
                stage="Initial Access",
                status="observed",
                event_ids=["evt-0001"],
                knowledge_source_ids=["T1021.004", "T1078.004"],
            ),
            AttackPathNode(
                node_id="n2",
                label="Unbacked Observed Step",
                stage="Impact",
                status="observed",
                event_ids=[],  # Invalid: observed with no event_id!
                knowledge_source_ids=["T1548.003"],
            ),
        ],
        edges=[
            AttackPathEdge(
                source_node_id="n1",
                target_node_id="n2",
                label="escalates to",
                status="observed",
                evidence_event_ids=[],  # Invalid: observed with no event_id!
            )
        ],
        missing_evidence=["Exit code of sudo /bin/cat /etc/shadow is not logged."],
    )

    issues, warnings = validate_subagent_outputs(
        event_index=events,
        knowledge_catalog=catalog,
        related_knowledge_map={},
        event_analysis=ea,
        knowledge_enrichment=ke,
        attack_path=ap,
    )

    issue_types = {i.issue_type for i in issues}
    assert "hallucinated_knowledge_id" in issue_types
    assert "missing_evidence_ref" in issue_types
    assert any("T1078.004" in w for w in warnings)

    # Sanitization removes T1078.004 and downgrades unbacked observed nodes/edges
    sanitized_kn, kn_warn = sanitize_enriched_knowledge(
        knowledge_enrichment=ke,
        knowledge_catalog=catalog,
        knowledge_scores={"T1021.004": 0.8839},
        related_knowledge_map={},
        valid_event_ids=set(events.keys()),
    )
    assert [k.source_id for k in sanitized_kn] == ["T1021.004"]
    assert sanitized_kn[0].is_evidence_proof is False
    assert any("T1078.004" in w for w in kn_warn)

    sanitized_ap, ap_warn = sanitize_attack_path(ap, set(events.keys()), valid_ids)
    assert sanitized_ap.nodes[0].knowledge_source_ids == ["T1021.004"]
    assert sanitized_ap.nodes[1].status == "inferred"
    assert sanitized_ap.edges[0].status == "inferred"
    assert "flowchart TD" in sanitized_ap.mermaid_diagram
    assert "-.->" in sanitized_ap.mermaid_diagram
    assert "[MISSING EVIDENCE]" in sanitized_ap.mermaid_diagram
    assert any("T1078.004" in w for w in ap_warn)

    # Findings & recommendation guardrails (including OKF record_id -> canonical source_id normalization)
    record_map = build_record_to_source_map(catalog)
    draft = FinalSynthesisDraft(
        overall_threat_level="high",
        overall_confidence="high",
        executive_summary="Summary",
        findings=[
            InvestigationFinding(
                finding_id="find-001",
                title="SSH + Sudo",
                severity="high",
                confidence="high",
                observed_facts=["evt-0001 failed login"],
                inferences=["Possible credential compromise"],
                supporting_event_ids=["evt-0001", "evt-fake"],
                knowledge_source_ids=["okf-mitre-t1021.004", "T1078.004"],
            )
        ],
    )
    clean_findings, f_warn = sanitize_findings(draft, events, valid_ids, record_map)
    assert clean_findings[0].supporting_event_ids == ["evt-0001"]
    assert clean_findings[0].evidence_ref_ids == ["ev-0001"]
    assert clean_findings[0].knowledge_source_ids == ["T1021.004"]
    assert any("T1078.004" in w for w in f_warn)

    rec_out = RecommendationOutput(
        status="drafted",
        recommendations=[
            RecommendationItem(
                recommendation_id="rec-001",
                priority="immediate",
                title="Audit sudoers",
                target="workstation-17",
                action="Inspect /etc/sudoers for alex",
                expected_effect="Prevents unauthorized /etc/shadow access",
                supporting_finding_ids=["find-001"],
                evidence_event_ids=["evt-0002", "evt-fake"],
                knowledge_mitigation_ids=["M9999"],
            )
        ],
    )
    clean_recs = sanitize_recommendations(
        rec_out, set(events.keys()), {"find-001"}, valid_ids
    )
    assert len(clean_recs) == 1
    assert clean_recs[0].requires_human_approval is True
    assert clean_recs[0].auto_executable is False
    assert clean_recs[0].evidence_event_ids == ["evt-0002"]
    assert clean_recs[0].knowledge_mitigation_ids == []


def test_mermaid_distinguishes_observed_vs_inferred_arrows() -> None:
    ap = AttackPathOutput(
        nodes=[
            AttackPathNode(
                node_id="step 1",
                label="Failed SSH logins",
                stage="Credential Access",
                status="observed",
                event_ids=["evt-0001"],
                knowledge_source_ids=["T1110.001"],
            ),
            AttackPathNode(
                node_id="step 2",
                label="Successful SSH login",
                stage="Initial Access",
                status="observed",
                event_ids=["evt-0002"],
                knowledge_source_ids=["T1021.004"],
            ),
            AttackPathNode(
                node_id="step 3",
                label="Offline hash cracking",
                stage="Credential Access",
                status="unconfirmed",
                event_ids=[],
            ),
        ],
        edges=[
            AttackPathEdge(
                source_node_id="step 1",
                target_node_id="step 2",
                label="preceded login",
                status="observed",
                evidence_event_ids=["evt-0001", "evt-0002"],
            ),
            AttackPathEdge(
                source_node_id="step 2",
                target_node_id="step 3",
                label="possible cracking",
                status="unconfirmed",
            ),
        ],
    )
    diagram = render_attack_path_mermaid(ap)
    assert 'step_1 -->|"OBSERVED: preceded login"| step_2' in diagram
    assert 'step_2 -.->|"UNCONFIRMED: possible cracking"| step_3' in diagram
