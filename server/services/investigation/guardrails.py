"""Deterministic anti-hallucination guardrails and Mermaid attack-path rendering."""

from __future__ import annotations

import re
from typing import Iterable

from contracts import KnowledgeRecord, NormalizedEvent
from services.investigation.models import (
    AttackPathOutput,
    EnrichedKnowledgeItem,
    EventAnalysisOutput,
    FinalSynthesisDraft,
    InvestigationFinding,
    KnowledgeEnrichmentOutput,
    RecommendationItem,
    RecommendationOutput,
    ReviewIssue,
)


_MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_MITRE_MITIGATION_RE = re.compile(r"\bM\d{4}\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_security_ids(text: str) -> set[str]:
    """Extract canonical uppercase MITRE ATT&CK technique/mitigation and CVE IDs from text."""
    if not text:
        return set()
    ids: set[str] = set()
    ids.update(m.upper() for m in _MITRE_TECHNIQUE_RE.findall(text))
    ids.update(m.upper() for m in _MITRE_MITIGATION_RE.findall(text))
    ids.update(m.upper() for m in _CVE_RE.findall(text))
    return ids


def build_verified_source_ids(
    knowledge_catalog: dict[str, KnowledgeRecord],
    related_knowledge_map: dict[str, list[KnowledgeRecord]] | None = None,
) -> set[str]:
    """Collect every verified ATT&CK/CVE/mitigation source_id from retrieved OKF records."""
    valid: set[str] = {k.upper() for k in knowledge_catalog.keys()}
    for rec in knowledge_catalog.values():
        valid.add(rec.source_id.upper())
        for rel in rec.relationships:
            valid.add(rel.target_source_id.upper())
    if related_knowledge_map:
        for rel_list in related_knowledge_map.values():
            for rel_rec in rel_list:
                valid.add(rel_rec.source_id.upper())
    return valid


def build_record_to_source_map(
    knowledge_catalog: dict[str, KnowledgeRecord],
    related_knowledge_map: dict[str, list[KnowledgeRecord]] | None = None,
) -> dict[str, str]:
    """Map verified OKF ``record_id`` and ``source_id`` variants (lowercased) to canonical ``source_id``."""
    mapping: dict[str, str] = {}
    for rec in knowledge_catalog.values():
        canonical = rec.source_id.upper()
        mapping[rec.source_id.lower()] = canonical
        mapping[rec.record_id.lower()] = canonical
        for rel in rec.relationships:
            mapping[rel.target_source_id.lower()] = rel.target_source_id.upper()
    if related_knowledge_map:
        for rel_list in related_knowledge_map.values():
            for rel_rec in rel_list:
                canonical = rel_rec.source_id.upper()
                mapping[rel_rec.source_id.lower()] = canonical
                mapping[rel_rec.record_id.lower()] = canonical
    return mapping


def _resolve_verified_id(
    candidate: str,
    valid_source_ids: set[str],
    record_to_source: dict[str, str] | None = None,
) -> str | None:
    """Resolve a candidate source_id or record_id to its canonical uppercase source_id if verified."""
    cleaned = candidate.strip()
    if not cleaned:
        return None
    if cleaned.upper() in valid_source_ids:
        return cleaned.upper()
    if record_to_source:
        resolved = record_to_source.get(cleaned.lower())
        if resolved and resolved in valid_source_ids:
            return resolved
    return None


def build_evidence_ref_ids(event_index: dict[str, NormalizedEvent]) -> set[str]:
    """Collect every valid EvidenceReference.reference_id from the indexed normalized events."""
    return {evt.evidence_ref.reference_id for evt in event_index.values()}


def _dedupe_preserve(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def validate_subagent_outputs(
    event_index: dict[str, NormalizedEvent],
    knowledge_catalog: dict[str, KnowledgeRecord],
    related_knowledge_map: dict[str, list[KnowledgeRecord]] | None,
    event_analysis: EventAnalysisOutput | None,
    knowledge_enrichment: KnowledgeEnrichmentOutput | None,
    attack_path: AttackPathOutput | None,
) -> tuple[list[ReviewIssue], list[str]]:
    """Run deterministic grounding checks across sub-agent outputs.

    Returns:
        ``(review_issues, warning_messages)``
    """
    issues: list[ReviewIssue] = []
    warnings: list[str] = []

    valid_event_ids = set(event_index.keys())
    valid_ev_refs = build_evidence_ref_ids(event_index)
    valid_source_ids = build_verified_source_ids(knowledge_catalog, related_knowledge_map)

    # 1. Validate EventAnalysis references
    if event_analysis is not None:
        for obs in event_analysis.observations:
            if obs.event_id not in valid_event_ids:
                msg = (
                    f"Event observation {obs.observation_id} cited unknown event_id "
                    f"{obs.event_id!r}."
                )
                issues.append(
                    ReviewIssue(
                        issue_type="missing_evidence_ref",
                        target_agent="event_analyst",
                        description=msg,
                        resolution_action="Prune or replace with verified event_id.",
                    )
                )
                warnings.append(msg)
            if obs.evidence_ref_id not in valid_ev_refs:
                msg = (
                    f"Event observation {obs.observation_id} cited unknown evidence_ref_id "
                    f"{obs.evidence_ref_id!r}."
                )
                issues.append(
                    ReviewIssue(
                        issue_type="missing_evidence_ref",
                        target_agent="event_analyst",
                        description=msg,
                        resolution_action="Restore exact evidence_ref_id from event_index.",
                    )
                )
                warnings.append(msg)

    # 2. Validate KnowledgeEnrichment against verified OKF catalog
    if knowledge_enrichment is not None:
        for item in knowledge_enrichment.enriched_records:
            src_upper = item.source_id.upper()
            if src_upper not in valid_source_ids:
                msg = (
                    f"KnowledgeEnricher cited unverified source_id {item.source_id!r} "
                    "not present in retrieved OKF/Cognee records."
                )
                issues.append(
                    ReviewIssue(
                        issue_type="hallucinated_knowledge_id",
                        target_agent="knowledge_enricher",
                        description=msg,
                        resolution_action="Remove unverified record or query Cognee to verify.",
                    )
                )
                warnings.append(msg)

            bad_evts = [eid for eid in item.supporting_event_ids if eid not in valid_event_ids]
            if bad_evts:
                msg = (
                    f"Knowledge item {item.source_id} referenced unknown event_ids {bad_evts}."
                )
                issues.append(
                    ReviewIssue(
                        issue_type="missing_evidence_ref",
                        target_agent="knowledge_enricher",
                        description=msg,
                        resolution_action="Keep only verified event_ids.",
                    )
                )
                warnings.append(msg)

    # 3. Validate AttackPath knowledge IDs and evidence links
    if attack_path is not None:
        for node in attack_path.nodes:
            for kid in node.knowledge_source_ids:
                if kid.upper() not in valid_source_ids:
                    msg = (
                        f"Attack-path node {node.node_id!r} cited unverified ATT&CK/CVE ID "
                        f"{kid!r} not in retrieved OKF catalog."
                    )
                    issues.append(
                        ReviewIssue(
                            issue_type="hallucinated_knowledge_id",
                            target_agent="attack_path_analyst",
                            description=msg,
                            resolution_action=(
                                f"Remove {kid!r} or retrieve it from Cognee before citing."
                            ),
                        )
                    )
                    warnings.append(msg)

            # Also check node label/notes for stray hallucinated technique/CVE IDs
            for mentioned_id in extract_security_ids(f"{node.label} {node.notes}"):
                if mentioned_id not in valid_source_ids:
                    msg = (
                        f"Attack-path node {node.node_id!r} text mentioned unverified ID "
                        f"{mentioned_id!r}."
                    )
                    issues.append(
                        ReviewIssue(
                            issue_type="hallucinated_knowledge_id",
                            target_agent="attack_path_analyst",
                            description=msg,
                            resolution_action=f"Drop unsupported mention of {mentioned_id!r}.",
                        )
                    )
                    warnings.append(msg)

            if node.status == "observed":
                valid_node_evts = [e for e in node.event_ids if e in valid_event_ids]
                if not valid_node_evts:
                    msg = (
                        f"Attack-path node {node.node_id!r} marked 'observed' without any "
                        "verified supporting event_id."
                    )
                    issues.append(
                        ReviewIssue(
                            issue_type="missing_evidence_ref",
                            target_agent="attack_path_analyst",
                            description=msg,
                            resolution_action="Downgrade node status from 'observed' to 'inferred'.",
                        )
                    )
                    warnings.append(msg)

        for edge in attack_path.edges:
            if edge.status == "observed":
                valid_edge_evts = [e for e in edge.evidence_event_ids if e in valid_event_ids]
                if not valid_edge_evts:
                    msg = (
                        f"Attack-path edge {edge.source_node_id}->{edge.target_node_id} marked "
                        "'observed' without verified evidence_event_ids."
                    )
                    issues.append(
                        ReviewIssue(
                            issue_type="missing_evidence_ref",
                            target_agent="attack_path_analyst",
                            description=msg,
                            resolution_action="Downgrade edge status from 'observed' to 'inferred'.",
                        )
                    )
                    warnings.append(msg)

    return issues, warnings


def sanitize_enriched_knowledge(
    knowledge_enrichment: KnowledgeEnrichmentOutput | None,
    knowledge_catalog: dict[str, KnowledgeRecord],
    knowledge_scores: dict[str, float],
    related_knowledge_map: dict[str, list[KnowledgeRecord]],
    valid_event_ids: set[str],
) -> tuple[list[EnrichedKnowledgeItem], list[str]]:
    """Filter and ground EnrichedKnowledgeItem records strictly against the OKF catalog."""
    warnings: list[str] = []
    catalog_by_source = {k.upper(): v for k, v in knowledge_catalog.items()}
    sanitized: list[EnrichedKnowledgeItem] = []
    seen_sources: set[str] = set()

    if knowledge_enrichment is not None:
        for item in knowledge_enrichment.enriched_records:
            src_key = item.source_id.upper()
            rec = catalog_by_source.get(src_key)
            if rec is None:
                warnings.append(
                    f"Removed unverified knowledge item {item.source_id!r} during final synthesis."
                )
                continue
            if src_key in seen_sources:
                continue
            seen_sources.add(src_key)

            content = rec.content or {}
            tactics = content.get("tactics") or item.tactics or []
            if isinstance(tactics, str):
                tactics = [t.strip() for t in tactics.split(",") if t.strip()]
            platforms = content.get("platforms") or item.platforms or []
            if isinstance(platforms, str):
                platforms = [p.strip() for p in platforms.split(",") if p.strip()]

            # Pull authoritative 1-hop related mitigations & detections from Cognee if available
            rel_recs = related_knowledge_map.get(src_key, [])
            mitigations = list(item.related_mitigations)
            detections = list(item.related_detections)
            for rel_rec in rel_recs:
                rel_kind = str((rel_rec.content or {}).get("kind", "")).lower()
                rel_name = str(
                    (rel_rec.content or {}).get("name")
                    or (rel_rec.content or {}).get("title")
                    or rel_rec.source_id
                )
                label = f"{rel_rec.source_id}: {rel_name}"
                if rel_kind in ("mitigation", "course-of-action") or rel_rec.source_id.upper().startswith("M"):
                    mitigations.append(label)
                elif rel_kind in ("data_component", "data_source", "x-mitre-data-component"):
                    detections.append(label)

            # Extract CVSS if CVE
            cvss_score = item.cvss_score
            if cvss_score is None and rec.source_type == "cve":
                sev = content.get("severity") or {}
                if isinstance(sev, dict) and sev.get("base_score") is not None:
                    try:
                        cvss_score = float(sev["base_score"])
                    except (TypeError, ValueError):
                        cvss_score = None

            score = knowledge_scores.get(src_key, item.relevance_score)
            score = round(max(0.0, min(1.0, float(score))), 4)

            sanitized.append(
                EnrichedKnowledgeItem(
                    record_id=rec.record_id,
                    source_type=rec.source_type,
                    source_id=rec.source_id,
                    source_version=rec.source_version,
                    name=str(content.get("name") or content.get("title") or item.name or rec.source_id),
                    description_excerpt=str(
                        content.get("summary")
                        or content.get("description")
                        or item.description_excerpt
                        or ""
                    )[:400],
                    tactics=[str(t) for t in tactics],
                    platforms=[str(p) for p in platforms],
                    cvss_score=cvss_score,
                    relevance_score=score,
                    is_evidence_proof=False,
                    supporting_event_ids=[
                        eid for eid in _dedupe_preserve(item.supporting_event_ids) if eid in valid_event_ids
                    ],
                    relevance_rationale=item.relevance_rationale,
                    missing_confirmation_evidence=_dedupe_preserve(item.missing_confirmation_evidence),
                    related_mitigations=_dedupe_preserve(mitigations),
                    related_detections=_dedupe_preserve(detections),
                    provenance_uri=str(
                        (rec.provenance or {}).get("source_uri") or item.provenance_uri or ""
                    ),
                )
            )

    sanitized.sort(key=lambda x: x.relevance_score, reverse=True)
    return sanitized, warnings


def sanitize_attack_path(
    attack_path: AttackPathOutput | None,
    valid_event_ids: set[str],
    valid_source_ids: set[str],
    record_to_source: dict[str, str] | None = None,
) -> tuple[AttackPathOutput, list[str]]:
    """Enforce verified IDs and observed-vs-inferred integrity on AttackPathOutput."""
    if attack_path is None:
        return AttackPathOutput(), []

    warnings: list[str] = []
    clean_nodes = []
    for node in attack_path.nodes:
        clean_evts = [eid for eid in _dedupe_preserve(node.event_ids) if eid in valid_event_ids]
        clean_kids = []
        for kid in _dedupe_preserve(node.knowledge_source_ids):
            resolved = _resolve_verified_id(kid, valid_source_ids, record_to_source)
            if resolved:
                clean_kids.append(resolved)
            else:
                warnings.append(
                    f"Stripped unverified ID {kid!r} from attack-path node {node.node_id!r}."
                )
        clean_kids = _dedupe_preserve(clean_kids)
        status = node.status
        if status == "observed" and not clean_evts:
            status = "inferred"
            warnings.append(
                f"Downgraded attack-path node {node.node_id!r} from 'observed' to 'inferred' (no valid event_id)."
            )
        clean_nodes.append(
            node.model_copy(
                update={
                    "status": status,
                    "event_ids": clean_evts,
                    "knowledge_source_ids": clean_kids,
                }
            )
        )

    valid_node_ids = {n.node_id for n in clean_nodes}
    clean_edges = []
    for edge in attack_path.edges:
        if edge.source_node_id not in valid_node_ids or edge.target_node_id not in valid_node_ids:
            continue
        clean_evts = [
            eid for eid in _dedupe_preserve(edge.evidence_event_ids) if eid in valid_event_ids
        ]
        status = edge.status
        if status == "observed" and not clean_evts:
            status = "inferred"
            warnings.append(
                f"Downgraded attack-path edge {edge.source_node_id}->{edge.target_node_id} "
                "from 'observed' to 'inferred' (no valid evidence_event_id)."
            )
        clean_edges.append(
            edge.model_copy(update={"status": status, "evidence_event_ids": clean_evts})
        )

    cleaned = attack_path.model_copy(update={"nodes": clean_nodes, "edges": clean_edges})
    mermaid = render_attack_path_mermaid(cleaned)
    return cleaned.model_copy(update={"mermaid_diagram": mermaid}), warnings


def sanitize_findings(
    draft: FinalSynthesisDraft,
    event_index: dict[str, NormalizedEvent],
    valid_source_ids: set[str],
    record_to_source: dict[str, str] | None = None,
) -> tuple[list[InvestigationFinding], list[str]]:
    """Ensure every finding cites only verified event_ids, evidence_ref_ids, and OKF IDs."""
    warnings: list[str] = []
    valid_event_ids = set(event_index.keys())
    clean_findings: list[InvestigationFinding] = []

    for finding in draft.findings:
        clean_evts = [
            eid for eid in _dedupe_preserve(finding.supporting_event_ids) if eid in valid_event_ids
        ]
        derived_refs = [event_index[eid].evidence_ref.reference_id for eid in clean_evts]
        clean_refs = _dedupe_preserve(
            [r for r in finding.evidence_ref_ids if r in build_evidence_ref_ids(event_index)]
            + derived_refs
        )
        clean_kids: list[str] = []
        for kid in _dedupe_preserve(finding.knowledge_source_ids):
            resolved = _resolve_verified_id(kid, valid_source_ids, record_to_source)
            if resolved:
                clean_kids.append(resolved)
            else:
                warnings.append(
                    f"Stripped unverified ID {kid!r} from finding {finding.finding_id!r}."
                )
        clean_findings.append(
            finding.model_copy(
                update={
                    "supporting_event_ids": clean_evts,
                    "evidence_ref_ids": clean_refs,
                    "knowledge_source_ids": _dedupe_preserve(clean_kids),
                }
            )
        )

    return clean_findings, warnings


def sanitize_recommendations(
    recommendations_output: RecommendationOutput | None,
    valid_event_ids: set[str],
    valid_finding_ids: set[str],
    valid_source_ids: set[str],
    record_to_source: dict[str, str] | None = None,
) -> list[RecommendationItem]:
    """Enforce approval gates and valid references on every RecommendationItem."""
    if recommendations_output is None or recommendations_output.status != "drafted":
        return []

    cleaned: list[RecommendationItem] = []
    for rec in recommendations_output.recommendations:
        resolved_mits = []
        for mid in _dedupe_preserve(rec.knowledge_mitigation_ids):
            resolved = _resolve_verified_id(mid, valid_source_ids, record_to_source)
            if resolved:
                resolved_mits.append(resolved)
        is_manual = rec.playbook_id == "manual_only" or not rec.playbook_params
        fixable = False if is_manual else bool(rec.fixable_via_tui)
        fix_tier = "tier_3_advisory" if not fixable else rec.fix_tier
        playbook_id = "manual_only" if not fixable else rec.playbook_id
        playbook_params = (
            {}
            if not fixable
            else {str(k): str(v) for k, v in rec.playbook_params.items() if str(k).strip()}
        )
        cleaned.append(
            RecommendationItem(
                recommendation_id=rec.recommendation_id,
                priority=rec.priority,
                title=rec.title,
                target=rec.target,
                action=rec.action,
                expected_effect=rec.expected_effect,
                supporting_finding_ids=[
                    fid
                    for fid in _dedupe_preserve(rec.supporting_finding_ids)
                    if not valid_finding_ids or fid in valid_finding_ids
                ],
                evidence_event_ids=[
                    eid for eid in _dedupe_preserve(rec.evidence_event_ids) if eid in valid_event_ids
                ],
                knowledge_mitigation_ids=_dedupe_preserve(resolved_mits),
                requires_human_approval=True,
                auto_executable=False,
                rollback_notes=rec.rollback_notes,
                fixable_via_tui=fixable,
                fix_tier=fix_tier,
                playbook_id=playbook_id,
                playbook_params=playbook_params,
                execution_status=rec.execution_status,
            )
        )
    return cleaned


def _mermaid_safe_id(raw: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", raw.strip())
    if not cleaned or not cleaned[0].isalpha():
        cleaned = f"{fallback}_{cleaned}" if cleaned else fallback
    return cleaned


def _mermaid_safe_text(text: str, max_len: int = 80) -> str:
    cleaned = text.replace('"', "'").replace("\n", " ").replace("<", "(").replace(">", ")")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def render_attack_path_mermaid(attack_path: AttackPathOutput) -> str:
    """Deterministically render an AttackPathOutput into a valid Mermaid flowchart.

    - Solid arrows (``-->``) represent ``observed`` transitions.
    - Dashed arrows (``-.->``) represent ``inferred`` or ``unconfirmed`` transitions.
    - Explicit gap nodes surface ``missing_evidence``.
    """
    if not attack_path.nodes:
        return ""

    lines: list[str] = ["flowchart TD"]
    id_map: dict[str, str] = {}

    for idx, node in enumerate(attack_path.nodes, start=1):
        safe_id = _mermaid_safe_id(node.node_id, f"step_{idx}")
        id_map[node.node_id] = safe_id
        tag = node.status.upper()
        kids = f" ({', '.join(node.knowledge_source_ids[:3])})" if node.knowledge_source_ids else ""
        label = _mermaid_safe_text(f"[{tag}] {node.stage}: {node.label}{kids}", max_len=95)
        lines.append(f'    {safe_id}["{label}"]')

    for edge in attack_path.edges:
        src = id_map.get(edge.source_node_id)
        dst = id_map.get(edge.target_node_id)
        if not src or not dst:
            continue
        elabel = _mermaid_safe_text(f"{edge.status.upper()}: {edge.label}", max_len=55)
        arrow = "-->" if edge.status == "observed" else "-.->"
        lines.append(f'    {src} {arrow}|"{elabel}"| {dst}')

    if attack_path.missing_evidence:
        last_node_id = id_map.get(attack_path.nodes[-1].node_id)
        for g_idx, gap in enumerate(attack_path.missing_evidence[:3], start=1):
            gap_id = f"gap_{g_idx}"
            gap_label = _mermaid_safe_text(f"[MISSING EVIDENCE] {gap}", max_len=90)
            lines.append(f'    {gap_id}["{gap_label}"]')
            if last_node_id:
                lines.append(f'    {last_node_id} -.->|"UNCONFIRMED GAP"| {gap_id}')

    return "\n".join(lines)
