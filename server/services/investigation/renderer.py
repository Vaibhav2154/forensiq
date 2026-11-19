"""Deterministic Markdown report & summary renderers for InvestigationResult."""

from __future__ import annotations

from services.investigation.models import InvestigationResult


def render_summary(result: InvestigationResult) -> str:
    """Render a concise, structured summary compatible with LogAnalysisResponse.summary."""
    lines: list[str] = [
        "**ForensIQ Multi-Agent Log Analysis Summary**",
        f"**Investigation ID:** `{result.investigation_id}`",
        f"**Overall Threat Level:** {result.overall_threat_level.upper()} | "
        f"**Confidence:** {result.overall_confidence.upper()}",
        "",
        "---",
        "",
        "### Executive Summary",
        result.executive_summary or "No executive summary generated.",
        "",
    ]

    if result.observations:
        lines.append("### Direct Log Observations (Evidence-Backed)")
        for obs in result.observations:
            anom = " `[ANOMALOUS]`" if obs.is_anomalous else ""
            lines.append(
                f"* **{obs.observation_id}** ({obs.severity.upper()}{anom}) "
                f"[`{obs.event_id}` / `{obs.evidence_ref_id}`]: {obs.summary}"
            )
        lines.append("")

    if result.timeline:
        lines.append("### Chronological Timeline (IST / UTC)")
        for entry in result.timeline:
            actor_part = f" | actor=`{entry.actor}`" if entry.actor else ""
            ip_part = f" | ip=`{entry.source_ip}`" if entry.source_ip else ""
            lines.append(
                f"* **{entry.timestamp_ist}** ({entry.timestamp_utc}) "
                f"[`{entry.event_id}`]{actor_part}{ip_part}: {entry.summary}"
            )
        lines.append("")

    if result.iocs:
        lines.append("### Observed Indicators of Compromise (IOCs)")
        for ioc in result.iocs:
            ev_refs = ", ".join(f"`{e}`" for e in ioc.event_ids[:4])
            ref_suffix = f" (events: {ev_refs})" if ev_refs else ""
            lines.append(f"* **{ioc.ioc_type.upper()}**: `{ioc.value}` — {ioc.context}{ref_suffix}")
        lines.append("")

    return "\n".join(lines).strip()


def render_markdown_report(result: InvestigationResult) -> str:
    """Render the full multi-agent evidence-backed forensic report in Markdown."""
    lines: list[str] = [
        "# ForensIQ Multi-Agent Investigation Report",
        "",
        f"- **Investigation ID:** `{result.investigation_id}`",
        f"- **Overall Threat Level:** **{result.overall_threat_level.upper()}**",
        f"- **Overall Confidence:** **{result.overall_confidence.upper()}**",
        f"- **Status:** `{result.status}` | **Refinement Rounds:** `{result.refinement_rounds_executed}` | "
        f"**Processing Time:** `{result.processing_time_ms:.1f} ms`",
        "",
        "> **Evidence Boundary Notice:** Retrieved MITRE ATT&CK and CVE records provide investigative "
        "context only (`is_evidence_proof=false`) and are never standalone proof of compromise. "
        "All proposed remediations require explicit human review and approval.",
        "",
        "---",
        "",
        "## 1. Executive Threat Assessment",
        "",
        result.executive_summary or "No assessment available.",
        "",
    ]

    # Section 2: Findings (Evidence vs Inference)
    lines.append("## 2. Evidence-Backed Findings (Facts vs. Inferences)")
    lines.append("")
    if result.findings:
        for finding in result.findings:
            kids = (
                ", ".join(f"`{k}`" for k in finding.knowledge_source_ids)
                if finding.knowledge_source_ids
                else "None"
            )
            evts = (
                ", ".join(f"`{e}`" for e in finding.supporting_event_ids)
                if finding.supporting_event_ids
                else "None"
            )
            lines.append(
                f"### {finding.finding_id}: {finding.title} "
                f"({finding.severity.upper()} | Confidence: {finding.confidence.upper()})"
            )
            lines.append(f"- **Supporting Events:** {evts} | **Related OKF IDs:** {kids}")
            if finding.observed_facts:
                lines.append("- **Observed Facts (Direct Log Evidence):**")
                for fact in finding.observed_facts:
                    lines.append(f"  - {fact}")
            if finding.inferences:
                lines.append("- **Analyst Inferences (Hypotheses):**")
                for inf in finding.inferences:
                    lines.append(f"  - {inf}")
            if finding.uncertainty:
                lines.append(f"- **Uncertainty / What Is Unconfirmed:** {finding.uncertainty}")
            lines.append("")
    else:
        lines.append("No material security findings were escalated from the analyzed logs.")
        lines.append("")

    # Section 3: Grounded OKF Knowledge (MITRE ATT&CK & CVE)
    lines.append("## 3. Retrieved MITRE ATT&CK & CVE Context (Verified OKF/Cognee)")
    lines.append("")
    if result.retrieved_knowledge:
        for item in result.retrieved_knowledge:
            tactics = ", ".join(item.tactics) if item.tactics else "N/A"
            cvss_str = f" | CVSS: `{item.cvss_score}`" if item.cvss_score is not None else ""
            evts = ", ".join(f"`{e}`" for e in item.supporting_event_ids) or "General context"
            lines.append(
                f"* **`{item.source_id}` — {item.name}** "
                f"(`{item.source_type}`, score=`{item.relevance_score:.4f}`{cvss_str}, "
                f"tactics=`{tactics}`, `is_evidence_proof=False`)"
            )
            if item.relevance_rationale:
                lines.append(f"  * *Context Rationale (events: {evts}):* {item.relevance_rationale}")
            if item.missing_confirmation_evidence:
                lines.append(
                    f"  * *Evidence Required to Confirm:* {'; '.join(item.missing_confirmation_evidence)}"
                )
            if item.related_mitigations:
                lines.append(
                    f"  * *Cognee Graph Mitigations:* {', '.join(item.related_mitigations[:5])}"
                )
            if item.related_detections:
                lines.append(
                    f"  * *Cognee Graph Detections:* {', '.join(item.related_detections[:5])}"
                )
            if item.provenance_uri:
                lines.append(f"  * *Provenance:* {item.provenance_uri}")
        lines.append("")
    else:
        lines.append("No verified ATT&CK or CVE records were matched for this investigation.")
        lines.append("")

    # Section 4: Chronological Timeline & Relationships
    lines.append("## 4. Correlated Timeline & Entity Relationships")
    lines.append("")
    if result.timeline:
        lines.append("### Chronological Timeline")
        for entry in result.timeline:
            lines.append(
                f"* **{entry.timestamp_ist}** ({entry.timestamp_utc}) | "
                f"`{entry.scope_key}` | `{entry.event_id}` (`{entry.evidence_ref_id}`): {entry.summary}"
            )
        lines.append("")

    if result.relationships:
        lines.append("### Entity Relationships")
        for rel in result.relationships:
            tag = rel.evidence_type.upper()
            evts = ", ".join(f"`{e}`" for e in rel.supporting_event_ids) or "None"
            lines.append(
                f"* **[{tag}]** `{rel.source_entity}` — *{rel.relation}* → `{rel.target_entity}` "
                f"(confidence: {rel.confidence}, events: {evts}): {rel.reasoning}"
            )
        lines.append("")

    # Section 5: Attack-Path Hypothesis
    lines.append("## 5. Attack-Path Hypothesis (Observed vs. Inferred Links)")
    lines.append("")
    ap = result.attack_path
    if ap.summary:
        lines.append(ap.summary)
        lines.append("")
    if ap.mermaid_diagram:
        lines.append("```mermaid")
        lines.append(ap.mermaid_diagram)
        lines.append("```")
        lines.append("")
    if ap.missing_evidence:
        lines.append("### Missing Evidence in Attack Path")
        for gap in ap.missing_evidence:
            lines.append(f"* {gap}")
        lines.append("")
    if ap.alternative_hypotheses:
        lines.append("### Alternative Hypotheses Considered")
        for alt in ap.alternative_hypotheses:
            lines.append(f"* {alt}")
        lines.append("")

    # Section 6: Potential Impact & Uncertainty
    if result.potential_impact or result.uncertainty_and_gaps:
        lines.append("## 6. Potential Impact & Uncertainty / Telemetry Gaps")
        lines.append("")
        if result.potential_impact:
            lines.append("### Potential Impact (Conditional on Confirmed Compromise)")
            for imp in result.potential_impact:
                lines.append(f"* {imp}")
            lines.append("")
        if result.uncertainty_and_gaps:
            lines.append("### Explicit Uncertainty & Missing Telemetry")
            for gap in result.uncertainty_and_gaps:
                lines.append(f"* {gap}")
            lines.append("")

    # Section 7: Recommendations (Approval-Gated)
    lines.append("## 7. Evidence-Linked Recommendations (Human Approval Required)")
    lines.append("")
    if result.recommendations:
        for priority_key, header in (
            ("immediate", "Immediate Actions (Critical Priority)"),
            ("short_term", "Short-Term Actions"),
            ("long_term", "Long-Term Hardening"),
        ):
            group = [r for r in result.recommendations if r.priority == priority_key]
            if not group:
                continue
            lines.append(f"### {header}")
            for rec in group:
                mits = (
                    f" | MITRE Mitigations: {', '.join(f'`{m}`' for m in rec.knowledge_mitigation_ids)}"
                    if rec.knowledge_mitigation_ids
                    else ""
                )
                evts = ", ".join(f"`{e}`" for e in rec.evidence_event_ids) or "N/A"
                lines.append(
                    f"1. **{rec.title}** (`{rec.recommendation_id}` — `requires_human_approval=True`)"
                )
                lines.append(f"   - **Target:** {rec.target}")
                lines.append(f"   - **Action:** {rec.action}")
                lines.append(f"   - **Expected Effect:** {rec.expected_effect}")
                lines.append(f"   - **Evidence:** {evts}{mits}")
                if rec.rollback_notes:
                    lines.append(f"   - **Rollback / Recovery:** {rec.rollback_notes}")
            lines.append("")
    else:
        lines.append(
            f"No remediation actions proposed (`status={result.recommendation_status}`)."
        )
        lines.append("")

    # Section 8: Observed IOCs
    lines.append("## 8. Observed Indicators of Compromise (IOCs)")
    lines.append("")
    if result.iocs:
        for ioc in result.iocs:
            evts = ", ".join(f"`{e}`" for e in ioc.event_ids) or "N/A"
            lines.append(f"* **{ioc.ioc_type.upper()}** `{ioc.value}` (events: {evts}) — {ioc.context}")
        lines.append("")
    else:
        lines.append("No discrete IOCs extracted.")
        lines.append("")

    # Section 9: Sequence Context (LSTM Hook) & Multi-Agent Audit Trail
    lines.append("## 9. Sequence Context (LSTM Hook) & Multi-Agent Audit Trail")
    lines.append("")
    lines.append(
        f"- **LSTM Sequence Assessment:** `{result.sequence_assessment.status}` — "
        f"{result.sequence_assessment.summary}"
    )
    if result.guardrail_warnings:
        lines.append("- **Guardrail Corrections Applied:**")
        for warn in result.guardrail_warnings:
            lines.append(f"  - {warn}")
    if result.audit_trail:
        lines.append("")
        lines.append("| Step | Agent Role | Status | Model | Key Slot | Duration (ms) | Summary |")
        lines.append("| --- | --- | --- | --- | --- | ---: | --- |")
        for entry in result.audit_trail:
            summary_clean = entry.output_summary.replace("|", "/").replace("\n", " ")[:90]
            lines.append(
                f"| `{entry.node_name}` | `{entry.agent_role}` | `{entry.status}` | "
                f"`{entry.model_name or 'deterministic'}` | `{entry.api_key_slot or 'n/a'}` | "
                f"{entry.duration_ms:.1f} | {summary_clean} |"
            )
    lines.append("")

    return "\n".join(lines).strip()
