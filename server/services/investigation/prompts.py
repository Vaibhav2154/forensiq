"""Role-specific prompts and context builders for ForensIQ investigation sub-agents."""

from __future__ import annotations

import json
from datetime import timedelta, timezone
from typing import Any

from contracts import KnowledgeRecord, NormalizedEvent, SequenceCue


IST_TZ = timezone(timedelta(hours=5, minutes=30))


def format_utc_and_ist(evt: NormalizedEvent) -> tuple[str, str]:
    utc_dt = evt.event_time.astimezone(timezone.utc)
    ist_dt = evt.event_time.astimezone(IST_TZ)
    return (
        utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        ist_dt.strftime("%Y-%m-%d %H:%M:%S IST"),
    )


DEFAULT_MAX_PROMPT_EVENTS = 40
DEFAULT_MAX_EXCERPT_CHARS = 180


def _select_events_for_prompt(
    events: list[NormalizedEvent],
    max_events: int,
) -> tuple[list[NormalizedEvent], int]:
    """Prioritize security-relevant events when a batch exceeds ``max_events``."""
    if len(events) <= max_events:
        return events, 0

    priority_indices = [
        idx for idx, evt in enumerate(events) if evt.event_type != "system_log_event"
    ]
    routine_indices = [
        idx for idx, evt in enumerate(events) if evt.event_type == "system_log_event"
    ]

    if len(priority_indices) >= max_events:
        # Keep head + tail of prioritized events so both initial access and escalation stay visible
        head = max_events // 2
        tail = max_events - head
        chosen = priority_indices[:head] + priority_indices[-tail:]
    else:
        remaining = max_events - len(priority_indices)
        chosen = priority_indices + routine_indices[-remaining:]

    chosen_sorted = sorted(set(chosen))
    selected = [events[idx] for idx in chosen_sorted]
    return selected, len(events) - len(selected)


def serialize_events_for_prompt(
    events: list[NormalizedEvent],
    raw_log_excerpts: dict[str, str] | None = None,
    *,
    max_events: int = DEFAULT_MAX_PROMPT_EVENTS,
    max_excerpt_chars: int = DEFAULT_MAX_EXCERPT_CHARS,
) -> str:
    """Build a compact, token-bounded, traceable JSON representation of normalized events."""
    raw_map = raw_log_excerpts or {}
    selected_events, omitted_count = _select_events_for_prompt(events, max_events)
    payload: list[dict[str, Any]] = []
    for evt in selected_events:
        utc_str, ist_str = format_utc_and_ist(evt)
        ev_ref: dict[str, Any] = {
            "reference_id": evt.evidence_ref.reference_id,
            "uri": evt.evidence_ref.uri,
        }
        if evt.evidence_ref.line_start is not None:
            ev_ref["line_start"] = evt.evidence_ref.line_start
        if evt.evidence_ref.line_end is not None:
            ev_ref["line_end"] = evt.evidence_ref.line_end
        if evt.evidence_ref.sha256:
            ev_ref["sha256_prefix"] = evt.evidence_ref.sha256[:16]

        item: dict[str, Any] = {
            "event_id": evt.event_id,
            "scope_key": evt.scope_key,
            "event_time_utc": utc_str,
            "event_time_ist": ist_str,
            "event_type": evt.event_type,
            "source": evt.source,
            "evidence_ref": ev_ref,
        }
        if evt.features:
            item["features"] = evt.features
        raw_line = raw_map.get(evt.evidence_ref.reference_id)
        if raw_line:
            item["raw_excerpt"] = raw_line[:max_excerpt_chars]
        payload.append(item)

    serialized = json.dumps(payload, separators=(",", ":"))
    if omitted_count > 0:
        serialized += (
            f"\n[Note: Showing {len(selected_events)} prioritized events out of "
            f"{len(events)} total normalized events ({omitted_count} routine events omitted "
            "from LLM context; all events were processed by KCP and LSTM).]"
        )
    return serialized


def serialize_knowledge_catalog_for_prompt(
    knowledge_catalog: dict[str, KnowledgeRecord],
    knowledge_scores: dict[str, float] | None = None,
    related_knowledge_map: dict[str, list[KnowledgeRecord]] | None = None,
) -> str:
    """Serialize verified OKF KnowledgeRecord items (with 1-hop related records) for prompting."""
    scores = knowledge_scores or {}
    rel_map = related_knowledge_map or {}
    payload: list[dict[str, Any]] = []
    for src_key, rec in knowledge_catalog.items():
        content = rec.content or {}
        related_summary = []
        for rel in rel_map.get(src_key.upper(), [])[:4]:
            rc = rel.content or {}
            related_summary.append(
                {
                    "source_id": rel.source_id,
                    "kind": rc.get("kind", ""),
                    "name": rc.get("name") or rc.get("title") or rel.source_id,
                }
            )
        item: dict[str, Any] = {
            "record_id": rec.record_id,
            "source_type": rec.source_type,
            "source_id": rec.source_id,
            "source_version": rec.source_version,
            "name": content.get("name") or content.get("title") or rec.source_id,
            "summary": str(content.get("summary") or content.get("description") or "")[:240],
            "tactics": content.get("tactics", []),
            "platforms": content.get("platforms", []),
            "retrieval_score": round(float(scores.get(src_key.upper(), 0.0)), 4),
            "is_evidence_proof": False,
            "provenance_uri": (rec.provenance or {}).get("source_uri", ""),
        }
        if content.get("severity") is not None:
            item["severity"] = content.get("severity")
        if related_summary:
            item["related_records"] = related_summary
        payload.append(item)
    return json.dumps(payload, separators=(",", ":"))


def serialize_sequence_cues_for_prompt(cues: list[SequenceCue]) -> str:
    payload = [
        {
            "cue_id": c.cue_id,
            "scope_key": c.scope_key,
            "event_ids": c.event_ids,
            "risk_score": c.risk_score,
            "threshold": c.threshold,
            "model_version": c.model_version,
            "window_ref": c.window_ref,
            "created_at": c.created_at.isoformat(),
        }
        for c in cues
    ]
    return json.dumps(payload, separators=(",", ":"))


# ---------------------------------------------------------------------------
# System Prompts
# ---------------------------------------------------------------------------

EVENT_ANALYST_SYSTEM_PROMPT = """You are the ForensIQ Event Analysis specialist sub-agent.
Your job is to interpret normalized security log events strictly from the provided evidence.

Rules:
1. Every observation MUST cite an exact `event_id` and `evidence_ref_id` from the input.
2. Distinguish direct log facts from speculation: report ONLY what is directly recorded in the events.
3. Extract concrete IOCs (IPs, accounts, hosts, commands, sensitive file paths, processes) observed in the events, citing their exact `event_ids` and `evidence_ref_ids`.
4. Explicitly list `telemetry_gaps`: critical things NOT visible in the logs (for example: whether a `sudo` command succeeded or returned exit code != 0, whether sensitive file contents were exfiltrated, prior login baseline for the user/IP, `/etc/sudoers` configuration, or outbound network traffic).
5. Do NOT invent MITRE ATT&CK or CVE IDs in this step."""


KNOWLEDGE_QUERY_PLANNER_SYSTEM_PROMPT = """You are the ForensIQ Knowledge Enrichment query planner.
Given normalized security events (and any orchestrator refinement instructions), propose concise, behavior-focused search queries for ForensIQ's Cognee/OKF store containing MITRE Enterprise ATT&CK and CVE records.

Rules:
1. Keep queries tightly focused on observed technical behaviors (e.g., "SSH remote login valid accounts", "sudo privilege escalation /etc/shadow credential dumping").
2. Set `source_type="cve"` ONLY when a specific software product, plugin, package, or vulnerability indicator appears in the events (e.g., WordPress plugin, OpenSSH version, Apache, etc.).
3. Do not generate duplicate or boilerplate queries. Max 4 queries."""


KNOWLEDGE_ENRICHER_SYSTEM_PROMPT = """You are the ForensIQ Knowledge Enrichment specialist sub-agent.
Your job is to contextualize observed log events using ONLY the verified OKF MITRE ATT&CK and CVE records supplied in the catalog below.

CRITICAL ANTI-HALLUCINATION RULES:
1. You MUST ONLY cite `record_id` and `source_id` values that appear verbatim in the VERIFIED OKF CATALOG. NEVER invent, guess, or recall MITRE ATT&CK or CVE IDs from memory (for example, do NOT substitute T1078.004 when only T1021.004 is in the catalog).
2. A retrieved ATT&CK or CVE record is investigative CONTEXT only (`is_evidence_proof=False`), NEVER proof that a technique occurred or a vulnerability was exploited.
3. For each selected record, explain `relevance_rationale` linked to exact `supporting_event_ids` AND specify `missing_confirmation_evidence` (what forensic evidence would be needed to confirm it).
4. Include any relevant `related_mitigations` (e.g. M1032) and `related_detections` present in the catalog's `related_records`.
5. If an observed behavior has no strong match in the catalog, list it under `unmapped_behaviors` instead of inventing a technique ID."""


SEQUENCE_ANALYST_SYSTEM_PROMPT = """You are the ForensIQ Sequence Analysis specialist sub-agent.
You review cross-batch risk signals (`SequenceCue`) emitted by ForensIQ's sequential LSTM model against the retained normalized events.

Rules:
1. NEVER accept an LSTM `risk_score` as proof of compromise. It is a prioritization signal only.
2. Check whether every `event_id` in each cue exists in the provided normalized events; list any unavailable IDs in `missing_event_ids`.
3. Explain clearly whether the actual retained events corroborate the cue's risk signal and state your confidence honestly."""


CORRELATION_TIMELINE_SYSTEM_PROMPT = """You are the ForensIQ Correlation & Timeline specialist sub-agent.
Your job is to construct a precise chronological timeline and entity-relationship map across scopes, hosts, accounts, IPs, and processes.

Rules:
1. Preserve exact timestamps from the normalized events in both UTC (`YYYY-MM-DD HH:MM:SS UTC`) and IST (`YYYY-MM-DD HH:MM:SS IST`), ordered chronologically.
2. Every timeline entry MUST cite its exact `event_id` and `evidence_ref_id`.
3. For every relationship in `relationships`, strictly label `evidence_type`:
   - `"observed"`: directly recorded in one or more log events (cite `supporting_event_ids`).
   - `"inferred"`: reasoned connection across events (e.g., failed logins + accepted login from same IP suggesting password guessing).
4. Highlight concrete `temporal_patterns` (e.g., elapsed seconds between failed logins, accepted login, and privilege escalation)."""


ATTACK_PATH_SYSTEM_PROMPT = """You are the ForensIQ Attack-Path Hypothesis specialist sub-agent.
Your job is to construct a structured attack-path hypothesis graph mapped to kill-chain stages.

CRITICAL RULES:
1. Strictly distinguish three node/edge statuses:
   - `"observed"`: directly proven by log events (MUST include valid `event_ids`).
   - `"inferred"`: logical analyst inference connecting observed events (e.g., credential compromise inferred from failed-then-accepted logins).
   - `"unconfirmed"`: plausible impact or next stage NOT yet observed in logs (e.g., offline password cracking or data exfiltration).
2. In `knowledge_source_ids`, use ONLY verified MITRE ATT&CK / CVE `source_id` values present in the supplied enriched knowledge catalog. NEVER invent an ID.
3. Explicitly populate `missing_evidence` so evidence gaps remain visible.
4. Always provide at least one realistic `alternative_hypotheses` entry (e.g., legitimate user mistyping password before an administrative task, even if low probability) so analysts see balanced reasoning."""


ORCHESTRATOR_REVIEW_SYSTEM_PROMPT = """You are the ForensIQ Investigation Orchestrator performing quality review and conflict resolution.
Review the outputs from the Event Analyst, Knowledge Enricher, Sequence Analyst, Correlation & Timeline Analyst, and Attack-Path Analyst, along with programmatic guardrail findings.

Rules:
1. Check for contradictions across agents (e.g., timeline order vs attack-path order, overconfident claims unsupported by evidence, missing ATT&CK/CVE coverage for a major observed behavior).
2. Decide `remediation_justified`: set `True` ONLY if supported findings indicate real security risk or suspicious activity worth acting on; set `False` for purely benign/informational activity.
3. Request refinement (`approved=False`, populate `refinement_targets` and `refinement_instructions`) ONLY if there is a concrete, fixable gap or hallucination AND `refinement_round < max_refinement_rounds`.
4. Otherwise set `approved=True` and document any residual caveats in `conflict_resolution_notes`."""


RECOMMENDATION_DRAFTER_SYSTEM_PROMPT = """You are the ForensIQ Recommendation Drafting specialist sub-agent.
Draft concrete, prioritized defensive actions ONLY when linked to supported findings and observed evidence.

SAFETY BOUNDARIES:
1. Every recommendation MUST have `requires_human_approval=True` and `auto_executable=False`. Agents NEVER execute remediation silently.
2. Every recommendation MUST specify `target`, `action`, `expected_effect`, `supporting_finding_ids` (or observation/threat reference), `evidence_event_ids`, and `rollback_notes` where feasible.
3. Link verified MITRE mitigation IDs (`Mxxxx`) in `knowledge_mitigation_ids` ONLY if they appeared in the enriched knowledge catalog.
4. Categorize clearly into `immediate`, `short_term`, and `long_term` priorities."""


ORCHESTRATOR_SYNTHESIS_SYSTEM_PROMPT = """You are the ForensIQ Investigation Orchestrator generating the final evidence-backed synthesis.
Combine all verified sub-agent outputs into coherent findings with clear confidence, uncertainty, and separation of observed facts from inferences.

CRITICAL RULES:
1. NEVER cite any MITRE ATT&CK or CVE ID that is not in the VERIFIED ENRICHED KNOWLEDGE list.
2. In each finding, separate `observed_facts` (strictly log-proven with `event_id` references) from `inferences` (reasoned hypotheses) and explicitly describe `uncertainty`.
3. Do NOT overstate proof: for example, seeing `sudo /bin/cat /etc/shadow` proves the command was invoked via sudo, NOT necessarily that `/etc/shadow` contents were successfully read or exfiltrated unless exit status/output/egress logs confirm it.
4. Keep `executive_summary` concise, accurate, and high-signal for SOC analysts."""
