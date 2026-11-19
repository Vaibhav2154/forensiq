"""Deterministic visualization metrics builder for threat analysis & dashboards."""

from __future__ import annotations

from typing import Any


CANONICAL_KILL_CHAIN_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

_PHASE_INDEX: dict[str, int] = {
    phase: idx for idx, phase in enumerate(CANONICAL_KILL_CHAIN_ORDER)
}

_THREAT_LEVEL_BASELINE: dict[str, int] = {
    "critical": 90,
    "high": 75,
    "medium": 55,
    "low": 30,
    "informational": 10,
}

_CONFIDENCE_WEIGHT: dict[str, float] = {
    "high": 0.85,
    "medium": 0.65,
    "low": 0.40,
}

_STATUS_WEIGHT: dict[str, float] = {
    "observed": 1.0,
    "inferred": 0.80,
    "unconfirmed": 0.50,
}


def _clamp_pct(value: float) -> int:
    return max(0, min(100, int(round(value))))


def _normalize_phase(phase: Any) -> str:
    return str(phase or "").strip().lower().replace("_", "-").replace(" ", "-")


def _phase_order_index(phase: str) -> int:
    return _PHASE_INDEX.get(phase, len(CANONICAL_KILL_CHAIN_ORDER))


def _confidence_to_pct(confidence: Any, status: Any) -> int:
    conf_w = _CONFIDENCE_WEIGHT.get(str(confidence or "").strip().lower(), 0.50)
    stat_w = _STATUS_WEIGHT.get(str(status or "").strip().lower(), 0.75)
    return _clamp_pct(conf_w * stat_w * 100.0)


def _normalize_techniques(
    matched_techniques: list[dict[str, Any]] | list[Any] | None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    if not matched_techniques:
        return normalized
    for item in matched_techniques:
        if hasattr(item, "model_dump"):
            raw = item.model_dump()
        elif isinstance(item, dict):
            raw = dict(item)
        else:
            continue
        raw_phases = raw.get("kill_chain_phases") or []
        if isinstance(raw_phases, str):
            raw_phases = [p.strip() for p in raw_phases.split(",") if p.strip()]
        phases = [_normalize_phase(p) for p in raw_phases if str(p).strip()]
        try:
            score = float(raw.get("relevance_score", 0.0) or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        score = max(0.0, min(1.0, score))
        normalized.append(
            {
                "technique_id": str(raw.get("technique_id") or ""),
                "name": str(raw.get("name") or raw.get("technique_id") or "Unknown"),
                "description": str(raw.get("description") or ""),
                "kill_chain_phases": phases,
                "platforms": [str(p) for p in (raw.get("platforms") or [])],
                "relevance_score": score,
            }
        )
    return normalized


def compute_visualization_metrics(
    matched_techniques: list[dict[str, Any]] | list[Any] | None,
    investigation: dict[str, Any] | None = None,
    processing_time_ms: float | None = None,
) -> dict[str, Any]:
    """Compute finite, deterministic dashboard & visualization metrics from analysis results."""
    techniques = _normalize_techniques(matched_techniques)
    inv = investigation if isinstance(investigation, dict) else {}

    relevance_scores = [t["relevance_score"] for t in techniques]
    max_relevance = max(relevance_scores) if relevance_scores else 0.0
    avg_relevance = (
        sum(relevance_scores) / len(relevance_scores) if relevance_scores else 0.0
    )

    max_confidence_pct = _clamp_pct(max_relevance * 100.0)
    avg_confidence_pct = _clamp_pct(avg_relevance * 100.0)

    raw_threat_level = str(inv.get("overall_threat_level") or "").strip().lower()
    if raw_threat_level in _THREAT_LEVEL_BASELINE:
        overall_threat_level = raw_threat_level
    elif max_relevance >= 0.8:
        overall_threat_level = "critical"
    elif max_relevance >= 0.6:
        overall_threat_level = "high"
    elif max_relevance >= 0.4:
        overall_threat_level = "medium"
    elif max_relevance > 0.0:
        overall_threat_level = "low"
    else:
        overall_threat_level = "informational"

    raw_confidence_label = str(inv.get("overall_confidence") or "").strip().lower()
    if raw_confidence_label in ("high", "medium", "low"):
        overall_confidence_label = raw_confidence_label
    elif avg_relevance >= 0.7:
        overall_confidence_label = "high"
    elif avg_relevance >= 0.4:
        overall_confidence_label = "medium"
    else:
        overall_confidence_label = "low"

    retrieved_knowledge = [
        item for item in (inv.get("retrieved_knowledge") or []) if isinstance(item, dict)
    ]
    cve_matches = [
        {
            "source_id": str(item.get("source_id") or ""),
            "name": str(item.get("name") or item.get("source_id") or ""),
            "description_excerpt": str(item.get("description_excerpt") or ""),
            "cvss_score": item.get("cvss_score"),
            "relevance_score": round(
                max(0.0, min(1.0, float(item.get("relevance_score") or 0.0))), 4
            ),
            "relevance_rationale": str(item.get("relevance_rationale") or ""),
            "missing_confirmation_evidence": list(
                item.get("missing_confirmation_evidence") or []
            ),
            "provenance_uri": str(item.get("provenance_uri") or ""),
        }
        for item in retrieved_knowledge
        if str(item.get("source_type") or "").lower() == "cve"
    ]

    timeline = [item for item in (inv.get("timeline") or []) if isinstance(item, dict)]
    iocs = [item for item in (inv.get("iocs") or []) if isinstance(item, dict)]
    findings = [item for item in (inv.get("findings") or []) if isinstance(item, dict)]
    recommendations = [
        item for item in (inv.get("recommendations") or []) if isinstance(item, dict)
    ]
    raw_attack_path = inv.get("attack_path")
    attack_path = dict(raw_attack_path) if isinstance(raw_attack_path, dict) else {}
    attack_path_nodes = [
        n for n in (attack_path.get("nodes") or []) if isinstance(n, dict)
    ]
    uncertainty_and_gaps = [str(g) for g in (inv.get("uncertainty_and_gaps") or [])]
    guardrail_warnings = [str(w) for w in (inv.get("guardrail_warnings") or [])]

    if raw_threat_level in _THREAT_LEVEL_BASELINE:
        if overall_threat_level == "informational" and not techniques and not findings:
            overall_risk_score = 0
        elif overall_threat_level in ("critical", "high", "medium"):
            overall_risk_score = _clamp_pct(
                max(_THREAT_LEVEL_BASELINE[overall_threat_level], max_confidence_pct)
            )
        else:
            overall_risk_score = _clamp_pct(
                max(_THREAT_LEVEL_BASELINE[overall_threat_level], max_confidence_pct)
                if (techniques or findings)
                else _THREAT_LEVEL_BASELINE[overall_threat_level]
            )
    else:
        overall_risk_score = max_confidence_pct

    # Collect unique phases across techniques and attack-path nodes
    unique_phases: set[str] = set()
    for t in techniques:
        unique_phases.update(t["kill_chain_phases"])
    for node in attack_path_nodes:
        norm_stage = _normalize_phase(node.get("stage"))
        if norm_stage:
            unique_phases.add(norm_stage)

    def _phase_score(target_phases: list[str]) -> int:
        targets = {_normalize_phase(p) for p in target_phases}
        matched_scores: list[float] = []
        for t in techniques:
            if any(p in targets for p in t["kill_chain_phases"]):
                matched_scores.append(t["relevance_score"])
        for node in attack_path_nodes:
            norm_stage = _normalize_phase(node.get("stage"))
            if norm_stage in targets or any(tp in norm_stage for tp in targets):
                matched_scores.append(_confidence_to_pct(node.get("confidence"), node.get("status")) / 100.0)
        if not matched_scores:
            return 0
        return _clamp_pct(max(matched_scores) * 100.0)

    if techniques or findings:
        tech_complexity = _clamp_pct(
            avg_confidence_pct * 0.7 + min(len(unique_phases), 5) * 6
        )
    else:
        tech_complexity = 0

    evasion_cap = _phase_score(["defense-evasion"])
    impact_pot = _phase_score(["impact", "exfiltration", "collection", "credential-access"])
    detection_diff = _clamp_pct(
        evasion_cap * 0.6 + _phase_score(["command-and-control", "credential-access"]) * 0.4
    )
    persistence_lvl = _phase_score(["persistence", "privilege-escalation"])
    lateral_mov = _phase_score(["lateral-movement", "discovery", "initial-access"])

    sophistication_radar = [
        {"subject": "Technical Complexity", "value": tech_complexity, "fullMark": 100},
        {"subject": "Evasion Capability", "value": evasion_cap, "fullMark": 100},
        {"subject": "Impact Potential", "value": impact_pot, "fullMark": 100},
        {"subject": "Detection Difficulty", "value": detection_diff, "fullMark": 100},
        {"subject": "Persistence Level", "value": persistence_lvl, "fullMark": 100},
        {"subject": "Lateral Movement", "value": lateral_mov, "fullMark": 100},
    ]

    threat_assessment_bars = [
        {"label": "Attack Complexity", "value": tech_complexity, "color": "text-orange-400"},
        {"label": "Stealth Level", "value": evasion_cap, "color": "text-yellow-400"},
        {"label": "Persistence Capability", "value": persistence_lvl, "color": "text-red-400"},
        {"label": "Lateral Movement Risk", "value": lateral_mov, "color": "text-blue-400"},
    ]

    # Phase aggregation for bar chart & attack journey
    phase_buckets: dict[str, list[dict[str, Any]]] = {}
    for t in techniques:
        for phase in t["kill_chain_phases"]:
            phase_buckets.setdefault(phase, []).append(t)

    sorted_phases = sorted(phase_buckets.keys(), key=_phase_order_index)

    phase_risk_distribution = []
    attack_journey = []
    for idx, phase in enumerate(sorted_phases):
        bucket = phase_buckets[phase]
        scores = [t["relevance_score"] for t in bucket]
        avg_s = sum(scores) / len(scores)
        max_s = max(scores)
        phase_risk_distribution.append(
            {
                "phase": phase.replace("-", " "),
                "phase_key": phase,
                "risk": _clamp_pct(avg_s * 100.0),
                "max_risk": _clamp_pct(max_s * 100.0),
                "techniques": len(bucket),
            }
        )
        risk_level = (
            "critical"
            if max_s > 0.8
            else "high"
            if max_s > 0.6
            else "medium"
            if max_s > 0.4
            else "low"
        )
        attack_journey.append(
            {
                "id": f"phase-{idx}",
                "phase": phase.replace("-", " ").upper(),
                "phase_key": phase,
                "techniques": [t["name"] for t in bucket],
                "risk_level": risk_level,
                "description": bucket[0]["description"] or "No description available",
            }
        )

    # Event ID -> timestamp lookup from timeline
    event_ts_map: dict[str, str] = {}
    for entry in timeline:
        eid = str(entry.get("event_id") or "")
        ts = str(entry.get("timestamp_ist") or entry.get("timestamp_utc") or "")
        if eid and ts:
            event_ts_map[eid] = ts

    attack_progression: list[dict[str, Any]] = []
    if attack_path_nodes:
        for idx, node in enumerate(attack_path_nodes):
            node_eids = [str(eid) for eid in (node.get("event_ids") or [])]
            matching_ts = next((event_ts_map[eid] for eid in node_eids if eid in event_ts_map), "")
            attack_progression.append(
                {
                    "step": idx + 1,
                    "technique": str(node.get("label") or f"Step {idx + 1}"),
                    "phase": str(node.get("stage") or "unknown"),
                    "risk": _confidence_to_pct(node.get("confidence"), node.get("status")),
                    "status": str(node.get("status") or "inferred"),
                    "timestamp": matching_ts or f"Step {idx + 1}",
                    "knowledge_ids": [str(k) for k in (node.get("knowledge_source_ids") or [])],
                }
            )
    else:
        ordered_techs = sorted(
            techniques,
            key=lambda t: min(
                (_phase_order_index(p) for p in t["kill_chain_phases"]),
                default=len(CANONICAL_KILL_CHAIN_ORDER),
            ),
        )
        for idx, t in enumerate(ordered_techs):
            attack_progression.append(
                {
                    "step": idx + 1,
                    "technique": t["name"],
                    "technique_id": t["technique_id"],
                    "phase": t["kill_chain_phases"][0] if t["kill_chain_phases"] else "unknown",
                    "risk": _clamp_pct(t["relevance_score"] * 100.0),
                    "status": "inferred",
                    "timestamp": f"Step {idx + 1}",
                    "knowledge_ids": [t["technique_id"]] if t["technique_id"] else [],
                }
            )

    summary_counts = {
        "techniques_detected": len(techniques),
        "cve_count": len(cve_matches),
        "attack_phases": len(unique_phases),
        "findings_count": len(findings),
        "iocs_count": len(iocs),
        "timeline_events_count": len(timeline),
        "recommendations_count": len(recommendations),
        "analysis_time_sec": round(max(0.0, float(processing_time_ms or 0.0)) / 1000.0, 2),
    }

    return {
        "overall_threat_level": overall_threat_level,
        "overall_confidence_label": overall_confidence_label,
        "overall_risk_score": overall_risk_score,
        "max_confidence_pct": max_confidence_pct,
        "avg_confidence_pct": avg_confidence_pct,
        "summary_counts": summary_counts,
        "sophistication_radar": sophistication_radar,
        "threat_assessment_bars": threat_assessment_bars,
        "phase_risk_distribution": phase_risk_distribution,
        "attack_progression": attack_progression,
        "attack_journey": attack_journey,
        "attack_path": attack_path,
        "cve_matches": cve_matches,
        "timeline": timeline,
        "iocs": iocs,
        "findings": findings,
        "recommendations": recommendations,
        "uncertainty_and_gaps": uncertainty_and_gaps,
        "guardrail_warnings": guardrail_warnings,
    }

