"""Normalization utilities for MITRE ATT&CK and CVE knowledge items."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from services.knowledge.models import ParsedKnowledgeItem


_WHITESPACE_RE = re.compile(r"\s+")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_CWE_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)
_CAPEC_RE = re.compile(r"(CAPEC-\d+)", re.IGNORECASE)

_CVSS_PRIORITY: dict[str, tuple[int, str]] = {
    "cvssV4_0": (4, "4.0"),
    "cvssV3_1": (3, "3.1"),
    "cvssV3_0": (2, "3.0"),
    "cvssV2_0": (1, "2.0"),
}

_PLACEHOLDER_NAMES = {"", "n/a", "na", "unknown", "none", "unspecified", "-"}


def normalize_mitre_id(raw_id: str) -> str:
    """Canonicalize MITRE ATT&CK identifiers (e.g., t1110.001 -> T1110.001)."""
    return raw_id.strip().upper()


def normalize_cve_id(raw_id: str) -> str:
    """Canonicalize CVE identifiers (e.g., cve-2025-39447 -> CVE-2025-39447)."""
    return raw_id.strip().upper()


def normalize_cwe_id(raw_id: str) -> str | None:
    """Extract and uppercase a canonical CWE-NNN identifier if present."""
    match = _CWE_RE.search(raw_id or "")
    return match.group(1).upper() if match else None


def normalize_capec_id(raw_id: str) -> str | None:
    """Extract and uppercase a canonical CAPEC-NNN identifier if present."""
    match = _CAPEC_RE.search(raw_id or "")
    return match.group(1).upper() if match else None


def normalize_timestamp(value: str | None) -> str | None:
    """Convert an ISO timestamp string to canonical UTC ISO-8601 ending in Z."""
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return str(value).strip()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def normalize_vendor_product(value: str | None) -> str | None:
    """Normalize a vendor, product, or package identifier safely."""
    if not value:
        return None
    cleaned = _WHITESPACE_RE.sub(" ", str(value).strip()).lower()
    if cleaned in _PLACEHOLDER_NAMES:
        return None
    slug = _NON_ALNUM_RE.sub("_", cleaned).strip("_")
    return slug or None


def normalize_platforms(platforms: list[str]) -> list[str]:
    """Deduplicate and sort platform strings cleanly."""
    seen: set[str] = set()
    normalized: list[str] = []
    for item in platforms:
        clean = _WHITESPACE_RE.sub(" ", str(item).strip())
        if clean and clean.lower() not in seen:
            seen.add(clean.lower())
            normalized.append(clean)
    return sorted(normalized)


def select_primary_cvss(metrics: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Select the highest-precedence CVSS score across CNA and ADP metrics."""
    candidates: list[tuple[tuple[int, int, float], dict[str, Any]]] = []
    for entry in metrics:
        mkey = entry.get("metric_key", "")
        if mkey not in _CVSS_PRIORITY:
            continue
        version_rank, version_label = _CVSS_PRIORITY[mkey]
        raw_score = entry.get("baseScore")
        if raw_score is None:
            continue
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            continue
        is_cna = 1 if entry.get("source") == "cna" else 0
        candidates.append(
            (
                (version_rank, is_cna, score),
                {
                    "version": str(entry.get("version") or version_label),
                    "base_score": score,
                    "base_severity": str(entry.get("baseSeverity") or "").upper() or None,
                    "vector_string": str(entry.get("vectorString") or "") or None,
                    "source": str(entry.get("source") or "cna"),
                },
            )
        )
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    return candidates[0][1]


def _extract_ssvc(metrics: list[dict[str, Any]]) -> dict[str, Any] | None:
    for entry in metrics:
        if entry.get("metric_key") == "other" and str(entry.get("other_type", "")).lower() == "ssvc":
            content = entry.get("content") or {}
            options: dict[str, str] = {}
            for opt in content.get("options", []):
                if isinstance(opt, dict):
                    for k, v in opt.items():
                        options[str(k).lower().replace(" ", "_")] = str(v)
            return {
                "role": content.get("role"),
                "timestamp": normalize_timestamp(content.get("timestamp")),
                "options": options,
            }
    return None


def normalize_item(item: ParsedKnowledgeItem) -> ParsedKnowledgeItem:
    """Normalize identifiers, timestamps, platforms, and CVE metadata in place."""
    fields = dict(item.fields)

    if item.source_type == "mitre_attack":
        source_id = normalize_mitre_id(item.source_id)
        if "platforms" in fields:
            fields["platforms"] = normalize_platforms(fields["platforms"])
        if "tactics" in fields:
            fields["tactics"] = sorted({str(t).strip().lower() for t in fields["tactics"] if str(t).strip()})
        if "tactic_ids" in fields:
            fields["tactic_ids"] = sorted({normalize_mitre_id(str(t)) for t in fields["tactic_ids"] if str(t).strip()})
        for ts_key in ("source_created", "source_modified", "first_seen", "last_seen"):
            if ts_key in fields:
                fields[ts_key] = normalize_timestamp(fields[ts_key])
        return item.model_copy(update={"source_id": source_id, "fields": fields})

    source_id = normalize_cve_id(item.source_id)
    fields["cve_id"] = source_id
    for ts_key in ("date_reserved", "date_published", "date_updated", "date_rejected"):
        if ts_key in fields:
            fields[ts_key] = normalize_timestamp(fields[ts_key])

    normalized_affected: list[dict[str, Any]] = []
    product_keys: list[str] = []
    seen_products: set[str] = set()
    for aff in fields.get("affected", []):
        vendor_raw = str(aff.get("vendor") or "").strip()
        product_raw = str(aff.get("product") or "").strip()
        pkg_raw = str(aff.get("package_name") or "").strip()
        vendor_norm = normalize_vendor_product(vendor_raw)
        product_norm = normalize_vendor_product(product_raw) or normalize_vendor_product(pkg_raw)
        if not vendor_norm and not product_norm and not aff.get("cpes"):
            continue
        entry = dict(aff)
        if vendor_norm:
            entry["vendor_normalized"] = vendor_norm
        if product_norm:
            entry["product_normalized"] = product_norm
        normalized_affected.append(entry)
        if vendor_norm and product_norm:
            key = f"{vendor_norm}:{product_norm}"
        elif product_norm:
            key = product_norm
        else:
            key = ""
        if key and key not in seen_products:
            seen_products.add(key)
            product_keys.append(key)

    fields["affected"] = normalized_affected
    if product_keys:
        fields["affected_products_normalized"] = product_keys

    metrics = fields.get("all_metrics", [])
    severity = select_primary_cvss(metrics)
    if severity:
        fields["severity"] = severity
    ssvc = _extract_ssvc(metrics)
    if ssvc:
        fields["ssvc"] = ssvc

    fields["cwe_ids"] = sorted(
        {c for c in (normalize_cwe_id(x) for x in fields.get("cwe_ids", [])) if c}
    )
    fields["capec_ids"] = sorted(
        {c for c in (normalize_capec_id(x) for x in fields.get("capec_ids", [])) if c}
    )

    from contracts import KnowledgeRelationship

    rels = list(item.relationships)
    existing_targets = {(r.relationship_type, r.target_source_id) for r in rels}
    for key in product_keys:
        if ("affects_product", key) not in existing_targets:
            rels.append(
                KnowledgeRelationship(
                    relationship_type="affects_product",
                    target_source_id=key,
                    source="kcp",
                )
            )
            existing_targets.add(("affects_product", key))

    return item.model_copy(
        update={
            "source_id": source_id,
            "fields": fields,
            "relationships": rels,
        }
    )

