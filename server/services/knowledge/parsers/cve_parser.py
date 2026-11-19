"""Streaming CVE List v5 JSON and delta.json parser."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterator

from contracts import KnowledgeRelationship
from services.knowledge.models import ParsedKnowledgeItem


_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
_CWE_ID_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)
_CAPEC_ID_RE = re.compile(r"(CAPEC-\d+)", re.IGNORECASE)


class CveParseError(ValueError):
    """Raised when a CVE JSON file cannot be parsed or lacks required metadata."""


def resolve_cve_path(root: Path, cve_id: str) -> Path | None:
    """Resolve a CVE JSON file path in O(1) using CVE List v5 bucket layout."""
    match = _CVE_ID_RE.match(cve_id.strip())
    if not match:
        return None
    year, seq = match.group(1), match.group(2)
    bucket = f"{int(seq) // 1000}xxx"
    normalized_id = f"CVE-{year}-{seq}"
    candidate = root / year / bucket / f"{normalized_id}.json"
    if candidate.is_file():
        return candidate
    return None


def iter_cve_files(
    path: Path,
    years: list[int] | None = None,
    cve_ids: list[str] | None = None,
    delta_file: Path | None = None,
) -> Iterator[Path]:
    """Lazily yield CVE JSON file paths without buffering all 428k entries."""
    if path.is_file():
        yield path
        return

    if delta_file is not None:
        delta_data = json.loads(delta_file.read_text(encoding="utf-8"))
        seen: set[str] = set()
        for bucket in ("new", "updated"):
            for entry in delta_data.get(bucket, []):
                cid = str(entry.get("cveId", "")).strip().upper()
                if not cid or cid in seen:
                    continue
                seen.add(cid)
                resolved = resolve_cve_path(path, cid)
                if resolved is not None:
                    yield resolved
        return

    if cve_ids:
        seen = set()
        for raw_id in cve_ids:
            cid = raw_id.strip().upper()
            if not cid or cid in seen:
                continue
            seen.add(cid)
            resolved = resolve_cve_path(path, cid)
            if resolved is not None:
                yield resolved
        return

    if years:
        for year in sorted(set(years)):
            year_dir = path / str(year)
            if year_dir.is_dir():
                yield from sorted(year_dir.rglob("CVE-*.json"))
        return

    for child in sorted(path.iterdir()):
        if child.is_dir() and child.name.isdigit():
            yield from sorted(child.rglob("CVE-*.json"))


def _extract_description(descriptions: list[dict[str, Any]]) -> tuple[str, list[str]]:
    omitted: list[str] = []
    if not descriptions:
        return "", omitted

    chosen = None
    for entry in descriptions:
        lang = str(entry.get("lang", "")).lower()
        if lang.startswith("en"):
            chosen = entry
            break
    if chosen is None:
        chosen = descriptions[0]

    if chosen.get("supportingMedia"):
        omitted.append("supportingMedia")
    if len(descriptions) > 1:
        omitted.append("alternate_language_descriptions")

    return str(chosen.get("value") or ""), omitted


def _extract_metrics(
    cna: dict[str, Any], adp_list: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    containers: list[tuple[str, dict[str, Any]]] = [("cna", cna)]
    for idx, adp in enumerate(adp_list):
        short = (
            adp.get("providerMetadata", {}).get("shortName")
            or adp.get("title")
            or f"adp-{idx}"
        )
        containers.append((f"adp:{short}", adp))

    for source_label, container in containers:
        for metric in container.get("metrics", []):
            for cvss_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if cvss_key in metric and isinstance(metric[cvss_key], dict):
                    payload = dict(metric[cvss_key])
                    payload["metric_key"] = cvss_key
                    payload["source"] = source_label
                    collected.append(payload)
            if "other" in metric and isinstance(metric["other"], dict):
                other = metric["other"]
                collected.append(
                    {
                        "metric_key": "other",
                        "other_type": other.get("type", ""),
                        "content": other.get("content", {}),
                        "source": source_label,
                    }
                )
    return collected


def _extract_problem_types(
    cna: dict[str, Any], adp_list: list[dict[str, Any]]
) -> tuple[list[dict[str, str]], list[str]]:
    items: list[dict[str, str]] = []
    cwe_ids: list[str] = []
    seen_cwes: set[str] = set()

    containers = [cna, *adp_list]
    for container in containers:
        for pt in container.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                raw_cwe = desc.get("cweId") or ""
                text = desc.get("description") or ""
                match = _CWE_ID_RE.search(raw_cwe or text)
                cwe_id = match.group(1).upper() if match else ""
                if cwe_id and cwe_id not in seen_cwes:
                    seen_cwes.add(cwe_id)
                    cwe_ids.append(cwe_id)
                if cwe_id or (text and text.lower() != "n/a"):
                    items.append(
                        {
                            "cwe_id": cwe_id,
                            "description": text,
                            "type": str(desc.get("type") or ""),
                        }
                    )
    return items, cwe_ids


def _extract_impacts(cna: dict[str, Any], adp_list: list[dict[str, Any]]) -> list[str]:
    capec_ids: list[str] = []
    seen: set[str] = set()
    for container in [cna, *adp_list]:
        for imp in container.get("impacts", []):
            raw_capec = str(imp.get("capecId") or "")
            match = _CAPEC_ID_RE.search(raw_capec)
            if match:
                cid = match.group(1).upper()
                if cid not in seen:
                    seen.add(cid)
                    capec_ids.append(cid)
    return capec_ids


def _extract_affected(
    cna: dict[str, Any], adp_list: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    affected: list[dict[str, Any]] = []
    for container in [cna, *adp_list]:
        for entry in container.get("affected", []):
            versions = [
                {
                    k: v
                    for k, v in ver.items()
                    if k
                    in (
                        "version",
                        "status",
                        "lessThan",
                        "lessThanOrEqual",
                        "versionType",
                        "changes",
                    )
                }
                for ver in entry.get("versions", [])
            ]
            affected.append(
                {
                    "vendor": str(entry.get("vendor") or ""),
                    "product": str(entry.get("product") or ""),
                    "package_name": str(entry.get("packageName") or ""),
                    "default_status": str(entry.get("defaultStatus") or ""),
                    "cpes": list(entry.get("cpes", [])),
                    "versions": versions,
                }
            )
    return affected


def _extract_references(
    cna: dict[str, Any], adp_list: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for container in [cna, *adp_list]:
        for ref in container.get("references", []):
            url = str(ref.get("url") or "").strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            refs.append(
                {
                    "url": url,
                    "tags": list(ref.get("tags", [])),
                    "name": str(ref.get("name") or ""),
                }
            )
    return refs


def parse_cve_file(
    path: Path,
    include_rejected: bool = False,
) -> ParsedKnowledgeItem | None:
    """Parse a single CVE List v5 JSON file into an intermediate KCP item.

    Returns ``None`` for REJECTED records unless ``include_rejected=True``.
    Raises ``CveParseError`` on malformed JSON or missing mandatory metadata.
    """
    try:
        raw_bytes = path.read_bytes()
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        data = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CveParseError(f"{path}: invalid CVE JSON ({exc})") from exc

    if data.get("dataType") != "CVE_RECORD":
        raise CveParseError(f"{path}: unexpected dataType {data.get('dataType')!r}")

    meta = data.get("cveMetadata") or {}
    cve_id = str(meta.get("cveId") or "").strip().upper()
    if not _CVE_ID_RE.match(cve_id):
        raise CveParseError(f"{path}: invalid or missing cveId {cve_id!r}")

    state = str(meta.get("state") or "PUBLISHED").upper()
    data_version = str(data.get("dataVersion") or "5.0")
    date_updated = meta.get("dateUpdated") or meta.get("datePublished") or ""
    source_version = f"{data_version}@{date_updated}" if date_updated else data_version
    source_uri = f"https://www.cve.org/CVERecord?id={cve_id}"

    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    adp_list = [a for a in (containers.get("adp") or []) if isinstance(a, dict)]

    if state == "REJECTED":
        if not include_rejected:
            return None
        reasons, _ = _extract_description(cna.get("rejectedReasons", []))
        return ParsedKnowledgeItem(
            source_type="cve",
            source_id=cve_id,
            source_version=source_version,
            kind="cve-record",
            name=cve_id,
            description=reasons or "Rejected CVE record.",
            status="rejected",
            raw_sha256=raw_sha256,
            source_uri=source_uri,
            source_file=str(path),
            source_object_id=cve_id,
            source_format=f"cve-json-{data_version}",
            fields={
                "kind": "cve-record",
                "cve_id": cve_id,
                "state": state,
                "assigner": str(meta.get("assignerShortName") or ""),
                "date_published": meta.get("datePublished"),
                "date_updated": meta.get("dateUpdated"),
                "date_rejected": meta.get("dateRejected"),
            },
            relationships=[],
            omitted_fields=[],
        )

    description, omitted = _extract_description(cna.get("descriptions", []))
    if "x_legacyV4Record" in cna:
        omitted.append("x_legacyV4Record")
    if "x_generator" in cna:
        omitted.append("x_generator")
    if "credits" in cna:
        omitted.append("credits")

    metrics = _extract_metrics(cna, adp_list)
    problem_types, cwe_ids = _extract_problem_types(cna, adp_list)
    capec_ids = _extract_impacts(cna, adp_list)
    affected = _extract_affected(cna, adp_list)
    references = _extract_references(cna, adp_list)

    relationships: list[KnowledgeRelationship] = []
    for cwe_id in cwe_ids:
        relationships.append(
            KnowledgeRelationship(
                relationship_type="has_weakness",
                target_source_id=cwe_id,
                source="source",
            )
        )
    for capec_id in capec_ids:
        relationships.append(
            KnowledgeRelationship(
                relationship_type="has_attack_pattern",
                target_source_id=capec_id,
                source="source",
            )
        )

    title = str(cna.get("title") or cve_id)
    fields: dict[str, Any] = {
        "kind": "cve-record",
        "cve_id": cve_id,
        "title": title,
        "state": state,
        "assigner": str(meta.get("assignerShortName") or ""),
        "date_reserved": meta.get("dateReserved"),
        "date_published": meta.get("datePublished"),
        "date_updated": meta.get("dateUpdated"),
        "affected": affected,
        "cwe_ids": cwe_ids,
        "problem_types": problem_types,
        "capec_ids": capec_ids,
        "all_metrics": metrics,
        "references": references,
    }

    return ParsedKnowledgeItem(
        source_type="cve",
        source_id=cve_id,
        source_version=source_version,
        kind="cve-record",
        name=title,
        description=description,
        status=state.lower(),
        raw_sha256=raw_sha256,
        source_uri=source_uri,
        source_file=str(path),
        source_object_id=cve_id,
        source_format=f"cve-json-{data_version}",
        fields=fields,
        relationships=relationships,
        omitted_fields=omitted,
    )

