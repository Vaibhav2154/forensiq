"""MITRE Enterprise ATT&CK STIX 2.1 bundle parser."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from contracts import KnowledgeRelationship
from services.knowledge.models import ParsedKnowledgeItem


SUPPORTED_MITRE_TYPES: set[str] = {
    "attack-pattern",
    "x-mitre-tactic",
    "course-of-action",
    "malware",
    "tool",
    "intrusion-set",
    "campaign",
    "x-mitre-data-source",
    "x-mitre-data-component",
}

_RELATIONSHIP_TYPE_MAP: dict[str, str] = {
    "subtechnique-of": "subtechnique_of",
    "attributed-to": "attributed_to",
    "revoked-by": "revoked_by",
    "uses": "uses",
    "mitigates": "mitigates",
    "detects": "detects",
}

_MITRE_URL_PREFIX = {
    "attack-pattern": "https://attack.mitre.org/techniques/",
    "x-mitre-tactic": "https://attack.mitre.org/tactics/",
    "course-of-action": "https://attack.mitre.org/mitigations/",
    "malware": "https://attack.mitre.org/software/",
    "tool": "https://attack.mitre.org/software/",
    "intrusion-set": "https://attack.mitre.org/groups/",
    "campaign": "https://attack.mitre.org/campaigns/",
    "x-mitre-data-source": "https://attack.mitre.org/datasources/",
}

_OMITTED_STIX_FIELDS = (
    "object_marking_refs",
    "created_by_ref",
    "x_mitre_modified_by_ref",
    "x_mitre_contributors",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_canonical(obj: dict[str, Any]) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _extract_mitre_ref(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def _is_inactive(obj: dict[str, Any]) -> bool:
    return bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated"))


def _status_label(obj: dict[str, Any]) -> str:
    if obj.get("revoked"):
        return "revoked"
    if obj.get("x_mitre_deprecated"):
        return "deprecated"
    return "active"


def _default_source_id(obj: dict[str, Any]) -> str:
    stix_id = obj.get("id", "")
    suffix = stix_id.split("--")[-1].replace("-", "")[:8].upper()
    if obj.get("type") == "x-mitre-data-component":
        return f"DC-{suffix}"
    return stix_id


def parse_mitre_stix_file(
    path: Path,
    entity_types: set[str] | None = None,
    include_deprecated: bool = False,
    limit: int | None = None,
) -> tuple[list[ParsedKnowledgeItem], dict[str, Any]]:
    """Parse a MITRE Enterprise ATT&CK STIX 2.1 bundle into intermediate items.

    Active objects are indexed prior to deprecated/revoked objects so legacy
    colliding external IDs (e.g., deprecated T1110 mitigations) never shadow
    active techniques.
    """
    selected_types = entity_types or SUPPORTED_MITRE_TYPES
    unknown = selected_types - SUPPORTED_MITRE_TYPES
    if unknown:
        raise ValueError(f"Unsupported MITRE entity types: {sorted(unknown)}")

    dataset_sha256 = _sha256_file(path)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])

    source_version = "unknown"
    attack_spec_version = ""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            source_version = str(obj.get("x_mitre_version") or "unknown")
            attack_spec_version = str(obj.get("x_mitre_attack_spec_version") or "")
            break

    # Pass 1: Index active objects first, then optionally deprecated/revoked ones.
    stix_id_to_source_id: dict[str, str] = {}
    tactic_shortname_to_id: dict[str, str] = {}
    active_source_ids: set[str] = set()
    candidate_objects: list[tuple[dict[str, Any], str, str | None, str | None]] = []
    filtered_count = 0

    for obj in objects:
        obj_type = obj.get("type")
        if obj_type not in SUPPORTED_MITRE_TYPES:
            continue
        inactive = _is_inactive(obj)
        if inactive:
            if not include_deprecated:
                if obj_type in selected_types:
                    filtered_count += 1
                continue

        ext_id, ext_url = _extract_mitre_ref(obj)
        source_id = ext_id or _default_source_id(obj)
        stix_id = obj.get("id", "")
        if not inactive:
            active_source_ids.add(source_id)
            stix_id_to_source_id[stix_id] = source_id
            if obj_type == "x-mitre-tactic" and obj.get("x_mitre_shortname"):
                tactic_shortname_to_id[obj["x_mitre_shortname"]] = source_id
        else:
            stix_id_to_source_id[stix_id] = source_id

        if obj_type in selected_types:
            candidate_objects.append((obj, source_id, ext_url, stix_id))

    # Pass 2: Build outgoing relationship map keyed by source_ref STIX ID.
    outgoing_rels: dict[str, list[KnowledgeRelationship]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if _is_inactive(obj) and not include_deprecated:
            continue
        src_ref = obj.get("source_ref")
        tgt_ref = obj.get("target_ref")
        rel_type = obj.get("relationship_type", "")
        if not src_ref or not tgt_ref or tgt_ref not in stix_id_to_source_id:
            continue
        mapped_type = _RELATIONSHIP_TYPE_MAP.get(rel_type, rel_type.replace("-", "_"))
        outgoing_rels.setdefault(src_ref, []).append(
            KnowledgeRelationship(
                relationship_type=mapped_type,
                target_source_id=stix_id_to_source_id[tgt_ref],
                source="source",
            )
        )

    # Pass 3: Construct ParsedKnowledgeItem list.
    items: list[ParsedKnowledgeItem] = []
    for obj, source_id, ext_url, stix_id in candidate_objects:
        if limit is not None and len(items) >= limit:
            break

        obj_type = obj["type"]
        inactive = _is_inactive(obj)
        status = _status_label(obj)
        disambiguator: str | None = None
        if inactive and source_id in active_source_ids:
            disambiguator = stix_id.split("--")[-1].replace("-", "")[:8]

        rels: list[KnowledgeRelationship] = list(outgoing_rels.get(stix_id, []))

        # Map kill_chain_phases to TAxxxx tactic IDs when present.
        tactic_shortnames: list[str] = []
        tactic_ids: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            phase_name = phase.get("phase_name", "")
            if not phase_name:
                continue
            tactic_shortnames.append(phase_name)
            tactic_id = tactic_shortname_to_id.get(phase_name)
            if tactic_id:
                tactic_ids.append(tactic_id)
                rels.append(
                    KnowledgeRelationship(
                        relationship_type="uses_tactic",
                        target_source_id=tactic_id,
                        source="source",
                    )
                )

        # Link data components to their parent data source.
        ds_ref = obj.get("x_mitre_data_source_ref")
        if ds_ref and ds_ref in stix_id_to_source_id:
            rels.append(
                KnowledgeRelationship(
                    relationship_type="part_of_data_source",
                    target_source_id=stix_id_to_source_id[ds_ref],
                    source="source",
                )
            )

        references = [
            {
                "source_name": ref.get("source_name", ""),
                "url": ref.get("url", ""),
                "external_id": ref.get("external_id", ""),
            }
            for ref in obj.get("external_references", [])
            if ref.get("url") or ref.get("external_id")
        ]

        default_url = ""
        if obj_type in _MITRE_URL_PREFIX and source_id:
            url_id = source_id.replace(".", "/")
            default_url = f"{_MITRE_URL_PREFIX[obj_type]}{url_id}/"

        omitted = [field for field in _OMITTED_STIX_FIELDS if field in obj]

        fields: dict[str, Any] = {
            "kind": obj_type,
            "name": obj.get("name", ""),
            "status": status,
            "tactics": tactic_shortnames,
            "tactic_ids": tactic_ids,
            "platforms": list(obj.get("x_mitre_platforms", [])),
            "domains": list(obj.get("x_mitre_domains", [])),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "data_sources": list(obj.get("x_mitre_data_sources", [])),
            "detection": obj.get("x_mitre_detection", "") or "",
            "aliases": list(obj.get("aliases") or obj.get("x_mitre_aliases") or []),
            "shortname": obj.get("x_mitre_shortname", ""),
            "collection_layers": list(obj.get("x_mitre_collection_layers", [])),
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
            "object_version": str(obj.get("x_mitre_version") or ""),
            "attack_spec_version": str(
                obj.get("x_mitre_attack_spec_version") or attack_spec_version
            ),
            "source_created": obj.get("created"),
            "source_modified": obj.get("modified"),
            "references": references,
        }
        # Strip empty optional lists/strings so OKF content stays clean and compact.
        fields = {
            k: v
            for k, v in fields.items()
            if v not in (None, "", []) or k in ("kind", "name", "status")
        }

        items.append(
            ParsedKnowledgeItem(
                source_type="mitre_attack",
                source_id=source_id,
                source_version=source_version,
                kind=obj_type,
                name=obj.get("name", ""),
                description=obj.get("description", "") or "",
                status=status,
                disambiguator=disambiguator,
                raw_sha256=_sha256_canonical(obj),
                dataset_sha256=dataset_sha256,
                source_uri=ext_url or default_url,
                source_file=str(path),
                source_object_id=stix_id,
                source_format="stix-2.1",
                fields=fields,
                relationships=rels,
                omitted_fields=omitted,
            )
        )

    metadata = {
        "source_version": source_version,
        "attack_spec_version": attack_spec_version,
        "dataset_sha256": dataset_sha256,
        "filtered_count": filtered_count,
    }
    return items, metadata

