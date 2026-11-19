"""Repeatable CLI for MITRE ATT&CK / CVE KCP ingestion and Cognee retrieval."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from services.knowledge.config import KnowledgeSettings, SERVER_ROOT
from services.knowledge.models import KnowledgeSearchQuery
from services.knowledge.service import KnowledgeService


SAMPLE_FIXTURES_DIR = SERVER_ROOT / "tests" / "fixtures" / "knowledge"


def _build_service(data_dir: str | None, backend: str = "cognee") -> KnowledgeService:
    kwargs: dict[str, Any] = {"store_backend": backend}
    if data_dir:
        kwargs["data_dir"] = Path(data_dir)
    settings = KnowledgeSettings(**kwargs)
    return KnowledgeService(settings=settings)


async def _run_ingest_sample(args: argparse.Namespace) -> int:
    service = _build_service(args.data_dir, args.backend)
    mitre_sample = SAMPLE_FIXTURES_DIR / "mitre_sample_bundle.json"
    cve_sample = SAMPLE_FIXTURES_DIR / "cve_sample"
    try:
        await service.initialize()
        mitre_run = await service.ingest_mitre(path=mitre_sample)
        cve_run = await service.ingest_cve(path=cve_sample)

        t1110 = await service.get_by_source(
            "mitre_attack", "T1110", include_related=True
        )
        cve_39447 = await service.get_by_source(
            "cve", "CVE-2025-39447", include_related=True
        )
        mitre_search = await service.search(
            KnowledgeSearchQuery(
                query="password guessing brute force",
                source_type="mitre_attack",
                top_k=3,
            )
        )
        cve_search = await service.search(
            KnowledgeSearchQuery(
                query="WordPress Elementor broken access control",
                source_type="cve",
                top_k=3,
            )
        )

        payload = {
            "mitre_run": mitre_run.model_dump(mode="json"),
            "cve_run": cve_run.model_dump(mode="json"),
            "verified_t1110": t1110.model_dump(mode="json") if t1110 else None,
            "verified_cve_2025_39447": (
                cve_39447.model_dump(mode="json") if cve_39447 else None
            ),
            "sample_mitre_search": mitre_search.model_dump(mode="json"),
            "sample_cve_search": cve_search.model_dump(mode="json"),
        }
        print(json.dumps(payload, indent=2))
        if t1110 is None or cve_39447 is None:
            return 1
        return 0
    finally:
        await service.close()


async def _run_ingest_mitre(args: argparse.Namespace) -> int:
    service = _build_service(args.data_dir, args.backend)
    try:
        entity_types = set(args.entity_types) if args.entity_types else None
        run = await service.ingest_mitre(
            path=Path(args.path) if args.path else None,
            entity_types=entity_types,
            include_deprecated=args.include_deprecated,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        print(run.model_dump_json(indent=2))
        return 0 if run.status != "failed" else 1
    finally:
        await service.close()


async def _run_ingest_cve(args: argparse.Namespace) -> int:
    service = _build_service(args.data_dir, args.backend)
    try:
        run = await service.ingest_cve(
            path=Path(args.path) if args.path else None,
            years=args.years,
            cve_ids=args.cve_ids,
            delta_file=Path(args.delta) if args.delta else None,
            include_rejected=args.include_rejected,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        print(run.model_dump_json(indent=2))
        return 0 if run.status != "failed" else 1
    finally:
        await service.close()


async def _run_search(args: argparse.Namespace) -> int:
    service = _build_service(args.data_dir, args.backend)
    try:
        await service.initialize()
        res = await service.search(
            KnowledgeSearchQuery(
                query=args.query,
                source_type=args.source_type,
                kind=args.kind,
                tactic=args.tactic,
                platform=args.platform,
                min_cvss=args.min_cvss,
                top_k=args.top_k,
                search_mode=args.mode,
            )
        )
        print(res.model_dump_json(indent=2))
        return 0
    finally:
        await service.close()


async def _run_get(args: argparse.Namespace) -> int:
    service = _build_service(args.data_dir, args.backend)
    try:
        await service.initialize()
        detail = await service.get_by_source(
            args.source_type, args.source_id, include_related=args.related
        )
        if detail is None:
            print(
                json.dumps(
                    {"error": f"{args.source_type}/{args.source_id} not found"}
                ),
                file=sys.stderr,
            )
            return 1
        print(detail.model_dump_json(indent=2))
        return 0
    finally:
        await service.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensiq-knowledge",
        description="ForensIQ KCP -> OKF -> Cognee CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--data-dir", help="Override KNOWLEDGE_DATA_DIR")
        p.add_argument(
            "--backend",
            choices=["cognee", "memory"],
            default="cognee",
            help="Storage backend",
        )

    p_sample = sub.add_parser(
        "ingest-sample",
        help="Load curated MITRE + CVE samples into Cognee and verify retrieval",
    )
    _add_common(p_sample)

    p_mitre = sub.add_parser("ingest-mitre", help="Ingest MITRE ATT&CK STIX JSON")
    _add_common(p_mitre)
    p_mitre.add_argument("--path", help="Path to MITRE STIX JSON bundle")
    p_mitre.add_argument("--entity-types", nargs="+", help="STIX types to include")
    p_mitre.add_argument("--include-deprecated", action="store_true")
    p_mitre.add_argument("--limit", type=int)
    p_mitre.add_argument("--dry-run", action="store_true")

    p_cve = sub.add_parser("ingest-cve", help="Ingest CVE List v5 JSON records")
    _add_common(p_cve)
    p_cve.add_argument("--path", help="Path to CVE root dir or JSON file")
    p_cve.add_argument("--years", nargs="+", type=int, help="Years to ingest")
    p_cve.add_argument("--cve-ids", nargs="+", help="Explicit CVE IDs to ingest")
    p_cve.add_argument("--delta", help="Path to CVE delta.json")
    p_cve.add_argument("--include-rejected", action="store_true")
    p_cve.add_argument("--limit", type=int)
    p_cve.add_argument("--dry-run", action="store_true")

    p_search = sub.add_parser("search", help="Search ingested OKF knowledge")
    _add_common(p_search)
    p_search.add_argument("query", help="Search query text")
    p_search.add_argument("--source-type", choices=["mitre_attack", "cve"])
    p_search.add_argument("--kind")
    p_search.add_argument("--tactic")
    p_search.add_argument("--platform")
    p_search.add_argument("--min-cvss", type=float)
    p_search.add_argument("--top-k", type=int, default=5)
    p_search.add_argument(
        "--mode",
        choices=["auto", "semantic", "lexical", "graph"],
        default="auto",
    )

    p_get = sub.add_parser("get", help="Fetch a single OKF record with provenance")
    _add_common(p_get)
    p_get.add_argument("source_type", choices=["mitre_attack", "cve"])
    p_get.add_argument("source_id", help="e.g. T1110 or CVE-2025-39447")
    p_get.add_argument("--related", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "ingest-sample": _run_ingest_sample,
        "ingest-mitre": _run_ingest_mitre,
        "ingest-cve": _run_ingest_cve,
        "search": _run_search,
        "get": _run_get,
    }
    return asyncio.run(dispatch[args.command](args))


if __name__ == "__main__":
    raise SystemExit(main())
