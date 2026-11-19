"""Interactive demo script exercising Log KCP, Knowledge KCP compression, and Cognee retrieval."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from contracts import BatchIngestRequest, EvidenceReference, NormalizedEvent, RawLogRecord
from services.knowledge.config import KnowledgeSettings, SERVER_ROOT
from services.knowledge.kcp import compress_text, normalize_batch
from services.knowledge.models import KnowledgeSearchQuery
from services.knowledge.service import KnowledgeService


FIXTURES_DIR = SERVER_ROOT / "tests" / "fixtures" / "knowledge"
_LEADING_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(.*)$")

DEFAULT_DEMO_LOGS: list[dict[str, Any]] = [
    {
        "record_id": "raw-demo-0001",
        "observed_at": "2026-11-19T09:15:00Z",
        "source_type": "linux-auth",
        "message": "Failed password for alex from 203.0.113.25 port 44120",
        "metadata": {"host": "workstation-17"},
    },
    {
        "record_id": "raw-demo-0002",
        "observed_at": "2026-11-19T09:15:18Z",
        "source_type": "linux-auth",
        "message": "Failed password for alex from 203.0.113.25 port 44124",
        "metadata": {"host": "workstation-17"},
    },
    {
        "record_id": "raw-demo-0003",
        "observed_at": "2026-11-19T09:16:02Z",
        "source_type": "linux-auth",
        "message": "Accepted password for alex from 203.0.113.25 port 44130",
        "metadata": {"host": "workstation-17"},
    },
    {
        "record_id": "raw-demo-0004",
        "observed_at": "2026-11-19T09:16:40Z",
        "source_type": "linux-auth",
        "message": "sudo: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "metadata": {"host": "workstation-17"},
    },
    {
        "record_id": "raw-demo-0005",
        "observed_at": "2026-11-19T09:17:05Z",
        "source_type": "app-security",
        "message": (
            "<p>2026-11-19 09:17:05 ERROR Security alert: Missing Authorization check in "
            "[JetElements For Elementor](https://patchstack.com/database) triggered by "
            "user=web_anon from 198.51.100.42 (Citation: WAF Rule 862)</p>"
        ),
        "metadata": {"host": "web-02"},
    },
]


def _make_raw_record(
    index: int,
    message: str,
    observed_at: datetime,
    source_type: str,
    uri: str,
    metadata: dict[str, Any] | None = None,
    record_id: str | None = None,
) -> RawLogRecord:
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return RawLogRecord(
        record_id=record_id or f"raw-{index:04d}",
        observed_at=observed_at,
        message=message,
        source_type=source_type,
        evidence_ref=EvidenceReference(
            reference_id=f"ev-{index:04d}",
            uri=uri,
            line_start=index,
            line_end=index,
            sha256=digest,
        ),
        metadata=metadata or {},
    )


def _load_log_file_records(log_path: Path) -> list[RawLogRecord]:
    records: list[RawLogRecord] = []
    uri = f"file://{log_path.resolve()}"
    for idx, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        ts = datetime.now(timezone.utc)
        if match := _LEADING_TS_RE.match(stripped):
            parsed_ts = datetime.fromisoformat(match.group(1).replace(" ", "T"))
            ts = parsed_ts.replace(tzinfo=timezone.utc)
        records.append(
            _make_raw_record(
                index=idx,
                message=stripped,
                observed_at=ts,
                source_type="app-security",
                uri=uri,
                metadata={"host": "local-host"},
            )
        )
    return records


def build_demo_batch(
    log_file: Path | None = None,
    include_cli_sample: bool = False,
) -> BatchIngestRequest:
    """Construct a validated BatchIngestRequest from built-in or file demo logs."""
    raw_records: list[RawLogRecord] = []

    if log_file is not None:
        raw_records.extend(_load_log_file_records(log_file))
        source = f"demo-file:{log_file.name}"
    else:
        for idx, item in enumerate(DEFAULT_DEMO_LOGS, start=1):
            ts = datetime.fromisoformat(item["observed_at"].replace("Z", "+00:00"))
            raw_records.append(
                _make_raw_record(
                    index=idx,
                    record_id=item["record_id"],
                    message=item["message"],
                    observed_at=ts,
                    source_type=item["source_type"],
                    uri=f"file:///var/log/demo/{item['source_type']}.log",
                    metadata=item["metadata"],
                )
            )
        source = "cli-agent:demo-cluster"

    if include_cli_sample:
        cli_sample = SERVER_ROOT.parent / "cli_agent" / "test_logs" / "sample_security.log"
        if cli_sample.is_file():
            offset = len(raw_records)
            for idx, rec in enumerate(_load_log_file_records(cli_sample), start=offset + 1):
                rec.record_id = f"raw-cli-{idx:04d}"
                raw_records.append(rec)

    return BatchIngestRequest(
        batch_id="batch-demo-kcp-001",
        source=source,
        records=raw_records,
        sent_at=datetime.now(timezone.utc),
    )


def _derive_queries_from_events(events: list[NormalizedEvent]) -> list[tuple[str, str | None]]:
    queries: list[tuple[str, str | None]] = []
    seen_types: set[str] = set()
    for evt in events:
        if evt.event_type == "authentication_failure" and "auth_fail" not in seen_types:
            seen_types.add("auth_fail")
            queries.append(("password guessing brute force credential access", "mitre_attack"))
        elif evt.event_type == "privilege_escalation" and "priv_esc" not in seen_types:
            seen_types.add("priv_esc")
            queries.append(("unauthorized access privilege escalation", None))
        elif evt.event_type == "security_alert" and "sec_alert" not in seen_types:
            seen_types.add("sec_alert")
            queries.append(("WordPress JetElements Elementor broken access control", "cve"))

    if not queries:
        queries.append(("failed login attempts unusual access", None))
    return queries


def _print_stage_1_logs(batch: BatchIngestRequest) -> list[NormalizedEvent]:
    print("=" * 72)
    print(f"STAGE 1: LOG KCP — Batch {batch.batch_id!r} ({len(batch.records)} raw records)")
    print("=" * 72)

    events = normalize_batch(batch)
    raw_total = 0
    clean_total = 0
    by_scope: dict[str, list[str]] = defaultdict(list)

    for raw, evt in zip(batch.records, events):
        cleaned_msg, c_stats = compress_text(raw.message)
        raw_total += len(raw.message)
        clean_total += len(cleaned_msg)
        by_scope[evt.scope_key].append(evt.event_type)

        print(f"\n[{raw.record_id}] -> {evt.event_id} ({evt.event_type})")
        print(f"  scope_key : {evt.scope_key}")
        print(f"  raw       : {raw.message}")
        if cleaned_msg != raw.message or c_stats["stripped_citations"] or c_stats["stripped_html_tags"]:
            print(
                f"  compressed: {cleaned_msg} "
                f"(html_tags={c_stats['stripped_html_tags']}, citations={c_stats['stripped_citations']})"
            )
        print(f"  features  : {json.dumps(evt.features)}")
        print(
            f"  evidence  : {evt.evidence_ref.reference_id} @ {evt.evidence_ref.uri}"
            f"#L{evt.evidence_ref.line_start} (sha256={evt.evidence_ref.sha256[:12]}...)"
        )

    print("\nScope grouping summary:")
    for scope, etypes in by_scope.items():
        print(f"  - {scope}: {len(etypes)} events -> {etypes}")
    print(
        f"Log text chars: raw={raw_total}, compressed={clean_total}, "
        f"ratio={round(clean_total / raw_total, 4) if raw_total else 1.0}"
    )
    return events


async def _print_stage_2_and_3_knowledge(
    events: list[NormalizedEvent],
    backend: str,
) -> None:
    print("\n" + "=" * 72)
    print(f"STAGE 2: KNOWLEDGE KCP COMPRESSION & OKF INGESTION (backend={backend})")
    print("=" * 72)

    with tempfile.TemporaryDirectory(prefix="forensiq_demo_kcp_") as tmpdir:
        settings = KnowledgeSettings(
            data_dir=Path(tmpdir),
            store_backend=backend,
        )
        service = KnowledgeService(settings=settings)
        try:
            await service.initialize()
            mitre_run = await service.ingest_mitre(
                path=FIXTURES_DIR / "mitre_sample_bundle.json"
            )
            cve_run = await service.ingest_cve(path=FIXTURES_DIR / "cve_sample")

            print(
                f"\nMITRE run {mitre_run.run_id}: parsed={mitre_run.parsed}, "
                f"inserted={mitre_run.inserted}, filtered={mitre_run.rejected_or_filtered}, "
                f"compression={mitre_run.compression_summary}"
            )
            print(
                f"CVE   run {cve_run.run_id}: parsed={cve_run.parsed}, "
                f"inserted={cve_run.inserted}, filtered={cve_run.rejected_or_filtered}, "
                f"failed={cve_run.failed}, compression={cve_run.compression_summary}"
            )

            print("\nSample compressed OKF records:")
            for rec_id in (
                "okf-mitre-t1110",
                "okf-mitre-t1110.001",
                "okf-mitre-m1032",
                "okf-cve-2025-39447",
                "okf-cve-2025-39664",
            ):
                detail = await service.get_record(rec_id, include_related=True)
                if detail is None:
                    continue
                rec = detail.record
                comp = rec.provenance.get("compression", {})
                print(
                    f"  - {rec.record_id} ({rec.source_id} / {rec.source_version}): "
                    f"raw={comp.get('raw_chars')} -> compressed={comp.get('compressed_chars')} "
                    f"(ratio={comp.get('compression_ratio')}, "
                    f"citations_stripped={comp.get('stripped_citations')}, "
                    f"omitted={comp.get('omitted_fields')})"
                )
                print(f"    summary : {rec.content.get('summary', '')}")
                print(
                    f"    related : {[r.source_id for r in detail.related_records]}"
                )

            print("\n" + "=" * 72)
            print("STAGE 3: LOG-DRIVEN KNOWLEDGE RETRIEVAL")
            print("=" * 72)
            for query_text, source_type in _derive_queries_from_events(events):
                res = await service.search(
                    KnowledgeSearchQuery(
                        query=query_text,
                        source_type=source_type,
                        top_k=3,
                    )
                )
                print(f"\nQuery: {query_text!r} (source_type={source_type}) -> {res.total_hits} hits")
                for hit in res.hits:
                    rec = hit.record
                    title = rec.content.get("name") or rec.content.get("title") or rec.source_id
                    print(
                        f"  * {rec.source_id} ({title}) | score={hit.score} | "
                        f"mode={hit.retrieval_mode} | is_evidence_proof={hit.is_evidence_proof}"
                    )
                    print(f"    source_uri : {rec.provenance.get('source_uri')}")
                    print(f"    source_hash: {rec.provenance.get('source_sha256', '')[:16]}...")
        finally:
            await service.close()


async def main_async(args: argparse.Namespace) -> int:
    log_path = Path(args.log_file) if args.log_file else None
    batch = build_demo_batch(
        log_file=log_path,
        include_cli_sample=args.include_cli_sample,
    )
    events = _print_stage_1_logs(batch)
    await _print_stage_2_and_3_knowledge(events=events, backend=args.backend)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="demo_logs_kcp",
        description="Run KCP compression & Cognee retrieval demo on sample security logs.",
    )
    parser.add_argument(
        "--log-file",
        help="Optional path to a plain-text log file to normalize and compress",
    )
    parser.add_argument(
        "--include-cli-sample",
        action="store_true",
        help="Also append cli_agent/test_logs/sample_security.log lines to the demo batch",
    )
    parser.add_argument(
        "--backend",
        choices=["cognee", "memory"],
        default="cognee",
        help="Knowledge store backend (default: cognee)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())

