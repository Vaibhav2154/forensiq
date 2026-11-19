"""High-level InvestigationService facade and LSTM SequenceCueProvider protocol."""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable

from contracts import (
    BatchIngestRequest,
    EvidenceReference,
    InvestigationInput,
    KnowledgeRecord,
    NormalizedEvent,
    RawLogRecord,
    SequenceCue,
)
from services.investigation.config import InvestigationSettings
from services.investigation.graph import build_investigation_graph
from services.investigation.llm_factory import GeminiAgentFactory, StructuredRunner
from services.investigation.models import InvestigationResult
from services.knowledge import KnowledgeSearchQuery, KnowledgeService


logger = logging.getLogger(__name__)

_IST_TZ = timezone(timedelta(hours=5, minutes=30))

# Common timestamp + optional timezone + optional syslog host patterns
_TS_WITH_TZ_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:\s+(?P<tz>IST|UTC|Z|[+-]\d{2}:?\d{2}))?\s+(?P<rest>.*)$",
    re.IGNORECASE,
)
_SYSLOG_HOST_PROC_RE = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{0,62})\s+(?P<proc>[A-Za-z0-9._-]+)(?:\[\d+\])?:",
)
_MONTH_SYSLOG_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{0,62})\s+"
    r"(?P<proc>[A-Za-z0-9._-]+)(?:\[\d+\])?:",
)


def _parse_line_timestamp_and_host(line: str, fallback_now: datetime) -> tuple[datetime, str | None, str | None]:
    """Best-effort extraction of timestamp, host, and process name from a raw log line."""
    stripped = line.strip()
    observed_at = fallback_now
    host: str | None = None
    process: str | None = None

    m = _TS_WITH_TZ_RE.match(stripped)
    if m:
        ts_str = m.group("ts").replace(" ", "T")
        tz_token = (m.group("tz") or "").upper()
        try:
            dt = datetime.fromisoformat(ts_str)
            if tz_token == "IST":
                observed_at = dt.replace(tzinfo=_IST_TZ).astimezone(timezone.utc)
            elif tz_token in ("", "UTC", "Z"):
                observed_at = dt.replace(tzinfo=timezone.utc)
            else:
                norm_tz = tz_token if ":" in tz_token else f"{tz_token[:3]}:{tz_token[3:]}"
                observed_at = datetime.fromisoformat(f"{ts_str}{norm_tz}").astimezone(timezone.utc)
        except ValueError:
            observed_at = fallback_now

        rest = m.group("rest").strip()
        hm = _SYSLOG_HOST_PROC_RE.match(rest)
        if hm:
            host = hm.group("host")
            process = hm.group("proc")
        return observed_at, host, process

    sm = _MONTH_SYSLOG_RE.match(stripped)
    if sm:
        try:
            parsed = datetime.strptime(
                f"{fallback_now.year} {sm.group('mon')} {sm.group('day')} {sm.group('time')}",
                "%Y %b %d %H:%M:%S",
            )
            observed_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            observed_at = fallback_now
        host = sm.group("host")
        process = sm.group("proc")
        return observed_at, host, process

    hm = _SYSLOG_HOST_PROC_RE.match(stripped)
    if hm:
        host = hm.group("host")
        process = hm.group("proc")
    return observed_at, host, process


def build_batch_from_raw_logs(
    raw_logs: str,
    username: str,
) -> tuple[BatchIngestRequest, dict[str, str]]:
    """Wrap raw log text into a traceable BatchIngestRequest plus evidence_ref -> raw line map."""
    now = datetime.now(timezone.utc)
    batch_id = f"batch-{uuid.uuid4().hex[:12]}"
    raw_lines = [line for line in raw_logs.splitlines() if line.strip()]
    if not raw_lines:
        raw_lines = [raw_logs.strip() or "(empty)"]

    records: list[RawLogRecord] = []
    excerpts: dict[str, str] = {}
    for idx, line in enumerate(raw_lines, start=1):
        observed_at, host, process = _parse_line_timestamp_and_host(line, now)
        line_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        ref_id = f"ev-{batch_id}-{idx:04d}"
        metadata: dict[str, Any] = {"submitted_by": username}
        if host:
            metadata["host"] = host
        if process:
            metadata["process"] = process
        excerpts[ref_id] = line
        records.append(
            RawLogRecord(
                record_id=f"raw-{batch_id}-{idx:04d}",
                observed_at=observed_at,
                message=line,
                source_type="api-analyze",
                evidence_ref=EvidenceReference(
                    reference_id=ref_id,
                    uri=f"api://analyze/{username}/{batch_id}",
                    line_start=idx,
                    line_end=idx,
                    sha256=line_hash,
                ),
                metadata=metadata,
            )
        )

    batch = BatchIngestRequest(
        batch_id=batch_id,
        source=f"api:{username}",
        records=records,
        sent_at=now,
    )
    return batch, excerpts


@runtime_checkable
class SequenceCueProvider(Protocol):
    """Future hook protocol for connecting Developer 2's LSTM sequential context service."""

    async def get_cues(self, events: list[NormalizedEvent]) -> list[SequenceCue]:
        """Score normalized events and return any cross-batch SequenceCues."""
        ...


class InvestigationService:
    """Facade coordinating KCP inputs, Cognee/OKF retrieval, and the LangGraph orchestrator."""

    def __init__(
        self,
        knowledge_service: KnowledgeService | None = None,
        settings: InvestigationSettings | None = None,
        llm_factory: GeminiAgentFactory | None = None,
        custom_runner: StructuredRunner | None = None,
        sequence_provider: SequenceCueProvider | None = None,
    ) -> None:
        self.settings = settings or InvestigationSettings()
        self.knowledge_service = knowledge_service
        self.sequence_provider = sequence_provider
        self.llm_factory = llm_factory or GeminiAgentFactory(
            settings=self.settings,
            custom_runner=custom_runner,
        )
        self._graph = build_investigation_graph(
            llm_factory=self.llm_factory,
            knowledge_service=self.knowledge_service,
            max_refinement_rounds=self.settings.max_refinement_rounds,
        )

    def set_sequence_provider(self, provider: SequenceCueProvider | None) -> None:
        """Attach or detach the future LSTM SequenceCueProvider without rebuilding the graph."""
        self.sequence_provider = provider

    def get_sanitized_config(self) -> dict[str, Any]:
        """Return safe diagnostic configuration (no secret keys)."""
        return self.settings.sanitized_summary(lstm_connected=self.sequence_provider is not None)

    async def run_investigation(
        self,
        investigation_input: InvestigationInput,
        raw_log_excerpts: dict[str, str] | None = None,
        initial_scores: dict[str, float] | None = None,
    ) -> InvestigationResult:
        """Execute the LangGraph multi-agent workflow on a validated ``InvestigationInput``."""
        initial_state: dict[str, Any] = {
            "investigation_input": investigation_input,
            "raw_log_excerpts": dict(raw_log_excerpts or {}),
            "knowledge_scores": dict(initial_scores or {}),
            "extra_knowledge_records": [],
            "audit_trail": [],
            "guardrail_warnings": [],
        }
        final_state = await self._graph.ainvoke(initial_state)
        result = final_state.get("final_result")
        if not isinstance(result, InvestigationResult):
            raise RuntimeError("LangGraph workflow completed without producing an InvestigationResult.")
        return result

    async def investigate_batch(
        self,
        batch: BatchIngestRequest,
        sequence_cues: list[SequenceCue] | None = None,
        top_k_knowledge: int | None = None,
        raw_log_excerpts: dict[str, str] | None = None,
    ) -> InvestigationResult:
        """Run KCP normalization, initial OKF/Cognee retrieval, optional LSTM hook, and LangGraph."""
        if self.knowledge_service is None:
            raise RuntimeError(
                "KnowledgeService is required for investigate_batch(). "
                "Use run_investigation() directly when providing InvestigationInput."
            )

        top_k = top_k_knowledge or self.settings.top_k_knowledge
        normalized_events = self.knowledge_service.normalize_batch(batch)

        # Resolve LSTM sequence cues if explicitly provided or if SequenceCueProvider is connected
        resolved_cues = list(sequence_cues or [])
        if not resolved_cues and self.sequence_provider is not None:
            try:
                resolved_cues = await self.sequence_provider.get_cues(normalized_events)
            except Exception as exc:
                logger.warning("SequenceCueProvider failed (continuing without cues): %s", exc)

        # Build concise initial retrieval query from KCP-normalized events
        query_terms: list[str] = []
        seen_terms: set[str] = set()
        for evt in normalized_events:
            candidates = [evt.event_type.replace("_", " ")]
            for key in ("process", "command", "outcome", "severity", "service"):
                val = evt.features.get(key)
                if val:
                    candidates.append(str(val))
            for term in candidates:
                cleaned = term.strip()
                if cleaned and cleaned.lower() not in seen_terms:
                    seen_terms.add(cleaned.lower())
                    query_terms.append(cleaned)

        initial_records: list[KnowledgeRecord] = []
        initial_scores: dict[str, float] = {}
        seen_record_ids: set[str] = set()
        if query_terms and top_k > 0:
            search_text = " ".join(query_terms[:18])
            # Retrieve top-k from both MITRE ATT&CK techniques and CVEs explicitly
            mitre_resp = await self.knowledge_service.search(
                KnowledgeSearchQuery(
                    query=search_text,
                    source_type="mitre_attack",
                    kind="attack-pattern",
                    top_k=top_k,
                    search_mode="auto",
                )
            )
            cve_resp = await self.knowledge_service.search(
                KnowledgeSearchQuery(
                    query=search_text,
                    source_type="cve",
                    top_k=top_k,
                    search_mode="auto",
                )
            )
            for hit in (*mitre_resp.hits, *cve_resp.hits):
                if hit.record.record_id not in seen_record_ids:
                    seen_record_ids.add(hit.record.record_id)
                    initial_records.append(hit.record)
                src_key = hit.record.source_id.upper()
                initial_scores[src_key] = max(
                    initial_scores.get(src_key, 0.0),
                    round(max(0.0, min(1.0, float(hit.score))), 4),
                )

        # Map raw log lines if not provided explicitly
        excerpts = dict(raw_log_excerpts or {})
        if not excerpts:
            for raw in batch.records:
                excerpts[raw.evidence_ref.reference_id] = raw.message

        inv_input = InvestigationInput(
            investigation_id=f"inv-{uuid.uuid4().hex[:12]}",
            normalized_events=normalized_events,
            knowledge_records=initial_records,
            sequence_cues=resolved_cues,
            created_at=datetime.now(timezone.utc),
        )
        return await self.run_investigation(
            investigation_input=inv_input,
            raw_log_excerpts=excerpts,
            initial_scores=initial_scores,
        )

    async def investigate_raw_logs(
        self,
        raw_logs: str,
        username: str = "anonymous",
        max_results: int = 5,
        sequence_cues: list[SequenceCue] | None = None,
    ) -> InvestigationResult:
        """Convenience entry point for raw text logs (used by POST /api/v1/analyze)."""
        batch, excerpts = build_batch_from_raw_logs(raw_logs=raw_logs, username=username)
        return await self.investigate_batch(
            batch=batch,
            sequence_cues=sequence_cues,
            top_k_knowledge=max(max_results, self.settings.top_k_knowledge),
            raw_log_excerpts=excerpts,
        )
