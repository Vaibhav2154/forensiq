"""KCP log normalizer converting BatchIngestRequest into NormalizedEvent records."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from contracts import BatchIngestRequest, NormalizedEvent, RawLogRecord


_SSH_FAIL_RE = re.compile(
    r"Failed\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?(?P<account>[A-Za-z0-9._@-]+)\s+from\s+(?P<remote_ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)
_SSH_ACCEPT_RE = re.compile(
    r"Accepted\s+(?:password|publickey)\s+for\s+(?P<account>[A-Za-z0-9._@-]+)\s+from\s+(?P<remote_ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)
_SUDO_RE = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?P<account>[A-Za-z0-9._-]+)\s*:.*COMMAND=(?P<command>.+)",
    re.IGNORECASE,
)
_KV_USER_RE = re.compile(r"\buser(?:name)?=([A-Za-z0-9._@-]+)", re.IGNORECASE)
_KV_STATUS_RE = re.compile(r"\bstatus=([A-Za-z0-9_-]+)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LEVEL_RE = re.compile(r"\b(CRITICAL|ALERT|ERROR|WARNING|WARN|INFO|DEBUG)\b", re.IGNORECASE)
_RAW_ID_RE = re.compile(r"^raw[-_]?(.+)$", re.IGNORECASE)


def _derive_event_id(batch_id: str, record_id: str) -> str:
    match = _RAW_ID_RE.match(record_id.strip())
    if match:
        return f"evt-{match.group(1)}"
    digest = hashlib.sha256(f"{batch_id}:{record_id}".encode("utf-8")).hexdigest()[:12]
    return f"evt-{digest}"


def _extract_host(raw: RawLogRecord, batch_source: str) -> str | None:
    for key in ("host", "hostname", "node"):
        val = raw.metadata.get(key)
        if val:
            return str(val).strip()
    if ":" in batch_source:
        candidate = batch_source.split(":", 1)[1].strip()
        if candidate:
            return candidate
    return None


def _build_scope_key(
    host: str | None,
    account: str | None,
    process: str | None,
    batch_source: str,
) -> str:
    parts: list[str] = []
    if host:
        parts.append(f"host:{host}")
    if account:
        parts.append(f"account:{account}")
    if process and not account:
        parts.append(f"process:{process}")
    if not parts:
        parts.append(f"source:{batch_source}")
    return "|".join(parts)


def normalize_log_record(
    raw: RawLogRecord,
    batch_source: str,
    batch_id: str = "",
) -> NormalizedEvent:
    """Normalize a single RawLogRecord into a traceable NormalizedEvent."""
    msg = raw.message.strip()
    host = _extract_host(raw, batch_source)
    account: str | None = (
        str(raw.metadata["account"]).strip()
        if raw.metadata.get("account")
        else str(raw.metadata["user"]).strip()
        if raw.metadata.get("user")
        else None
    )
    process: str | None = (
        str(raw.metadata["process"]).strip() if raw.metadata.get("process") else None
    )

    features: dict[str, Any] = {}
    if host:
        features["host"] = host

    event_type = "system_log_event"

    if m := _SSH_FAIL_RE.search(msg):
        event_type = "authentication_failure"
        account = account or m.group("account")
        features["account"] = account
        features["outcome"] = "failure"
        features["remote_ip"] = m.group("remote_ip")
        if m.group("port"):
            features["remote_port"] = int(m.group("port"))
    elif m := _SSH_ACCEPT_RE.search(msg):
        event_type = "authentication_success"
        account = account or m.group("account")
        features["account"] = account
        features["outcome"] = "success"
        features["remote_ip"] = m.group("remote_ip")
        if m.group("port"):
            features["remote_port"] = int(m.group("port"))
    elif m := _SUDO_RE.search(msg):
        event_type = "privilege_escalation"
        account = account or m.group("account")
        process = process or "sudo"
        features["account"] = account
        features["process"] = process
        features["command"] = m.group("command").strip()
        features["outcome"] = "executed"
    else:
        lower = msg.lower()
        kv_user = _KV_USER_RE.search(msg)
        if kv_user and not account:
            account = kv_user.group(1)
        if account:
            features["account"] = account

        kv_status = _KV_STATUS_RE.search(msg)
        if kv_status:
            features["outcome"] = kv_status.group(1).lower()

        if "failed login" in lower or "failed password" in lower or "authentication fail" in lower:
            event_type = "authentication_failure"
            features.setdefault("outcome", "failure")
        elif "user authentication" in lower and features.get("outcome") == "success":
            event_type = "authentication_success"
        elif "security alert" in lower or "unusual access" in lower:
            event_type = "security_alert"
        elif "connection timeout" in lower or "failed to connect" in lower:
            event_type = "network_connection_error"
        elif level_match := _LEVEL_RE.search(msg):
            sev = level_match.group(1).upper()
            features["severity"] = sev
            if sev in ("ERROR", "CRITICAL", "ALERT"):
                event_type = "application_error"
            elif sev in ("WARNING", "WARN"):
                event_type = "application_warning"

        ip_match = _IP_RE.search(msg)
        if ip_match:
            features.setdefault("remote_ip", ip_match.group(0))

    if process:
        features.setdefault("process", process)

    for extra_key in ("service", "protocol", "action"):
        if extra_key in raw.metadata and extra_key not in features:
            features[extra_key] = raw.metadata[extra_key]

    scope_key = _build_scope_key(
        host=host,
        account=account,
        process=process,
        batch_source=batch_source,
    )

    return NormalizedEvent(
        event_id=_derive_event_id(batch_id=batch_id, record_id=raw.record_id),
        scope_key=scope_key,
        event_time=raw.observed_at,
        event_type=event_type,
        source=raw.source_type,
        features=features,
        evidence_ref=raw.evidence_ref,
    )


def normalize_batch(batch: BatchIngestRequest) -> list[NormalizedEvent]:
    """Transform all raw records in a BatchIngestRequest into NormalizedEvents."""
    return [
        normalize_log_record(raw=record, batch_source=batch.source, batch_id=batch.batch_id)
        for record in batch.records
    ]

