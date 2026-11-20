"""Backend request limits and lossless log batch splitting.

The backend's ``LogAnalysisRequest.logs`` field has ``max_length=50000``
(``server/model/logs_model.py``).  Phase 6 avoided HTTP 422 by chopping the
tail of the collected text, which silently discarded earlier events.  Phase 7
splits the text into consecutive batches instead: every character collected is
sent, in order, and each request stays inside the limit.

The limit applies to the ``logs`` string only; JSON envelope overhead does not
count towards it.  Batches are therefore measured in Unicode characters, which
is what Pydantic's ``max_length`` enforces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# LogAnalysisRequest.logs: Field(..., max_length=50000)
MAX_LOG_CHARS = 50_000
# LogAnalysisRequest.max_results: Field(default=5, ge=1, le=20)
MIN_MAX_RESULTS = 1
MAX_MAX_RESULTS = 20

# Security-relevant keywords that must never be dropped by the noise filter.
_SECURITY_SIGNAL_RE = re.compile(
    r"(?:fail|error|crit|alert|emerg|warn|denied|invalid|refused|sudo|\bsu:|ssh|"
    r"accepted|auth|shadow|passwd|unauthorized|forbidden|attack|malware|"
    r"iptables|ufw|audit|segfault|killed|oom|exploit|brute|injection|payload|"
    r"reverse.?shell|nmap|curl|wget|chmod|chown|crontab|useradd|usermod|groupadd)",
    re.IGNORECASE,
)

# Routine OS/daemon chatter that adds high token volume with low security value.
_BENIGN_NOISE_RE = re.compile(
    r"(?:"
    r"systemd(?:\[\d+\])?: (?:Started |Starting |Finished |Stopped |Deactivated successfully|"
    r"Created slice|Removed slice|Reached target|Consumed |Listening on|Closed )"
    r"|CRON\[\d+\]: pam_unix\(cron:session\): session (?:opened|closed)"
    r"|systemd-logind\[\d+\]: (?:New session|Session \d+ logged out|Removed session)"
    r"|rtkit-daemon\[\d+\]: Successfully (?:made thread|demoted)"
    r"|dbus-daemon\[\d+\]: \[system\] Successfully activated service"
    r"|(?:\[DEBUG\]|\bDEBUG\b|\blevel=debug\b)"
    r")",
    re.IGNORECASE,
)


def filter_log_noise(text: str) -> tuple[str, int]:
    """Drop routine benign chatter and exact duplicate lines before batching.

    Lines containing security-relevant keywords are never dropped by the
    benign-chatter filter. If filtering would empty a non-empty input, falls
    back to keeping deduplicated non-empty lines so valid cycles are never
    silently discarded.

    Returns ``(filtered_text, dropped_line_count)``.
    """
    if not text or not text.strip():
        return text, 0

    lines = text.splitlines()
    deduped: list[str] = []
    filtered: list[str] = []
    seen: set[str] = set()
    dropped = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            dropped += 1
            continue
        if stripped in seen:
            dropped += 1
            continue
        seen.add(stripped)
        deduped.append(line)

        if _BENIGN_NOISE_RE.search(stripped) and not _SECURITY_SIGNAL_RE.search(stripped):
            dropped += 1
            continue
        filtered.append(line)

    if not filtered:
        # Never turn a non-empty log batch into an empty one.
        fallback_dropped = len(lines) - len(deduped)
        return "\n".join(deduped), fallback_dropped

    return "\n".join(filtered), dropped

# Retained for callers that still need the old helper.  The monitoring loop no
# longer uses it: silently dropping data is exactly what Phase 7 removes.
TRUNCATION_PREFIX = "[client truncated {dropped} chars to backend 50000 limit]\n"


def fit_logs_to_backend(text: str) -> tuple[str, int]:
    """Return ``(payload, dropped_chars)`` no longer than the backend limit.

    Deprecated: use :func:`split_logs_lossless` for delivery.  Kept for the
    one-shot CLI path, where the caller explicitly chooses a tail.
    """
    if len(text) <= MAX_LOG_CHARS:
        return text, 0
    prefix_room = 80
    keep = MAX_LOG_CHARS - prefix_room
    dropped = len(text) - keep
    prefix = TRUNCATION_PREFIX.format(dropped=dropped)
    payload = prefix + text[-keep:]
    if len(payload) > MAX_LOG_CHARS:
        payload = payload[-MAX_LOG_CHARS:]
    return payload, dropped


@dataclass(frozen=True)
class BatchSplit:
    """Lossless split of collected log text into backend-sized requests."""

    batches: tuple[str, ...]
    total_chars: int
    hard_splits: int = 0
    whitespace_fragments: int = 0

    @property
    def count(self) -> int:
        return len(self.batches)

    @property
    def oversized(self) -> int:
        """Batches that had to be cut inside an event (no newline boundary)."""
        return self.hard_splits


def split_logs_lossless(text: str, limit: int = MAX_LOG_CHARS) -> BatchSplit:
    """Split *text* into ordered chunks of at most *limit* characters.

    * Every non-whitespace character is preserved exactly once, in order.
    * Cuts prefer a newline inside the window so events stay whole.
    * A single event longer than *limit* is cut at the limit (``hard_splits``)
      rather than dropped; the remainder continues in the next batch.
    * Whitespace-only fragments (possible only for pathological input) are the
      one thing not sent, because the backend rejects an empty analysis; they
      are counted, never silently hidden.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    if not text or not text.strip():
        return BatchSplit(batches=(), total_chars=len(text or ""))

    batches: list[str] = []
    hard_splits = 0
    whitespace_fragments = 0
    remaining = text

    while remaining:
        if len(remaining) <= limit:
            chunk, remaining = remaining, ""
        else:
            window = remaining[:limit]
            cut = window.rfind("\n")
            # Only honour a boundary in the second half; otherwise a very early
            # newline would produce tiny batches.
            if cut >= limit // 2:
                chunk, remaining = remaining[:cut], remaining[cut:]
            else:
                chunk, remaining = window, remaining[limit:]
                hard_splits += 1
        if chunk.strip():
            batches.append(chunk)
        else:
            whitespace_fragments += 1

    return BatchSplit(
        batches=tuple(batches),
        total_chars=len(text),
        hard_splits=hard_splits,
        whitespace_fragments=whitespace_fragments,
    )
