"""Backend request limits the client must respect.

These mirror ``server/model/logs_model.py``.  They live in one module so the
CLI's one-shot analysis and the monitoring loop cannot drift apart.
"""

from __future__ import annotations

# LogAnalysisRequest.logs: Field(..., max_length=50000)
MAX_LOG_CHARS = 50_000
# LogAnalysisRequest.max_results: Field(default=5, ge=1, le=20)
MIN_MAX_RESULTS = 1
MAX_MAX_RESULTS = 20

# Marker kept short so truncation never itself overflows the backend limit.
TRUNCATION_PREFIX = "[client truncated {dropped} chars to backend 50000 limit]\n"


def fit_logs_to_backend(text: str) -> tuple[str, int]:
    """Return ``(payload, dropped_chars)`` no longer than the backend limit.

    The *tail* is kept because collected logs are chronological: the newest
    events are the ones an analyst needs.  Anything dropped is announced in the
    payload rather than silently removed.
    """
    if len(text) <= MAX_LOG_CHARS:
        return text, 0
    prefix_room = 80
    keep = MAX_LOG_CHARS - prefix_room
    dropped = len(text) - keep
    prefix = TRUNCATION_PREFIX.format(dropped=dropped)
    payload = prefix + text[-keep:]
    # Defensive: guarantee the invariant even if the marker grows.
    if len(payload) > MAX_LOG_CHARS:
        payload = payload[-MAX_LOG_CHARS:]
    return payload, dropped
