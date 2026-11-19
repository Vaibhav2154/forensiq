"""Adapter over the migrated legacy log collector.

The Windows Event Log / Linux file / process / network / filesystem collection
code in :mod:`cli_agent.legacy.dynamic_log_extractor` is reused unchanged. This
module only adds validation, per-call error reporting and a result object that
is safe to hand to a UI.

Known limitations inherited from the legacy collector (not fixed here, by
design -- see the Phase 1 report):

* Windows collection performs a single ``ReadEventLog`` pass filtered by
  timestamp; there is no record-number bookmark, so overlapping windows can
  emit duplicates;
* file offsets live in an in-memory dict and are lost on restart;
* there is no inode/rotation tracking for the file sources;
* the legacy per-source ``try/except`` logs failures to a logger, so this
  adapter can only report a source as empty rather than failed.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .errors import ConfigurationError, ForensIQError

DEFAULT_TIME_RANGE_MINUTES = 5
# Byte offsets are the only collector state worth surviving a restart; they live
# next to the session/config files and hold no credentials.
DEFAULT_COLLECTOR_STATE_PATH = Path.home() / ".config" / "forensiq" / "collector_state.json"


@dataclass(frozen=True)
class CollectionResult:
    """The outcome of one collection cycle."""

    entries_by_source: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    formatted_text: str = ""
    time_range_minutes: int = DEFAULT_TIME_RANGE_MINUTES
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def total_entries(self) -> int:
        return sum(len(entries) for entries in self.entries_by_source.values())

    @property
    def is_empty(self) -> bool:
        return self.total_entries == 0


def _default_extractor() -> Any:
    from ..legacy.dynamic_log_extractor import DynamicLogExtractor

    return DynamicLogExtractor()


class CollectorService:
    """Small, testable interface over the legacy collector."""

    def __init__(
        self,
        extractor: Any | None = None,
        *,
        extractor_factory: Callable[[], Any] | None = None,
        state_path: Path | str | None = None,
    ) -> None:
        self._extractor = extractor
        self._factory = extractor_factory or _default_extractor
        # ``None`` disables persistence; the CLI and TUI opt in explicitly.
        self._state_path = Path(state_path).expanduser() if state_path is not None else None
        self._restored = False
        self.rotation_resets: list[str] = []

    @property
    def extractor(self) -> Any:
        if self._extractor is None:
            self._extractor = self._factory()
        return self._extractor

    def available_sources(self) -> list[dict[str, Any]]:
        try:
            sources = self.extractor.get_available_sources()
        except Exception as exc:  # pragma: no cover - defensive
            raise ForensIQError(f"cannot enumerate log sources: {exc}") from exc
        return [dict(source) for source in (sources or [])]

    def source_ids(self) -> list[str]:
        return [str(source.get("id")) for source in self.available_sources()]

    def validate_sources(self, sources: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
        """Return a validated tuple of source ids, rejecting unknown ones."""
        available = self.source_ids()
        if sources is None or len(sources) == 0:
            if not available:
                raise ConfigurationError("no log sources are available on this system")
            return tuple(available)
        invalid = [source for source in sources if source not in available]
        if invalid:
            raise ConfigurationError(
                "unknown log source(s): " + ", ".join(sorted(invalid))
                + "; available: " + (", ".join(available) or "none")
            )
        return tuple(sources)

    def collect(
        self,
        sources: list[str] | tuple[str, ...] | None = None,
        time_range_minutes: int = DEFAULT_TIME_RANGE_MINUTES,
    ) -> CollectionResult:
        selected = self.validate_sources(sources)
        errors: dict[str, str] = {}
        self._restore_offsets()
        self.rotation_resets = self._reset_rotated_offsets()
        try:
            raw = self.extractor.extract_logs(list(selected), time_range_minutes)
        except Exception as exc:
            raise ForensIQError(f"log collection failed: {exc}") from exc
        finally:
            self._persist_offsets()

        entries: dict[str, list[dict[str, Any]]] = {}
        for source_id in selected:
            source_entries = (raw or {}).get(source_id) or []
            entries[source_id] = list(source_entries)
        # Surface sources that the extractor returned but we did not ask for.
        for extra_key in set(raw or {}) - set(entries):
            entries[str(extra_key)] = list((raw or {})[extra_key] or [])

        formatted = ""
        if any(entries.values()):
            formatted = self._format(raw if isinstance(raw, dict) else entries)
        return CollectionResult(
            entries_by_source=entries,
            formatted_text=formatted,
            time_range_minutes=time_range_minutes,
            errors=errors,
        )

    def system_summary(self) -> dict[str, Any]:
        summary = getattr(self.extractor, "get_system_summary", None)
        if callable(summary):
            try:
                return dict(summary())
            except Exception:  # pragma: no cover - defensive
                return {}
        return {}

    # -- restart safety --------------------------------------------------
    def _offsets(self) -> dict[str, int] | None:
        """The legacy extractor's in-memory byte offsets, when it has any."""
        raw = getattr(self.extractor, "last_extraction_time", None)
        return raw if isinstance(raw, dict) else None

    def _restore_offsets(self) -> None:
        """Reload persisted read positions once, so a restart does not replay."""
        if self._restored:
            return
        self._restored = True
        offsets = self._offsets()
        if offsets is None or self._state_path is None:
            return
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for path, position in raw.items():
            if isinstance(path, str) and isinstance(position, int) and position >= 0:
                offsets.setdefault(path, position)

    def _reset_rotated_offsets(self) -> list[str]:
        """Detect truncation/rotation: a stored offset past EOF would stall reads."""
        offsets = self._offsets()
        if offsets is None:
            return []
        resets: list[str] = []
        for path, position in list(offsets.items()):
            if not isinstance(position, int) or position <= 0:
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size < position:
                offsets[path] = 0
                resets.append(path)
        return resets

    def _persist_offsets(self) -> None:
        """Atomically store read positions; never let this break collection."""
        offsets = self._offsets()
        if offsets is None or self._state_path is None:
            return
        payload = {str(path): int(position) for path, position in offsets.items() if isinstance(position, int)}
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temp_name = tempfile.mkstemp(
                dir=str(self._state_path.parent), prefix=".collector-", suffix=".tmp"
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
            os.replace(temp_name, self._state_path)
        except OSError:  # pragma: no cover - persistence is best effort
            pass

    # -- internals -------------------------------------------------------
    def _format(self, extracted: dict[str, list[dict[str, Any]]]) -> str:
        formatter = getattr(self.extractor, "format_logs_for_analysis", None)
        if callable(formatter):
            try:
                return str(formatter(extracted))
            except Exception as exc:  # pragma: no cover - defensive
                raise ForensIQError(f"cannot format collected logs: {exc}") from exc
        return _fallback_format(extracted)


def _fallback_format(extracted: dict[str, list[dict[str, Any]]]) -> str:
    lines: list[str] = []
    for source_id, entries in extracted.items():
        for entry in entries:
            timestamp = entry.get("timestamp", "")
            message = entry.get("message", "")
            lines.append(f"{timestamp} [{source_id}] {message}".strip())
    return "\n".join(lines)
