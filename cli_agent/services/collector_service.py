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
* file offsets live in an in-memory dict in the legacy extractor; this adapter
  persists them selectively (see ``collect(persist=...)``) and tracks file
  identity so rotation/truncation cannot silently skip data;
* the legacy per-source ``try/except`` logs failures to a logger, so this
  adapter can only report a source as empty rather than failed.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .errors import ConfigurationError, ForensIQError, StatePersistenceError

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
        # File identity captured with the saved offsets: {"dev", "ino", "size"}.
        self._file_meta: dict[str, dict[str, int]] = {}
        self._lock = threading.RLock()
        self.state_corrupt = False

    @property
    def extractor(self) -> Any:
        if self._extractor is None:
            self._extractor = self._factory()
        return self._extractor

    @property
    def state_path(self) -> Path | None:
        return self._state_path

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
        *,
        persist: bool = True,
    ) -> CollectionResult:
        """Read new events from the selected sources.

        ``persist=False`` is used by the monitoring loop: it advances the
        in-memory offsets but leaves the durable checkpoint untouched until the
        collected events have been acknowledged by the backend
        (:meth:`commit_state`).  One-shot CLI collection keeps the Phase 5
        behaviour and persists immediately.
        """
        selected = self.validate_sources(sources)
        errors: dict[str, str] = {}
        self._restore_offsets()
        self.rotation_resets = self._reset_rotated_offsets()
        try:
            raw = self.extractor.extract_logs(list(selected), time_range_minutes)
        except Exception as exc:
            raise ForensIQError(f"log collection failed: {exc}") from exc
        finally:
            if persist:
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
        """Reload persisted read positions once, so a restart does not replay.

        Supports the Phase 5 flat mapping and the Phase 7 document:

            {"offsets": {path: position}, "_files": {path: {...}}, "version": 2}

        A corrupt checkpoint is preserved beside the original
        (``<name>.corrupt-<ts>``) and treated as "start from zero"; replaying
        logs is safe, skipping them is not.
        """
        if self._restored:
            return
        self._restored = True
        offsets = self._offsets()
        if offsets is None or self._state_path is None:
            return
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            if self._state_path.exists():
                self.state_corrupt = True
                self._quarantine_state()
            return
        if not isinstance(raw, dict):
            self.state_corrupt = True
            self._quarantine_state()
            return

        stored_offsets = raw.get("offsets") if isinstance(raw.get("offsets"), dict) else raw
        for path, position in stored_offsets.items():
            if path == "_files" or path == "version":
                continue
            if isinstance(path, str) and isinstance(position, int) and position >= 0:
                offsets.setdefault(path, position)

        files = raw.get("_files")
        if isinstance(files, dict):
            for path, meta in files.items():
                if not isinstance(path, str) or not isinstance(meta, dict):
                    continue
                clean: dict[str, int] = {}
                for key in ("dev", "ino", "size"):
                    value = meta.get(key)
                    if isinstance(value, int) and value >= 0:
                        clean[key] = value
                if clean:
                    self._file_meta[path] = clean

    def _signature(self, path: str) -> dict[str, int] | None:
        try:
            stat = os.stat(path)
        except OSError:
            return None
        return {
            "dev": int(getattr(stat, "st_dev", 0) or 0),
            "ino": int(getattr(stat, "st_ino", 0) or 0),
            "size": int(stat.st_size),
        }

    def _reset_rotated_offsets(self) -> list[str]:
        """Reset stored positions when the file they refer to was replaced.

        Phase 5 only compared the size, which misses a same-path replacement
        whose new file is already larger than the old offset.  The inode/device
        pair catches that; on Windows, where ``st_ino`` may be zero, the size
        check remains the fallback.
        """
        offsets = self._offsets()
        if offsets is None:
            return []
        resets: list[str] = []
        for path, position in list(offsets.items()):
            if not isinstance(position, int) or position <= 0:
                continue
            current = self._signature(path)
            if current is None:
                continue
            stored = self._file_meta.get(path)
            replaced = False
            if stored:
                stored_ino = stored.get("ino", 0)
                stored_dev = stored.get("dev", 0)
                if stored_ino and current.get("ino") and stored_ino != current.get("ino"):
                    replaced = True
                elif stored_dev and current.get("dev") and stored_dev != current.get("dev"):
                    replaced = True
            if replaced or current.get("size", 0) < position:
                offsets[path] = 0
                resets.append(path)
        return resets

    def snapshot_state(self) -> tuple[dict[str, int], dict[str, dict[str, int]]]:
        """Offsets and file identity as of the last collection (not yet saved)."""
        offsets = self._offsets() or {}
        clean_offsets = {
            str(path): int(position)
            for path, position in offsets.items()
            if isinstance(position, int) and position >= 0
        }
        files = {
            path: signature
            for path in clean_offsets
            if (signature := self._signature(path)) is not None
        }
        return clean_offsets, files

    def commit_state(
        self, offsets: dict[str, int], files: dict[str, dict[str, int]] | None = None
    ) -> None:
        """Persist an acknowledged checkpoint (raises on failure)."""
        with self._lock:
            effective_files = files if files is not None else {}
            if effective_files:
                self._file_meta.update(effective_files)
            self._persist_offsets(offsets=offsets, strict=True)

    def checkpoint(self) -> None:
        """Persist the current offsets, raising if that is impossible."""
        offsets, files = self.snapshot_state()
        self.commit_state(offsets, files)

    def _persist_offsets(self, *, offsets: dict[str, int] | None = None, strict: bool = False) -> None:
        """Atomically store read positions and file identity.

        ``strict`` is used for acknowledged checkpoints: a failed write must be
        surfaced so the caller does not treat data as safely committed.  The
        legacy one-shot path stays best-effort.
        """
        source = offsets if offsets is not None else self._offsets()
        if source is None or self._state_path is None:
            return
        clean = {
            str(path): int(position)
            for path, position in source.items()
            if isinstance(position, int) and position >= 0
        }
        files = {
            path: meta
            for path in clean
            if (meta := (self._file_meta.get(path) or self._signature(path))) is not None
        }
        self._file_meta.update(files)
        # Flat offsets keep the Phase 5 reader working; "_files"/"version" are
        # ignored by that reader and understood by this one.
        payload = {**clean, "_files": files, "version": 2}
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self._state_path.parent, 0o700)
            except OSError:  # pragma: no cover - platform dependent
                pass
            descriptor, temp_name = tempfile.mkstemp(
                dir=str(self._state_path.parent), prefix=".collector-", suffix=".tmp"
            )
            try:
                os.chmod(temp_name, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, self._state_path)
                try:
                    os.chmod(self._state_path, 0o600)
                except OSError:  # pragma: no cover
                    pass
            except BaseException:
                Path(temp_name).unlink(missing_ok=True)
                raise
        except OSError as exc:
            if strict:
                raise StatePersistenceError(
                    f"cannot persist collector checkpoint: {type(exc).__name__}"
                ) from exc
            # Legacy best-effort path: collection itself must keep working.

    def _quarantine_state(self) -> None:
        """Preserve an unreadable checkpoint instead of deleting it."""
        if self._state_path is None:
            return
        target = self._state_path.with_name(
            self._state_path.name + f".corrupt-{int(datetime.now().timestamp())}"
        )
        try:
            os.replace(self._state_path, target)
        except OSError:  # pragma: no cover
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
