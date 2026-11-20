"""Durable, bounded local journal for unacknowledged log batches.

Design goals (Phase 7):

* **No loss**: a collected batch is written here before the first HTTP request
  and only removed after the backend acknowledged it *and* the collector
  checkpoint covering it was committed.
* **At-least-once**: a crash between the acknowledgement and the journal /
  checkpoint update can resend a batch.  The backend has no idempotency key,
  so duplicates are possible; loss is not.
* **Bounded**: one pending collection cycle is retained (the monitoring loop
  stops collecting new logs while a delivery is pending).  Copies larger than
  ``max_bytes``/``max_batches`` are refused with :class:`OutboxFullError`, and
  monitoring pauses instead of discarding data.
* **Private**: the journal contains raw log text, so the file is written with
  ``0600`` permissions inside a ``0700`` directory.  No token or password is
  ever stored here.
* **Atomic**: write-to-temp + ``fsync`` + ``os.replace``.

Corrupt journals are preserved (renamed aside) and reported; they are never
silently deleted.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable

DEFAULT_OUTBOX_PATH = Path.home() / ".config" / "forensiq" / "pending_delivery.json"
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_BATCHES = 64
JOURNAL_VERSION = 1


class OutboxError(Exception):
    """The pending-delivery journal cannot be read or written."""


class OutboxCorruptError(OutboxError):
    """The journal exists but is not valid JSON/expected shape."""


class OutboxFullError(OutboxError):
    """Writing this delivery would exceed the configured local capacity."""


@dataclass(frozen=True)
class PendingBatch:
    """One backend request worth of log text awaiting acknowledgement."""

    text: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    attempts: int = 0
    last_error: str | None = None

    @property
    def size(self) -> int:
        return len(self.text.encode("utf-8"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "attempts": self.attempts,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PendingBatch":
        text = raw.get("text")
        if not isinstance(text, str) or not text.strip():
            raise OutboxCorruptError("pending batch has no text")
        batch_id = raw.get("id")
        return cls(
            text=text,
            id=str(batch_id) if batch_id else uuid.uuid4().hex,
            attempts=int(raw.get("attempts") or 0),
            last_error=raw.get("last_error") if isinstance(raw.get("last_error"), str) else None,
        )


@dataclass(frozen=True)
class PendingDelivery:
    """A whole collected cycle: its batches plus the checkpoint they cover."""

    batches: tuple[PendingBatch, ...]
    checkpoint: dict[str, int]
    checkpoint_files: dict[str, dict[str, int]]
    entries: int
    enhance_with_ai: bool
    max_results: int
    created_at: float = field(default_factory=time.time)

    @property
    def total_bytes(self) -> int:
        return sum(batch.size for batch in self.batches)

    @property
    def is_empty(self) -> bool:
        return not self.batches

    def with_batches(self, batches: Iterable[PendingBatch]) -> "PendingDelivery":
        return replace(self, batches=tuple(batches))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": JOURNAL_VERSION,
            "created_at": self.created_at,
            "entries": self.entries,
            "enhance_with_ai": self.enhance_with_ai,
            "max_results": self.max_results,
            "checkpoint": dict(self.checkpoint),
            "checkpoint_files": {
                path: dict(meta) for path, meta in self.checkpoint_files.items()
            },
            "batches": [batch.to_dict() for batch in self.batches],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PendingDelivery":
        if not isinstance(raw, dict):
            raise OutboxCorruptError("journal root must be an object")
        raw_batches = raw.get("batches")
        if not isinstance(raw_batches, list):
            raise OutboxCorruptError("journal has no batches list")
        batches = tuple(
            PendingBatch.from_dict(item)
            for item in raw_batches
            if isinstance(item, dict)
        )
        if len(batches) != len(raw_batches):
            raise OutboxCorruptError("journal contains a malformed batch")
        checkpoint_raw = raw.get("checkpoint")
        checkpoint: dict[str, int] = {}
        if isinstance(checkpoint_raw, dict):
            for path, value in checkpoint_raw.items():
                if isinstance(path, str) and isinstance(value, int) and value >= 0:
                    checkpoint[path] = value
        files_raw = raw.get("checkpoint_files")
        checkpoint_files: dict[str, dict[str, int]] = {}
        if isinstance(files_raw, dict):
            for path, meta in files_raw.items():
                if not isinstance(path, str) or not isinstance(meta, dict):
                    continue
                clean = {
                    key: int(value)
                    for key, value in meta.items()
                    if key in ("dev", "ino", "size")
                    and isinstance(value, int)
                    and value >= 0
                }
                if clean:
                    checkpoint_files[path] = clean
        entries = raw.get("entries")
        return cls(
            batches=batches,
            checkpoint=checkpoint,
            checkpoint_files=checkpoint_files,
            entries=int(entries) if isinstance(entries, int) and entries >= 0 else 0,
            enhance_with_ai=bool(raw.get("enhance_with_ai", True)),
            max_results=int(raw.get("max_results") or 5),
            created_at=float(raw.get("created_at") or time.time()),
        )


class Outbox:
    """Single-cycle durable pending-delivery journal."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_batches: int = DEFAULT_MAX_BATCHES,
    ) -> None:
        self.path = Path(path).expanduser() if path is not None else DEFAULT_OUTBOX_PATH
        self.max_bytes = max(1, int(max_bytes))
        self.max_batches = max(1, int(max_batches))

    # -- state -----------------------------------------------------------
    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> PendingDelivery | None:
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise OutboxError(f"cannot read pending-delivery journal: {exc}") from exc
        except ValueError as exc:
            self._quarantine()
            raise OutboxCorruptError(
                "pending-delivery journal is not valid JSON; preserved as .corrupt"
            ) from exc
        try:
            delivery = PendingDelivery.from_dict(raw)
        except OutboxCorruptError:
            self._quarantine()
            raise
        if delivery.is_empty:
            # A crash after acknowledging the last batch but before the
            # checkpoint commit leaves no text; checkpoint may still be
            # committed, which is safe (acknowledged data).
            return delivery
        return delivery

    def save(self, delivery: PendingDelivery) -> None:
        """Persist *delivery* atomically, enforcing capacity limits."""
        if delivery.total_bytes > self.max_bytes:
            raise OutboxFullError(
                f"pending delivery needs {delivery.total_bytes} bytes "
                f"(limit {self.max_bytes})"
            )
        if len(delivery.batches) > self.max_batches:
            raise OutboxFullError(
                f"pending delivery needs {len(delivery.batches)} batches "
                f"(limit {self.max_batches})"
            )
        payload = json.dumps(delivery.to_dict(), ensure_ascii=False)
        directory = self.path.parent
        try:
            directory.mkdir(parents=True, exist_ok=True)
            _chmod_quietly(directory, 0o700)
            descriptor, temp_name = tempfile.mkstemp(
                dir=str(directory), prefix=".pending-", suffix=".tmp"
            )
            try:
                os.chmod(temp_name, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, self.path)
                _chmod_quietly(self.path, 0o600)
            except BaseException:
                Path(temp_name).unlink(missing_ok=True)
                raise
        except OSError as exc:
            raise OutboxError(
                f"cannot write pending-delivery journal: {type(exc).__name__}"
            ) from exc

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            raise OutboxError(
                f"cannot remove pending-delivery journal: {type(exc).__name__}"
            ) from exc

    # -- helpers ---------------------------------------------------------
    def _quarantine(self) -> None:
        """Keep a corrupt journal for inspection instead of deleting it."""
        target = self.path.with_name(
            self.path.name + f".corrupt-{int(time.time())}"
        )
        try:
            os.replace(self.path, target)
            _chmod_quietly(target, 0o600)
        except OSError:
            pass


def _chmod_quietly(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - platform dependent
        pass


__all__ = [
    "DEFAULT_MAX_BATCHES",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_OUTBOX_PATH",
    "Outbox",
    "OutboxCorruptError",
    "OutboxError",
    "OutboxFullError",
    "PendingBatch",
    "PendingDelivery",
]
