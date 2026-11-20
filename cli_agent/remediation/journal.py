"""Local rollback journal (``~/.forensiq/remediation_journal.json``) and backups."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ExecutionReceipt, RollbackReceipt


def default_forensiq_home() -> Path:
    """Return ``$FORENSIQ_HOME`` if set, otherwise ``~/.forensiq``."""
    override = os.environ.get("FORENSIQ_HOME", "").strip()
    return Path(override).expanduser() if override else (Path.home() / ".forensiq")


class RollbackJournal:
    """Atomic local persistence for HITL remediation receipts and config file backups."""

    def __init__(
        self,
        journal_path: Path | str | None = None,
        backup_dir: Path | str | None = None,
    ) -> None:
        home = default_forensiq_home()
        self.journal_path = (
            Path(journal_path) if journal_path is not None else (home / "remediation_journal.json")
        )
        self.backup_dir = (
            Path(backup_dir) if backup_dir is not None else (home / "backups")
        )

    def _ensure_dirs(self) -> None:
        for directory in (self.journal_path.parent, self.backup_dir):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(directory, 0o700)
            except OSError:  # pragma: no cover - platform dependent
                pass

    def _read_all_raw(self) -> list[dict[str, Any]]:
        if not self.journal_path.exists():
            return []
        try:
            payload = json.loads(self.journal_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("receipts"), list):
            return [row for row in payload["receipts"] if isinstance(row, dict)]
        return []

    def _write_all_raw(self, records: list[dict[str, Any]]) -> None:
        self._ensure_dirs()
        serialized = json.dumps({"schema_version": "1.0", "receipts": records}, indent=2)
        temp_name = ""
        try:
            fd, temp_name = tempfile.mkstemp(
                dir=str(self.journal_path.parent),
                prefix=".remediation-journal-",
                suffix=".tmp",
            )
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
            os.replace(temp_name, self.journal_path)
            try:
                os.chmod(self.journal_path, 0o600)
            except OSError:  # pragma: no cover
                pass
        except OSError:
            if temp_name:
                Path(temp_name).unlink(missing_ok=True)
            raise

    def next_receipt_id(self) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        existing = self._read_all_raw()
        prefix = f"fix-{stamp}-"
        count = sum(1 for r in existing if str(r.get("receipt_id", "")).startswith(prefix))
        return f"{prefix}{count + 1:03d}"

    def append(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        records = self._read_all_raw()
        records.append(receipt.to_dict())
        self._write_all_raw(records)
        return receipt

    def list_receipts(self, *, limit: int = 50) -> list[ExecutionReceipt]:
        raw = self._read_all_raw()
        receipts = [ExecutionReceipt.from_dict(r) for r in raw]
        receipts.reverse()  # newest first
        return receipts[: max(1, int(limit))]

    def get_receipt(self, receipt_id: str) -> ExecutionReceipt | None:
        for row in self._read_all_raw():
            if row.get("receipt_id") == receipt_id:
                return ExecutionReceipt.from_dict(row)
        return None

    def mark_rolled_back(
        self,
        receipt_id: str,
        rollback: RollbackReceipt,
    ) -> ExecutionReceipt | None:
        records = self._read_all_raw()
        updated_receipt: ExecutionReceipt | None = None
        for row in records:
            if row.get("receipt_id") == receipt_id:
                row["status"] = "rolled_back" if rollback.success else row.get("status", "executed")
                row["rolled_back_at_utc"] = rollback.rolled_back_at_utc
                if rollback.message:
                    row["rollback_notes"] = rollback.message
                updated_receipt = ExecutionReceipt.from_dict(row)
                break
        if updated_receipt is not None:
            self._write_all_raw(records)
        return updated_receipt

    def snapshot_file(self, source_path: Path | str, label: str | None = None) -> Path:
        """Copy ``source_path`` into ``~/.forensiq/backups/<name>.<ts>.forensiq.bak``."""
        self._ensure_dirs()
        src = Path(source_path)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = (label or src.name).replace("/", "_").replace("\\", "_")
        dest = self.backup_dir / f"{safe_name}.{stamp}.forensiq.bak"
        shutil.copy2(src, dest)
        try:
            os.chmod(dest, 0o600)
        except OSError:  # pragma: no cover
            pass
        return dest

    def snapshot_text(self, content: str, label: str) -> Path:
        """Persist raw file text into ``~/.forensiq/backups/<label>.<ts>.forensiq.bak``."""
        self._ensure_dirs()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = label.replace("/", "_").replace("\\", "_")
        dest = self.backup_dir / f"{safe_name}.{stamp}.forensiq.bak"
        dest.write_text(content, encoding="utf-8")
        try:
            os.chmod(dest, 0o600)
        except OSError:  # pragma: no cover
            pass
        return dest
