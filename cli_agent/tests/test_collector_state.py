"""Collector restart safety: persisted byte offsets and rotation detection.

The legacy extractor keeps read positions in ``last_extraction_time`` for the
lifetime of the process. These tests cover the service-level adapter that makes
those positions survive a restart and that resets them when a log is truncated
or rotated (a stored offset past EOF would otherwise stall reads forever).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cli_agent.services.collector_service import CollectorService

from .conftest import FakeExtractor


class OffsetsExtractor(FakeExtractor):
    """Mimics the legacy file reader: seek to the stored offset, read, advance."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = str(path)
        self.last_extraction_time: dict[str, int] = {}

    def extract_logs(self, sources=None, time_range_minutes: int = 5):
        self.calls.append((list(sources or []), time_range_minutes))
        with open(self.path, "r", encoding="utf-8") as handle:
            handle.seek(self.last_extraction_time.get(self.path, 0))
            payload = handle.read()
            self.last_extraction_time[self.path] = handle.tell()
        return {
            "auth_logs": [
                {"timestamp": "", "message": line}
                for line in payload.splitlines()
                if line.strip()
            ]
        }


def make_service(path: Path, state_path: Path) -> CollectorService:
    return CollectorService(extractor=OffsetsExtractor(path), state_path=state_path)


def test_offsets_survive_a_restart(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("line one\nline two\n", encoding="utf-8")
    state = tmp_path / "collector_state.json"

    first = make_service(log, state)
    assert first.collect(["auth_logs"]).total_entries == 2
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved[str(log)] == log.stat().st_size

    log.write_text("line one\nline two\nline three\n", encoding="utf-8")

    restarted = make_service(log, state)
    result = restarted.collect(["auth_logs"])
    assert result.total_entries == 1, "restart replayed already-submitted lines"
    assert "line three" in result.formatted_text


def test_missing_state_file_starts_from_zero(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("only line\n", encoding="utf-8")

    service = make_service(log, tmp_path / "state.json")
    assert service.collect(["auth_logs"]).total_entries == 1
    assert service.rotation_resets == []


def test_corrupt_state_file_is_ignored(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("line\n", encoding="utf-8")
    state = tmp_path / "state.json"
    state.write_text("{not json", encoding="utf-8")

    service = make_service(log, state)
    assert service.collect(["auth_logs"]).total_entries == 1


def test_rotation_resets_a_stale_offset(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("after rotation\n", encoding="utf-8")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({str(log): 10_000}), encoding="utf-8")

    service = make_service(log, state)
    result = service.collect(["auth_logs"])

    assert result.total_entries == 1
    assert service.rotation_resets == [str(log)]
    assert service.extractor.last_extraction_time[str(log)] == os.path.getsize(log)


def test_persistence_is_opt_in(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("line\n", encoding="utf-8")

    service = CollectorService(extractor=OffsetsExtractor(log))
    service.collect(["auth_logs"])

    assert not list(tmp_path.glob("*.json"))
