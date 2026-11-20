"""Checkpoint integrity: inode rotation, truncation, corrupt state, deferred commits."""

from __future__ import annotations

import json
import os

import pytest

from cli_agent.services.collector_service import CollectorService
from cli_agent.services.errors import StatePersistenceError

from .test_collector_state import OffsetsExtractor


def service_for(log, state, *, source_path=None) -> CollectorService:
    return CollectorService(extractor=OffsetsExtractor(source_path or log), state_path=state)


def test_same_path_rotation_to_a_larger_file_is_detected(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("old one\nold two\n", encoding="utf-8")
    state = tmp_path / "state.json"
    first = service_for(log, state)
    first.collect(["auth_logs"])
    assert json.loads(state.read_text(encoding="utf-8"))[str(log)] > 0

    replacement = tmp_path / "auth.log.1"
    replacement.write_text("\n".join(f"new line {i}" for i in range(200)) + "\n", encoding="utf-8")
    os.replace(replacement, log)  # new inode, larger than the previous offset

    restarted = service_for(log, state)
    result = restarted.collect(["auth_logs"])
    assert result.total_entries == 200, "rotation was mistaken for already-read data"
    assert str(log) in restarted.rotation_resets


def test_truncation_to_a_smaller_file_is_detected(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("\n".join(f"line {i}" for i in range(100)) + "\n", encoding="utf-8")
    state = tmp_path / "state.json"
    service_for(log, state).collect(["auth_logs"])

    log.write_text("after truncate\n", encoding="utf-8")

    restarted = service_for(log, state)
    result = restarted.collect(["auth_logs"])
    assert result.total_entries == 1
    assert "after truncate" in result.formatted_text
    assert restarted.rotation_resets == [str(log)]


def test_corrupt_checkpoint_is_preserved_and_replayed_from_zero(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("line one\nline two\n", encoding="utf-8")
    state = tmp_path / "state.json"
    state.write_text("{definitely not json", encoding="utf-8")

    service = service_for(log, state)
    result = service.collect(["auth_logs"])

    assert service.state_corrupt is True
    assert result.total_entries == 2, "corrupt state must replay, never skip"
    preserved = list(tmp_path.glob("state.json.corrupt-*"))
    assert preserved and preserved[0].read_text(encoding="utf-8") == "{definitely not json"


def test_deferred_checkpoint_writes_nothing_until_committed(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("deferred line\n", encoding="utf-8")
    state = tmp_path / "state.json"
    service = service_for(log, state)

    result = service.collect(["auth_logs"], persist=False)
    assert result.total_entries == 1
    assert not state.exists()

    offsets, files = service.snapshot_state()
    service.commit_state(offsets, files)
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved[str(log)] == log.stat().st_size
    assert saved["_files"][str(log)]["size"] == log.stat().st_size


def test_legacy_flat_checkpoint_is_still_readable(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("one line\n", encoding="utf-8")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({str(log): 0}), encoding="utf-8")

    service = service_for(log, state)
    assert service.collect(["auth_logs"]).total_entries == 1
    assert service.state_corrupt is False


def test_missing_state_file_starts_from_zero(tmp_path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("fresh\n", encoding="utf-8")
    service = CollectorService(extractor=OffsetsExtractor(log), state_path=tmp_path / "missing.json")
    assert service.collect(["auth_logs"]).total_entries == 1


def test_strict_checkpoint_failure_is_reported(tmp_path, monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    log = tmp_path / "auth.log"
    log.write_text("line\n", encoding="utf-8")
    service = CollectorService(
        extractor=OffsetsExtractor(log), state_path=tmp_path / "state.json"
    )
    service.collect(["auth_logs"], persist=False)
    offsets, files = service.snapshot_state()
    monkeypatch.setattr("cli_agent.services.collector_service.tempfile.mkstemp", refuse)
    with pytest.raises(StatePersistenceError):
        service.commit_state(offsets, files)
