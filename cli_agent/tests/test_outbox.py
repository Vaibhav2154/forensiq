"""Durable pending-delivery journal: atomic, private, bounded, corrupt-safe."""

from __future__ import annotations

import json
import os
import stat

import pytest

from cli_agent.services.outbox import (
    Outbox,
    OutboxCorruptError,
    OutboxFullError,
    PendingBatch,
    PendingDelivery,
)


def delivery(*texts: str, entries: int = 3) -> PendingDelivery:
    return PendingDelivery(
        batches=tuple(PendingBatch(text=text) for text in texts),
        checkpoint={"/var/log/auth.log": 4096},
        checkpoint_files={"/var/log/auth.log": {"dev": 1, "ino": 2, "size": 4096}},
        entries=entries,
        enhance_with_ai=True,
        max_results=5,
    )


def test_roundtrip_preserves_batches_and_checkpoint(tmp_path) -> None:
    box = Outbox(tmp_path / "pending.json")
    saved = delivery("first", "second")
    box.save(saved)

    loaded = box.load()
    assert loaded is not None
    assert [batch.text for batch in loaded.batches] == ["first", "second"]
    assert loaded.checkpoint == {"/var/log/auth.log": 4096}
    assert loaded.checkpoint_files["/var/log/auth.log"]["ino"] == 2
    assert loaded.entries == 3
    assert loaded.enhance_with_ai is True
    assert loaded.max_results == 5


def test_permissions_are_restrictive(tmp_path) -> None:
    path = tmp_path / "forensiq" / "pending.json"
    Outbox(path).save(delivery("secret log line"))

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_save_is_atomic_and_leaves_no_temp_files(tmp_path) -> None:
    box = Outbox(tmp_path / "pending.json")
    box.save(delivery("one"))
    box.save(delivery("two"))
    assert [p.name for p in tmp_path.iterdir()] == ["pending.json"]
    assert box.load().batches[0].text == "two"


def test_clear_removes_the_journal(tmp_path) -> None:
    box = Outbox(tmp_path / "pending.json")
    box.save(delivery("one"))
    box.clear()
    assert box.load() is None
    box.clear()  # idempotent


def test_byte_capacity_is_enforced_without_overwriting(tmp_path) -> None:
    box = Outbox(tmp_path / "pending.json", max_bytes=16)
    box.save(delivery("small"))
    with pytest.raises(OutboxFullError):
        box.save(delivery("x" * 1_000))
    assert box.load().batches[0].text == "small"


def test_batch_capacity_is_enforced(tmp_path) -> None:
    box = Outbox(tmp_path / "pending.json", max_batches=1)
    with pytest.raises(OutboxFullError):
        box.save(delivery("one", "two"))


def test_corrupt_journal_is_preserved_and_reported(tmp_path) -> None:
    path = tmp_path / "pending.json"
    path.write_text("{not valid json", encoding="utf-8")
    box = Outbox(path)

    with pytest.raises(OutboxCorruptError):
        box.load()

    preserved = list(tmp_path.glob("pending.json.corrupt-*"))
    assert preserved, "the corrupt journal must not be deleted"
    assert preserved[0].read_text(encoding="utf-8") == "{not valid json"


def test_malformed_batch_is_treated_as_corrupt(tmp_path) -> None:
    path = tmp_path / "pending.json"
    path.write_text(json.dumps({"batches": [{"text": ""}]}), encoding="utf-8")
    with pytest.raises(OutboxCorruptError):
        Outbox(path).load()
    assert list(tmp_path.glob("pending.json.corrupt-*"))


def test_empty_delivery_is_readable_and_clearable(tmp_path) -> None:
    box = Outbox(tmp_path / "pending.json")
    box.save(PendingDelivery((), {}, {}, 0, True, 5))
    loaded = box.load()
    assert loaded is not None and loaded.is_empty
    box.clear()
    assert box.load() is None


def test_attempts_survive_roundtrip(tmp_path) -> None:
    box = Outbox(tmp_path / "pending.json")
    batch = PendingBatch(text="payload", attempts=2, last_error="HTTP 503")
    box.save(
        PendingDelivery(
            (batch,), {}, {}, 1, False, 3
        )
    )
    loaded = box.load()
    assert loaded.batches[0].attempts == 2
    assert loaded.batches[0].last_error == "HTTP 503"


def test_write_failure_is_reported(tmp_path, monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("cli_agent.services.outbox.tempfile.mkstemp", refuse)
    with pytest.raises(Exception) as excinfo:
        Outbox(tmp_path / "pending.json").save(delivery("one"))
    assert "pending-delivery journal" in str(excinfo.value)
