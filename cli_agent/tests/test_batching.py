"""Lossless log batching: no truncation, no reordering, no dropped records."""

from __future__ import annotations

import pytest

from cli_agent.services.limits import MAX_LOG_CHARS, split_logs_lossless


def test_small_text_is_one_batch() -> None:
    split = split_logs_lossless("line one\nline two")
    assert split.count == 1
    assert split.batches == ("line one\nline two",)
    assert split.oversized == 0


def test_exact_limit_is_not_split() -> None:
    text = "x" * MAX_LOG_CHARS
    split = split_logs_lossless(text)
    assert split.count == 1
    assert split.batches[0] == text


def test_one_char_over_limit_splits_without_loss() -> None:
    text = "a" * (MAX_LOG_CHARS + 1)
    split = split_logs_lossless(text)
    assert split.count == 2
    assert "".join(split.batches) == text
    assert all(len(batch) <= MAX_LOG_CHARS for batch in split.batches)
    assert split.oversized == 1


def test_many_events_are_split_on_newline_boundaries_and_ordered() -> None:
    events = [f"2026-01-01T00:00:{index % 60:02d} host sshd: event {index} " + "a" * 40 for index in range(1_500)]
    text = "\n".join(events)
    assert len(text) > MAX_LOG_CHARS

    split = split_logs_lossless(text)
    assert split.count > 1
    assert "".join(split.batches) == text  # byte-for-byte reconstruction
    assert all(len(batch) <= MAX_LOG_CHARS for batch in split.batches)
    assert split.oversized == 0, "newline boundaries were available"
    # Order is preserved: concatenating batches is the original sequence.
    assert split.batches[0].startswith(events[0])
    assert events[-1] in split.batches[-1]


def test_single_oversized_event_is_preserved_across_batches() -> None:
    text = "y" * (MAX_LOG_CHARS * 2 + 123)
    split = split_logs_lossless(text)
    assert split.count == 3
    assert "".join(split.batches) == text
    assert split.oversized == 2


def test_whitespace_is_not_a_record() -> None:
    assert split_logs_lossless("   \n\n \t").count == 0
    assert split_logs_lossless("").count == 0


def test_smaller_custom_limit() -> None:
    text = "one\ntwo\nthree\nfour\nfive\n"
    split = split_logs_lossless(text, limit=10)
    assert "".join(split.batches) == text
    assert all(len(batch) <= 10 for batch in split.batches)
    assert split.count >= 3


def test_invalid_limit_is_rejected() -> None:
    with pytest.raises(ValueError):
        split_logs_lossless("x", limit=0)
