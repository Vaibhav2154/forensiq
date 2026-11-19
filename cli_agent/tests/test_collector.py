"""Checkpoint 4: collector adapter behaviour with a fake extractor."""

from __future__ import annotations

import pytest

from cli_agent.services.collector_service import CollectorService
from cli_agent.services.errors import ConfigurationError, ForensIQError

from .conftest import FakeExtractor


def test_available_sources_are_passed_through() -> None:
    service = CollectorService(extractor=FakeExtractor())
    assert service.source_ids() == ["auth_logs", "process_monitor"]


def test_defaults_to_every_available_source() -> None:
    service = CollectorService(extractor=FakeExtractor())
    assert service.validate_sources(None) == ("auth_logs", "process_monitor")


def test_unknown_source_is_rejected() -> None:
    service = CollectorService(extractor=FakeExtractor())
    with pytest.raises(ConfigurationError) as excinfo:
        service.validate_sources(["does_not_exist"])
    assert "does_not_exist" in str(excinfo.value)


def test_no_sources_available_is_an_error() -> None:
    service = CollectorService(extractor=FakeExtractor(sources=[]))
    with pytest.raises(ConfigurationError):
        service.validate_sources(None)


def test_empty_collection_is_not_an_error() -> None:
    service = CollectorService(extractor=FakeExtractor())
    result = service.collect(["auth_logs"])
    assert result.is_empty is True
    assert result.total_entries == 0
    assert result.formatted_text == ""
    assert result.errors == {}


def test_collection_returns_entries_and_text() -> None:
    extractor = FakeExtractor(
        batches=[
            {
                "auth_logs": [
                    {"timestamp": "2026-01-01T00:00:00+00:00", "message": "Failed password for root"},
                    {"timestamp": "2026-01-01T00:00:01+00:00", "message": "Accepted publickey"},
                ]
            }
        ]
    )
    service = CollectorService(extractor=extractor)
    result = service.collect(["auth_logs"], time_range_minutes=5)

    assert result.total_entries == 2
    assert result.entries_by_source["auth_logs"][0]["message"].startswith("Failed password")
    assert "Failed password for root" in result.formatted_text
    assert extractor.calls == [(["auth_logs"], 5)]


def test_sources_not_requested_are_still_reported() -> None:
    extractor = FakeExtractor(
        batches=[{"auth_logs": [{"message": "a"}], "process_monitor": [{"message": "b"}]}]
    )
    service = CollectorService(extractor=extractor)
    result = service.collect(["auth_logs"])
    assert "process_monitor" in result.entries_by_source


def test_extractor_failure_is_wrapped() -> None:
    service = CollectorService(extractor=FakeExtractor(error=RuntimeError("boom")))
    with pytest.raises(ForensIQError) as excinfo:
        service.collect(["auth_logs"])
    assert "boom" in str(excinfo.value)


def test_formatter_failure_is_wrapped() -> None:
    extractor = FakeExtractor(
        batches=[{"auth_logs": [{"message": "a"}]}],
        format_error=RuntimeError("format boom"),
    )
    service = CollectorService(extractor=extractor)
    with pytest.raises(ForensIQError):
        service.collect(["auth_logs"])


def test_system_summary() -> None:
    service = CollectorService(extractor=FakeExtractor())
    assert service.system_summary()["system"] == "Fake"


def test_missing_summary_support_returns_empty() -> None:
    class Bare:
        def get_available_sources(self):
            return [{"id": "x", "type": "file", "description": "x"}]

    service = CollectorService(extractor=Bare())
    assert service.system_summary() == {}
