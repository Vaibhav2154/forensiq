"""Checkpoint 5: backend response adaptation."""

from __future__ import annotations

import pytest

from cli_agent.client.errors import MalformedResponseError
from cli_agent.client.response_adapter import adapt_analysis, next_interval

CURRENT_RESPONSE = {
    "summary": "3 events across 1 scope; 1 technique retrieved.",
    "matched_techniques": [
        {
            "technique_id": "T1110",
            "name": "Brute Force",
            "description": "Adversaries may use brute force.",
            "kill_chain_phases": ["credential-access"],
            "platforms": ["Linux", "Windows"],
            "relevance_score": 0.82,
        }
    ],
    "enhanced_analysis": "## Report\n...",
    "investigation": {"investigation_id": "inv-1"},
    "analysis_timestamp": "2026-01-01T00:00:00Z",
    "processing_time_ms": 42.5,
}


def test_current_backend_response_maps() -> None:
    view = adapt_analysis(CURRENT_RESPONSE)
    assert view.summary.startswith("3 events")
    assert view.technique_count == 1
    technique = view.techniques[0]
    assert technique.technique_id == "T1110"
    assert technique.name == "Brute Force"
    assert technique.platforms == ("Linux", "Windows")
    assert technique.relevance_score == pytest.approx(0.82)
    assert view.enhanced_analysis.startswith("## Report")
    assert view.has_investigation is True
    assert view.processing_time_ms == pytest.approx(42.5)


def test_legacy_mitre_techniques_key_is_still_accepted() -> None:
    payload = {"summary": "s", "mitre_techniques": [{"technique_id": "T1059", "name": "CLI"}]}
    view = adapt_analysis(payload)
    assert view.technique_count == 1
    assert view.techniques[0].technique_id == "T1059"


def test_empty_techniques_are_not_an_error() -> None:
    view = adapt_analysis({"summary": "no matches", "matched_techniques": []})
    assert view.techniques == ()
    assert view.technique_count == 0


def test_missing_threat_level_is_none_not_low() -> None:
    """The backend no longer reports a threat level; do not invent one."""
    view = adapt_analysis(CURRENT_RESPONSE)
    assert view.threat_level is None
    assert view.threat_level_source == "unavailable"


def test_backend_supplied_threat_level_is_used() -> None:
    view = adapt_analysis({"summary": "s", "threat_level": "HIGH"})
    assert view.threat_level == "high"
    assert view.threat_level_source == "backend"


def test_invalid_threat_level_is_ignored() -> None:
    view = adapt_analysis({"summary": "s", "threat_level": "catastrophic"})
    assert view.threat_level is None


def test_visualization_metrics_are_passed_through() -> None:
    payload = dict(CURRENT_RESPONSE, visualization_metrics={"severity": {"high": 2}})
    view = adapt_analysis(payload)
    assert view.visualization_metrics == {"severity": {"high": 2}}


def test_absent_visualization_metrics_are_none() -> None:
    assert adapt_analysis({"summary": "s"}).visualization_metrics is None


def test_malformed_payloads_raise() -> None:
    for payload in (None, [], "string", 42):
        with pytest.raises(MalformedResponseError):
            adapt_analysis(payload)


def test_missing_optional_fields_are_none() -> None:
    view = adapt_analysis({"summary": ""})
    assert view.summary == ""
    assert view.enhanced_analysis is None
    assert view.investigation is None
    assert view.processing_time_ms is None


def test_unknown_threat_level_keeps_base_interval() -> None:
    view = adapt_analysis({"summary": "s"})
    assert next_interval(view, base_interval=300) == 300


def test_known_threat_levels_use_legacy_ratios() -> None:
    high = adapt_analysis({"summary": "s", "threat_level": "high"})
    medium = adapt_analysis({"summary": "s", "threat_level": "medium"})
    low = adapt_analysis({"summary": "s", "threat_level": "low"})
    assert next_interval(high, 300) == 100
    assert next_interval(high, 90) == 60          # floor
    assert next_interval(medium, 300) == 150
    assert next_interval(low, 300) == 300


def test_no_fabricated_findings() -> None:
    """An empty payload must not gain invented techniques or a risk rating."""
    view = adapt_analysis({"summary": "nothing observed"})
    assert view.technique_count == 0
    assert view.threat_level is None
    assert view.investigation is None
