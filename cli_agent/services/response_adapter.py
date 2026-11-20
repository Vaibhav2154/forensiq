"""Translate backend analysis payloads into a stable view.

The current ForensIQ backend answers ``POST /api/v1/analyze`` with
``summary``, ``matched_techniques``, ``enhanced_analysis``, ``investigation``
and ``processing_time_ms``. The legacy CLI expected ``mitre_techniques`` and
``threat_level``, neither of which the backend provides any more.

Policy for the missing threat level -- no fabrication:

* ``threat_level`` is ``None`` unless the backend actually supplies a valid
  value;
* ``threat_level_source`` records where it came from;
* :func:`next_interval` falls back to the configured base interval when the
  level is unknown, instead of silently classifying the batch as low risk.

Legacy payload keys are still accepted so the adapter works against both the
old LogIQ backend and the current one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .errors import MalformedResponseError

VALID_THREAT_LEVELS = ("low", "medium", "high", "critical")
LEGACY_TECHNIQUE_KEYS = ("matched_techniques", "mitre_techniques")


@dataclass(frozen=True)
class Technique:
    technique_id: str | None = None
    name: str | None = None
    description: str | None = None
    kill_chain_phases: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    relevance_score: float | None = None


@dataclass(frozen=True)
class AnalysisView:
    """What the CLI/TUI is allowed to display."""

    summary: str = ""
    techniques: tuple[Technique, ...] = ()
    enhanced_analysis: str | None = None
    investigation: dict[str, Any] | None = None
    # Added to the backend response in commit 0d4dd4c; passed through untouched
    # so the TUI can use it without this layer inventing any metric of its own.
    visualization_metrics: dict[str, Any] | None = None
    processing_time_ms: float | None = None
    threat_level: str | None = None
    threat_level_source: str = "unavailable"
    analysis_id: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @property
    def technique_count(self) -> int:
        return len(self.techniques)

    @property
    def has_investigation(self) -> bool:
        return isinstance(self.investigation, dict) and bool(self.investigation)


def adapt_analysis(payload: Any) -> AnalysisView:
    """Build an :class:`AnalysisView` from a backend response body."""
    if payload is None:
        raise MalformedResponseError("analysis response was empty")
    if not isinstance(payload, dict):
        raise MalformedResponseError("analysis response must be a JSON object")

    techniques = tuple(_adapt_techniques(payload))
    level, source = _adapt_threat_level(payload)

    return AnalysisView(
        summary=_as_text(payload.get("summary")),
        techniques=techniques,
        enhanced_analysis=_optional_text(payload.get("enhanced_analysis")),
        investigation=_optional_mapping(payload.get("investigation")),
        visualization_metrics=_optional_mapping(payload.get("visualization_metrics")),
        processing_time_ms=_optional_float(payload.get("processing_time_ms")),
        threat_level=level,
        threat_level_source=source,
        analysis_id=_optional_text(payload.get("id")),
        raw=payload,
    )


def next_interval(
    view: AnalysisView,
    base_interval: int,
    *,
    minimum_floor: int = 60,
) -> int:
    """Adaptive interval using the legacy ratios, only when a level is known.

    Legacy behaviour (``cli_tool.py:1260-1271``): high -> ``max(60, base/3)``,
    medium -> ``max(120, base/2)``, otherwise base. When the backend supplies no
    threat level we keep the base interval rather than assuming "low".
    """
    level = view.threat_level
    if level == "high" or level == "critical":
        return max(minimum_floor, base_interval // 3)
    if level == "medium":
        return max(120, base_interval // 2)
    return base_interval


# -- helpers -------------------------------------------------------------
def _adapt_techniques(payload: Mapping[str, Any]) -> list[Technique]:
    for key in LEGACY_TECHNIQUE_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            return [_adapt_technique(item) for item in value if isinstance(item, Mapping)]
    return []


def _adapt_technique(item: Mapping[str, Any]) -> Technique:
    return Technique(
        technique_id=_optional_text(item.get("technique_id")),
        name=_optional_text(item.get("name") or item.get("technique_name")),
        description=_optional_text(item.get("description")),
        kill_chain_phases=_string_tuple(item.get("kill_chain_phases")),
        platforms=_string_tuple(item.get("platforms")),
        relevance_score=_optional_float(item.get("relevance_score") or item.get("confidence")),
    )


def _adapt_threat_level(payload: Mapping[str, Any]) -> tuple[str | None, str]:
    level = payload.get("threat_level")
    if isinstance(level, str) and level.strip().lower() in VALID_THREAT_LEVELS:
        return level.strip().lower(), "backend"
    return None, "unavailable"


def _as_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _optional_text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _optional_mapping(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, Mapping) else None


def _optional_float(value: Any) -> float | None:
    if isinstance(value, bool):  # bool is an int subclass - reject it
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, list):
        return tuple(str(item) for item in value if str(item).strip())
    return ()
