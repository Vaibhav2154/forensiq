"""Per-scope sequence state and the state-store boundary.

Authority: ``docs/Sequential_Log_Context_Model.md``.

* "The model must not maintain one global state for every event in the
  environment. Context is stored separately for a defined investigation scope."
* A context record contains the scope key, ordered normalized-event feature
  vectors, the LSTM hidden/cell state after the last processed event, the last
  event timestamp, the model version, source/evidence references, and expiry
  and reset status.
* "Persist state durably per scope and model version."
* "Reset state on material schema/model changes, corrupted state, or a clearly
  defined scope identity change."

The documentation does not choose a persistence technology (decision point 3).
This module therefore defines the storage boundary (:class:`StateStore`) and
only the in-memory implementation needed to run and test the engine.  A
durable backend must be supplied by whoever owns that approved decision; the
state survives a full ``to_dict`` / ``from_dict`` round trip, so any backend
that can store JSON-serialisable records can persist it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from .errors import StateCorruptionError
from .scoring import LstmState
from .window import WindowEntry, window_event_ids

#: Version of the serialized state record.  A different value means the stored
#: context was written by an incompatible state layout and must be reset, in
#: line with the documented "material schema changes" reset rule.
STATE_FORMAT_VERSION = 1


@dataclass(slots=True)
class ScopeState:
    """Everything retained for one investigation scope under one model version."""

    scope_key: str
    model_version: str
    entries: list[WindowEntry] = field(default_factory=list)
    last_event_time: datetime | None = None
    #: True once the bounded window has dropped history, meaning the state
    #: before the oldest retained event is no longer the true beginning.
    trimmed: bool = False
    #: Set when a late event could not be replayed because the history needed
    #: to recompute it is no longer retained.
    replay_incomplete: bool = False
    #: Most recent documented reason for discarding earlier state.
    reset_reason: str | None = None
    state_format_version: int = STATE_FORMAT_VERSION

    @property
    def window_size(self) -> int:
        return len(self.entries)

    @property
    def event_ids(self) -> list[str]:
        return window_event_ids(self.entries)

    @property
    def current_state(self) -> LstmState | None:
        """LSTM state after the last processed event, if any."""
        return self.entries[-1].state_after if self.entries else None

    @property
    def anchor_state(self) -> LstmState | None:
        """State immediately before the oldest retained event, if any.

        This is the replay anchor.  It is ``None`` for a fresh scope, where the
        scorer's initial state applies.
        """
        return self.entries[0].state_before if self.entries else None

    @property
    def evidence_references(self) -> list[str]:
        """Durable evidence pointers retained with the window."""
        return [entry.event.evidence_ref.reference_id for entry in self.entries]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_format_version": self.state_format_version,
            "scope_key": self.scope_key,
            "model_version": self.model_version,
            "last_event_time": (
                self.last_event_time.isoformat() if self.last_event_time is not None else None
            ),
            "trimmed": self.trimmed,
            "replay_incomplete": self.replay_incomplete,
            "reset_reason": self.reset_reason,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScopeState":
        try:
            version = int(data["state_format_version"])
            if version != STATE_FORMAT_VERSION:
                raise StateCorruptionError(
                    f"state format version {version} is not {STATE_FORMAT_VERSION}"
                )
            last_event_time = data.get("last_event_time")
            return cls(
                scope_key=str(data["scope_key"]),
                model_version=str(data["model_version"]),
                entries=[WindowEntry.from_dict(item) for item in data.get("entries", [])],
                last_event_time=(
                    datetime.fromisoformat(last_event_time) if last_event_time else None
                ),
                trimmed=bool(data.get("trimmed", False)),
                replay_incomplete=bool(data.get("replay_incomplete", False)),
                reset_reason=data.get("reset_reason"),
                state_format_version=version,
            )
        except StateCorruptionError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise StateCorruptionError(f"invalid scope state: {exc}") from exc


@runtime_checkable
class StateStore(Protocol):
    """Storage boundary for per-scope context records.

    Implementations must key records by scope key and must only ever return a
    record belonging to that key.  The approved durable backend replaces
    :class:`InMemoryStateStore` without touching the engine.
    """

    def get(self, scope_key: str) -> ScopeState | None:
        """Return the stored state for ``scope_key`` or ``None``."""

    def put(self, state: ScopeState) -> None:
        """Store (or replace) the state for ``state.scope_key``."""

    def delete(self, scope_key: str) -> None:
        """Discard the state for ``scope_key``."""

    def scope_keys(self) -> Iterable[str]:
        """List stored scope keys."""


class InMemoryStateStore:
    """Process-local :class:`StateStore` used by tests and single-process runs.

    This is deliberately *not* presented as the durable store the documentation
    requires: it holds no persistence guarantee across process restarts.
    """

    def __init__(self, initial: Iterable[ScopeState] = ()) -> None:
        self._states: dict[str, ScopeState] = {state.scope_key: state for state in initial}

    def get(self, scope_key: str) -> ScopeState | None:
        return self._states.get(scope_key)

    def put(self, state: ScopeState) -> None:
        self._states[state.scope_key] = state

    def delete(self, scope_key: str) -> None:
        self._states.pop(scope_key, None)

    def scope_keys(self) -> Iterable[str]:
        return tuple(self._states)

    def __len__(self) -> int:
        return len(self._states)
