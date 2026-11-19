"""Exception types for the sequence workstream.

Kept separate so every other module in this package can raise a narrow,
named failure without importing the engine.
"""

from __future__ import annotations


class SequenceError(Exception):
    """Base class for all sequence workstream failures."""


class SequenceConfigError(SequenceError):
    """Raised when required sequence configuration is missing or out of range."""


class InvalidEventBatchError(SequenceError):
    """Raised when a caller supplies something other than ``NormalizedEvent`` objects."""


class StateCorruptionError(SequenceError):
    """Raised when persisted sequence state cannot be restored.

    The sequence documentation requires state to be reset on corrupted state
    rather than silently reused, so callers handle this by discarding the
    affected scope record.
    """


class ScoringError(SequenceError):
    """Raised when the scorer produces output the shared contract cannot accept."""
