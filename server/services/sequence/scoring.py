"""Scorer boundary and a dependency-free LSTM cell implementation.

Authority: ``docs/Sequential_Log_Context_Model.md`` mandates an LSTM with
"hidden state and cell state" and a risk score.  It does not specify a model
framework, hidden-size, number of stacked layers, an initialisation scheme, an
output layer, or a training procedure.  Those are open decisions, so:

* :class:`SequenceScorer` is the narrow interface the engine depends on.  Any
  approved model (or a framework-backed one) plugs in here.
* :class:`LstmCellScorer` implements the standard LSTM cell recurrence in pure
  Python, with **every** dimension, input encoding and weight injected through
  the supplied artifact.  It performs no initialisation of its own beyond what
  the artifact contains, and it is **not trained**: its scores are not
  meaningful detection results until an approved artifact and dataset exist.

No third-party dependency is introduced.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable

from .errors import ScoringError
from .features import EventObservation

#: Weight keys expected in an LSTM cell artifact.
GATE_NAMES: tuple[str, ...] = ("i", "f", "o", "g")


def _sigmoid(value: float) -> float:
    if value >= 0.0:
        return 1.0 / (1.0 + math.exp(-value))
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


def _tanh(value: float) -> float:
    return math.tanh(value)


def _as_finite_float(name: str, value: Any) -> float:
    if isinstance(value, bool):
        raise ScoringError(f"{name} must contain numeric values, not bool")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ScoringError(f"{name} is not numeric: {exc}") from exc
    if not math.isfinite(numeric):
        raise ScoringError(f"{name} must be finite, received {numeric!r}")
    return numeric


def _as_finite_tuple(name: str, value: Any) -> tuple[float, ...]:
    if isinstance(value, (str, bytes, Mapping)):
        raise ScoringError(f"{name} must be a sequence of numbers")
    try:
        return tuple(_as_finite_float(name, item) for item in value)
    except ScoringError:
        raise
    except TypeError as exc:
        raise ScoringError(f"{name} must be a sequence of numbers: {exc}") from exc


@dataclass(frozen=True, slots=True)
class LstmState:
    """The documented LSTM hidden state and cell state for one scope.

    The state is an opaque pair of float vectors: its width is whatever the
    supplied artifact produces, because hidden dimensions are not specified by
    the documentation.
    """

    hidden: tuple[float, ...]
    cell: tuple[float, ...]

    def to_dict(self) -> dict[str, list[float]]:
        return {"hidden": list(self.hidden), "cell": list(self.cell)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LstmState":
        if not isinstance(data, Mapping):
            raise ScoringError("invalid LSTM state payload: expected mapping")
        try:
            return cls(
                hidden=_as_finite_tuple("hidden", data["hidden"]),
                cell=_as_finite_tuple("cell", data["cell"]),
            )
        except ScoringError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ScoringError(f"invalid LSTM state payload: {exc}") from exc


@runtime_checkable
class SequenceScorer(Protocol):
    """Narrow model interface used by the sequence engine."""

    def initial_state(self) -> LstmState:
        """Return the state to use before a scope's first processed event."""

    def step(
        self, state: LstmState, observation: EventObservation
    ) -> tuple[LstmState, float]:
        """Consume one observation and return the next state and its score."""


def _as_matrix(name: str, value: Any) -> list[list[float]]:
    if isinstance(value, (str, bytes, Mapping)):
        raise ScoringError(f"artifact weight {name!r} is not a numeric matrix")
    try:
        matrix: list[list[float]] = []
        for row in value:
            if isinstance(row, (str, bytes, Mapping)):
                raise ScoringError(f"artifact weight {name!r} is not a numeric matrix")
            matrix.append([_as_finite_float(f"artifact weight {name!r}", cell) for cell in row])
    except ScoringError:
        raise
    except (TypeError, ValueError) as exc:
        raise ScoringError(f"artifact weight {name!r} is not a numeric matrix") from exc
    if not matrix or not matrix[0]:
        raise ScoringError(f"artifact weight {name!r} must be a non-empty matrix")
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise ScoringError(f"artifact weight {name!r} has ragged rows")
    return matrix


def _as_vector(name: str, value: Any, expected: int | None = None) -> list[float]:
    if isinstance(value, (str, bytes, Mapping)):
        raise ScoringError(f"{name} is not a numeric vector")
    try:
        vector = [_as_finite_float(name, item) for item in value]
    except ScoringError:
        raise
    except (TypeError, ValueError) as exc:
        raise ScoringError(f"{name} is not a numeric vector") from exc
    if expected is not None and len(vector) != expected:
        raise ScoringError(
            f"{name} has length {len(vector)}, expected {expected}"
        )
    return vector


class LstmCellScorer:
    """Single LSTM cell plus a sigmoid output unit, driven by an artifact.

    Args:
        weights: Mapping containing ``w_i``/``w_f``/``w_o``/``w_g``
            (``hidden x input``), ``u_i``/``u_f``/``u_o``/``u_g``
            (``hidden x hidden``), ``b_i``/``b_f``/``b_o``/``b_g``
            (``hidden``), ``w_out`` (``hidden``) and ``b_out`` (scalar).
        vectorise: Callable turning an :class:`EventObservation` into the
            input vector.  The encoding and input dimension are supplied by
            the artifact owner; this module does not choose them.
        initial_hidden/initial_cell: Optional starting state.  When omitted the
            state starts at zero, which is the conventional LSTM cell default
            and is recorded here as an implementation choice, not a documented
            parameter.

    Scores are in ``(0, 1)`` because the shared ``SequenceCue`` contract bounds
    ``risk_score`` to ``[0.0, 1.0]``.
    """

    def __init__(
        self,
        weights: Mapping[str, Any],
        *,
        vectorise: Callable[[EventObservation], Sequence[float]],
        initial_hidden: Sequence[float] | None = None,
        initial_cell: Sequence[float] | None = None,
    ) -> None:
        missing = [
            key
            for gate in GATE_NAMES
            for key in (f"w_{gate}", f"u_{gate}", f"b_{gate}")
            if key not in weights
        ]
        for key in ("w_out", "b_out"):
            if key not in weights:
                missing.append(key)
        if missing:
            raise ScoringError(f"artifact is missing weights: {', '.join(sorted(missing))}")

        self._w = {gate: _as_matrix(f"w_{gate}", weights[f"w_{gate}"]) for gate in GATE_NAMES}
        self._u = {gate: _as_matrix(f"u_{gate}", weights[f"u_{gate}"]) for gate in GATE_NAMES}
        self._hidden_size = len(self._w["i"])
        self._input_size = len(self._w["i"][0])

        for gate in GATE_NAMES:
            if len(self._w[gate]) != self._hidden_size:
                raise ScoringError(f"w_{gate} row count does not match the hidden size")
            if len(self._w[gate][0]) != self._input_size:
                raise ScoringError(f"w_{gate} column count does not match the input size")
            if len(self._u[gate]) != self._hidden_size or any(
                len(row) != self._hidden_size for row in self._u[gate]
            ):
                raise ScoringError(f"u_{gate} must be hidden x hidden")
        self._b = {
            gate: _as_vector(f"artifact weight 'b_{gate}'", weights[f"b_{gate}"], self._hidden_size)
            for gate in GATE_NAMES
        }
        self._w_out = _as_vector("artifact weight 'w_out'", weights["w_out"], self._hidden_size)
        self._b_out = _as_finite_float("artifact weight 'b_out'", weights["b_out"])

        if initial_hidden is None:
            self._initial = LstmState(
                hidden=tuple(0.0 for _ in range(self._hidden_size)),
                cell=tuple(0.0 for _ in range(self._hidden_size)),
            )
        else:
            hidden = tuple(_as_vector("initial_hidden", initial_hidden, self._hidden_size))
            cell = (
                tuple(_as_vector("initial_cell", initial_cell, self._hidden_size))
                if initial_cell is not None
                else hidden
            )
            self._initial = LstmState(hidden=hidden, cell=cell)

        self._vectorise = vectorise

    @property
    def input_size(self) -> int:
        return self._input_size

    @property
    def hidden_size(self) -> int:
        return self._hidden_size

    def initial_state(self) -> LstmState:
        return self._initial

    def step(
        self, state: LstmState, observation: EventObservation
    ) -> tuple[LstmState, float]:
        vector = _as_vector("vectorise output", self._vectorise(observation), self._input_size)
        if len(state.hidden) != self._hidden_size or len(state.cell) != self._hidden_size:
            raise ScoringError("incoming state does not match the artifact hidden size")

        gates: dict[str, list[float]] = {}
        for gate in GATE_NAMES:
            row_weights = self._w[gate]
            recurrent = self._u[gate]
            bias = self._b[gate]
            values = []
            for unit in range(self._hidden_size):
                total = bias[unit]
                weighted = row_weights[unit]
                for index, item in enumerate(vector):
                    total += weighted[index] * item
                previous = recurrent[unit]
                for index, item in enumerate(state.hidden):
                    total += previous[index] * item
                values.append(total)
            gates[gate] = values

        input_gate = [_sigmoid(v) for v in gates["i"]]
        forget_gate = [_sigmoid(v) for v in gates["f"]]
        output_gate = [_sigmoid(v) for v in gates["o"]]
        candidate = [_tanh(v) for v in gates["g"]]

        new_cell = tuple(
            forget_gate[unit] * state.cell[unit] + input_gate[unit] * candidate[unit]
            for unit in range(self._hidden_size)
        )
        new_hidden = tuple(
            output_gate[unit] * _tanh(new_cell[unit]) for unit in range(self._hidden_size)
        )

        activation = self._b_out + sum(
            weight * value for weight, value in zip(self._w_out, new_hidden)
        )
        score = _sigmoid(activation)
        return LstmState(hidden=new_hidden, cell=new_cell), validate_score(score)


def validate_score(score: float) -> float:
    """Reject scores the shared contract could not represent."""
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        raise ScoringError(f"scorer returned a non-numeric score: {score!r}")
    value = float(score)
    if math.isnan(value) or value < 0.0 or value > 1.0:
        raise ScoringError(f"scorer returned {value!r}, which is outside [0.0, 1.0]")
    return value
