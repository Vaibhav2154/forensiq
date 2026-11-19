"""Deterministic NumPy BPTT + Adam trainer for ForensIQ's single-layer LSTM scorer."""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

from contracts.models import EvidenceReference, NormalizedEvent

from .features import FeatureExtractor
from .scoring import LstmCellScorer
from .vectorizer import VECTOR_SIZE, vectorize_observation

DEFAULT_ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "lstm_v1_0.json"
DEFAULT_MODEL_VERSION = "lstm-sequence-v1.0"
DEFAULT_THRESHOLD = 0.70

_BASE_TIME = datetime(2026, 11, 19, 9, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class TrainingSample:
    """One labeled event sequence ready for LSTM BPTT."""

    name: str
    vectors: np.ndarray  # shape (T, D)
    targets: np.ndarray  # shape (T,)
    weights: np.ndarray  # shape (T,)


def _sigmoid_arr(x: np.ndarray) -> np.ndarray:
    x_clipped = np.clip(x, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-x_clipped))


def _make_event(
    event_id: str,
    offset_seconds: float,
    event_type: str,
    *,
    scope_key: str = "host:workstation-17|account:alex",
    source: str = "linux-auth",
    features: dict[str, Any] | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        scope_key=scope_key,
        event_time=_BASE_TIME + timedelta(seconds=offset_seconds),
        event_type=event_type,
        source=source,
        features=features or {"host": "workstation-17", "account": "alex"},
        evidence_ref=EvidenceReference(
            reference_id=f"ref-{event_id}",
            uri=f"s3://forensiq-evidence/{event_id}.log",
        ),
    )


def _featurize_sequence(
    name: str,
    specs: list[tuple[float, str, dict[str, Any], float, float]],
    extractor: FeatureExtractor,
    seq_idx: int,
) -> TrainingSample:
    """Convert raw event specs `(dt_sec, event_type, features, target, mask)` via FeatureExtractor."""
    t = 0.0
    prev_time: datetime | None = None
    observations = []
    vectors: list[list[float]] = []
    targets: list[float] = []
    weights: list[float] = []

    for step_idx, (dt_sec, event_type, feat, target, mask) in enumerate(specs):
        t += dt_sec
        evt = _make_event(
            f"train-{seq_idx}-{step_idx}",
            t,
            event_type,
            features=feat,
        )
        obs = extractor.build(
            evt,
            previous_event_time=prev_time,
            window_observations=observations,
        )
        observations.append(obs)
        prev_time = evt.event_time
        vectors.append(vectorize_observation(obs))
        targets.append(target)
        weights.append(mask)

    return TrainingSample(
        name=name,
        vectors=np.asarray(vectors, dtype=np.float64),
        targets=np.asarray(targets, dtype=np.float64),
        weights=np.asarray(weights, dtype=np.float64),
    )


def build_training_corpus() -> list[TrainingSample]:
    """Build a balanced dataset passed through the live feature pipeline."""
    extractor = FeatureExtractor()
    raw_sequences: list[tuple[str, list[tuple[float, str, dict[str, Any], float, float]]]] = []

    def auth_fail(
        dt: float,
        target: float = 0.0,
        mask: float = 1.0,
        *,
        with_ip: bool = True,
    ) -> tuple[float, str, dict[str, Any], float, float]:
        feat: dict[str, Any] = {
            "host": "workstation-17",
            "account": "alex",
            "outcome": "failure",
        }
        if with_ip:
            feat["remote_ip"] = "203.0.113.25"
        return (dt, "authentication_failure", feat, target, mask)

    def auth_ok(
        dt: float, target: float = 0.0, mask: float = 1.0
    ) -> tuple[float, str, dict[str, Any], float, float]:
        return (
            dt,
            "authentication_success",
            {
                "host": "workstation-17",
                "account": "alex",
                "outcome": "success",
                "remote_ip": "10.0.0.15",
            },
            target,
            mask,
        )

    def priv_esc(
        dt: float,
        target: float,
        *,
        outcome: str | None = "executed",
        mask: float = 1.0,
    ) -> tuple[float, str, dict[str, Any], float, float]:
        feat: dict[str, Any] = {
            "host": "workstation-17",
            "account": "alex",
            "process": "/usr/bin/sudo",
        }
        if outcome is not None:
            feat["outcome"] = outcome
        return (dt, "privilege_escalation", feat, target, mask)

    def sec_alert(
        dt: float, target: float, mask: float = 1.0
    ) -> tuple[float, str, dict[str, Any], float, float]:
        return (
            dt,
            "security_alert",
            {
                "host": "workstation-17",
                "account": "alex",
                "severity": "ALERT",
                "remote_ip": "203.0.113.25",
            },
            target,
            mask,
        )

    def net_err(
        dt: float, target: float = 0.0, mask: float = 1.0
    ) -> tuple[float, str, dict[str, Any], float, float]:
        return (
            dt,
            "network_connection_error",
            {"host": "workstation-17", "remote_ip": "198.51.100.8", "outcome": "error"},
            target,
            mask,
        )

    def app_err(
        dt: float, sev: str = "ERROR", target: float = 0.0
    ) -> tuple[float, str, dict[str, Any], float, float]:
        return (
            dt,
            "application_error",
            {"host": "workstation-17", "process": "sshd", "severity": sev},
            target,
            1.0,
        )

    def app_warn(dt: float) -> tuple[float, str, dict[str, Any], float, float]:
        return (
            dt,
            "application_warning",
            {"host": "workstation-17", "service": "cron", "severity": "WARNING"},
            0.0,
            1.0,
        )

    def sys_log(dt: float) -> tuple[float, str, dict[str, Any], float, float]:
        return (
            dt,
            "system_log_event",
            {"host": "workstation-17", "service": "systemd"},
            0.0,
            1.0,
        )

    # --- Positive Pattern 1: Auth failure(s) -> privilege escalation ---
    for n_fails in (1, 2, 3):
        for outcome in ("success", "executed", None):
            for gap in (30.0, 120.0, 240.0, 600.0):
                steps = [auth_fail(0.0 if i == 0 else 45.0) for i in range(n_fails)]
                steps.append(priv_esc(gap, 1.0, outcome=outcome))
                raw_sequences.append((f"pos_af{n_fails}_pe_{outcome}_{int(gap)}", steps))

    # Auth failure(s) with routine intermediate noise before privilege escalation
    for mid in (sys_log(60.0), app_warn(90.0), net_err(45.0)):
        raw_sequences.append(
            (
                "pos_af_noise_pe",
                [auth_fail(0.0), auth_fail(60.0), mid, priv_esc(120.0, 1.0, outcome="executed")],
            )
        )
        raw_sequences.append(
            (
                "pos_af_noise_pe_succ",
                [auth_fail(0.0), mid, priv_esc(90.0, 1.0, outcome="success")],
            )
        )

    # Routine prefix before auth failure -> privilege escalation
    for outcome in ("success", "executed"):
        raw_sequences.append(
            (
                f"pos_prefix_af_pe_{outcome}",
                [sys_log(0.0), auth_ok(120.0), auth_fail(60.0), auth_fail(45.0), priv_esc(180.0, 1.0, outcome=outcome)],
            )
        )

    # --- Positive Pattern 2: Auth failure(s) -> auth success -> privilege escalation / alert ---
    for n_fails in (1, 2, 3):
        for outcome in ("success", "executed"):
            raw_sequences.append(
                (
                    f"pos_af{n_fails}_ok_pe_{outcome}",
                    [auth_fail(0.0 if i == 0 else 30.0) for i in range(n_fails)]
                    + [auth_ok(30.0), priv_esc(60.0, 1.0, outcome=outcome)],
                )
            )
        raw_sequences.append(
            (
                f"pos_af{n_fails}_ok_alert",
                [auth_fail(0.0 if i == 0 else 30.0) for i in range(n_fails)]
                + [auth_ok(45.0), sec_alert(90.0, 1.0)],
            )
        )

    # --- Positive Pattern 3: Rapid auth-failure burst (5+ failures <= 120s apart) ---
    for burst_len in (5, 6, 7):
        for dt in (10.0, 30.0, 75.0):
            burst_steps = []
            for idx in range(burst_len):
                step_dt = 0.0 if idx == 0 else dt
                if idx < 3:
                    target, mask = 0.0, 1.0
                elif idx == 3:
                    target, mask = 0.0, 0.0  # smooth transition around 4th attempt
                else:
                    target, mask = 1.0, 1.0
                burst_steps.append(auth_fail(step_dt, target=target, mask=mask))
            raw_sequences.append((f"pos_burst_{burst_len}_{int(dt)}", burst_steps))

    # --- Positive Pattern 4: Network errors -> auth failure -> escalation/alert ---
    for n_net in (2, 3):
        raw_sequences.append(
            (
                f"pos_net{n_net}_af_pe",
                [net_err(0.0 if i == 0 else 20.0) for i in range(n_net)]
                + [auth_fail(30.0), priv_esc(90.0, 1.0, outcome="executed")],
            )
        )
        raw_sequences.append(
            (
                f"pos_net{n_net}_af_alert",
                [net_err(0.0 if i == 0 else 20.0) for i in range(n_net)]
                + [auth_fail(30.0), sec_alert(90.0, 1.0)],
            )
        )

    # --- Positive Pattern 5: Error / alert -> privilege escalation ---
    for sev in ("ERROR", "CRITICAL", "ALERT"):
        raw_sequences.append(
            (
                f"pos_err_{sev}_pe",
                [app_err(0.0, sev=sev), priv_esc(60.0, 1.0, outcome="executed")],
            )
        )
        raw_sequences.append(
            (
                f"pos_err_{sev}_pe_succ",
                [app_err(0.0, sev=sev), priv_esc(60.0, 1.0, outcome="success")],
            )
        )
    raw_sequences.append(
        ("pos_alert_pe", [sec_alert(0.0, 0.0), priv_esc(60.0, 1.0, outcome="executed")])
    )
    raw_sequences.append(
        ("pos_alert_pe_succ", [sec_alert(0.0, 0.0), priv_esc(60.0, 1.0, outcome="success")])
    )

    # --- Negative Pattern 1: Auth failure(s) alone (1-3 events) ---
    for n_fails in (1, 2, 3):
        for dt in (20.0, 60.0, 180.0):
            for repeat in range(2):
                steps = [auth_fail(0.0 if i == 0 else dt) for i in range(n_fails)]
                raw_sequences.append((f"neg_af{n_fails}_{int(dt)}_{repeat}", steps))

    # --- Negative Pattern 2: Isolated privilege escalation alone ---
    for outcome in ("success", "executed", None):
        for repeat in range(4):
            raw_sequences.append(
                (f"neg_pe_alone_{outcome}_{repeat}", [priv_esc(0.0, 0.0, outcome=outcome)])
            )

    # --- Negative Pattern 3: Normal admin workflow (auth_success -> routine logs / sudo) ---
    for outcome in ("success", "executed", None):
        for gap in (15.0, 60.0, 300.0):
            raw_sequences.append(
                (
                    f"neg_admin_ok_pe_{outcome}_{int(gap)}",
                    [auth_ok(0.0), priv_esc(gap, 0.0, outcome=outcome)],
                )
            )
            raw_sequences.append(
                (
                    f"neg_admin_ok_sys_pe_{outcome}_{int(gap)}",
                    [auth_ok(0.0), sys_log(30.0), priv_esc(gap, 0.0, outcome=outcome)],
                )
            )
    raw_sequences.append(
        ("neg_admin_multi_ok_pe", [auth_ok(0.0), auth_ok(120.0), priv_esc(60.0, 0.0, outcome="executed")])
    )
    raw_sequences.append(
        ("neg_admin_ok_sys", [auth_ok(0.0), sys_log(20.0), app_warn(40.0), sys_log(60.0)])
    )

    # --- Negative Pattern 4: Single mistyped password -> auth_success -> routine logs ---
    for repeat in range(3):
        raw_sequences.append(
            (
                f"neg_typo_ok_{repeat}",
                [auth_fail(0.0), auth_ok(20.0), sys_log(40.0), app_warn(80.0)],
            )
        )

    # --- Negative Pattern 5: Routine noise & isolated errors/warnings/alerts ---
    raw_sequences.append(
        ("neg_sys_only", [sys_log(0.0), sys_log(30.0), sys_log(90.0), sys_log(120.0)])
    )
    raw_sequences.append(
        ("neg_warn_err_only", [app_warn(0.0), app_warn(40.0), app_err(60.0, "WARNING"), sys_log(80.0)])
    )
    raw_sequences.append(
        ("neg_err_routine", [app_err(0.0, "ERROR"), sys_log(60.0), app_warn(120.0)])
    )
    raw_sequences.append(
        ("neg_net_err_only", [net_err(0.0), net_err(30.0), net_err(60.0), sys_log(120.0)])
    )
    raw_sequences.append(("neg_single_alert", [sec_alert(0.0, 0.0)]))
    raw_sequences.append(
        ("neg_single_alert_followed_by_sys", [sec_alert(0.0, 0.0), sys_log(60.0), sys_log(120.0)])
    )

    return [
        _featurize_sequence(name, specs, extractor, idx)
        for idx, (name, specs) in enumerate(raw_sequences)
    ]


def _init_weights(hidden_size: int, input_size: int, seed: int = 42) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    scale_x = math.sqrt(2.0 / (input_size + hidden_size))
    scale_h = math.sqrt(1.0 / hidden_size)
    params: dict[str, np.ndarray] = {}
    for gate in ("i", "f", "o", "g"):
        params[f"w_{gate}"] = rng.normal(0.0, scale_x, size=(hidden_size, input_size))
        q, _ = np.linalg.qr(rng.normal(0.0, 1.0, size=(hidden_size, hidden_size)))
        params[f"u_{gate}"] = q * scale_h
        params[f"b_{gate}"] = np.full(
            hidden_size, 1.0 if gate == "f" else 0.0, dtype=np.float64
        )
    params["w_out"] = rng.normal(0.0, scale_h, size=(hidden_size,))
    params["b_out"] = np.array([-0.5], dtype=np.float64)
    return params


def _forward_and_backward(
    params: dict[str, np.ndarray],
    sample: TrainingSample,
) -> tuple[float, dict[str, np.ndarray]]:
    """Run exact LSTM forward pass + BPTT gradients for one sequence."""
    vectors = sample.vectors
    targets = sample.targets
    weights = sample.weights
    t_len, _ = vectors.shape
    hidden_size = params["w_i"].shape[0]

    h_list = [np.zeros(hidden_size, dtype=np.float64)]
    c_list = [np.zeros(hidden_size, dtype=np.float64)]
    caches: list[tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, float, float]] = []

    loss = 0.0
    eps = 1e-12

    for t in range(t_len):
        x_t = vectors[t]
        h_prev = h_list[-1]
        c_prev = c_list[-1]

        a_i = params["w_i"] @ x_t + params["u_i"] @ h_prev + params["b_i"]
        a_f = params["w_f"] @ x_t + params["u_f"] @ h_prev + params["b_f"]
        a_o = params["w_o"] @ x_t + params["u_o"] @ h_prev + params["b_o"]
        a_g = params["w_g"] @ x_t + params["u_g"] @ h_prev + params["b_g"]

        i_t = _sigmoid_arr(a_i)
        f_t = _sigmoid_arr(a_f)
        o_t = _sigmoid_arr(a_o)
        g_t = np.tanh(a_g)

        c_t = f_t * c_prev + i_t * g_t
        tanh_c = np.tanh(c_t)
        h_t = o_t * tanh_c

        z_t = float(params["w_out"] @ h_t + params["b_out"][0])
        y_hat = float(_sigmoid_arr(np.array([z_t]))[0])
        y_true = float(targets[t])
        m_t = float(weights[t])

        if m_t > 0.0:
            loss += -m_t * (
                y_true * math.log(max(y_hat, eps))
                + (1.0 - y_true) * math.log(max(1.0 - y_hat, eps))
            )

        h_list.append(h_t)
        c_list.append(c_t)
        caches.append((x_t, i_t, f_t, o_t, g_t, tanh_c, y_hat, y_true))

    grads = {k: np.zeros_like(v) for k, v in params.items()}
    dh_next = np.zeros(hidden_size, dtype=np.float64)
    dc_next = np.zeros(hidden_size, dtype=np.float64)

    for t in range(t_len - 1, -1, -1):
        x_t, i_t, f_t, o_t, g_t, tanh_c, y_hat, y_true = caches[t]
        h_t = h_list[t + 1]
        h_prev = h_list[t]
        c_prev = c_list[t]
        m_t = float(weights[t])

        dz = m_t * (y_hat - y_true)
        grads["w_out"] += dz * h_t
        grads["b_out"][0] += dz

        dh = dz * params["w_out"] + dh_next
        do = dh * tanh_c
        da_o = do * o_t * (1.0 - o_t)

        dc = dh * o_t * (1.0 - tanh_c * tanh_c) + dc_next
        df = dc * c_prev
        da_f = df * f_t * (1.0 - f_t)

        di = dc * g_t
        da_i = di * i_t * (1.0 - i_t)

        dg = dc * i_t
        da_g = dg * (1.0 - g_t * g_t)

        gate_deltas = {"i": da_i, "f": da_f, "o": da_o, "g": da_g}
        dh_prev = np.zeros(hidden_size, dtype=np.float64)
        for gate, da in gate_deltas.items():
            grads[f"w_{gate}"] += np.outer(da, x_t)
            grads[f"u_{gate}"] += np.outer(da, h_prev)
            grads[f"b_{gate}"] += da
            dh_prev += params[f"u_{gate}"].T @ da

        dh_next = dh_prev
        dc_next = dc * f_t

    return loss, grads


def train_lstm_artifact(
    *,
    hidden_size: int = 12,
    epochs: int = 450,
    learning_rate: float = 0.02,
    weight_decay: float = 5e-5,
    seed: int = 42,
    model_version: str = DEFAULT_MODEL_VERSION,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    """Train the LSTM weights using Adam + BPTT and return JSON-serializable artifact."""
    corpus = build_training_corpus()
    total_active_steps = float(sum(float(sample.weights.sum()) for sample in corpus))
    params = _init_weights(hidden_size=hidden_size, input_size=VECTOR_SIZE, seed=seed)

    m_state = {k: np.zeros_like(v) for k, v in params.items()}
    v_state = {k: np.zeros_like(v) for k, v in params.items()}
    beta1, beta2, eps = 0.9, 0.999, 1e-8

    rng = random.Random(seed)
    final_loss = 0.0
    step_num = 0

    for epoch in range(1, epochs + 1):
        indices = list(range(len(corpus)))
        rng.shuffle(indices)

        total_loss = 0.0
        agg_grads = {k: np.zeros_like(v) for k, v in params.items()}

        for idx in indices:
            loss, grads = _forward_and_backward(params, corpus[idx])
            total_loss += loss
            for key, g in grads.items():
                agg_grads[key] += g

        final_loss = total_loss / max(total_active_steps, 1.0)
        step_num += 1

        grad_norm_sq = sum(float(np.sum((g / total_active_steps) ** 2)) for g in agg_grads.values())
        grad_norm = math.sqrt(grad_norm_sq)
        clip_scale = min(1.0, 5.0 / max(grad_norm, 1e-12))

        for key in params:
            g = (agg_grads[key] / total_active_steps) * clip_scale
            if not key.startswith("b_"):
                g = g + weight_decay * params[key]
            m_state[key] = beta1 * m_state[key] + (1.0 - beta1) * g
            v_state[key] = beta2 * v_state[key] + (1.0 - beta2) * (g * g)
            m_hat = m_state[key] / (1.0 - beta1**step_num)
            v_hat = v_state[key] / (1.0 - beta2**step_num)
            params[key] = params[key] - learning_rate * m_hat / (np.sqrt(v_hat) + eps)

        if epoch % 100 == 0 or epoch == epochs:
            print(f"[epoch {epoch:03d}/{epochs}] avg_bce_loss={final_loss:.6f}")

    serializable_weights: dict[str, Any] = {}
    for key, arr in params.items():
        if key == "b_out":
            serializable_weights[key] = round(float(arr[0]), 8)
        elif arr.ndim == 1:
            serializable_weights[key] = [round(float(x), 8) for x in arr.tolist()]
        else:
            serializable_weights[key] = [
                [round(float(x), 8) for x in row] for row in arr.tolist()
            ]

    return {
        "model_version": model_version,
        "architecture": "single_layer_lstm",
        "input_size": VECTOR_SIZE,
        "hidden_size": hidden_size,
        "threshold": threshold,
        "weights": serializable_weights,
        "training_metadata": {
            "epochs": epochs,
            "learning_rate": learning_rate,
            "weight_decay": weight_decay,
            "seed": seed,
            "num_sequences": len(corpus),
            "active_timesteps": int(total_active_steps),
            "final_avg_bce_loss": round(final_loss, 6),
        },
    }


def save_artifact(artifact: dict[str, Any], path: Path = DEFAULT_ARTIFACT_PATH) -> Path:
    """Write trained LSTM weights JSON artifact to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    return path


def verify_artifact_with_scorer(artifact: dict[str, Any]) -> None:
    """Run trained weights through LstmCellScorer on canonical attack vs benign scenarios."""
    scorer = LstmCellScorer(artifact["weights"], vectorise=vectorize_observation)
    extractor = FeatureExtractor()

    def score_events(events: list[NormalizedEvent]) -> list[float]:
        state = scorer.initial_state()
        prev_t: datetime | None = None
        obs_hist = []
        scores: list[float] = []
        for evt in events:
            obs = extractor.build(evt, previous_event_time=prev_t, window_observations=obs_hist)
            state, sc = scorer.step(state, obs)
            obs_hist.append(obs)
            prev_t = evt.event_time
            scores.append(sc)
        return scores

    scenarios: dict[str, list[NormalizedEvent]] = {
        "batch_12_alone": [
            _make_event("s1-1", 0, "authentication_failure", features={"host": "workstation-17", "account": "alex", "outcome": "failure", "remote_ip": "203.0.113.25"}),
            _make_event("s1-2", 60, "authentication_failure", features={"host": "workstation-17", "account": "alex", "outcome": "failure", "remote_ip": "203.0.113.25"}),
        ],
        "batch_13_alone": [
            _make_event("s2-1", 0, "privilege_escalation", source="linux-audit", features={"host": "workstation-17", "account": "alex", "process": "/usr/bin/sudo", "outcome": "success"}),
        ],
        "batch_12_plus_13": [
            _make_event("s3-1", 0, "authentication_failure", features={"host": "workstation-17", "account": "alex", "outcome": "failure", "remote_ip": "203.0.113.25"}),
            _make_event("s3-2", 60, "authentication_failure", features={"host": "workstation-17", "account": "alex", "outcome": "failure", "remote_ip": "203.0.113.25"}),
            _make_event("s3-3", 300, "privilege_escalation", source="linux-audit", features={"host": "workstation-17", "account": "alex", "process": "/usr/bin/sudo", "outcome": "success"}),
        ],
        "kcp_ssh_fail_then_sudo_executed": [
            _make_event("s4-1", 0, "authentication_failure", features={"host": "srv-1", "account": "alex", "outcome": "failure", "remote_ip": "203.0.113.25"}),
            _make_event("s4-2", 180, "privilege_escalation", features={"host": "srv-1", "account": "alex", "process": "sudo", "outcome": "executed"}),
        ],
        "benign_admin_login_then_sudo": [
            _make_event("s5-1", 0, "authentication_success", features={"host": "srv-1", "account": "alex", "outcome": "success", "remote_ip": "10.0.0.5"}),
            _make_event("s5-2", 60, "privilege_escalation", features={"host": "srv-1", "account": "alex", "process": "sudo", "outcome": "executed"}),
        ],
    }

    for label, evts in scenarios.items():
        sc = score_events(evts)
        print(f"Scenario {label}: {[round(x, 4) for x in sc]}")


if __name__ == "__main__":
    artifact = train_lstm_artifact()
    saved_path = save_artifact(artifact)
    print(f"Saved trained LSTM artifact to {saved_path}")
    verify_artifact_with_scorer(artifact)

