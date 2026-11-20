# Sequential log-context model

> **Status:** Proposed design. This LSTM model is not implemented in the current repository.

## Goal

Some attacks consist of individually low-risk events spread across multiple log batches. For example, batch 12 and batch 13 may each look benign when evaluated alone, while their ordered combination indicates an attack pattern. The proposed LSTM model provides bounded historical context while processing the current batch.

It complements KCP and the multi-agent workflow; it does not replace forensic evidence, ATT&CK/CVE retrieval, or agent reasoning.

## Position in the flow

```text
Raw logs
   |
   v
KCP: parse, normalize, preserve evidence references
   |
   +--> persisted event sequence / context window
   |
   v
LSTM sequence model
   |  prior state + current batch features
   v
cross-batch risk score and sequence signals
   |
   v
Multi-agent orchestrator: correlate, investigate, and generate findings
```

The LSTM output is a prioritization signal and candidate sequence, not a final incident verdict.

## Context scope

The model must not maintain one global state for every event in the environment. Context is stored separately for a defined investigation scope, such as a host, user/account, process tree, network flow, or correlation key selected by KCP. A context record contains:

- `scope_key` and scope type.
- Ordered normalized-event feature vectors.
- LSTM hidden state and cell state after the last processed event.
- Last event timestamp, model version, and source/evidence references.
- Expiry and reset status.

This avoids unrelated hosts or users contaminating one another's sequence history.

## Batch processing behavior

For each scope, events are ordered by event time. The model processes the current batch with the saved LSTM state from the prior batch:

```text
batch 12 events + state before batch 12
              |
              v
       state after batch 12
              |
              +--> persist for this scope
              |
batch 13 events + state after batch 12
              |
              v
       cross-batch score and state after batch 13
```

The system retains a bounded event window in addition to the LSTM state. That window lets analysts and downstream agents inspect the actual events that led to a score; the hidden state alone is not auditable evidence.

When events arrive late or out of order, the system should replay the affected bounded window in event-time order rather than append them to a later state. A batch boundary must not be treated as an attack boundary.

## Input features

KCP produces the model inputs. The first model version should use features that can be traced to normalized logs, for example:

- Event type, outcome, severity, and source category.
- Time since the previous event and time-of-day bucket.
- Host, account, process, service, and network relationship features.
- Authentication, privilege, process, file, and network activity indicators when present.
- Counts or novelty indicators within the current bounded window.

Raw identifiers and free-text logs should remain linked as evidence, but feature design must avoid unintentionally exposing sensitive data or creating an unbounded vocabulary.

## Model outputs and handoff

For each current event or completed sequence, the LSTM can produce:

- A sequence anomaly or risk score.
- A predicted sequence class, if trained labels support one.
- The event-window references that produced the signal.
- Model version, threshold, and confidence/calibration information.

If a score crosses a defined threshold, it creates an investigation cue for the orchestrator. The orchestrator then assigns sub-agents to review the retained events, retrieve relevant ATT&CK/CVE knowledge from Cognee, and determine whether the pattern is evidence-supported.

## State lifecycle and safeguards

- Persist state durably per scope and model version.
- Expire inactive context after a defined time-to-live; do not carry old state indefinitely.
- Reset state on material schema/model changes, corrupted state, or a clearly defined scope identity change.
- Keep the event window and evidence references for every alert-worthy score.
- Recompute a bounded sequence when late events arrive.
- Monitor state size, sequence length, inference latency, and drift.
- Do not treat a high LSTM score as proof of an attack or automatic authority to remediate.

## Training and evaluation

Training examples must preserve event order and prevent future events from leaking into earlier training samples. Split training, validation, and test data by time and, where possible, by host or environment.

Evaluate both event-level and sequence-level behavior, including:

- Whether a pattern spanning adjacent batches is detected when neither batch alone is sufficient.
- False-positive rate for normal long-running workflows.
- Recall and precision on labeled multi-stage attack sequences.
- Score calibration, alert latency, and state-expiry effects.
- Robustness to missing, duplicated, delayed, and out-of-order logs.

## First implementation decision points

1. Select scope keys and context time-to-live values for each log source.
2. Define the normalized event schema and initial feature set.
3. Choose the sequence/window length and state-store design.
4. Establish labelled attack and benign sequence datasets.
5. Define escalation thresholds and the orchestrator handoff contract.
6. Compare the LSTM against simpler baselines before adopting it as a production component.
