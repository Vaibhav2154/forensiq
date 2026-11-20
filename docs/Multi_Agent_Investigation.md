# Multi-agent investigation

## Purpose

ForensIQ uses a multi-agent investigation workflow rather than one undifferentiated analysis call. An **orchestrator** receives the prepared log investigation, assigns focused tasks to sub-agents, collects their results, resolves gaps or conflicts, and generates the final evidence-backed investigation output.

## Investigation flow

```text
Log sources
  |  CLI collection, ZIP upload, future connectors
  v
KCP for logs
  |  parse, normalize, extract entities, group related events,
  |  retain source references
  v
LSTM sequence model
  |  retain bounded per-scope context across batches
  |  emit cross-batch investigation cues
  v
Investigation orchestrator
  |-- assigns event analysis
  |-- assigns ATT&CK / CVE retrieval from Cognee
  |-- assigns correlation and timeline work
  |-- assigns attack-path hypothesis analysis
  |-- assigns recommendation drafting when justified
  v
Evidence-backed findings, attack-path view, and final report
```

## Orchestrator responsibilities

The orchestrator owns the investigation lifecycle. It should:

1. Create shared investigation state from KCP log output.
2. Select and assign tasks to the appropriate sub-agents.
3. Pass scoped evidence and source references to each agent.
4. Request clarification or additional analysis when results conflict or lack support.
5. Combine supported outputs into a coherent timeline, findings, and report.
6. Label confidence, uncertainty, and the difference between evidence and inference.
7. Retain an audit trail of task assignments, inputs, outputs, and the generated result.

The initial agent list is intentionally flexible. The orchestrator—not the presence of a fixed set of agents—is the required design element.

## Candidate sub-agent tasks

- **Event analysis:** Interpret individual normalized events and flag noteworthy activity.
- **Sequence analysis:** Review LSTM cross-batch signals against the retained event window; do not accept a model score as proof.
- **Knowledge enrichment:** Retrieve relevant MITRE Enterprise ATT&CK and CVE records from Cognee's OKF data.
- **Correlation and timeline analysis:** Relate events across hosts, entities, and time.
- **Attack-path analysis:** Form and test possible sequences of attacker activity using the available evidence.
- **Recommendation drafting:** Propose preventive actions only when linked to supported findings.

Sub-agent conclusions are inputs to the orchestrator; they are not automatically final findings.

## Output requirements

The generated investigation output should include:

- Direct observations and their supporting log references.
- Relevant ATT&CK and CVE records retrieved from Cognee.
- A timeline and, where supported, an attack-path hypothesis.
- Relationships, with their evidence and reasoning.
- Confidence and uncertainty for material conclusions.
- Recommendations linked to evidence, if recommendations are produced.

An attack-path visual must clearly distinguish observed facts from inferred or unconfirmed links. Missing evidence must remain visible.

## Safety boundaries

- Do not treat an ATT&CK or CVE retrieval as proof of compromise.
- Do not create unsupported ATT&CK or CVE mappings.
- Do not silently execute remediation proposed by an agent.
- Preserve original log evidence or durable references before compression and analysis.

## Open decisions

1. What shared-state and agent input/output schema will be used?
2. Which agent tasks are required for the first release?
3. How will the orchestrator evaluate conflicting sub-agent results?
4. Which model provider interface will power the agents?
5. What latency and cost limits apply to an investigation?
