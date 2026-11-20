# Platform evolution and delivery

> **Status:** Proposed architecture. The new KCP, Cognee/OKF, and multi-agent components are not implemented features.

## Existing baseline

The current LogIQ repository provides a useful foundation:

- CLI-based monitoring and log collection.
- FastAPI backend and monitoring/analysis routes.
- Next.js dashboard.
- Existing AI, retrieval, storage, encryption, and MITRE-related code.

The legacy pre-RAG classifier is not part of the target flow. KCP should prepare and retain evidence rather than recreate a `FILTER_OUT` / `SEND_TO_RAG` gate.

AWS Bedrock is excluded from the proposed target architecture. The existing Gemini service may remain behind a provider-neutral interface until a model-provider decision is made.

## Repository migration map

| Existing area | Suggested treatment |
| --- | --- |
| `cli_agent/cli_tool.py`, log extraction | Reuse or adapt for collection and approved remediation. |
| `cli_agent/ai_agent.py` | Reassess useful analysis logic for sub-agent tasks. |
| `cli_agent/Scripts/prerag_classifier.py` | Exclude from the new KCP-to-orchestrator flow. |
| `server/main.py` and routers | Retain foundation; add ingestion and investigation coordination. |
| `server/services/mitre_validation_service.py` | Reuse only if it supports evidence-backed mappings. |
| `server/services/chromadb_service.py` | Evaluate against Cognee; retain or remove only after validation. |
| `server/services/aws_bedrock_service.py` | Exclude from target service wiring. |
| Next.js client | Add investigation, timeline, evidence, and attack-path views. |

Verify real runtime behavior and tests before reusing any module.

## Dashboard, recommendations, and remediation

The dashboard should show incident summaries, timeline, affected systems where known, retrieved ATT&CK/CVE context, source evidence, and clear confidence labels. It must not present an inferred relationship as a proven fact.

Recommendations must explain their supporting evidence. Any CLI-assisted remediation follows this sequence:

1. The system proposes an action with its target and expected effect.
2. An administrator reviews and explicitly approves it.
3. The CLI validates applicability and authorization.
4. The action runs with appropriate permissions.
5. Result, audit information, and recovery outcome are recorded.

High-impact actions require approval, authorization checks, audit logs, and a rollback or recovery strategy where feasible.

## Delivery roadmap

1. **Stabilize the baseline:** map current CLI-to-backend-to-dashboard behavior and document reusable interfaces.
2. **Build KCP:** define log and knowledge schemas, source references, parsing, normalization, and compression evaluation.
3. **Build Cognee/OKF ingestion:** load compressed MITRE Enterprise ATT&CK and CVE JSON into Cognee and validate retrieval.
4. **Implement sequence context and orchestration:** add the LSTM's bounded, per-scope state and event-window retention; then define shared state, sub-agent contracts, task assignment, and evidence-backed result generation.
5. **Add analyst views:** build timeline, evidence, and attack-path visualization and validate curated scenarios.
6. **Add controlled remediation:** implement approval, execution, reporting, and audit history.
7. **Evaluate:** measure evidence retention, retrieval relevance, mapping quality, investigation quality, latency, and failure handling.

## Cross-cutting principles

- Preserve original forensic evidence.
- Maintain source provenance and data versioning.
- Separate source facts, observations, hypotheses, and conclusions.
- Make KCP compression auditable.
- Preserve and bound sequential context so a pattern can span batches without mixing unrelated entities.
- Require explicit authorization for remediation.
- Treat an unimplemented component as proposed until it is built and tested.
