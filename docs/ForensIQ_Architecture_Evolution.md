# ForensIQ architecture evolution

> **Status:** Proposed architecture. The components described here are design targets, not claims of implementation in the current LogIQ codebase.

This document is the entry point for the ForensIQ evolution design. The previous single document has been split by responsibility:

- [Knowledge pipeline and OKF](Knowledge_Pipeline_and_OKF.md) defines KCP, the knowledge inputs, the OKF representation, and Cognee's role.
- [Multi-agent investigation](Multi_Agent_Investigation.md) defines how an orchestrator delegates investigation work to sub-agents and produces evidence-backed results.
- [Sequential log-context model](Sequential_Log_Context_Model.md) defines the proposed LSTM model that carries bounded context across log batches.
- [Platform evolution and delivery](Platform_Evolution_and_Delivery.md) covers the existing LogIQ baseline, migration, dashboard, remediation, governance, roadmap, and open decisions.

## Architecture at a glance

```text
MITRE Enterprise ATT&CK data + CVE JSON
                 |
                 v
Knowledge Compression Pipeline (KCP)
                 |
                 v
OKF records in Cognee
                 |
                 v
Logs --> KCP --> Multi-agent orchestrator --> Findings and reports
                              |                    |
                              +-- delegates to -----+
                                  specialist agents

KCP log events --> LSTM sequence model --> cross-batch risk signals
```

**Important boundary:** In this proposal, the Organization Knowledge Framework (OKF) is not an organization-context store. It is the compressed, structured representation of MITRE Enterprise ATT&CK data and CVE JSON in Cognee. Organization-specific context is not assumed to be an OKF input or responsibility.
