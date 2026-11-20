# ForensIQ developer work plan

## Objective

Build the proposed ForensIQ backend and terminal experience in parallel
without developers editing the same implementation files.

The initial scope is backend and CLI/TUI only. Frontend work and the
multi-agent system are intentionally deferred.

## Mandatory first step: shared contracts

Before starting feature work, every developer must read the contract
models in `server/contracts/models.py` and the example payloads in
`server/tests/fixtures/`. These contracts are the only supported data
boundary between workstreams. Do not create local duplicate versions of
these models.

The contracts are deliberately independent of Cognee, the LSTM library,
the terminal UI framework, and the future agent framework. This lets all
workstreams move in parallel.

## Team allocation

### Developer 1 — KCP, OKF, and Cognee

**Goal:** Ingest MITRE Enterprise ATT&CK data and CVE JSON, process them
through the Knowledge Compression Pipeline (KCP), convert the results to
OKF records, and store/retrieve them through Cognee.

**Owns:**

- `server/services/knowledge/`
- `server/routers/knowledge.py`
- `server/tests/knowledge/`
- Knowledge-specific fixtures under `server/tests/fixtures/knowledge/`

**Tasks:**

1. Consume and emit the shared `KnowledgeRecord` contract. Propose any
   required additive field through the shared-contract review process.
2. Define parsers for the selected MITRE Enterprise ATT&CK and CVE JSON
   source formats.
3. Implement normalization, compression, provenance, and versioning.
4. Convert processed source data into the agreed `KnowledgeRecord` OKF
   schema.
5. Implement a Cognee adapter for upsert and retrieval.
6. Add API endpoints for ingestion status and knowledge retrieval.
7. Add tests for source traceability, duplicate handling, and retrieval.

**Deliverable:** A repeatable sample-data ingestion command/test that
loads MITRE and CVE records into Cognee and retrieves a known record
with its provenance.

**Must not modify:** LSTM code, CLI/TUI code, the future investigation
orchestrator, or shared contracts without agreement.

### Developer 2 — LSTM sequential context

**Goal:** Detect suspicious sequences that span log batches by retaining
bounded state per investigation scope.

**Owns:**

- `server/services/sequence/`
- `server/routers/sequence.py`
- `server/tests/sequence/`
- Sequence-specific fixtures under `server/tests/fixtures/sequence/`

**Tasks:**

1. Consume `NormalizedEvent` and emit `SequenceCue`; do not define
   separate local request/response models for those boundaries.
2. Transform `NormalizedEvent` records into model features.
3. Define scope keys (for example: host, account, process tree, or
   network flow) so unrelated events do not share state.
4. Implement an event-window store and a durable LSTM hidden/cell-state
   store per scope.
5. Process each batch using the previous state for the same scope.
6. Emit a `SequenceCue` containing risk score, event references, model
   version, threshold, and context-window reference.
7. Handle late or out-of-order events by replaying the affected bounded
   window in event-time order.
8. Add tests that demonstrate a batch-12 + batch-13 pattern can create
   a cue even when either batch alone does not.

**Deliverable:** A tested endpoint/service that accepts normalized events
and emits explainable cross-batch sequence cues.

**Must not modify:** Cognee/OKF ingestion code, CLI/TUI code, the future
investigation orchestrator, or shared contracts without agreement.

### Developer 3 — Interactive terminal application

**Goal:** Replace command/flag-heavy user flows with an interactive
terminal application that offers selectable and mouse-clickable choices.

**Recommended technology:** Textual. It works well with the existing
Rich-based CLI and supports mouse interaction plus full keyboard
navigation in capable terminals.

**Owns:**

- `cli_agent/tui/`
- `cli_agent/client/`
- `cli_agent/tests/tui/`
- CLI/TUI documentation
- CLI-only dependency updates, such as adding `textual`

**Tasks:**

1. Use `BatchIngestRequest` for server submissions. The UI must not
   construct undocumented payload shapes.
2. Create a Textual application entry point and clickable main menu.
3. Provide guided screens for login, profile/configuration, one-time log
   analysis, monitoring start/stop, viewing status, and exit.
4. Add forms, file/path selection where terminal-supported, validation,
   progress views, success/error messages, and confirmation before any
   action with side effects.
5. Extract a thin `CliService` or client facade so widgets call methods
   rather than embedding HTTP/API logic.
6. Keep existing command behaviour reusable during the migration; the
   TUI should call the same underlying operations where possible.
7. Test screens and service calls against a mocked server contract.

**Deliverable:** A terminal UI that can be launched without flags and
lets a user complete at least login, select a log file, submit analysis,
and view results through interactive controls.

**Must not modify:** Server implementation files, multi-agent behavior,
or shared schemas without agreement.

### Developer 4 — Multi-agent investigation (starts later)

**Goal:** Build the orchestrator after the first three workstreams have
stable contracts and fixtures.

**Owns:**

- `server/services/investigation/`
- `server/routers/investigations.py`
- `server/tests/investigation/`

**Tasks:**

1. Consume `InvestigationInput` as the only orchestrator input boundary.
   It combines the upstream `NormalizedEvent`, `KnowledgeRecord`, and
   `SequenceCue` outputs.
2. Create shared investigation state from `NormalizedEvent`,
   `KnowledgeRecord`, and `SequenceCue` inputs.
3. Implement task delegation to specialist agents.
4. Collect sub-agent results, request follow-up analysis when evidence
   conflicts, and generate final evidence-backed findings.
5. Preserve evidence references, confidence, uncertainty, and an audit
   record of assigned tasks and outputs.
6. Use Cognee retrieval and LSTM cues as inputs, not as proof of an
   incident.

**Deliverable:** A fixture-based orchestrator endpoint that generates a
structured investigation result from the completed workstreams.

**Must not modify:** Earlier workstream internals. Interface changes must
be proposed as a versioned shared-contract change.

## Shared contracts — agree before parallel development

Create an owner-neutral package at `server/contracts/`. The team should
agree on and merge these Pydantic models before feature development
begins:

1. **`NormalizedEvent`**
   - `event_id`, `scope_key`, `event_time`, `event_type`, `features`,
     `evidence_ref`, `source`, and schema version.
2. **`KnowledgeRecord`**
   - `record_id`, `source_type`, `source_id`, `version`, `content`,
     `relationships`, `provenance`, and ingestion time.
3. **`SequenceCue`**
   - `scope_key`, `event_ids`, `risk_score`, `model_version`, `threshold`,
     `window_ref`, and creation time.
4. **`BatchIngestRequest`**
   - `batch_id`, `source`, normalized events or raw evidence references,
     and submission time.
5. **`InvestigationInput`**
   - normalized events, relevant knowledge references, and sequence cues.

Add sample JSON fixtures for each contract. Producers must validate their
outputs against these fixtures; consumers must test against the same
fixtures rather than another developer's unfinished code.

### Contract ownership and usage

- The contract files are shared infrastructure, not owned by an
  individual feature developer. Changes require review from every
  affected producer and consumer.
- Developer 3 produces `BatchIngestRequest`; Developer 1 consumes it
  and transforms its raw records into `NormalizedEvent` records.
- Developer 1 produces `KnowledgeRecord` records for Cognee retrieval.
- Developer 2 consumes `NormalizedEvent` records and produces
  `SequenceCue` records.
- Developer 4 later consumes `InvestigationInput`, which contains the
  outputs from Developers 1 and 2.
- New fields must be optional and have a safe default in contract version
  `1.0`; breaking changes require a new schema version and fixtures.

## Conflict-prevention rules

1. **One developer owns each implementation folder.** Do not edit files
   owned by another workstream.
2. **Choose one integration owner.** This person alone updates
   `server/main.py`, `server/routers/__init__.py`, shared requirements,
   and server-wide configuration after reviewing each PR.
3. **Add new modules instead of concurrently rewriting legacy files.**
   Avoid parallel edits to `server/routers/analysis.py`,
   `server/routers/monitoring.py`, and `server/core/orchestrator.py`.
4. **No direct imports between workstreams.** Use models in
   `server/contracts/` and narrow service interfaces.
5. **Make contract changes additive.** Add optional fields first; do not
   rename or remove shared fields while another branch is active.
6. **Use short-lived feature branches and small pull requests.** Each PR
   should have tests and should be reviewable independently.
7. **Do not merge secret or local environment files.** Keep Cognee/model
   credentials in local environment configuration.

## Recommended integration order

1. Merge the shared contracts and fixtures.
2. Merge Developer 1's KCP/Cognee work.
3. Merge Developer 2's LSTM work.
4. Merge Developer 3's terminal UI, initially against a mocked contract
   if the API is not ready.
5. Add one integration test: terminal/client batch submission → normalized
   events → LSTM sequence cue plus Cognee knowledge retrieval.
6. Start Developer 4 using the stable contracts and integration fixtures.
7. Add frontend work only after the multi-agent response format is stable.

## Definition of done for this phase

- Knowledge ingestion stores traceable MITRE and CVE OKF records in Cognee.
- The LSTM produces explainable, per-scope cross-batch sequence cues.
- The terminal UI supports interactive selection and mouse/keyboard use.
- All services validate their shared contracts and have isolated tests.
- No multi-agent or frontend implementation is required yet.
