# Knowledge Compression Pipeline (KCP) Design

> **Status:** Covers both the **Implemented (v1.0)** KCP/OKF/Cognee service in `server/services/knowledge/` and `server/routers/knowledge.py`, and the **Proposed Evolution (v1.1)** adapting multi-stage document compression (AKUs, graph importance scoring, token-budgeted hierarchical summarization, and AKU validation) to ForensIQ's security datasets.

Related documents:

- [Knowledge pipeline and OKF](Knowledge_Pipeline_and_OKF.md)
- [ForensIQ architecture evolution](ForensIQ_Architecture_Evolution.md)
- [ForensIQ developer work plan](Developer_Work_Plan.md)

---

## 1. Overview & Objectives

ForensIQ's Knowledge Compression Pipeline (KCP) transforms raw security knowledge datasets (**MITRE Enterprise ATT&CK STIX 2.1** and **CVE List v5 JSON**) and incoming raw log batches into traceable, structured records without discarding source facts or inventing unsupported mappings.

Core objectives:

1. **Preserve factual integrity and provenance:** Retain exact SHA-256 hashes, source URIs, versions, and compression audits on every output record.
2. **Avoid silent information loss:** Never use a lossy binary gate (such as the legacy pre-RAG `FILTER_OUT`/`SEND_TO_RAG` pattern) or invent ATT&CK↔CVE links via keyword overlap.
3. **Bridge graph and vector retrieval:** Persist OKF (`KnowledgeRecord`) nodes and typed edges in Cognee (LanceDB + Kuzu) backed by an exact SQLite provenance catalog (`ManifestStore`).
4. **Emit provider-neutral shared contracts:** Consume and emit only the strict Pydantic v2 contracts defined in `server/contracts/models.py` (`KnowledgeRecord`, `KnowledgeRelationship`, `BatchIngestRequest`, `NormalizedEvent`).

---

## 2. Comparison: Generic Prose Compression vs. ForensIQ Security KCP

A generic document compression pipeline (e.g., for long AWS documentation) typically splits prose into overlapping token windows, extracts Atomic Knowledge Units (AKUs) with an LLM, builds a knowledge graph, and produces multi-level token-budgeted summaries. ForensIQ shares the **fact-preserving, graph-backed, auditable philosophy**, while adapting its mechanics for **already-structured security JSON feeds**:

| Aspect | Generic Prose Compression Design | ForensIQ KCP v1.0 (Implemented) | ForensIQ KCP v1.1 (Proposed Evolution) |
| --- | --- | --- | --- |
| **Input shape** | Long, unstructured markdown/HTML prose | Structured MITRE STIX 2.1 bundle (`enterprise-attack-17.1.json`) & 428k+ CVE List v5 JSON files | Same structured feeds + optional extraction over long ATT&CK `description` / `detection` blocks |
| **Segmentation / Chunking** | Heading/paragraph split into 500–1000 token chunks with 100-token overlap | **One semantic entity per source object/file** (splitting a CVE by token windows would sever CVSS metrics from affected versions) | Same entity-level segmentation; prose sub-splitting only for very long ATT&CK narrative fields |
| **Atomic Knowledge Units (AKUs)** | LLM-extracted `(Subject, Predicate, Object)` triples | Explicit typed `KnowledgeRelationship` edges + structured `content` fields | Unified `content["akus"]` triple list (deterministic rules + optional prose extraction) |
| **Knowledge Graph** | Entities & relationships extracted during topic analysis | Built deterministically in Cognee/Kuzu (`OKFRecordNode`, `OKFConceptNode`, typed edges) | Adds **graph importance scoring** (connectivity, group/software usage, CVSS/SSVC criticality) |
| **Compression & Summarization** | 5-level hierarchy (Section → Document → Topic → Category → Global) with token budgets | Single-level deterministic cleanup (HTML/markdown/citation stripping) + extractive `summary` (`<= 280` chars) | **Domain-adapted hierarchy** (Technique/CVE → Parent/Product/CWE → Tactic → Domain) with explicit token budgets |
| **Validation & Auditability** | AKU coverage verification against summaries | `CompressionAudit` (`raw_chars`, `compressed_chars`, `compression_ratio`, `omitted_fields`) + `source_sha256` / `content_sha256` | Adds `fact_retention_score` and `missing_akus` checks stored inside `provenance["compression"]` |

---

## 3. Implemented Architecture (v1.0)

### 3.1 End-to-End Data Flow

```text
MITRE ATT&CK STIX 2.1                 CVE List v5 JSON (+ delta.json)
         |                                         |
         v                                         v
  mitre_parser.py                           cve_parser.py (streaming)
         +--------------------+--------------------+
                              |
                              v
                  KCP Normalizer (normalizer.py)
        IDs, UTC timestamps, vendor/product slugs, CVSS priority
                              |
                              v
                 KCP Compressor (compressor.py)
       Strip HTML/markdown links/citations + extractive summary
                  Emit CompressionAudit metrics
                              |
                              v
                 OKF Builder (okf_builder.py)
        Emit validated contracts.KnowledgeRecord + SHA-256 hashes
                              |
                              v
              CogneeKnowledgeStore (cognee_adapter.py)
         +--------------------+--------------------+
         |                                         |
         v                                         v
  ManifestStore (SQLite)                Cognee (LanceDB + Kuzu)
  - Exact KnowledgeRecord JSON          - OKFRecordNode (fastembed vectors)
  - Version lineage & dedup hashes      - OKFConceptNode (CWE/CAPEC/product)
  - IngestionRunStatus registry         - Typed graph relationships

------------------------------------------------------------------------
Log KCP: BatchIngestRequest --> log_normalizer.py --> NormalizedEvent[]
```

### 3.2 Module Inventory (`server/services/knowledge/` & `server/routers/knowledge.py`)

| Module | Responsibility |
| --- | --- |
| `server/services/knowledge/config.py` | `KnowledgeSettings` (`KNOWLEDGE_*` env vars), isolated from `core.config` so knowledge runs without MongoDB or cloud API keys. |
| `server/services/knowledge/models.py` | Internal DTOs (`CompressionAudit`, `ParsedKnowledgeItem`, `UpsertSummary`, `IngestionRunStatus`, `KnowledgeSearchQuery`, `KnowledgeSearchHit`, `KnowledgeSearchResponse`, `KnowledgeRecordDetailResponse`, `KnowledgeStoreStats`) reusing `contracts` models directly. |
| `server/services/knowledge/parsers/mitre_parser.py` | `parse_mitre_stix_file()` for `attack-pattern`, `x-mitre-tactic`, `course-of-action`, `malware`, `tool`, `intrusion-set`, `campaign`, `x-mitre-data-source`, and `x-mitre-data-component`. |
| `server/services/knowledge/parsers/cve_parser.py` | `iter_cve_files()`, `resolve_cve_path()`, and `parse_cve_file()` streaming CVE JSON 5.1/5.2 files, explicit CVE IDs, year filters, and `delta.json`. |
| `server/services/knowledge/kcp/normalizer.py` | `normalize_item()`, `select_primary_cvss()`, and ID/timestamp/vendor-product/platform normalizers. |
| `server/services/knowledge/kcp/compressor.py` | `compress_text()`, `extractive_summary()`, and `compress_item()` producing `CompressionAudit`. |
| `server/services/knowledge/kcp/okf_builder.py` | `make_record_id()` and `build_knowledge_record()` outputting validated `contracts.KnowledgeRecord` objects. |
| `server/services/knowledge/kcp/pipeline.py` | `KCPPipeline` executing batched MITRE and streaming CVE runs with compression aggregation and error isolation. |
| `server/services/knowledge/kcp/log_normalizer.py` | `normalize_log_record()` and `normalize_batch()` transforming `BatchIngestRequest` into `NormalizedEvent` while preserving `evidence_ref`. |
| `server/services/knowledge/storage/base.py` | `KnowledgeStore` protocol, deterministic UUID5 helpers (`node_uuid_for_record`, `node_uuid_for_concept`), `build_searchable_text`, `matches_filters`, and `lexical_score`. |
| `server/services/knowledge/storage/manifest_store.py` | Durable SQLite catalog (`records`, `record_versions`, `ingestion_runs`) providing hash-based deduplication, version audit history, exact ID lookup, and lexical fallback. |
| `server/services/knowledge/storage/cognee_adapter.py` | `CogneeKnowledgeStore` integrating Cognee `DataPoint` models (`OKFRecordNode`, `OKFConceptNode`), `add_data_points`, LanceDB vector search (`fastembed` `BAAI/bge-small-en-v1.5`), and Kuzu graph connections. |
| `server/services/knowledge/storage/memory_store.py` | `InMemoryKnowledgeStore` implementing `KnowledgeStore` for fast unit and router tests. |
| `server/services/knowledge/service.py` | `KnowledgeService` facade exposed to the FastAPI router and CLI. |
| `server/services/knowledge/cli.py` | CLI entry point (`python -m services.knowledge.cli`) for `ingest-sample`, `ingest-mitre`, `ingest-cve`, `search`, and `get`. |
| `server/routers/knowledge.py` | FastAPI `APIRouter` mounted under `/api/v1/knowledge`. |

### 3.3 OKF v1.0 Schema Mapping (`contracts.KnowledgeRecord`)

Every processed entity maps to `contracts.KnowledgeRecord`:

- **`record_id`:**
  - Active MITRE ATT&CK: `okf-mitre-<source_id.lower()>` (e.g., `okf-mitre-t1110`, matching `server/tests/fixtures/knowledge_record.json`).
  - Deprecated/revoked MITRE (only when `include_deprecated=True` and colliding with an active ID): `okf-mitre-<source_id.lower()>-<status>-<uuid8>`.
  - CVE: `okf-<cve_id.lower()>` (e.g., `okf-cve-2025-39447`).
- **`source_type`:** `"mitre_attack"` or `"cve"`.
- **`source_id` / `source_version`:**
  - MITRE: canonical external ID (`T1110`, `TA0006`, `M1032`, `G0117`, `S0039`, `DS0029`, or `DC-<uuid8>`) and collection version (`17.1`).
  - CVE: canonical `CVE-YYYY-NNNN+` and `<dataVersion>@<dateUpdated>` (e.g., `5.2@2026-04-29T09:51:55.028Z`).
- **`content`:**
  - Common keys: `kind`, `name` / `title`, `description`, `summary`, `status`/`state`, `references`.
  - ATT&CK keys: `tactics`, `tactic_ids`, `platforms`, `domains`, `is_subtechnique`, `data_sources`, `detection`, `aliases`, `source_created`, `source_modified`.
  - CVE keys: `cve_id`, `assigner`, `date_reserved`, `date_published`, `date_updated`, `affected` (including `vendor_normalized` / `product_normalized`), `affected_products_normalized`, `cwe_ids`, `problem_types`, `capec_ids`, `severity` (primary CVSS), `all_metrics`, `ssvc`.
- **`relationships`:** List of `KnowledgeRelationship(relationship_type, target_source_id, source)`:
  - ATT&CK (`source="source"`): `uses_tactic`, `subtechnique_of`, `uses`, `mitigates`, `detects`, `attributed_to`, `part_of_data_source`.
  - CVE: `has_weakness` (`CWE-xxx`, `source="source"`), `has_attack_pattern` (`CAPEC-xxx`, `source="source"`), `affects_product` (`vendor:product`, `source="kcp"`).
- **`provenance`:** `source_uri`, `source_file`, `source_object_id`, `source_sha256`, `dataset_sha256` (for STIX bundles), `content_sha256`, `source_format`, `kcp_version`, `ingestion_run_id`, and `compression` (`CompressionAudit`).

### 3.4 Data Integrity & Scale Safeguards

- **Deprecated MITRE ID collisions:** Active STIX objects are indexed prior to deprecated/revoked objects, preventing legacy deprecated `course-of-action` entries (e.g., `"Brute Force Mitigation"` carrying `external_id="T1110"`) from shadowing active techniques (`"Brute Force"`).
- **Tactic ID & data-component resolution:** `x-mitre-tactic` shortnames (`credential-access`) resolve to `TAxxxx` IDs (`TA0006`); `x-mitre-data-component` items without `external_id` receive deterministic `DC-<uuid8>` IDs and link via `part_of_data_source -> DSxxxx`.
- **CVE streaming & O(1) lookup:** `iter_cve_files()` streams `server/frameworks/cve/` without loading 428k paths into memory, resolves explicit `cve_ids` in O(1) via `<year>/<seq // 1000>xxx/<CVE-ID>.json`, and supports `delta.json` (`new` + `updated`).
- **Error isolation & rejection filtering:** `REJECTED` CVEs are skipped by default (`rejected_or_filtered`) unless `include_rejected=True`; malformed JSON files raise `CveParseError`, increment `failed`, and never abort the remaining batch.
- **Idempotency & version lineage:** `ManifestStore.upsert_records()` compares `(content_sha256, source_version)` before indexing into Cognee, skipping unchanged records (`skipped`), appending `record_versions` rows on updates (`updated`), and materializing graph edges cleanly even when target MITRE records arrive in a later batch.
- **Evidence boundary:** Every `KnowledgeSearchHit` carries `is_evidence_proof=False`, and `KnowledgeSearchResponse.notice` reminds downstream agents that retrieved ATT&CK/CVE context is never proof of compromise.

### 3.5 Endpoints & CLI

Mounted at `/api/v1/knowledge`:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/v1/knowledge/ingest/mitre` | `POST` | Ingest MITRE Enterprise ATT&CK STIX JSON (`file_path`, `entity_types`, `include_deprecated`, `limit`, `dry_run`) |
| `/api/v1/knowledge/ingest/cve` | `POST` | Stream CVE List v5 JSON (`path`, `years`, `cve_ids`, `delta_file`, `include_rejected`, `limit`, `dry_run`) |
| `/api/v1/knowledge/ingestion/status` | `GET` | List recent `IngestionRunStatus` entries |
| `/api/v1/knowledge/ingestion/status/{run_id}` | `GET` | Inspect a specific ingestion run (`404` if missing) |
| `/api/v1/knowledge/search` | `GET` / `POST` | Search Cognee/Manifest with `source_type`, `kind`, `tactic`, `platform`, `min_cvss`, `top_k`, and `search_mode` (`auto`, `semantic`, `lexical`, `graph`) |
| `/api/v1/knowledge/records/{record_id}` | `GET` | Fetch exact `KnowledgeRecord` by OKF `record_id` (`include_related=true` expands 1-hop neighbors) |
| `/api/v1/knowledge/source/{source_type}/{source_id}` | `GET` | Fetch exact `KnowledgeRecord` by `(source_type, source_id)` |
| `/api/v1/knowledge/stats` | `GET` | Store counts by `source_type` and `kind`, active versions, and run count |
| `/api/v1/knowledge/normalize/batch` | `POST` | Transform `BatchIngestRequest` into validated `NormalizedEvent[]` |

Repeatable CLI commands (run from `server/` or with `PYTHONPATH=server`):

```bash
python -m services.knowledge.cli ingest-sample
python -m services.knowledge.cli ingest-mitre --limit 50
python -m services.knowledge.cli ingest-cve --years 2025 --limit 100
python -m services.knowledge.cli search "password guessing brute force" --top-k 5
python -m services.knowledge.cli get mitre_attack T1110 --related
```

---

## 4. Proposed Evolution (v1.1): Multi-Stage AKU & Hierarchical Compression

To incorporate the strongest parts of the multi-stage document compression design without breaking `contracts.KnowledgeRecord` (version `1.0`), v1.1 extends `server/services/knowledge/kcp/` across four additive stages:

### 4.1 Stage 1: Atomic Knowledge Units (AKUs)

Each `KnowledgeRecord` emits an additive `content["akus"]` list of self-contained `(subject, predicate, object)` triples:

- **Deterministic structural AKUs (zero LLM cost):** Derived directly from parsed fields and `relationships`, e.g.:
  - `(T1110, uses_tactic, TA0006)`
  - `(T1110, targets_platform, Linux)`
  - `(CVE-2025-39447, has_cvss_v3_1, "7.5 HIGH")`
  - `(CVE-2025-39447, has_weakness, CWE-862)`
  - `(CVE-2025-39447, affects_product, "crocoblock:jetelements_for_elementor <= 2.7.4.1")`
- **Optional prose AKU extraction (for long ATT&CK `description`/`detection` text):** Split only multi-paragraph ATT&CK descriptions at sentence boundaries and extract behavioral/detection triples anchored to the technique ID.

### 4.2 Stage 2: Graph Importance Scoring & Topic Clustering

Compute an `importance_score` per node inside Kuzu / `ManifestStore` using deterministic structural signals:

- **ATT&CK importance:** In-degree/out-degree in Kuzu (how many `intrusion-set` and `malware`/`tool` entities `uses` the technique, sub-technique count, mitigation/data-component coverage).
- **CVE importance:** Normalized CVSS base score (`0.0–10.0` scaled to `0.0–1.0`) boosted by CISA ADP SSVC flags (`Exploitation=active`, `Automatable=yes`, `Technical Impact=total`) and affected product breadth.

Importance scores prioritize which facts survive under strict token budgets and serve as an additive ranking signal during `search()`.

### 4.3 Stage 3: Domain-Adapted Hierarchical Summarization & Token Budgets

Instead of generic prose chapters, ForensIQ maps hierarchical summarization onto the natural taxonomy of ATT&CK and CVE while staying additive inside `content["hierarchy_summaries"]` (and optional roll-up records):

| Level | ATT&CK Scope | CVE Scope | Target Budget | Consumer Use Case |
| --- | --- | --- | --- | --- |
| **Level 3 (Entity Detail)** | Sub-technique / Technique (`T1110.001`) with detection & platforms | Individual CVE (`CVE-2025-39447`) with exact affected versions & CVSS | ~200–400 tokens | Deep inspection by specialist sub-agents |
| **Level 2 (Group Roll-up)** | Parent Technique (`T1110`) aggregating its sub-techniques & mitigations | Product or CWE roll-up (`crocoblock:jetelements_for_elementor`, `CWE-862`) | ~100–150 tokens | Hypothesis & timeline correlation |
| **Level 1 (Category Summary)** | Tactic summary (`TA0006` Credential Access) | Feed/Severity cluster (e.g., 2025 HIGH CWE-862 web CVEs) | ~50–100 tokens | Orchestrator triage & prompt budgeting |
| **Level 0 (Global Overview)** | Enterprise ATT&CK domain digest | Vulnerability corpus digest | ~25–50 tokens | Executive/health context |

Each higher level is aggregated strictly from the validated summaries and AKUs of the level below it, keeping numerical facts (CVSS scores, version operators like `<= 2.7.4.1`, and `Txxxx`/`CVE-xxxx` IDs) exact.

### 4.4 Stage 4: Constraint-Based Summarization & AKU Validation

Every generated summary (extractive or LLM-assisted) is verified against the record's AKUs before persistence:

1. **Entity & identifier anchor check:** Confirm canonical IDs (`source_id`, CWE/CAPEC IDs, key tactic IDs) and exact numeric values (CVSS score, affected version bounds) present in core AKUs are preserved without alteration.
2. **Unsupported-claim check:** Reject or flag any ATT&CK/CVE identifier appearing in a summary that does not exist in the source item's AKUs or `relationships`.
3. **Auditable metrics in `provenance["compression"]`:** Record `aku_count`, `retained_aku_count`, `fact_retention_score` (`retained / total`), `missing_akus`, and `validation_passed` alongside the existing v1.0 character-level `CompressionAudit` fields. This directly addresses the open quality-measurement requirement in [Knowledge pipeline and OKF](Knowledge_Pipeline_and_OKF.md#L62).

---

## 5. Verification & Test Suite

Curated, repository-contained test fixtures live under `server/tests/fixtures/knowledge/` (`mitre_sample_bundle.json` and `cve_sample/`), and automated tests under `server/tests/knowledge/`:

- `server/tests/knowledge/test_mitre_parser.py` — active vs. deprecated `T1110` collision resolution, tactic mapping, relationship and data-component extraction.
- `server/tests/knowledge/test_cve_parser.py` — CVSS 3.1/4.0, legacy v4, `REJECTED` filtering, `delta.json`, explicit IDs, and malformed JSON isolation.
- `server/tests/knowledge/test_kcp_pipeline.py` — auditable compression, duplicate skip / version update lineage, and `BatchIngestRequest` → `NormalizedEvent` validation against `server/tests/fixtures/`.
- `server/tests/knowledge/test_cognee_adapter.py` — local Cognee (LanceDB + Kuzu + `fastembed`) round-trip ingestion, deduplication, provenance retrieval, and semantic/graph search.
- `server/tests/knowledge/test_knowledge_router.py` — isolated FastAPI `TestClient` coverage for all `/api/v1/knowledge/*` endpoints.

Run tests and the repeatable sample deliverable from the repository root:

```bash
PYTHONPATH=server server/.venv/bin/python -m pytest server/tests/contracts/ server/tests/knowledge/ -v
PYTHONPATH=server server/.venv/bin/python -m services.knowledge.cli ingest-sample --data-dir /tmp/forensiq_sample
```

