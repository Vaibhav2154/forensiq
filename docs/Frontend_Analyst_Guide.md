# ForensIQ (`[LOGIQ_V2.0]`) — Frontend Architecture & Cybersecurity Analyst Guide

This guide documents every page, navigation panel, tab, sub-tab, chart, badge, modal, and interactive tool exposed in the ForensIQ (`[LOGIQ_V2.0]`) web interface (`client/`), along with how cybersecurity / SOC analysts use each capability across triage, investigation, threat hunting, detection engineering, containment, and executive reporting.

---

## Platform Architecture Overview

```
Raw Logs / Collectors
   │
   ▼
[ANALYSIS.EXE] (/dashboard/analysis)  ──or──  [KCP_BATCH_SANDBOX] (/dashboard/knowledge)
   │                                              │
   ▼                                              ▼
KCP Normalization (NormalizedEvent) ──► Persistent SQLite LSTM Engine (SequenceCue)
   │                                              │
   ├──► OKF / Cognee Knowledge Hub (MITRE ATT&CK + CVE Context)
   └──► LangGraph Multi-Agent Investigation (Orchestrator + Specialist Agents)
          │
          ▼
Encrypted MongoDB Storage ──► [DASHBOARD.SYS] / [VISUALIZATION] / [ASK_AI_CHATBOT]
```

### Key Design Principles for Analysts
1. **Epistemic Discipline (`Observed` vs. `Inferred` vs. `Unconfirmed`):** Raw log lines remain the source of truth. MITRE ATT&CK techniques, CVEs (`is_evidence_proof: false`), and LSTM sequence cues are explicitly treated as investigative context and prioritization signals—never standalone proof of compromise.
2. **Evidence Traceability:** Findings, attack-path steps, timeline entries, and chatbot citations link back to specific `event_id`s, `evidence_ref` pointers, and knowledge `record_id`s.
3. **Human-in-the-Loop Containment:** Every remediation action displays `HUMAN_APPROVAL_REQUIRED` and `AUTO_EXEC: FALSE` alongside rollback guidance.
4. **Encrypted History:** Stored analyses in MongoDB are encrypted using a key derived from the analyst's account credentials and decrypted on demand when viewed or queried by the chatbot.

---

## Global Navigation Bar & Entry Pages

### Top Navigation Bar (`[LOGIQ_V2.0]`)
Present across all operational views (`client/components/navbar.tsx`):

| Element | Route | What It Shows / Opens | Value to Cybersecurity Analysts |
| :--- | :--- | :--- | :--- |
| **`> DASHBOARD.SYS`** | `/dashboard` | Central SOC overview, analytics, history, and endpoint monitoring sessions | Shift situational awareness, historical triage, and collector session management |
| **`> MITRE_ATTACK.DB`** | `/dashboard/mitre` | Enterprise MITRE ATT&CK browser, kill-chain filters, and semantic technique search | Fast lookup of adversary tactics, techniques, and target platforms |
| **`> KNOWLEDGE.DB`** | `/dashboard/knowledge` | Unified OKF/Cognee hub (MITRE + CVE search, graph lookup, ingestion, KCP sandbox) | Cross-source threat intel hunting and pipeline validation |
| **`> ANALYSIS.EXE`** | `/dashboard/analysis` | Interactive log ingestion, AI/KCP analysis, and LSTM stateful sequence evaluation | Ad-hoc log triage, cross-batch attack correlation, and immediate reporting |
| **`> CLI_GUIDE`** | `/dashboard/cliguide` | Step-by-step setup guide for host CLI log collectors (`StepGuide`) | Onboarding endpoints and automated log forwarders consistently |
| **Live Health Indicator** | Global (`GET /health`) | Animated dot + `[ONLINE]` (green), `[DEGRADED]` (yellow), or `[OFFLINE]` (red) | Immediate visibility if Gemini AI, LangGraph, LSTM, or OKF/Cognee is down before trusting empty results |
| **Profile Icon (`👤`)** | `/profileupdate` | Terminal-style profile and password update screen | Credential hygiene and account management |

### Authentication & Landing Routes
- **Landing Page (`/`):** Matrix-style entry console linking to Login, Sign Up, and Dashboard.
- **Terminal Auth Consoles (`/login`, `/signup`, `/profileupdate`):** Keyboard-driven terminal authentication flows issuing JWT bearer tokens and managing password-based encryption keys for stored analysis history.

---

## 1. Security Operations Dashboard (`DASHBOARD.SYS` — `/dashboard`)

The primary landing workspace for SOC analysts once authenticated (`client/app/dashboard/page.tsx`).

### 1.1 Header & System Health KPIs
Four top-level telemetry cards provide instant operational status:

| Card | Data Shown | Analyst Value |
| :--- | :--- | :--- |
| **`[TOTAL_ANALYSES]`** | Total number of stored forensic runs for the user | Measures case throughput and investigation volume over time |
| **`[TOTAL_TECHNIQUES_PROCESSED]`** | Aggregate count of MITRE ATT&CK techniques matched across displayed runs | Tracks exposure breadth and TTP density across ingested logs |
| **`[CLI_STATUS]`** | `ACTIVE` or `INACTIVE` based on user profile collector telemetry (`cli_active`) | Confirms whether automated endpoint log agents are actively streaming data |
| **`[SYSTEM_STATUS]`** | Overall backend health (`HEALTHY` / `DEGRADED` / `OFFLINE`) plus individual service pills: `gemini_ai`, `multi_agent_investigation`, `sequence_lstm`, `knowledge` | Confirms all investigative engines—including the LSTM sequence detector (`sequence_lstm: healthy`) and Cognee knowledge store—are operational before triaging alerts |

### 1.2 Analytics & Multi-Agent Orchestrator Status Row

| Panel | Fields Displayed | Analyst Value |
| :--- | :--- | :--- |
| **`[USER_ANALYTICS.STAT]`** | • **`AVG_TIME`**: Mean processing latency per analysis<br>• **`TOP_MATCHED_TECHNIQUES`**: Up to 6 most frequent technique IDs with occurrence counts (e.g., `T1110.001 (5)`)<br>• **`RECENT_ACTIVITY_DAYS`**: Daily analysis run counts across recent dates | Surfaces recurring adversary behaviors (e.g., repeated brute-force or sudo abuse) so Tier 2/3 analysts know which detections or hardening controls need priority |
| **`[ORCHESTRATOR_CONFIG.SYS]`** | • **`KEY_POOL`**: Number of configured Gemini API key slots<br>• **`REFINEMENT_ROUNDS`**: Max orchestrator self-critique/refinement loops<br>• **`LSTM_SEQUENCE`**: `ACTIVE` (green) or `STANDBY` (yellow) reflecting `lstm_connected`<br>• **`STORE`**: Active knowledge backend (e.g., `okf-cognee`)<br>• **`OKF_TECH`**: Total indexed MITRE ATT&CK techniques | Verifies that cross-batch temporal detection (`LSTM_SEQUENCE: ACTIVE`) and verification loops (`REFINEMENT_ROUNDS`) are active for incoming investigations |

### 1.3 Quick-Launch Module Cards (`> EXEC_MODULE --RUN`)
Clickable module cards linking directly into operational workflows:
- **`> LOG_ANALYSIS.SYS`** (`[REALTIME_ANALYSIS]` → `/dashboard/analysis`)
- **`> THREAT_VISUALIZATION.EXE`** (`[INTERACTIVE_CHARTS]` → `/dashboard/visualization`)
- **`> MITRE_ATTACK.DB`** (`[ENTERPRISE_TECH]` → `/dashboard/mitre`)
- **`> KNOWLEDGE_OKF.DB`** (`[OKF_COGNEE]` → `/dashboard/knowledge`)
- **`> THREAT_INTEL.NET`** (`[THREAT_INTEL]` → `/dashboard`)

### 1.4 Stored Analysis History (`[RECENT_ANALYSES.LOG]`)
Displays paginated, decrypted MongoDB analysis records:
- **Row Header & Metadata:** `ANALYSIS_#N`, IST timestamp, extracted summary preview.
- **Triage Badges:**
  - **`[N_TECH]`**: Number of matched MITRE techniques.
  - **`[N_CVE]`**: Number of retrieved CVE records (shown when > 0).
  - **Threat Severity Pill** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) sourced from structured investigation output.
  - **`CONF:*`** badge (`HIGH`, `MEDIUM`, `LOW`) showing overall evidence confidence.
- **Row Actions:**
  - **`[ASK_AI]`**: Opens the Gemini Forensic Chatbot scoped specifically to that decrypted analysis.
  - **`[VIEW]`** (or clicking the card): Opens the **`[ANALYSIS_DETAILS.EXE]`** modal showing timestamp, processing time, `[THREAT_SUMMARY.LOG]`, `[MITRE_TECHNIQUES.DB]`, the embedded multi-agent `InvestigationReportPanel`, and buttons for **`[DELETE]`**, **`[VIEW_VISUALIZATION]`**, **`[ASK_AI_CHATBOT]`**, and **`[EXPORT]`** (PDF).
  - **`[DELETE]`**: Permanently deletes the stored analysis record (with confirmation prompt).
- **Header Action — `[ASK_AI_HISTORY]`:** Launches the Gemini Forensic Chatbot in cross-history mode to correlate patterns across multiple recent investigations.

### 1.5 Continuous Monitoring Control (`[MONITORING_SESSIONS.SVC]`)
Manages automated background log-file monitoring sessions:
- **Counters:** 30-day analysis count (`30d System Analyses`) and live `Active Sessions`.
- **Controls:** Toggle `FILTER: ACTIVE_ONLY | ALL_SESSIONS` and `[REFRESH]`.
- **Create Session Form:** Input target log path (default `/var/log/auth.log`), polling interval in seconds (min `10`), `[x] AI` toggle, and `[+ START_SESSION]`.
- **Per-Session Actions:** `[INSPECT]` (displays full JSON session status/metadata) and `[STOP]` (terminates active watchers).
- **Analyst Value:** Eliminates manual copy-paste for critical log files (e.g., SSH `auth.log`, audit logs) by automating periodic collection and analysis.

---

## 2. Log Analysis Workbench (`ANALYSIS.EXE` — `/dashboard/analysis`)

The interactive triage console where analysts submit raw log excerpts and trigger real-time KCP + LSTM + Multi-Agent investigations (`client/app/dashboard/analysis/page.tsx`).

### 2.1 Header Status Badges
- **`KEY_POOL`**, **`REFINEMENT_ROUNDS`**, and **`LSTM_HOOK: CONNECTED | STANDBY`**: Lets the analyst confirm before running a batch whether stateful cross-batch LSTM scoring is online.

### 2.2 Configuration Panel (`[ANALYSIS_CONFIG.SYS]`)
- **`> LOG_DATA_INPUT:`** Multi-line textarea accepting syslog, SSHD, sudo, Windows, or application logs.
- **`[AI_ENHANCEMENT]` Toggle:**
  - **ON (`true`):** Executes the full pipeline—raw log wrapping (`SHA-256` + timestamps + hosts) → KCP `normalize_batch()` → persistent SQLite **LSTM Sequence Engine** (`SequenceEngineCueProvider`) → dual MITRE + CVE retrieval via OKF/Cognee → LangGraph **Multi-Agent Investigation** (Orchestrator, Log Evidence Analyst, Knowledge Enricher, Correlation & Timeline, Sequence Analyst, Attack Path Reasoner, Verification Guardrails, Report Synthesizer).
  - **OFF (`false`):** Runs the lightweight path—KCP normalization + OKF/Cognee MITRE search without calling the LLM orchestrator or LSTM provider.
- **`[MAX_RESULTS]` Slider (`1–20`):** Controls `top_k` MITRE/CVE hits retrieved and returned.
- **`> EXECUTE_ANALYSIS.EXE`:** Submits the logs and shows a multi-stage animated CLI progress loader until completion.

### 2.3 Results Panel (`[ANALYSIS_RESULTS.LOG]`)
- **Action & Status Bar:** Displays `[PROCESSED_IN]` duration, IST `[TIMESTAMP]`, `[N_TECHNIQUES_FOUND]`, `[STATUS: COMPLETE]`, **`[VIEW_ENHANCED_VISUALIZATION]`** (caches and opens `/dashboard/visualization`), and **`[ASK_AI_CHATBOT]`** (launches `AnalysisChatModal` bound to the newly saved analysis ID).
- **`[EXECUTIVE_SUMMARY.TXT]`:** Concise narrative synthesis of what happened and why it matters.
- **`[MITRE_ATTACK_TECHNIQUES.DB]`:** Ranked technique cards displaying ID + name, color-coded `[RELEVANCE: %]` (`>= 70%` red, `50–69%` yellow, `< 50%` green), description, `[KILL_CHAIN]` phase tags, and `[PLATFORMS]`.
- **`[AI_ENHANCED_THREAT_ANALYSIS.AI]`:** Full structured Markdown forensic report rendered when AI Enhancement is enabled.
- **Embedded `InvestigationReportPanel`:** Interactive 7-tab structured multi-agent explorer (Findings & Observations, OKF Knowledge, Relationships & Path, Timeline & IOCs, Recommendations, Sequence LSTM, and Audit Trail) directly inline below the report.

**Analyst Value:** Supports both fast 2-second keyword/vector triage (`AI_ENHANCEMENT: OFF`) during high-volume alert floods and deep multi-agent root-cause investigations—with automatic stateful LSTM tracking across consecutive log submissions for the same host/account scope.

---

## 3. Threat Intelligence Visualization Dashboard (`/dashboard/visualization`)

Deep visual analytics workspace powered by structured backend `investigation` and `visualization_metrics` data (`client/app/dashboard/visualization/page.tsx`, `client/components/enhanced-threat-dashboard.tsx`).

### 3.1 Top Control Bar & Threat Header
- **`[DATA_SOURCE]` Bar:** Indicates `LATEST_ANALYSIS` (loaded from selected history item, `GET /api/v1/latest`, or cached `localStorage`) vs. `SAMPLE_DATA`, with buttons to reload latest server data or inspect sample telemetry.
- **`[THREAT_INTELLIGENCE_DASHBOARD]` Banner:**
  - Right badges: `THREAT: CRITICAL|HIGH|MEDIUM|LOW` and `CONFIDENCE: HIGH|MEDIUM|LOW`.
  - 4 Quick Metric Tiles: **`TECHNIQUES_DETECTED`**, **`OVERALL_RISK`** (`%` — or `MAX_CONFIDENCE` when falling back), **`ATTACK_PHASES`** (+ retrieved `CVE(S)` count), and **`ANALYSIS_TIME`** (`s`).

### 3.2 Seven Main Visualization Tabs

#### Tab 1: `[THREAT_NARRATIVE]` (`ThreatNarrativeEngine`)
Transforms technical telemetry into an interactive multi-chapter briefing (`client/components/threat-narrative-engine.tsx`):
- **Playback Controls:** `PLAY` / `PAUSE`, `RESTART`, and `SPEED` (`0.5x`, `1x`, `1.5x`, `2x`), plus `← PREVIOUS` / `NEXT →` chapter navigation.
- **`STORY_CHAPTERS` Sidebar:**
  1. `Threat Overview` (AI summary + timestamp)
  2. One chapter per detected canonical MITRE kill-chain phase (`Reconnaissance` → `Impact`), showing technique relevance cards
  3. `Full Threat Analysis` (complete enhanced Markdown report)
- **`THREAT_ACTOR_PROFILE` Card:** Heuristic classification (`Advanced Persistent Threat`, `Skilled Adversary`, `Opportunistic Attacker`), sophistication `%`, inferred primary motivation (`Data Exfiltration`, `Long-term Access`, `Destructive Attack`, `Intelligence Gathering`, `System Compromise`), and detected tactic pills.
- **Analyst Value:** Ideal for SOC shift briefings, incident commander walk-throughs, and communicating complex multi-step intrusions sequentially.

#### Tab 2: `[ATTACK_JOURNEY]`
Combines structured multi-agent attack-path reasoning with kill-chain phase mapping:
- **`[ATTACK_PATH_HYPOTHESIS]`:** Renders ordered steps (`1, 2, 3...`) from the Attack Path Reasoner with color-coded epistemic tags:
  - Green **`OBSERVED = LOG FACT`**: Directly witnessed in normalized log events.
  - Yellow **`INFERRED = HYPOTHESIS`**: Logically deduced bridge between observed steps.
  - Purple **`UNCONFIRMED = GAP`**: Possible next/missing stage not yet evidenced in logs.
  - Each node shows `STAGE`, `CONF`, linked MITRE/CVE IDs (red), and linked `event_id`s (green).
  - Bottom side-by-side panels display **`[MISSING_EVIDENCE]`** (exact telemetry gaps analysts should collect) and **`[ALTERNATIVE_HYPOTHESES]`** (benign or alternate explanations, e.g., admin maintenance vs. credential theft, preventing confirmation bias).
- **`[ATTACK_KILL_CHAIN_PROGRESSION]`:** Expandable phase timeline ordered along MITRE's 14 canonical phases, displaying `[RISK]` badge, technique counts, and collapsible lists of associated techniques.

#### Tab 3: `[PROGRESSION_ANALYSIS]`
Quantifies escalation risk across steps and tactics:
- **`ATTACK_PROGRESSION_TIMELINE` (Line Chart):** Tracks `risk` (`0–100`) over chronological steps/timestamps to highlight the inflection point where benign or failed events escalated.
- **`RISK_DISTRIBUTION_BY_PHASE` (Bar Chart):** Compares average risk across kill-chain phases (e.g., `credential access` vs. `privilege escalation`).
- **`STEP_BY_STEP_PROGRESSION` Table:** Tabular breakdown with columns `STEP`, `TECHNIQUE / ACTION`, `PHASE`, `STATUS` (`observed`/`inferred`/`unconfirmed`), `RISK %`, and `TIMESTAMP`.

#### Tab 4: `[SOPHISTICATION_RADAR]`
Evaluates attacker tradecraft complexity without fabricated metrics:
- **`THREAT_SOPHISTICATION_ANALYSIS` (6-Axis Radar Chart):** Scores `Technical Complexity`, `Evasion Capability`, `Impact Potential`, `Detection Difficulty`, `Persistence Level`, and `Lateral Movement` (`0–100`) derived deterministically from backend `visualization_metrics` (with client calculation only as fallback).
- **`THREAT_ASSESSMENT_SUMMARY`:** Visual progress bars for `Overall Threat Level`, `Attack Complexity`, `Stealth Level`, `Persistence Capability`, and `Lateral Movement Risk`.
- **Analyst Value:** Helps Tier 2/3 analysts distinguish automated commodity scanning from stealthy defense-evading or lateral-movement intrusions requiring escalation.

#### Tab 5: `[INVESTIGATION_INTEL (N)]` (`InvestigationReportPanel`)
Exposes the complete structured output of the LangGraph multi-agent system (`client/components/investigation-report-panel.tsx`). Badge count `(N)` equals `findings + CVE matches + IOCs`.

- **Top Overview Banner:** Displays `investigation_id`, `status`, `Refinement Rounds`, `THREAT` & `CONFIDENCE` badges, `executive_summary`, **`[POTENTIAL_IMPACT]`**, **`[GUARDRAIL_WARNINGS]`**, and **`[UNCERTAINTY_&_GAPS]`**.
- **Seven Inner Sub-Tabs:**

| Sub-Tab | What It Contains | How Analysts Use It |
| :--- | :--- | :--- |
| **`FINDINGS_&_OBS`** | **`[FINDINGS]`** separating `[OBSERVED_FACTS]`, `[INFERENCES]`, `[UNCERTAINTY]`, `supporting_event_ids`, `ref:evidence_ref_ids`, and `knowledge_source_ids`; plus **`[DIRECT_EVIDENCE_OBSERVATIONS]`** tagged with `ANOMALOUS`, UTC timestamps, `scope_key`, and extracted entities | Audits every claim back to exact log lines so analysts never act on unsupported LLM assertions |
| **`OKF_KNOWLEDGE`** | Unified MITRE ATT&CK + CVE cards with **`ALL / MITRE / CVE`** filter buttons, explicit notice (`is_evidence_proof: false`), `CVSS` score, `REL %`, `[RATIONALE]`, tactics, `[MITIGATIONS]`, `[DETECTIONS]`, `[CONFIRMATION_NEEDED]`, record version, and `provenance_uri` | Provides immediate remediation/detection playbooks and shows *which* confirmation evidence is required to validate whether a matched CVE or ATT&CK technique truly applies |
| **`RELATIONSHIPS_&_PATH`** | **`[ENTITY_RELATIONSHIPS]`** (`source --[relation]--> target`, `observed`/`inferred`, confidence, reasoning) and **`[ATTACK_PATH_EDGES]`** showing causal links between steps | Maps lateral connections between IPs, accounts, hosts, and commands during pivot analysis |
| **`TIMELINE_&_IOCS`** | **`[CHRONOLOGICAL_TIMELINE]`** (IST/UTC timestamps, significance badge, event ID, actor, host, source IP) side-by-side with **`[OBSERVED_IOCS]`** (IOC type, exact value, context) | Feeds SIEM/EDR blocking rules and pivot queries directly from verified IOCs and exact event timestamps |
| **`RECOMMENDATIONS`** | **`[APPROVAL_GATED_RECOMMENDATIONS]`** displaying `priority`, `HUMAN_APPROVAL_REQUIRED · AUTO_EXEC: FALSE`, `Target`, `Action`, `Expected Effect`, and `Rollback` notes | Gives responders actionable containment steps (e.g., disable account, block IP, inspect `/etc/shadow`) with explicit safe-rollback procedures |
| **`SEQUENCE_LSTM`** | **`[LSTM_SEQUENCE_ASSESSMENT]`** showing status (`analyzed` vs. `skipped_no_cues`), summary, and per-cue cards (`cue_id`, `scope_key`, `risk %` vs. `threshold %`, `CORROBORATED` / `UNCORROBORATED`, assessment text) | **Primary check for whether the LSTM model fired on cross-batch behavior** (e.g., failed SSH attempts in an earlier batch escalating upon `sudo` in a later batch for the same host/user) |
| **`AUDIT_TRAIL`** | **`[ORCHESTRATOR_AUDIT_TRAIL]`** table listing `STEP` (`node_name`), `ROLE`, `STATUS` (`completed`, `skipped`, `fallback`, `error`), `MODEL / SLOT`, latency `MS`, and `SUMMARY` | Provides full AI governance/observability—showing which agents ran, whether `sequence_analyst` executed or skipped, which model/API slot ran, and latency per stage |

#### Tab 6: `[EVENT_TIMELINE]` (`SecurityLogDashboard`)
Interactive time-series and distribution dashboard (`client/components/timeline.tsx`):
- **Four View Buttons (`[overview]`, `[timeline]`, `[events]`, `[analysis]`):**
  - `[overview]`: KPI cards for `[SECURITY_RISK]`, `[TIMELINE_ACTIVITY]` (`NORMALIZED_KCP_EVENTS`), and `[OBSERVED_IOCS]`.
  - `[timeline]`: Vertical chronological timeline of normalized events showing severity, actor, host, event type, and IST/UTC timestamps.
  - `[events]`: **`[DETAILED_EVENT_ANALYSIS.LOG]`** cards detailing timestamp, actor/IP, `scope_key`, and per-event numeric risk score.
  - `[analysis]`: **`[THREAT_ASSESSMENT.DB]`** pairing `[FINDINGS_IDENTIFIED]` with `[APPROVAL_GATED_ACTIONS]`.
- **Always-Visible Analytical Charts:**
  - `[SEVERITY_DISTRIBUTION.CHART]` (bar chart across `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
  - `[EVENT_TYPE_DISTRIBUTION.CHART]` (pie chart of KCP event types or kill-chain phases)
  - `[HOURLY_ACTIVITY.CHART]` (line chart showing event bursts by hour)
  - `[EVENT_SUMMARY.TABLE]` (compact searchable/scrollable summary table)

#### Tab 7: `[EXECUTIVE_SUMMARY]` (`ExecutiveThreatSummary`)
Management and governance reporting view (`client/components/executive-threat-summary.tsx`):
- **Export Toolbar:** **`[EXPORT_PDF]`** and **`[COPY_REPORT]`**, plus 4 high-level risk indicators (`OVERALL_RISK_LEVEL`, `MITRE_TECHNIQUES` + `CVE(S) RETRIEVED`, `ATTACK_PHASES`, `CONFIDENCE_SCORE` `EVIDENCE_GROUNDED`).
- **Three Mode Tabs:**
  - **`[EXECUTIVE_OVERVIEW]`:** `[IMPACT_ASSESSMENT]` across `Data Security`, `System Availability`, and `Compliance & Governance` (Scope, Operational impact, Governance impact), `[OBSERVED_PROGRESSION_RISK]` area chart, `[ATTACK_TECHNIQUE_DISTRIBUTION]` pie chart, and `[EXECUTIVE_SUMMARY.TXT]`.
  - **`[RISK_ANALYSIS]`:** `[DETAILED_RISK_ANALYSIS]` listing every matched technique with relevance score, description, and kill-chain tags.
  - **`[ACTION_ITEMS]`:** `[APPROVAL_GATED_ACTION_ITEMS]` prioritized cleanly (`IMMEDIATE`, `SHORT_TERM`, etc.) with target, expected effect, rollback notes, and `HUMAN_APPROVAL_REQUIRED` badges.

---

## 4. OKF Knowledge Hub (`KNOWLEDGE.DB` — `/dashboard/knowledge`)

Operational threat intelligence database and pipeline test bench powered by KCP and Cognee (`client/app/dashboard/knowledge/page.tsx`).

### 4.1 Store Telemetry Header
Displays 5 live store cards (`TOTAL_OKF_RECORDS`, `MITRE_ATTACK`, `CVE_RECORDS`, `INGESTION_RUNS`, `STORE_BACKEND`) with `[REFRESH_STATS]`.

### 4.2 Three Knowledge Hub Tabs

| Tab | Controls & Displays | Cybersecurity Analyst Value |
| :--- | :--- | :--- |
| **`[SEARCH_OKF]`** | • **`[QUERY_OKF_KNOWLEDGE]`**: Free-text query + filters for `SOURCE_TYPE` (`all`, `mitre_attack`, `cve`), `kind`, `tactic`, `platform`, `min_cvss`, `top_k`, and `search_mode` (`auto`, `semantic`, `lexical`, `graph`)<br>• **`[SOURCE_ID_LOOKUP]`**: Exact ID fetch (e.g., `T1548.003` or `CVE-2025-39447`)<br>• **Hit Cards + `[INSPECT_RECORD_&_GRAPH]` Modal**: Shows score, retrieval mode, epistemic notice (`searchResults.notice`), raw `[CONTENT]`, `[PROVENANCE]`, and clickable **`[1_HOP_RELATED_RECORDS]`** graph traversal | Lets threat hunters search 20,000+ CVEs and MITRE techniques semantically or lexically, pivot through 1-hop knowledge graph relationships (techniques ↔ mitigations ↔ data components / CVEs), and inspect source provenance |
| **`[INGESTION_PIPELINE]`** | • **`[INGEST_MITRE_ATTACK]`**: Limit, `Dry run` toggle, `Include deprecated STIX objects` toggle<br>• **`[INGEST_CVE_JSON]`**: Limit, target `YEARS`, optional specific `CVE_IDS`, `Dry run` toggle<br>• **`[INGESTION_RUN_HISTORY]`**: Audit log (`RUN_ID`, `SOURCE`, `STATUS`, `PARSED`, `INSERTED`, `SKIPPED`, `[INSPECT]` JSON detail) | Enables threat intel engineers to safely dry-run STIX/CVE feed updates, track deduplication (`INSERTED` vs. `SKIPPED`), and maintain fresh vulnerability intelligence |
| **`[KCP_BATCH_SANDBOX]`** | JSON editor pre-populated with a contract-compliant `BatchIngestRequest` fixture and 3 sequential stage buttons:<br>1. **`[1. KCP_NORMALIZE_BATCH]`** → previews `NormalizedEvent` records (`scope_key`, `event_type`, `features`, `evidence_ref`)<br>2. **`[2. PREPARE_INVESTIGATION_INPUT]`** → builds validated `InvestigationInput` with pre-retrieved OKF records<br>3. **`[3. RUN_FROM_BATCH]` / `[3. RUN_PREPARED_INVESTIGATION]`** → executes the full LangGraph multi-agent graph and renders `InvestigationReportPanel` inline | Lets detection engineers test custom collector log formats, verify `scope_key` extraction and KCP normalization rules, and debug multi-agent outputs step-by-step |

---

## 5. MITRE ATT&CK Explorer (`MITRE_ATTACK.DB` — `/dashboard/mitre`)

Dedicated Enterprise ATT&CK reference browser (`client/app/dashboard/mitre/page.tsx`, `client/components/themed-mitre-search.tsx`):
- **`[KILL_CHAIN_FILTER.SYS]`:** Dynamic tactic filter buttons built from `/api/mitre/tactics` (`ALL_PHASES`, `INITIAL ACCESS`, `EXECUTION`, etc.).
- **Statistics Strip:** `[TOTAL_TECHNIQUES]`, `[KILL_CHAIN_PHASES]`, `[PLATFORMS]`, `[ACTIVE_FILTER]`.
- **`[ATTACK_TECHNIQUES.DB]` Cards:** Clicking any technique opens `/chat?query=Tell me about <ID>: <Name>` for deep Q&A.
- **`[AI_ENHANCED_THREAT_ANALYSIS.SYS]` (`ThemedMitreSearch`):** Semantic search and RAG mode toggle with terminal history, relevance %, and click-to-chat workflow.

---

## 6. AI Forensic Chatbots

The frontend provides two complementary conversational interfaces tailored to different analyst tasks:

### 6.1 Stored Analysis Gemini Chatbot (`AnalysisChatModal`)
- **Where Accessed:** **`[ASK_AI]`** and **`[ASK_AI_HISTORY]`** on `DASHBOARD.SYS`, **`[ASK_AI_CHATBOT]`** inside the Analysis Details modal, and **`[ASK_AI_CHATBOT]`** on `ANALYSIS.EXE` after an analysis completes (`client/components/analysis-chat-modal.tsx`).
- **Key Controls:**
  - **`[SCOPE]` Switcher:** Ask questions about one specific decrypted analysis **or** select `ALL RECENT STORED ANALYSES (CROSS-HISTORY)`.
  - **`Compare w/ recent history` Checkbox:** Enriches a single-incident conversation with context from recent stored runs (`include_recent_context`).
  - **Starter & Follow-Up Question Pills:** Pre-built forensic prompts (e.g., *"Explain the attack path and distinguish observed facts from inferences"*, *"What evidence or telemetry is still missing or unconfirmed?"*).
- **Grounded Evidence Widgets on Replies:**
  - **`OKF_REFS:`** Validated MITRE ATT&CK / CVE IDs cited.
  - **`EVENT_REFS:`** Validated log `event_id`s supporting the answer (the backend filters out hallucinated IDs).
  - **`[EVIDENCE_CAVEATS]`:** Highlights gaps, unconfirmed assumptions, or missing telemetry.
  - Metadata footer showing consulted analysis count, Gemini model used, and response latency.

### 6.2 Threat Intel & MITRE Assistant (`/chat`)
- **Where Accessed:** Clicking technique cards on `MITRE_ATTACK.DB` or navigating to `/chat` (`client/app/chat/page.tsx`).
- **Structured Collapsible Output:** Renders Markdown and interactive expandable sections for **`[TOP_FINDINGS]`**, **`[DETECTION_QUERIES]`** (ready-to-adapt query snippets with log source & priority), **`[RECOMMENDATIONS]`**, **`[FOLLOW_UP_QUESTIONS]`**, **`[REFERENCES]`**, and **`[CONFIDENCE]`** meter—ideal for detection engineers building SIEM rules.

---

## 7. CLI Collector Setup Guide (`CLI_GUIDE` — `/dashboard/cliguide`)

Interactive onboarding wizard (`client/components/stepguide.tsx`) guiding analysts and infrastructure engineers through installing dependencies, verifying server connectivity, authenticating collectors, and managing CLI log monitoring sessions.

---

## 8. Cybersecurity Analyst Quick-Reference Matrix

| Role / Scenario | Primary Screens & Tabs to Open | What to Look For |
| :--- | :--- | :--- |
| **Tier 1 SOC — Alert & Log Triage** | `DASHBOARD.SYS` → `ANALYSIS.EXE` (`AI_ENHANCEMENT` ON) → `VISUALIZATION` → `[EVENT_TIMELINE]` | Check `SYSTEM_STATUS` & `LSTM_HOOK: CONNECTED`; inspect `THREAT` / `CONFIDENCE` levels, matched MITRE techniques, and chronological KCP events |
| **Multi-Stage / Cross-Batch Intrusion Detection** | `ANALYSIS.EXE` → `InvestigationReportPanel` → `SEQUENCE_LSTM` & `AUDIT_TRAIL` tabs (or `VISUALIZATION` → `[INVESTIGATION_INTEL]` → `SEQUENCE_LSTM`) | Confirm `sequence_assessment.status === "analyzed"`, review `risk_score` vs. `threshold (0.70)`, and trace event IDs across prior and current batches |
| **Tier 2/3 — Root-Cause & Hypothesis Validation** | `VISUALIZATION` → `[ATTACK_JOURNEY]` & `[INVESTIGATION_INTEL]` (`FINDINGS_&_OBS`, `RELATIONSHIPS_&_PATH`) + `[ASK_AI_CHATBOT]` | Separate `OBSERVED = LOG FACT` from `INFERRED` and `UNCONFIRMED`; review `[ALTERNATIVE_HYPOTHESES]` and `[MISSING_EVIDENCE]` before escalating |
| **Threat Hunting & Vulnerability Correlation** | `KNOWLEDGE.DB` → `[SEARCH_OKF]` + `[INSPECT_RECORD_&_GRAPH]`; `MITRE_ATTACK.DB`; `DASHBOARD.SYS` → `[ASK_AI_HISTORY]` | Cross-search MITRE + CVEs, traverse 1-hop mitigations/detections, check `[CONFIRMATION_NEEDED]`, and ask Gemini to spot recurring TTPs/IOCs across recent analyses |
| **Detection Engineering & Collector Onboarding** | `/chat` (`[DETECTION_QUERIES]`), `KNOWLEDGE.DB` → `[KCP_BATCH_SANDBOX]`, `CLI_GUIDE`, `DASHBOARD.SYS` → `[MONITORING_SESSIONS.SVC]` | Build SIEM hunting queries, validate custom `BatchIngestRequest` normalization, and schedule automated log watchers |
| **Incident Containment & Executive Briefing** | `VISUALIZATION` → `[EXECUTIVE_SUMMARY]` (`[EXPORT_PDF]` / `[COPY_REPORT]`) & `[INVESTIGATION_INTEL]` → `RECOMMENDATIONS` | Review `HUMAN_APPROVAL_REQUIRED` actions and rollback notes; export stakeholder-ready PDF briefings backed by verified evidence |

