export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type EvidenceLinkType = 'observed' | 'inferred';
export type AttackPathStatus = 'observed' | 'inferred' | 'unconfirmed';

// ---------------------------------------------------------------------------
// Shared Contracts (server/contracts/models.py)
// ---------------------------------------------------------------------------

export interface EvidenceReference {
  reference_id: string;
  uri: string;
  line_start?: number | null;
  line_end?: number | null;
  sha256?: string | null;
}

export interface RawLogRecord {
  record_id: string;
  observed_at: string;
  message: string;
  source_type: string;
  evidence_ref: EvidenceReference;
  metadata?: Record<string, unknown>;
}

export interface NormalizedEvent {
  schema_version: string;
  event_id: string;
  scope_key: string;
  event_time: string;
  event_type: string;
  source: string;
  features: Record<string, unknown>;
  evidence_ref: EvidenceReference;
}

export interface KnowledgeRelationship {
  relationship_type: string;
  target_source_id: string;
  source: 'source' | 'kcp';
}

export interface KnowledgeRecord {
  schema_version: string;
  record_id: string;
  source_type: 'mitre_attack' | 'cve';
  source_id: string;
  source_version: string;
  content: Record<string, unknown>;
  relationships: KnowledgeRelationship[];
  provenance: Record<string, unknown>;
  ingested_at: string;
}

export interface SequenceCue {
  schema_version: string;
  cue_id: string;
  scope_key: string;
  event_ids: string[];
  risk_score: number;
  threshold: number;
  model_version: string;
  window_ref: string;
  created_at: string;
}

export interface BatchIngestRequest {
  schema_version: string;
  batch_id: string;
  source: string;
  records: RawLogRecord[];
  sent_at: string;
}

export interface InvestigationInput {
  schema_version: string;
  investigation_id: string;
  normalized_events: NormalizedEvent[];
  knowledge_records: KnowledgeRecord[];
  sequence_cues: SequenceCue[];
  created_at: string;
}

// ---------------------------------------------------------------------------
// Multi-Agent Investigation Schemas (server/services/investigation/models.py)
// ---------------------------------------------------------------------------

export interface EvidenceObservation {
  observation_id: string;
  event_id: string;
  evidence_ref_id: string;
  timestamp_utc: string;
  scope_key: string;
  summary: string;
  severity: SeverityLevel;
  entities: string[];
  is_anomalous: boolean;
}

export interface ObservedIOC {
  ioc_type: 'ip' | 'account' | 'host' | 'command' | 'file_path' | 'process' | 'domain' | 'other' | string;
  value: string;
  event_ids: string[];
  evidence_ref_ids: string[];
  context: string;
}

export interface EnrichedKnowledgeItem {
  record_id: string;
  source_type: 'mitre_attack' | 'cve' | string;
  source_id: string;
  source_version: string;
  name: string;
  description_excerpt: string;
  tactics: string[];
  platforms: string[];
  cvss_score?: number | null;
  relevance_score: number;
  is_evidence_proof: boolean;
  supporting_event_ids: string[];
  relevance_rationale: string;
  missing_confirmation_evidence: string[];
  related_mitigations: string[];
  related_detections: string[];
  provenance_uri: string;
}

export interface SequenceCueReview {
  cue_id: string;
  scope_key: string;
  risk_score: number;
  threshold: number;
  corroborated_by_events: boolean;
  supporting_event_ids: string[];
  missing_event_ids: string[];
  assessment: string;
  confidence: ConfidenceLevel;
}

export interface SequenceAnalysisOutput {
  status: 'analyzed' | 'skipped_no_cues' | string;
  reviews: SequenceCueReview[];
  summary: string;
}

export interface TimelineEntry {
  timestamp_utc: string;
  timestamp_ist: string;
  event_id: string;
  evidence_ref_id: string;
  scope_key: string;
  event_type: string;
  actor: string;
  source_ip: string;
  host: string;
  summary: string;
  significance: SeverityLevel | string;
}

export interface EntityRelationship {
  source_entity: string;
  relation: string;
  target_entity: string;
  evidence_type: EvidenceLinkType | string;
  supporting_event_ids: string[];
  reasoning: string;
  confidence: ConfidenceLevel | string;
}

export interface AttackPathNode {
  node_id: string;
  label: string;
  stage: string;
  status: AttackPathStatus | string;
  event_ids: string[];
  knowledge_source_ids: string[];
  confidence: ConfidenceLevel | string;
  notes: string;
}

export interface AttackPathEdge {
  source_node_id: string;
  target_node_id: string;
  label: string;
  status: AttackPathStatus | string;
  evidence_event_ids: string[];
  reasoning: string;
  confidence: ConfidenceLevel | string;
}

export interface AttackPathOutput {
  hypothesis_title: string;
  summary: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  missing_evidence: string[];
  alternative_hypotheses: string[];
  mermaid_diagram: string;
}

export interface RecommendationItem {
  recommendation_id: string;
  priority: 'immediate' | 'short_term' | 'long_term' | string;
  title: string;
  target: string;
  action: string;
  expected_effect: string;
  supporting_finding_ids: string[];
  evidence_event_ids: string[];
  knowledge_mitigation_ids: string[];
  requires_human_approval: boolean;
  auto_executable: boolean;
  rollback_notes: string;
}

export interface InvestigationFinding {
  finding_id: string;
  title: string;
  severity: SeverityLevel | string;
  confidence: ConfidenceLevel | string;
  observed_facts: string[];
  inferences: string[];
  uncertainty: string;
  supporting_event_ids: string[];
  evidence_ref_ids: string[];
  knowledge_source_ids: string[];
}

export interface AuditEntry {
  step_id: string;
  node_name: string;
  agent_role: string;
  status: 'completed' | 'skipped' | 'retried' | 'fallback' | 'error' | string;
  model_name: string;
  api_key_slot: string;
  started_at: string;
  duration_ms: number;
  input_summary: string;
  output_summary: string;
  notes: string[];
}

export interface InvestigationResult {
  schema_version: string;
  investigation_id: string;
  status: 'completed' | 'completed_with_warnings' | string;
  overall_threat_level: SeverityLevel | string;
  overall_confidence: ConfidenceLevel | string;
  executive_summary: string;
  observations: EvidenceObservation[];
  findings: InvestigationFinding[];
  retrieved_knowledge: EnrichedKnowledgeItem[];
  timeline: TimelineEntry[];
  relationships: EntityRelationship[];
  attack_path: AttackPathOutput;
  iocs: ObservedIOC[];
  recommendations: RecommendationItem[];
  recommendation_status: 'drafted' | 'skipped_unjustified' | string;
  sequence_assessment: SequenceAnalysisOutput;
  potential_impact: string[];
  uncertainty_and_gaps: string[];
  guardrail_warnings: string[];
  refinement_rounds_executed: number;
  audit_trail: AuditEntry[];
  rendered_summary: string;
  rendered_markdown_report: string;
  completed_at: string;
  processing_time_ms: number;
}

// ---------------------------------------------------------------------------
// Analysis & Visualization Models (server/model/logs_model.py & visualization_metrics.py)
// ---------------------------------------------------------------------------

export interface AttackTechnique {
  technique_id: string;
  name: string;
  description: string;
  kill_chain_phases: string[];
  platforms: string[];
  relevance_score: number;
  tactic?: string;
}

export interface CveMatchMetric {
  source_id: string;
  name?: string;
  description_excerpt?: string;
  cvss_score?: number | null;
  relevance_score: number;
  relevance_rationale?: string;
  missing_confirmation_evidence?: string[];
  provenance_uri?: string;
}

export interface ThreatJourneyNode {
  id: string;
  phase: string;
  phase_key?: string;
  techniques: string[];
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  timestamp?: string;
  description: string;
}

export interface VisualizationMetrics {
  overall_threat_level?: string;
  overall_confidence_label?: string;
  overall_risk_score?: number;
  max_confidence_pct?: number;
  avg_confidence_pct?: number;
  summary_counts?: {
    techniques_detected?: number;
    cve_count?: number;
    attack_phases?: number;
    findings_count?: number;
    iocs_count?: number;
    timeline_events_count?: number;
    recommendations_count?: number;
    analysis_time_sec?: number;
  };
  sophistication_radar?: Array<{
    subject: string;
    value: number;
    fullMark: number;
  }>;
  threat_assessment_bars?: Array<{
    label: string;
    value: number;
    color: string;
  }>;
  phase_risk_distribution?: Array<{
    phase: string;
    phase_key?: string;
    risk: number;
    max_risk?: number;
    techniques: number;
  }>;
  attack_progression?: Array<{
    step: number;
    technique: string;
    technique_id?: string;
    phase: string;
    risk: number;
    status?: string;
    timestamp: string;
    knowledge_ids?: string[];
  }>;
  attack_journey?: ThreatJourneyNode[];
  attack_path?: Partial<AttackPathOutput>;
  cve_matches?: CveMatchMetric[];
  timeline?: TimelineEntry[];
  iocs?: ObservedIOC[];
  findings?: InvestigationFinding[];
  recommendations?: RecommendationItem[];
  uncertainty_and_gaps?: string[];
  guardrail_warnings?: string[];
}

export interface LogAnalysisResponse {
  id?: string;
  summary: string;
  matched_techniques: AttackTechnique[];
  enhanced_analysis?: string | null;
  investigation?: InvestigationResult | null;
  visualization_metrics?: VisualizationMetrics | null;
  analysis_timestamp: string;
  processing_time_ms: number;
}

// ---------------------------------------------------------------------------
// Knowledge Pipeline & OKF Models (server/services/knowledge/models.py)
// ---------------------------------------------------------------------------

export interface KnowledgeSearchParams {
  query: string;
  source_type?: 'mitre_attack' | 'cve' | null;
  kind?: string | null;
  tactic?: string | null;
  platform?: string | null;
  min_cvss?: number | null;
  top_k?: number;
  search_mode?: 'auto' | 'semantic' | 'lexical' | 'graph';
}

export interface KnowledgeSearchHit {
  record: KnowledgeRecord;
  score: number;
  retrieval_mode: string;
  matched_via: string;
  is_evidence_proof: boolean;
}

export interface KnowledgeSearchResponse {
  query: string;
  total_hits: number;
  retrieval_mode: string;
  hits: KnowledgeSearchHit[];
  notice: string;
}

export interface KnowledgeRecordDetailResponse {
  record: KnowledgeRecord;
  related_records: KnowledgeRecord[];
}

export interface KnowledgeStoreStats {
  backend: string;
  total_records: number;
  counts_by_source_type: Record<string, number>;
  counts_by_kind: Record<string, number>;
  active_versions: Record<string, string[]>;
  total_ingestion_runs: number;
  last_ingested_at?: string | null;
}

export interface IngestionRunStatus {
  run_id: string;
  source_type: 'mitre_attack' | 'cve';
  status: 'running' | 'completed' | 'completed_with_errors' | 'failed';
  started_at: string;
  completed_at?: string | null;
  source_path: string;
  source_version: string;
  dry_run: boolean;
  parsed: number;
  inserted: number;
  updated: number;
  skipped: number;
  rejected_or_filtered: number;
  failed: number;
  errors: string[];
  compression_summary: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Operational / Health / Analytics / Monitoring Models
// ---------------------------------------------------------------------------

export interface DatabaseStats {
  total_techniques: number;
  collection_name: string;
  embedding_model: string;
  last_updated?: string | null;
}

export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy' | string;
  timestamp: string;
  services: Record<string, string>;
  database_stats?: DatabaseStats | null;
}

export interface UserAnalyticsStats {
  total_analyses: number;
  avg_processing_time: number;
  most_common_techniques: Array<{
    technique_id: string;
    name: string;
    count: number;
  }>;
  analysis_timeline: Array<{
    date: string;
    count: number;
    techniques_count: number;
  }>;
}

export interface MonitoringSession {
  session_id: string;
  username?: string;
  log_path: string;
  interval_seconds: number;
  ai_agent_enabled: boolean;
  status: string;
  created_at?: string | null;
  last_checked?: string | null;
  stopped_at?: string | null;
}

export interface MonitoringAnalysisStats {
  total_analyses: number;
  active_sessions: number;
  period_days: number;
}

export interface InvestigationConfig {
  lstm_connected?: boolean;
  key_pool_size?: number;
  models?: Record<string, string>;
  role_models?: Record<string, string>;
  max_refinement_rounds?: number;
  max_followup_queries?: number;
  [key: string]: unknown;
}

