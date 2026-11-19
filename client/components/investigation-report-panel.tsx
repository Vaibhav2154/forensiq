'use client'
import React, { useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Cpu,
  Eye,
  GitBranch,
  Link2,
  Shield,
  Terminal,
} from 'lucide-react';
import type {
  EnrichedKnowledgeItem,
  InvestigationResult,
  VisualizationMetrics,
} from '@/lib/types';

interface InvestigationReportPanelProps {
  investigation?: InvestigationResult | null;
  visualizationMetrics?: VisualizationMetrics | null;
  compact?: boolean;
}

const getSeverityBadge = (severity?: string) => {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 'text-red-400 bg-red-900/30 border-red-500/60';
    case 'high':
      return 'text-orange-400 bg-orange-900/30 border-orange-500/60';
    case 'medium':
      return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/60';
    case 'low':
      return 'text-blue-400 bg-blue-900/30 border-blue-500/60';
    default:
      return 'text-gray-300 bg-gray-900/40 border-gray-600/60';
  }
};

const getEvidenceBadge = (kind?: string) => {
  switch ((kind || '').toLowerCase()) {
    case 'observed':
      return 'text-green-400 bg-green-900/30 border-green-500/60';
    case 'inferred':
      return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/60';
    case 'unconfirmed':
      return 'text-purple-300 bg-purple-900/30 border-purple-500/60';
    default:
      return 'text-gray-300 bg-gray-900/40 border-gray-600/60';
  }
};

const getRemediationTierBadge = (fixTier?: string, fixable?: boolean) => {
  if (!fixable || fixTier === 'tier_3_advisory') {
    return {
      label: 'ADVISORY_ONLY',
      className: 'text-gray-300 bg-gray-900/40 border-gray-600/60',
    };
  }
  if (fixTier === 'tier_1_playbook') {
    return {
      label: 'TIER_1_PLAYBOOK',
      className: 'text-cyan-300 bg-cyan-900/30 border-cyan-500/60',
    };
  }
  if (fixTier === 'tier_2_config_diff') {
    return {
      label: 'TIER_2_CONFIG_DIFF',
      className: 'text-blue-300 bg-blue-900/30 border-blue-500/60',
    };
  }
  return {
    label: 'ADVISORY_ONLY',
    className: 'text-gray-300 bg-gray-900/40 border-gray-600/60',
  };
};

const getExecutionStatusBadge = (status?: string) => {
  switch ((status || 'pending_approval').toLowerCase()) {
    case 'executed':
      return 'text-green-300 bg-green-900/30 border-green-500/60';
    case 'rolled_back':
      return 'text-orange-300 bg-orange-900/30 border-orange-500/60';
    case 'rejected':
      return 'text-gray-300 bg-gray-900/40 border-gray-500/60';
    case 'failed':
      return 'text-red-300 bg-red-900/30 border-red-500/60';
    case 'approved':
      return 'text-cyan-300 bg-cyan-900/30 border-cyan-500/60';
    default:
      return 'text-yellow-300 bg-yellow-900/20 border-yellow-500/50';
  }
};

type SectionTab =
  | 'findings'
  | 'knowledge'
  | 'graph'
  | 'timeline'
  | 'recommendations'
  | 'sequence'
  | 'audit';

const InvestigationReportPanel: React.FC<InvestigationReportPanelProps> = ({
  investigation,
  visualizationMetrics,
  compact = false,
}) => {
  const [activeTab, setActiveTab] = useState<SectionTab>('findings');
  const [knowledgeFilter, setKnowledgeFilter] = useState<'all' | 'mitre_attack' | 'cve'>('all');

  if (!investigation) {
    return (
      <div className="bg-black/80 border border-gray-700/60 p-6 text-center font-mono">
        <Cpu className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
        <h3 className="text-base font-bold text-cyan-400 mb-1">[NO_MULTI_AGENT_INVESTIGATION_PAYLOAD]</h3>
        <p className="text-gray-400 text-xs sm:text-sm">
          Run an AI-enhanced analysis or multi-agent batch investigation to view findings, observations, CVEs, relationships, attack-path edges, sequence cues, and the audit trail.
        </p>
      </div>
    );
  }

  const findings = Array.isArray(investigation.findings) ? investigation.findings : [];
  const observations = Array.isArray(investigation.observations) ? investigation.observations : [];
  const retrievedKnowledge = Array.isArray(investigation.retrieved_knowledge)
    ? investigation.retrieved_knowledge
    : [];
  const relationships = Array.isArray(investigation.relationships) ? investigation.relationships : [];
  const attackPath = investigation.attack_path;
  const attackPathEdges = Array.isArray(attackPath?.edges) ? attackPath.edges : [];
  const iocs = Array.isArray(investigation.iocs) ? investigation.iocs : [];
  const timeline = Array.isArray(investigation.timeline) ? investigation.timeline : [];
  const recommendations = Array.isArray(investigation.recommendations) ? investigation.recommendations : [];
  const remediationHistory = Array.isArray(investigation.remediation_history)
    ? investigation.remediation_history
    : [];
  const seqAssessment = investigation.sequence_assessment;
  const auditTrail = Array.isArray(investigation.audit_trail) ? investigation.audit_trail : [];
  const potentialImpact = Array.isArray(investigation.potential_impact) ? investigation.potential_impact : [];
  const uncertaintyAndGaps = Array.isArray(investigation.uncertainty_and_gaps)
    ? investigation.uncertainty_and_gaps
    : visualizationMetrics?.uncertainty_and_gaps || [];
  const guardrailWarnings = Array.isArray(investigation.guardrail_warnings)
    ? investigation.guardrail_warnings
    : visualizationMetrics?.guardrail_warnings || [];

  const filteredKnowledge: EnrichedKnowledgeItem[] = retrievedKnowledge.filter((item) => {
    if (knowledgeFilter === 'all') return true;
    return (item.source_type || '').toLowerCase() === knowledgeFilter;
  });

  const mitreCount = retrievedKnowledge.filter((k) => k.source_type === 'mitre_attack').length;
  const cveCount = retrievedKnowledge.filter((k) => k.source_type === 'cve').length;

  const tabs: Array<{ id: SectionTab; label: string }> = [
    { id: 'findings', label: `FINDINGS_&_OBS (${findings.length}/${observations.length})` },
    { id: 'knowledge', label: `OKF_KNOWLEDGE (${mitreCount} MITRE · ${cveCount} CVE)` },
    { id: 'graph', label: `RELATIONSHIPS_&_PATH (${relationships.length}/${attackPathEdges.length})` },
    { id: 'timeline', label: `TIMELINE_&_IOCS (${timeline.length}/${iocs.length})` },
    { id: 'recommendations', label: `RECOMMENDATIONS (${recommendations.length})` },
    { id: 'sequence', label: `SEQUENCE_LSTM (${seqAssessment?.reviews?.length || 0})` },
    { id: 'audit', label: `AUDIT_TRAIL (${auditTrail.length})` },
  ];

  return (
    <div className="space-y-4 font-mono">
      {/* Overview Banner */}
      <div className="bg-black/80 border border-cyan-500/40 p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <div>
            <h3 className="text-base sm:text-lg font-bold text-cyan-400">
              [MULTI_AGENT_INVESTIGATION: {investigation.investigation_id}]
            </h3>
            <p className="text-xs text-gray-400">
              Status: {investigation.status} · Refinement Rounds: {investigation.refinement_rounds_executed ?? 0}
            </p>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            <span className={`px-2 py-1 border font-bold uppercase ${getSeverityBadge(investigation.overall_threat_level)}`}>
              THREAT: {investigation.overall_threat_level}
            </span>
            <span className="px-2 py-1 border border-cyan-500/40 text-cyan-300 uppercase">
              CONFIDENCE: {investigation.overall_confidence}
            </span>
          </div>
        </div>

        {investigation.executive_summary && (
          <p className="text-xs sm:text-sm text-gray-200 leading-relaxed mb-3">
            {investigation.executive_summary}
          </p>
        )}

        {potentialImpact.length > 0 && (
          <div className="mb-3">
            <span className="text-xs text-orange-400 font-semibold">[POTENTIAL_IMPACT]:</span>
            <ul className="mt-1 space-y-1 text-xs text-gray-300 list-disc list-inside">
              {potentialImpact.map((item, idx) => (
                <li key={idx}>{item}</li>
              ))}
            </ul>
          </div>
        )}

        {(guardrailWarnings.length > 0 || uncertaintyAndGaps.length > 0) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
            {guardrailWarnings.length > 0 && (
              <div className="bg-yellow-950/20 border border-yellow-500/40 p-3">
                <div className="text-xs text-yellow-400 font-semibold mb-1">[GUARDRAIL_WARNINGS]</div>
                <ul className="space-y-1 text-xs text-gray-300 list-disc list-inside">
                  {guardrailWarnings.map((w, idx) => (
                    <li key={idx}>{w}</li>
                  ))}
                </ul>
              </div>
            )}
            {uncertaintyAndGaps.length > 0 && (
              <div className="bg-purple-950/20 border border-purple-500/40 p-3">
                <div className="text-xs text-purple-300 font-semibold mb-1">[UNCERTAINTY_&_GAPS]</div>
                <ul className="space-y-1 text-xs text-gray-300 list-disc list-inside">
                  {uncertaintyAndGaps.map((g, idx) => (
                    <li key={idx}>{g}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Sub-navigation Tabs */}
      <div className="flex flex-wrap gap-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-1.5 border text-xs transition-colors ${
              activeTab === tab.id
                ? 'bg-cyan-500/20 border-cyan-400 text-cyan-300'
                : 'bg-black/70 border-gray-700 text-gray-400 hover:border-cyan-500/50 hover:text-cyan-300'
            }`}
          >
            [{tab.label}]
          </button>
        ))}
      </div>

      {/* 1. Findings & Observations */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          <div className="bg-black/80 border border-red-500/30 p-4">
            <h4 className="text-sm font-semibold text-red-400 mb-3">
              [FINDINGS ({findings.length})]
            </h4>
            {findings.length === 0 ? (
              <p className="text-xs text-gray-400">No material findings reported.</p>
            ) : (
              <div className="space-y-3">
                {findings.map((f, idx) => (
                  <div key={f.finding_id || idx} className="bg-black/60 border border-gray-700/60 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <span className="font-bold text-white text-sm">
                        {f.finding_id ? `[${f.finding_id}] ` : ''}{f.title}
                      </span>
                      <div className="flex gap-2 text-xs">
                        <span className={`px-2 py-0.5 border uppercase ${getSeverityBadge(f.severity)}`}>
                          {f.severity}
                        </span>
                        <span className="px-2 py-0.5 border border-cyan-500/40 text-cyan-300 uppercase">
                          CONF: {f.confidence}
                        </span>
                      </div>
                    </div>
                    {f.observed_facts?.length > 0 && (
                      <div className="mb-2">
                        <div className="text-xs text-green-400 font-semibold">[OBSERVED_FACTS]</div>
                        <ul className="text-xs text-gray-300 list-disc list-inside space-y-0.5">
                          {f.observed_facts.map((fact, i) => <li key={i}>{fact}</li>)}
                        </ul>
                      </div>
                    )}
                    {f.inferences?.length > 0 && (
                      <div className="mb-2">
                        <div className="text-xs text-yellow-400 font-semibold">[INFERENCES]</div>
                        <ul className="text-xs text-gray-300 list-disc list-inside space-y-0.5">
                          {f.inferences.map((inf, i) => <li key={i}>{inf}</li>)}
                        </ul>
                      </div>
                    )}
                    {f.uncertainty && (
                      <p className="text-xs text-purple-300 mb-2">
                        <span className="font-semibold">[UNCERTAINTY]:</span> {f.uncertainty}
                      </p>
                    )}
                    <div className="flex flex-wrap gap-1.5 text-[11px]">
                      {(f.supporting_event_ids || []).map((eid) => (
                        <span key={eid} className="px-1.5 py-0.5 bg-green-900/20 border border-green-500/40 text-green-300">
                          {eid}
                        </span>
                      ))}
                      {(f.evidence_ref_ids || []).map((rid) => (
                        <span key={rid} className="px-1.5 py-0.5 bg-blue-900/20 border border-blue-500/40 text-blue-300">
                          ref:{rid}
                        </span>
                      ))}
                      {(f.knowledge_source_ids || []).map((kid) => (
                        <span key={kid} className="px-1.5 py-0.5 bg-red-900/20 border border-red-500/40 text-red-300">
                          {kid}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-black/80 border border-green-500/30 p-4">
            <h4 className="text-sm font-semibold text-green-400 mb-3 flex items-center gap-2">
              <Eye className="h-4 w-4" />
              [DIRECT_EVIDENCE_OBSERVATIONS ({observations.length})]
            </h4>
            {observations.length === 0 ? (
              <p className="text-xs text-gray-400">No direct observations recorded.</p>
            ) : (
              <div className={`space-y-2 ${compact ? 'max-h-72 overflow-y-auto pr-1' : ''}`}>
                {observations.map((obs, idx) => (
                  <div key={obs.observation_id || idx} className="bg-black/60 border border-gray-700/60 p-3 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                      <span className="text-green-300 font-semibold">
                        {obs.observation_id} · {obs.event_id} · ref:{obs.evidence_ref_id}
                      </span>
                      <div className="flex gap-2">
                        {obs.is_anomalous && (
                          <span className="px-2 py-0.5 border border-red-500/60 bg-red-900/30 text-red-300">
                            ANOMALOUS
                          </span>
                        )}
                        <span className={`px-2 py-0.5 border uppercase ${getSeverityBadge(obs.severity)}`}>
                          {obs.severity}
                        </span>
                      </div>
                    </div>
                    <p className="text-gray-200 mb-1">{obs.summary}</p>
                    <div className="text-[11px] text-gray-400 flex flex-wrap gap-3">
                      <span>{obs.timestamp_utc}</span>
                      <span>scope: {obs.scope_key}</span>
                      {obs.entities?.length > 0 && <span>entities: {obs.entities.join(', ')}</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 2. Retrieved OKF Knowledge (MITRE + CVEs + provenance + mitigations + detections) */}
      {activeTab === 'knowledge' && (
        <div className="bg-black/80 border border-orange-500/30 p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h4 className="text-sm font-semibold text-orange-400">
                [OKF_RETRIEVED_KNOWLEDGE ({retrievedKnowledge.length})]
              </h4>
              <p className="text-[11px] text-yellow-300 mt-0.5">
                Context only (is_evidence_proof: false) — retrieved ATT&amp;CK and CVE records are not proof of compromise or exploitation.
              </p>
            </div>
            <div className="flex gap-2 text-xs">
              {(['all', 'mitre_attack', 'cve'] as const).map((filterKey) => (
                <button
                  key={filterKey}
                  type="button"
                  onClick={() => setKnowledgeFilter(filterKey)}
                  className={`px-2.5 py-1 border uppercase ${
                    knowledgeFilter === filterKey
                      ? 'border-orange-400 bg-orange-500/20 text-orange-300'
                      : 'border-gray-700 text-gray-400 hover:border-orange-500/50'
                  }`}
                >
                  {filterKey === 'all' ? `ALL (${retrievedKnowledge.length})` : filterKey === 'mitre_attack' ? `MITRE (${mitreCount})` : `CVE (${cveCount})`}
                </button>
              ))}
            </div>
          </div>

          {filteredKnowledge.length === 0 ? (
            <p className="text-xs text-gray-400">No knowledge records match the current filter.</p>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {filteredKnowledge.map((item, idx) => (
                <div key={item.record_id || idx} className="bg-black/60 border border-gray-700/60 p-3 text-xs space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-bold text-cyan-300">
                      {item.source_id} {item.name && item.name !== item.source_id ? `— ${item.name}` : ''}
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      <span className={`px-2 py-0.5 border uppercase ${
                        item.source_type === 'cve'
                          ? 'border-orange-500/50 text-orange-300'
                          : 'border-red-500/50 text-red-300'
                      }`}>
                        {item.source_type}
                      </span>
                      {item.cvss_score != null && (
                        <span className="px-2 py-0.5 border border-red-500/50 text-red-300">
                          CVSS {item.cvss_score}
                        </span>
                      )}
                      <span className="px-2 py-0.5 border border-cyan-500/40 text-cyan-300">
                        REL {Math.round((item.relevance_score || 0) * 100)}%
                      </span>
                    </div>
                  </div>

                  {item.description_excerpt && (
                    <p className="text-gray-300 leading-relaxed">{item.description_excerpt}</p>
                  )}

                  {item.relevance_rationale && (
                    <p className="text-cyan-200">
                      <span className="text-cyan-400 font-semibold">[RATIONALE]:</span> {item.relevance_rationale}
                    </p>
                  )}

                  {item.tactics?.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      <span className="text-gray-400">Tactics:</span>
                      {item.tactics.map((t) => (
                        <span key={t} className="px-1.5 py-0.5 bg-purple-900/20 border border-purple-500/40 text-purple-300">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}

                  {item.related_mitigations?.length > 0 && (
                    <div>
                      <span className="text-green-400 font-semibold">[MITIGATIONS]:</span>{' '}
                      <span className="text-gray-300">{item.related_mitigations.join(' | ')}</span>
                    </div>
                  )}

                  {item.related_detections?.length > 0 && (
                    <div>
                      <span className="text-blue-400 font-semibold">[DETECTIONS]:</span>{' '}
                      <span className="text-gray-300">{item.related_detections.join(' | ')}</span>
                    </div>
                  )}

                  {item.missing_confirmation_evidence?.length > 0 && (
                    <div>
                      <span className="text-yellow-400 font-semibold">[CONFIRMATION_NEEDED]:</span>{' '}
                      <span className="text-gray-300">{item.missing_confirmation_evidence.join('; ')}</span>
                    </div>
                  )}

                  <div className="text-[11px] text-gray-500 flex flex-wrap justify-between gap-2 pt-1 border-t border-gray-800">
                    <span>record: {item.record_id} (v{item.source_version || '1'})</span>
                    {item.provenance_uri && <span className="truncate max-w-xs">src: {item.provenance_uri}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 3. Entity Relationships & Attack-Path Edges */}
      {activeTab === 'graph' && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="bg-black/80 border border-cyan-500/30 p-4">
            <h4 className="text-sm font-semibold text-cyan-400 mb-3 flex items-center gap-2">
              <Link2 className="h-4 w-4" />
              [ENTITY_RELATIONSHIPS ({relationships.length})]
            </h4>
            {relationships.length === 0 ? (
              <p className="text-xs text-gray-400">No entity relationships recorded.</p>
            ) : (
              <div className="space-y-2">
                {relationships.map((rel, idx) => (
                  <div key={idx} className="bg-black/60 border border-gray-700/60 p-3 text-xs space-y-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-white font-semibold">
                        {rel.source_entity} <span className="text-cyan-400">--[{rel.relation}]--&gt;</span> {rel.target_entity}
                      </span>
                      <div className="flex gap-1.5">
                        <span className={`px-2 py-0.5 border uppercase ${getEvidenceBadge(rel.evidence_type)}`}>
                          {rel.evidence_type}
                        </span>
                        <span className="px-2 py-0.5 border border-gray-600 text-gray-300 uppercase">
                          {rel.confidence}
                        </span>
                      </div>
                    </div>
                    {rel.reasoning && <p className="text-gray-300">{rel.reasoning}</p>}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-black/80 border border-purple-500/30 p-4">
            <h4 className="text-sm font-semibold text-purple-400 mb-3 flex items-center gap-2">
              <GitBranch className="h-4 w-4" />
              [ATTACK_PATH_EDGES ({attackPathEdges.length})]
            </h4>
            {attackPathEdges.length === 0 ? (
              <p className="text-xs text-gray-400">No attack-path edges recorded.</p>
            ) : (
              <div className="space-y-2">
                {attackPathEdges.map((edge, idx) => (
                  <div key={idx} className="bg-black/60 border border-gray-700/60 p-3 text-xs space-y-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-white font-semibold">
                        {edge.source_node_id} <span className="text-purple-400">--[{edge.label}]--&gt;</span> {edge.target_node_id}
                      </span>
                      <span className={`px-2 py-0.5 border uppercase ${getEvidenceBadge(edge.status)}`}>
                        {edge.status}
                      </span>
                    </div>
                    {edge.reasoning && <p className="text-gray-300">{edge.reasoning}</p>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. Timeline & Observed IOCs */}
      {activeTab === 'timeline' && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="bg-black/80 border border-green-500/30 p-4">
            <h4 className="text-sm font-semibold text-green-400 mb-3 flex items-center gap-2">
              <Clock className="h-4 w-4" />
              [CHRONOLOGICAL_TIMELINE ({timeline.length})]
            </h4>
            {timeline.length === 0 ? (
              <p className="text-xs text-gray-400">No timeline entries recorded.</p>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {timeline.map((entry, idx) => (
                  <div key={entry.event_id || idx} className="bg-black/60 border-l-2 border-green-500 p-3 text-xs">
                    <div className="flex flex-wrap justify-between gap-2 mb-1">
                      <span className="text-green-400">{entry.timestamp_ist || entry.timestamp_utc}</span>
                      <span className={`px-2 py-0.5 border uppercase ${getSeverityBadge(entry.significance)}`}>
                        {entry.significance}
                      </span>
                    </div>
                    <p className="text-white mb-1">{entry.summary}</p>
                    <div className="text-[11px] text-gray-400 flex flex-wrap gap-3">
                      <span>event: {entry.event_id}</span>
                      {entry.actor && <span>actor: {entry.actor}</span>}
                      {entry.host && <span>host: {entry.host}</span>}
                      {entry.source_ip && <span>ip: {entry.source_ip}</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-black/80 border border-cyan-500/30 p-4">
            <h4 className="text-sm font-semibold text-cyan-400 mb-3">
              [OBSERVED_IOCS ({iocs.length})]
            </h4>
            {iocs.length === 0 ? (
              <p className="text-xs text-gray-400">No IOCs extracted from logs.</p>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {iocs.map((ioc, idx) => (
                  <div key={idx} className="bg-black/60 border border-gray-700/60 p-3 text-xs space-y-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="px-2 py-0.5 border border-cyan-500/40 text-cyan-300 uppercase">
                        {ioc.ioc_type}
                      </span>
                      <span className="text-white font-bold break-all">{ioc.value}</span>
                    </div>
                    {ioc.context && <p className="text-gray-300">{ioc.context}</p>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5. Approval-Gated Recommendations */}
      {activeTab === 'recommendations' && (
        <div className="bg-black/80 border border-purple-500/30 p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="text-sm font-semibold text-purple-400 flex items-center gap-2">
              <Shield className="h-4 w-4" />
              [APPROVAL_GATED_RECOMMENDATIONS ({recommendations.length})]
            </h4>
            <span className="text-xs text-gray-400">status: {investigation.recommendation_status}</span>
          </div>
          {recommendations.length === 0 ? (
            <p className="text-xs text-gray-400">
              No recommendations drafted (status: {investigation.recommendation_status}).
            </p>
          ) : (
            <div className="space-y-3">
              {recommendations.map((rec, idx) => {
                const tierBadge = getRemediationTierBadge(rec.fix_tier, rec.fixable_via_tui);
                const execStatus = rec.execution_status || 'pending_approval';
                return (
                  <div key={rec.recommendation_id || idx} className="bg-black/60 border border-gray-700/60 p-3 text-xs space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-bold text-white text-sm">{rec.title}</span>
                      <div className="flex flex-wrap gap-2">
                        <span className="px-2 py-0.5 border border-purple-500/50 text-purple-300 uppercase">
                          {rec.priority}
                        </span>
                        <span className={`px-2 py-0.5 border uppercase ${tierBadge.className}`}>
                          {tierBadge.label}
                        </span>
                        {rec.fixable_via_tui && rec.playbook_id && rec.playbook_id !== 'manual_only' && (
                          <span className="px-2 py-0.5 border border-cyan-500/50 text-cyan-300">
                            TUI_PLAYBOOK: {rec.playbook_id}
                          </span>
                        )}
                        <span className={`px-2 py-0.5 border uppercase ${getExecutionStatusBadge(execStatus)}`}>
                          STATUS: {execStatus}
                        </span>
                        <span className="px-2 py-0.5 border border-yellow-500/50 text-yellow-300 flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3" />
                          HUMAN_APPROVAL_REQUIRED · AUTO_EXEC: FALSE
                        </span>
                      </div>
                    </div>
                    <p className="text-cyan-300"><span className="font-semibold">Target:</span> {rec.target}</p>
                    <p className="text-gray-200"><span className="font-semibold">Action:</span> {rec.action}</p>
                    {rec.expected_effect && (
                      <p className="text-green-300"><span className="font-semibold">Expected Effect:</span> {rec.expected_effect}</p>
                    )}
                    {rec.rollback_notes && (
                      <p className="text-gray-400"><span className="font-semibold">Rollback:</span> {rec.rollback_notes}</p>
                    )}
                  </div>
                );
              })}
            </div>
          )}
          {remediationHistory.length > 0 && (
            <div className="mt-4 pt-3 border-t border-purple-500/30 space-y-2">
              <div className="text-xs font-semibold text-cyan-400">
                [TUI_REMEDIATION_AUDIT_SYNC ({remediationHistory.length})]
              </div>
              <div className="space-y-1.5">
                {remediationHistory.map((ev, idx) => (
                  <div key={`${ev.recommendation_id}-${ev.recorded_at}-${idx}`} className="bg-black/60 border border-gray-800 p-2 text-[11px] flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-white font-semibold">{ev.recommendation_id}</span>
                      <span className={`px-1.5 py-0.5 border uppercase ${getExecutionStatusBadge(ev.execution_status)}`}>
                        {ev.execution_status}
                      </span>
                      {ev.receipt_id && <span className="text-cyan-300">receipt: {ev.receipt_id}</span>}
                      {ev.executed_by && <span className="text-gray-400">by: {ev.executed_by}</span>}
                      {ev.notes && <span className="text-gray-300">({ev.notes})</span>}
                    </div>
                    <span className="text-gray-500">{ev.recorded_at}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 6. LSTM Sequence Context Assessment */}
      {activeTab === 'sequence' && (
        <div className="bg-black/80 border border-yellow-500/30 p-4 space-y-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="text-sm font-semibold text-yellow-400">[LSTM_SEQUENCE_ASSESSMENT]</h4>
            <span className="px-2 py-0.5 border border-yellow-500/40 text-yellow-300 uppercase">
              {seqAssessment?.status || 'skipped_no_cues'}
            </span>
          </div>
          <p className="text-gray-300">{seqAssessment?.summary || 'No LSTM sequence cues provided.'}</p>
          {(seqAssessment?.reviews || []).map((rev, idx) => (
            <div key={rev.cue_id || idx} className="bg-black/60 border border-gray-700/60 p-3 space-y-1">
              <div className="flex flex-wrap justify-between gap-2">
                <span className="text-white font-semibold">{rev.cue_id} · scope: {rev.scope_key}</span>
                <span className="text-yellow-300">
                  risk {(rev.risk_score * 100).toFixed(0)}% (threshold {(rev.threshold * 100).toFixed(0)}%) · {rev.corroborated_by_events ? 'CORROBORATED' : 'UNCORROBORATED'}
                </span>
              </div>
              <p className="text-gray-300">{rev.assessment}</p>
            </div>
          ))}
        </div>
      )}

      {/* 7. Multi-Agent Audit Trail */}
      {activeTab === 'audit' && (
        <div className="bg-black/80 border border-green-500/30 p-4">
          <h4 className="text-sm font-semibold text-green-400 mb-3 flex items-center gap-2">
            <Terminal className="h-4 w-4" />
            [ORCHESTRATOR_AUDIT_TRAIL ({auditTrail.length})]
          </h4>
          {auditTrail.length === 0 ? (
            <p className="text-xs text-gray-400">No audit entries recorded.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-green-500/40 text-cyan-400">
                    <th className="text-left py-2 pr-3">STEP</th>
                    <th className="text-left py-2 pr-3">ROLE</th>
                    <th className="text-left py-2 pr-3">STATUS</th>
                    <th className="text-left py-2 pr-3">MODEL / SLOT</th>
                    <th className="text-left py-2 pr-3">MS</th>
                    <th className="text-left py-2">SUMMARY</th>
                  </tr>
                </thead>
                <tbody>
                  {auditTrail.map((entry, idx) => (
                    <tr key={entry.step_id || idx} className="border-b border-gray-800 align-top">
                      <td className="py-2 pr-3 text-gray-300">{entry.node_name}</td>
                      <td className="py-2 pr-3 text-cyan-300">{entry.agent_role}</td>
                      <td className="py-2 pr-3">
                        <span className={`px-1.5 py-0.5 border uppercase ${
                          entry.status === 'completed'
                            ? 'border-green-500/50 text-green-400'
                            : entry.status === 'error'
                            ? 'border-red-500/50 text-red-400'
                            : 'border-yellow-500/50 text-yellow-300'
                        }`}>
                          {entry.status}
                        </span>
                      </td>
                      <td className="py-2 pr-3 text-gray-400">
                        {entry.model_name || '-'} {entry.api_key_slot ? `(${entry.api_key_slot})` : ''}
                      </td>
                      <td className="py-2 pr-3 text-gray-300">{Math.round(entry.duration_ms || 0)}</td>
                      <td className="py-2 text-gray-300">{entry.output_summary || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default InvestigationReportPanel;

