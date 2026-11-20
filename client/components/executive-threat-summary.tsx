'use client'
import React, { useState, useMemo } from 'react';
import {
  Building, ChevronRight, Download, Share, Eye,
  BarChart3, Target
} from 'lucide-react';
import {
  ResponsiveContainer, XAxis, YAxis, CartesianGrid,
  Tooltip, PieChart as RechartsPieChart, Pie, Cell, Area, AreaChart
} from 'recharts';
import { exportMarkdownToPdf } from '@/hooks/MarkDownToPdf';
import type { LogAnalysisResponse } from '@/lib/types';

interface BusinessImpact {
  area: string;
  risk_level: number;
  financial_impact: string;
  operational_impact: string;
  reputation_impact: string;
}

const SEVERITY_RISK_MAP: Record<string, number> = {
  critical: 95,
  high: 75,
  medium: 55,
  low: 30,
  informational: 15,
};

const ExecutiveThreatSummary: React.FC<{ data: LogAnalysisResponse }> = ({ data }) => {
  const [viewMode, setViewMode] = useState<'overview' | 'details' | 'recommendations'>('overview');

  const investigation = data.investigation || null;
  const vm = data.visualization_metrics || null;

  const executiveMetrics = useMemo(() => {
    const techniques = Array.isArray(data.matched_techniques) ? data.matched_techniques : [];
    const count = techniques.length;
    const avgConfidence =
      count > 0
        ? techniques.reduce((sum, t) => sum + (t.relevance_score || 0), 0) / count
        : 0;
    const maxRisk =
      count > 0
        ? Math.max(...techniques.map(t => t.relevance_score || 0))
        : 0;
    const uniquePhases = new Set(techniques.flatMap(t => t.kill_chain_phases || []));

    const overallRisk = vm?.overall_risk_score ?? Math.round(maxRisk * 100);
    const confidenceLabel = (investigation?.overall_confidence || vm?.overall_confidence_label || 'low').toUpperCase();
    const confidencePct = investigation?.overall_confidence
      ? (confidenceLabel === 'HIGH' ? 85 : confidenceLabel === 'MEDIUM' ? 65 : 35)
      : (vm?.avg_confidence_pct ?? Math.round(avgConfidence * 100));

    return {
      overall_risk: overallRisk,
      confidence_level: confidencePct,
      confidence_label: confidenceLabel,
      threat_level_label: (investigation?.overall_threat_level || vm?.overall_threat_level || '').toUpperCase(),
      attack_phases: vm?.summary_counts?.attack_phases ?? uniquePhases.size,
      techniques_detected: vm?.summary_counts?.techniques_detected ?? count,
      cve_count: vm?.summary_counts?.cve_count ?? 0,
      analysis_time: vm?.summary_counts?.analysis_time_sec ?? Math.round((data.processing_time_ms || 0) / 1000),
      threat_sophistication: confidencePct
    };
  }, [data, investigation, vm]);

  const businessImpacts: BusinessImpact[] = useMemo(() => {
    const impacts = Array.isArray(investigation?.potential_impact) ? investigation.potential_impact : [];
    return [
      {
        area: 'Data Security',
        risk_level: executiveMetrics.overall_risk,
        financial_impact: executiveMetrics.overall_risk > 70 ? 'High Exposure' : executiveMetrics.overall_risk > 40 ? 'Moderate Exposure' : 'Low Exposure',
        operational_impact: impacts[0] || (executiveMetrics.overall_risk > 70 ? 'Sensitive Data / Credentials at Risk' : 'Limited Direct Impact'),
        reputation_impact: executiveMetrics.overall_risk > 70 ? 'Significant Trust Impact' : 'Contained Scope'
      },
      {
        area: 'System Availability',
        risk_level: Math.round(executiveMetrics.overall_risk * 0.8),
        financial_impact: 'Potential Downtime & Containment Effort',
        operational_impact: impacts[1] || 'Service Continuity Monitoring Required',
        reputation_impact: 'Customer / Internal Service Impact'
      },
      {
        area: 'Compliance & Governance',
        risk_level: Math.round(executiveMetrics.overall_risk * 0.6),
        financial_impact: 'Audit & Reporting Scope',
        operational_impact: impacts[2] || 'Forensic Evidence & Provenance Preserved',
        reputation_impact: 'Regulatory & Stakeholder Review'
      }
    ];
  }, [executiveMetrics, investigation]);

  // Deterministic progression chart (no Math.random)
  const riskTrends = useMemo(() => {
    const progression = vm?.attack_progression || [];
    if (progression.length > 0) {
      return progression.map((step) => ({
        label: step.timestamp || `Step ${step.step}`,
        risk: step.risk,
      }));
    }

    const timeline = Array.isArray(investigation?.timeline) ? investigation.timeline : [];
    if (timeline.length > 0) {
      return timeline.map((entry, idx) => ({
        label: entry.timestamp_ist || entry.timestamp_utc || `Event ${idx + 1}`,
        risk: SEVERITY_RISK_MAP[(entry.significance || 'medium').toLowerCase()] ?? 50,
      }));
    }

    const techniques = Array.isArray(data.matched_techniques) ? data.matched_techniques : [];
    return techniques.map((t, idx) => ({
      label: t.technique_id || `Step ${idx + 1}`,
      risk: Math.round((t.relevance_score || 0) * 100),
    }));
  }, [vm, investigation, data.matched_techniques]);

  const techniqueDistribution = useMemo(() => {
    const techniques = Array.isArray(data.matched_techniques) ? data.matched_techniques : [];
    if (techniques.length === 0) return [];
    const phaseCount = techniques.reduce((acc, tech) => {
      (tech.kill_chain_phases || []).forEach(phase => {
        acc[phase] = (acc[phase] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);

    const totalAssignments = Object.values(phaseCount).reduce((sum, n) => sum + n, 0) || 1;
    return Object.entries(phaseCount).map(([phase, count]) => ({
      phase: phase.replace(/-/g, ' ').toUpperCase(),
      count,
      percentage: Math.round((count / totalAssignments) * 100)
    }));
  }, [data]);

  const getSeverityColor = (risk: number) => {
    if (risk >= 80) return 'text-red-400 bg-red-900/30 border-red-500';
    if (risk >= 60) return 'text-orange-400 bg-orange-900/30 border-orange-500';
    if (risk >= 40) return 'text-yellow-400 bg-yellow-900/30 border-yellow-500';
    return 'text-green-400 bg-green-900/30 border-green-500';
  };

  const getScoreLevel = (risk: number) => {
    if (risk >= 80) return 'CRITICAL';
    if (risk >= 60) return 'HIGH';
    if (risk >= 40) return 'MEDIUM';
    if (risk >= 20) return 'LOW';
    return 'INFORMATIONAL';
  };

  const getRiskLevel = (risk: number) => {
    if (executiveMetrics.threat_level_label) return executiveMetrics.threat_level_label;
    return getScoreLevel(risk);
  };

  const recommendationsList = useMemo(() => {
    const realRecs = Array.isArray(investigation?.recommendations) ? investigation.recommendations : [];
    if (realRecs.length > 0) {
      return realRecs.map((rec) => ({
        priority: (rec.priority || 'medium').toUpperCase(),
        title: rec.title,
        action: rec.action,
        target: rec.target,
        expectedEffect: rec.expected_effect,
        rollback: rec.rollback_notes,
        requiresApproval: rec.requires_human_approval,
      }));
    }

    if (executiveMetrics.techniques_detected === 0 && !investigation?.findings?.length) {
      return [];
    }

    return [
      {
        priority: executiveMetrics.overall_risk >= 70 ? 'IMMEDIATE' : 'MEDIUM',
        title: 'Verify Evidence and Scope',
        action: 'Corroborate observed log indicators with host and network telemetry before taking containment action.',
        target: 'Affected scope(s)',
        expectedEffect: 'Confirm true-positive scope without premature remediation.',
        rollback: '',
        requiresApproval: true,
      },
    ];
  }, [investigation, executiveMetrics]);

  return (
    <div className="space-y-6 text-white font-mono">
      {/* Executive Header */}
      <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-6">
        <div className="flex flex-wrap justify-between items-start gap-4 mb-6">
          <div>
            <h2 className="text-2xl font-bold text-green-400 tracking-wider mb-1">
              [EXECUTIVE_THREAT_SUMMARY.RPT]
            </h2>
            <p className="text-cyan-400 text-xs sm:text-sm">
              Evidence-backed security intelligence and approval-gated action items
            </p>
            <p className="text-gray-400 text-xs mt-2">
              Generated: {new Date(data.analysis_timestamp).toLocaleString()} | Analysis Time: {executiveMetrics.analysis_time}s
            </p>
          </div>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => exportMarkdownToPdf(data.enhanced_analysis || data.summary)}
              className="flex items-center gap-2 px-3 py-1.5 bg-black border-2 border-cyan-500/60 hover:border-cyan-400 hover:bg-cyan-500/15 text-cyan-400 text-xs transition-colors cursor-pointer"
            >
              <Download className="h-4 w-4" />
              [EXPORT_PDF]
            </button>
            <button
              type="button"
              onClick={() => {
                if (typeof navigator !== 'undefined' && navigator.clipboard) {
                  navigator.clipboard.writeText(data.enhanced_analysis || data.summary);
                }
              }}
              className="flex items-center gap-2 px-3 py-1.5 bg-black border-2 border-green-500/60 hover:border-green-400 hover:bg-green-500/15 text-green-400 text-xs transition-colors cursor-pointer"
            >
              <Share className="h-4 w-4" />
              [COPY_REPORT]
            </button>
          </div>
        </div>

        {/* Key Risk Indicators */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-black/60 border border-red-500/30 p-4 text-center">
            <div className={`text-2xl font-bold mb-1 ${executiveMetrics.overall_risk >= 70 ? 'text-red-400' : executiveMetrics.overall_risk >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>
              {getRiskLevel(executiveMetrics.overall_risk)} ({executiveMetrics.overall_risk}%)
            </div>
            <div className="text-xs text-gray-400">OVERALL_RISK_LEVEL</div>
          </div>
          <div className="bg-black/60 border border-orange-500/30 p-4 text-center">
            <div className="text-2xl font-bold text-orange-400 mb-1">{executiveMetrics.techniques_detected}</div>
            <div className="text-xs text-gray-400">MITRE_TECHNIQUES</div>
            <div className="text-[11px] text-orange-300 mt-1">{executiveMetrics.cve_count} CVE(S) RETRIEVED</div>
          </div>
          <div className="bg-black/60 border border-purple-500/30 p-4 text-center">
            <div className="text-2xl font-bold text-purple-400 mb-1">{executiveMetrics.attack_phases}</div>
            <div className="text-xs text-gray-400">ATTACK_PHASES</div>
            <div className="text-[11px] text-purple-300 mt-1">IDENTIFIED</div>
          </div>
          <div className="bg-black/60 border border-cyan-500/30 p-4 text-center">
            <div className="text-2xl font-bold text-cyan-400 mb-1">{executiveMetrics.confidence_level}%</div>
            <div className="text-xs text-gray-400">CONFIDENCE_SCORE ({executiveMetrics.confidence_label})</div>
            <div className="text-[11px] text-cyan-300 mt-1">EVIDENCE_GROUNDED</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex flex-wrap gap-3">
        {[
          { id: 'overview', label: '[EXECUTIVE_OVERVIEW]', icon: Eye },
          { id: 'details', label: '[RISK_ANALYSIS]', icon: BarChart3 },
          { id: 'recommendations', label: '[ACTION_ITEMS]', icon: Target }
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setViewMode(id as 'overview' | 'details' | 'recommendations')}
            className={`flex items-center gap-2 px-4 py-2 border-2 text-xs sm:text-sm transition-all cursor-pointer ${
              viewMode === id
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.25)]'
                : 'bg-black/80 text-gray-400 border-gray-700 hover:border-cyan-500/50 hover:text-cyan-300'
            }`}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Overview Mode */}
      {viewMode === 'overview' && (
        <div className="space-y-6">
          <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-6">
            <h3 className="text-lg font-bold text-cyan-400 mb-4 flex items-center gap-2">
              <Building className="h-5 w-5 text-cyan-400" />
              [IMPACT_ASSESSMENT]
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {businessImpacts.map((impact, index) => (
                <div key={index} className="bg-black/60 border border-gray-700/60 p-4">
                  <div className="flex justify-between items-start mb-3 gap-2">
                    <h4 className="text-base font-semibold text-white">{impact.area}</h4>
                    <span className={`px-2 py-0.5 border text-xs font-medium ${getSeverityColor(impact.risk_level)}`}>
                      {getScoreLevel(impact.risk_level)}
                    </span>
                  </div>
                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-cyan-400">Scope:</span>
                      <span className="text-gray-200 ml-2">{impact.financial_impact}</span>
                    </div>
                    <div>
                      <span className="text-cyan-400">Operational:</span>
                      <span className="text-gray-200 ml-2">{impact.operational_impact}</span>
                    </div>
                    <div>
                      <span className="text-cyan-400">Governance:</span>
                      <span className="text-gray-200 ml-2">{impact.reputation_impact}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-6">
              <h4 className="text-lg font-semibold text-green-400 mb-4">[OBSERVED_PROGRESSION_RISK]</h4>
              {riskTrends.length === 0 ? (
                <div className="h-[250px] flex items-center justify-center text-gray-400 text-xs">
                  No progression data available.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={riskTrends}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                    <XAxis dataKey="label" stroke="#00ff96" fontSize={11} />
                    <YAxis stroke="#00ff96" fontSize={12} domain={[0, 100]} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'black',
                        border: '1px solid #00ff96',
                        borderRadius: '0px',
                        color: '#00ff96',
                        fontFamily: 'monospace'
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="risk"
                      stroke="#ff6b6b"
                      fill="#ff6b6b"
                      fillOpacity={0.3}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-6">
              <h4 className="text-lg font-semibold text-purple-400 mb-4">[ATTACK_TECHNIQUE_DISTRIBUTION]</h4>
              {techniqueDistribution.length === 0 ? (
                <div className="h-[250px] flex items-center justify-center text-gray-400 text-xs">
                  No kill-chain phase distribution available.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={250}>
                  <RechartsPieChart>
                    <Pie
                      data={techniqueDistribution}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={(props) => {
                        const entry = props as unknown as {
                          phase?: string;
                          percentage?: number;
                          payload?: { phase?: string; percentage?: number };
                        };
                        const item = entry.payload ?? entry;
                        return `${item.phase || ''}: ${item.percentage ?? 0}%`;
                      }}
                      outerRadius={80}
                      fill="#8884d8"
                      stroke="#00ff96"
                      strokeWidth={1}
                      dataKey="count"
                    >
                      {techniqueDistribution.map((_entry, index) => (
                        <Cell key={`cell-${index}`} fill={`hsl(${index * 45}, 70%, 60%)`} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'black',
                        border: '1px solid #00ff96',
                        borderRadius: '0px',
                        color: '#00ff96',
                        fontFamily: 'monospace'
                      }}
                    />
                  </RechartsPieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-6">
            <h3 className="text-lg font-bold text-green-400 mb-3">[EXECUTIVE_SUMMARY.TXT]</h3>
            <p className="text-gray-300 leading-relaxed text-sm whitespace-pre-wrap">
              {investigation?.executive_summary || data.summary}
            </p>
          </div>
        </div>
      )}

      {/* Details Mode */}
      {viewMode === 'details' && (
        <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 p-6">
          <h3 className="text-lg font-bold text-red-400 mb-4">[DETAILED_RISK_ANALYSIS]</h3>
          {data.matched_techniques.length === 0 ? (
            <p className="text-gray-400 text-xs">No MITRE ATT&amp;CK techniques matched for this analysis.</p>
          ) : (
            <div className="space-y-4">
              {data.matched_techniques.map((technique) => (
                <div key={technique.technique_id} className="bg-black/60 border border-gray-700/60 p-4">
                  <div className="flex justify-between items-start mb-3 gap-4">
                    <div>
                      <h4 className="text-base font-semibold text-cyan-300">{technique.name}</h4>
                      <p className="text-gray-400 text-xs">{technique.technique_id}</p>
                    </div>
                    <div className="text-right">
                      <div className={`text-xl font-bold ${technique.relevance_score >= 0.7 ? 'text-red-400' : technique.relevance_score >= 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {Math.round(technique.relevance_score * 100)}%
                      </div>
                      <div className="text-gray-400 text-[11px]">RELEVANCE</div>
                    </div>
                  </div>
                  <p className="text-gray-300 text-xs mb-3 leading-relaxed">{technique.description}</p>
                  <div className="flex flex-wrap gap-2">
                    {technique.kill_chain_phases.map(phase => (
                      <span key={phase} className="px-2 py-0.5 bg-cyan-900/20 text-cyan-300 text-xs border border-cyan-500/40">
                        {phase.replace(/-/g, '_').toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Recommendations Mode */}
      {viewMode === 'recommendations' && (
        <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-6">
          <h3 className="text-lg font-bold text-purple-400 mb-4 flex items-center gap-2">
            <Target className="h-5 w-5 text-green-400" />
            [APPROVAL_GATED_ACTION_ITEMS]
          </h3>
          {recommendationsList.length === 0 ? (
            <p className="text-gray-400 text-xs">No remediation actions drafted for this analysis.</p>
          ) : (
            <div className="space-y-4">
              {recommendationsList.map((rec, index) => (
                <div key={index} className="bg-black/60 border border-gray-700/60 p-4 flex items-center justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <span className={`px-2 py-0.5 border text-xs font-medium ${
                        rec.priority === 'IMMEDIATE'
                          ? 'border-red-500/60 bg-red-900/30 text-red-400'
                          : rec.priority === 'SHORT_TERM' || rec.priority === 'HIGH'
                          ? 'border-orange-500/60 bg-orange-900/30 text-orange-400'
                          : 'border-cyan-500/60 bg-cyan-900/30 text-cyan-300'
                      }`}>
                        {rec.priority}
                      </span>
                      <h4 className="text-base font-semibold text-white">{rec.title}</h4>
                      {rec.requiresApproval && (
                        <span className="px-2 py-0.5 border border-yellow-500/50 bg-yellow-900/20 text-yellow-300 text-xs">
                          HUMAN_APPROVAL_REQUIRED
                        </span>
                      )}
                    </div>
                    <p className="text-gray-200 text-xs mb-1.5">{rec.action}</p>
                    <div className="text-gray-400 text-xs">
                      Target: {rec.target}
                      {rec.expectedEffect ? ` | Expected Effect: ${rec.expectedEffect}` : ''}
                      {rec.rollback ? ` | Rollback: ${rec.rollback}` : ''}
                    </div>
                  </div>
                  <ChevronRight className="h-5 w-5 text-gray-500 flex-shrink-0" />
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ExecutiveThreatSummary;
