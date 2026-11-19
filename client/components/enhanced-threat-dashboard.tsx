'use client'
import React, { useState, useEffect, useMemo } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis
} from 'recharts';
import {
  AlertTriangle, Activity, AlertCircle,
  TrendingUp, Target, FileText, ChevronRight, ChevronDown, GitBranch,
  HelpCircle, Cpu, Clock, BarChart3
} from 'lucide-react';
import ThreatNarrativeEngine from './threat-narrative-engine';
import InvestigationReportPanel from './investigation-report-panel';
import ExecutiveThreatSummary from './executive-threat-summary';
import SecurityLogDashboard from './timeline';
import type { LogAnalysisResponse, ThreatJourneyNode } from '@/lib/types';

type EnhancedAnalysisData = LogAnalysisResponse;

const CANONICAL_PHASES = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact'
];

const EnhancedThreatDashboard: React.FC<{ analysisData: EnhancedAnalysisData }> = ({ analysisData }) => {
  const [selectedView, setSelectedView] = useState('narrative');
  const [expandedPhases, setExpandedPhases] = useState<Set<string>>(new Set());
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  const techniques = useMemo(
    () => (Array.isArray(analysisData.matched_techniques) ? analysisData.matched_techniques : []),
    [analysisData.matched_techniques]
  );
  const vm = analysisData.visualization_metrics || null;
  const inv = (analysisData.investigation && typeof analysisData.investigation === 'object')
    ? analysisData.investigation
    : null;

  const fallbackMaxConfPct = useMemo(() => {
    if (techniques.length === 0) return 0;
    return Math.round(Math.max(...techniques.map(t => t.relevance_score || 0)) * 100);
  }, [techniques]);

  const fallbackAvgConfPct = useMemo(() => {
    if (techniques.length === 0) return 0;
    const total = techniques.reduce((acc, t) => acc + (t.relevance_score || 0), 0);
    return Math.round((total / techniques.length) * 100);
  }, [techniques]);

  const uniquePhasesCount = useMemo(() => {
    const phases = new Set(techniques.flatMap(t => t.kill_chain_phases || []));
    return phases.size;
  }, [techniques]);

  const overallRiskScore = vm?.overall_risk_score ?? fallbackMaxConfPct;
  const overallThreatLevel = (
    vm?.overall_threat_level ||
    (fallbackMaxConfPct >= 80 ? 'critical' : fallbackMaxConfPct >= 60 ? 'high' : fallbackMaxConfPct >= 40 ? 'medium' : fallbackMaxConfPct > 0 ? 'low' : 'informational')
  ).toUpperCase();
  const overallConfidenceLabel = (
    vm?.overall_confidence_label ||
    (fallbackAvgConfPct >= 70 ? 'high' : fallbackAvgConfPct >= 40 ? 'medium' : 'low')
  ).toUpperCase();

  const techniquesDetectedCount = vm?.summary_counts?.techniques_detected ?? techniques.length;
  const attackPhasesCount = vm?.summary_counts?.attack_phases ?? uniquePhasesCount;
  const cveCount = vm?.summary_counts?.cve_count ?? 0;
  const analysisTimeSec = vm?.summary_counts?.analysis_time_sec ?? Number(((analysisData.processing_time_ms || 0) / 1000).toFixed(2));

  // Threat journey by kill-chain phase (prefer backend metrics)
  const threatJourney: ThreatJourneyNode[] = useMemo(() => {
    if (vm?.attack_journey && vm.attack_journey.length > 0) {
      return vm.attack_journey;
    }
    const phases = techniques.reduce((acc, tech) => {
      (tech.kill_chain_phases || []).forEach(phase => {
        if (!acc[phase]) {
          acc[phase] = { techniques: [], maxRisk: 0, descriptions: [] };
        }
        acc[phase].techniques.push(tech.name);
        acc[phase].maxRisk = Math.max(acc[phase].maxRisk, tech.relevance_score || 0);
        acc[phase].descriptions.push(tech.description);
      });
      return acc;
    }, {} as Record<string, { techniques: string[]; maxRisk: number; descriptions: string[] }>);

    return Object.entries(phases)
      .sort(([a], [b]) => {
        const ai = CANONICAL_PHASES.indexOf(a);
        const bi = CANONICAL_PHASES.indexOf(b);
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      })
      .map(([phase, data], index) => ({
        id: `phase-${index}`,
        phase: phase.replace(/-/g, ' ').toUpperCase(),
        techniques: data.techniques,
        risk_level: data.maxRisk > 0.8 ? 'critical' : data.maxRisk > 0.6 ? 'high' : data.maxRisk > 0.4 ? 'medium' : 'low',
        description: data.descriptions[0] || 'No description available'
      }));
  }, [vm, techniques]);

  // Attack progression steps (prefer backend attack_path / progression)
  const attackProgression = useMemo(() => {
    if (vm?.attack_progression && vm.attack_progression.length > 0) {
      return vm.attack_progression.map(step => ({
        ...step,
        shortLabel: step.technique.length > 28 ? `${step.technique.substring(0, 28)}...` : step.technique,
      }));
    }
    return techniques.map((tech, index) => ({
      step: index + 1,
      technique: tech.name,
      shortLabel: tech.name.length > 28 ? `${tech.name.substring(0, 28)}...` : tech.name,
      risk: Math.round((tech.relevance_score || 0) * 100),
      phase: (tech.kill_chain_phases && tech.kill_chain_phases[0]) || 'unknown',
      status: 'inferred',
      timestamp: `Step ${index + 1}`
    }));
  }, [vm, techniques]);

  // Risk distribution by kill chain phase
  const phaseRiskData = useMemo(() => {
    if (vm?.phase_risk_distribution && vm.phase_risk_distribution.length > 0) {
      return vm.phase_risk_distribution;
    }
    const phaseRisks = techniques.reduce((acc, tech) => {
      (tech.kill_chain_phases || []).forEach(phase => {
        if (!acc[phase]) acc[phase] = { total: 0, count: 0 };
        acc[phase].total += tech.relevance_score || 0;
        acc[phase].count += 1;
      });
      return acc;
    }, {} as Record<string, { total: number; count: number }>);

    return Object.entries(phaseRisks).map(([phase, data]) => ({
      phase: phase.replace(/-/g, ' '),
      risk: Math.round((data.total / data.count) * 100),
      techniques: data.count
    }));
  }, [vm, techniques]);

  // Technique sophistication radar + breakdown bars (never hardcoded, zero when empty)
  const { sophisticationData, threatAssessmentBars } = useMemo(() => {
    if (vm?.sophistication_radar && vm.sophistication_radar.length > 0) {
      return {
        sophisticationData: vm.sophistication_radar,
        threatAssessmentBars: vm.threat_assessment_bars || []
      };
    }

    const getPhaseScore = (targetPhases: string[]) => {
      const relevant = techniques.filter(t =>
        (t.kill_chain_phases || []).some(p => targetPhases.includes(p))
      );
      if (relevant.length === 0) return 0;
      return Math.min(100, Math.round(Math.max(...relevant.map(t => t.relevance_score || 0)) * 100));
    };

    const techComplexity = techniques.length > 0
      ? Math.min(100, Math.round(fallbackAvgConfPct * 0.7 + Math.min(uniquePhasesCount, 5) * 6))
      : 0;
    const evasionCap = getPhaseScore(['defense-evasion']);
    const impactPot = getPhaseScore(['impact', 'exfiltration', 'collection', 'credential-access']);
    const detectionDiff = Math.round(
      evasionCap * 0.6 + getPhaseScore(['command-and-control', 'credential-access']) * 0.4
    );
    const persistenceLvl = getPhaseScore(['persistence', 'privilege-escalation']);
    const lateralMov = getPhaseScore(['lateral-movement', 'discovery', 'initial-access']);

    return {
      sophisticationData: [
        { subject: 'Technical Complexity', value: techComplexity, fullMark: 100 },
        { subject: 'Evasion Capability', value: evasionCap, fullMark: 100 },
        { subject: 'Impact Potential', value: impactPot, fullMark: 100 },
        { subject: 'Detection Difficulty', value: detectionDiff, fullMark: 100 },
        { subject: 'Persistence Level', value: persistenceLvl, fullMark: 100 },
        { subject: 'Lateral Movement', value: lateralMov, fullMark: 100 },
      ],
      threatAssessmentBars: [
        { label: 'Attack Complexity', value: techComplexity, color: 'text-orange-400' },
        { label: 'Stealth Level', value: evasionCap, color: 'text-yellow-400' },
        { label: 'Persistence Capability', value: persistenceLvl, color: 'text-red-400' },
        { label: 'Lateral Movement Risk', value: lateralMov, color: 'text-blue-400' },
      ]
    };
  }, [vm, techniques, fallbackAvgConfPct, uniquePhasesCount]);

  // Investigation Intel counts & attack path
  const attackPath = vm?.attack_path || inv?.attack_path || null;
  const attackPathNodes = Array.isArray(attackPath?.nodes) ? attackPath.nodes : [];
  const findingsCount = (vm?.findings || inv?.findings || []).length;
  const cveMatchesCount = (
    vm?.cve_matches ||
    (Array.isArray(inv?.retrieved_knowledge)
      ? inv.retrieved_knowledge.filter((item: { source_type?: string }) => item?.source_type === 'cve')
      : [])
  ).length;
  const iocsCount = (vm?.iocs || inv?.iocs || []).length;
  const intelBadgeCount = findingsCount + cveMatchesCount + iocsCount;

  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-900/30 border-red-500';
      case 'high': return 'text-orange-400 bg-orange-900/30 border-orange-500';
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500';
      case 'low': return 'text-blue-400 bg-blue-900/30 border-blue-500';
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500';
    }
  };

  const getStatusBadgeColor = (status?: string) => {
    switch ((status || '').toLowerCase()) {
      case 'observed': return 'text-green-400 bg-green-900/30 border-green-500/60';
      case 'inferred': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/60';
      case 'unconfirmed': return 'text-purple-300 bg-purple-900/30 border-purple-500/60';
      default: return 'text-gray-300 bg-gray-900/40 border-gray-600/60';
    }
  };

  const togglePhase = (phaseId: string) => {
    const newExpanded = new Set(expandedPhases);
    if (newExpanded.has(phaseId)) {
      newExpanded.delete(phaseId);
    } else {
      newExpanded.add(phaseId);
    }
    setExpandedPhases(newExpanded);
  };

  return (
    <div className="relative bg-black min-h-screen w-full text-white overflow-x-hidden font-mono">
      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-5 pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0, 255, 150, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 150, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '20px 20px'
        }}
      />

      <div className="relative container mx-auto px-4 py-8 max-w-full">
        {/* Header with threat summary */}
        <div className={`mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 rounded-lg p-6">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <div className="flex items-center gap-4">
                <AlertTriangle className="h-8 w-8 text-red-400" />
                <div>
                  <h1 className="text-2xl sm:text-3xl font-bold text-red-400 tracking-wider">[THREAT_INTELLIGENCE_DASHBOARD]</h1>
                  <p className="text-cyan-400 text-sm">Evidence-backed threat narrative, attack progression, and multi-agent investigation metrics</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-3 py-1 border text-xs font-bold ${getRiskColor(overallThreatLevel)}`}>
                  THREAT: {overallThreatLevel}
                </span>
                <span className="px-3 py-1 border border-cyan-500/40 bg-cyan-900/20 text-cyan-300 text-xs">
                  CONFIDENCE: {overallConfidenceLabel}
                </span>
              </div>
            </div>

            {/* Quick threat metrics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
              <div className="bg-black/60 border border-red-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-red-400">{techniquesDetectedCount}</div>
                <div className="text-xs text-gray-400">TECHNIQUES_DETECTED</div>
              </div>
              <div className="bg-black/60 border border-orange-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-orange-400">{overallRiskScore}%</div>
                <div className="text-xs text-gray-400">{vm ? 'OVERALL_RISK' : 'MAX_CONFIDENCE'}</div>
              </div>
              <div className="bg-black/60 border border-yellow-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-yellow-400">{attackPhasesCount}</div>
                <div className="text-xs text-gray-400">
                  ATTACK_PHASES{cveCount > 0 ? ` · ${cveCount} CVE(S)` : ''}
                </div>
              </div>
              <div className="bg-black/60 border border-green-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-green-400">{analysisTimeSec}s</div>
                <div className="text-xs text-gray-400">ANALYSIS_TIME</div>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation tabs */}
        <div className="flex flex-wrap gap-3 mb-8">
          {[
            { id: 'narrative', label: 'THREAT_NARRATIVE', icon: FileText },
            { id: 'journey', label: 'ATTACK_JOURNEY', icon: GitBranch },
            { id: 'progression', label: 'PROGRESSION_ANALYSIS', icon: TrendingUp },
            { id: 'sophistication', label: 'SOPHISTICATION_RADAR', icon: Target },
            {
              id: 'intel',
              label: intelBadgeCount > 0 ? `INVESTIGATION_INTEL (${intelBadgeCount})` : 'INVESTIGATION_INTEL',
              icon: Cpu
            },
            { id: 'timeline', label: 'EVENT_TIMELINE', icon: Clock },
            { id: 'executive', label: 'EXECUTIVE_SUMMARY', icon: BarChart3 },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setSelectedView(id)}
              className={`px-4 py-2 border-2 font-mono uppercase tracking-wider transition-all duration-300 text-xs sm:text-sm flex items-center gap-2 ${
                selectedView === id
                  ? 'bg-green-500/20 text-green-400 border-green-500 shadow-[0_0_10px_rgba(0,255,150,0.3)]'
                  : 'bg-black/80 text-green-600 border-green-500/30 hover:border-green-400 hover:text-green-400'
              }`}
            >
              <Icon className="h-4 w-4" />
              [{label}]
            </button>
          ))}
        </div>

        {/* Threat Narrative View */}
        {selectedView === 'narrative' && (
          <ThreatNarrativeEngine data={analysisData} />
        )}

        {/* Attack Journey View */}
        {selectedView === 'journey' && (
          <div className="space-y-6">
            {/* Multi-agent Attack-Path Hypothesis (when available) */}
            {attackPathNodes.length > 0 && (
              <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-6">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <h3 className="text-xl font-semibold flex items-center text-cyan-400">
                    <Activity className="h-5 w-5 mr-3" />
                    [ATTACK_PATH_HYPOTHESIS]
                  </h3>
                  <div className="flex gap-2 text-xs">
                    <span className="px-2 py-0.5 border border-green-500/50 text-green-400">OBSERVED = LOG FACT</span>
                    <span className="px-2 py-0.5 border border-yellow-500/50 text-yellow-400">INFERRED = HYPOTHESIS</span>
                    <span className="px-2 py-0.5 border border-purple-500/50 text-purple-300">UNCONFIRMED = GAP</span>
                  </div>
                </div>
                {attackPath?.hypothesis_title && (
                  <p className="text-white font-semibold mb-1">{attackPath.hypothesis_title}</p>
                )}
                {attackPath?.summary && (
                  <p className="text-gray-300 text-sm mb-6">{attackPath.summary}</p>
                )}

                <div className="relative">
                  <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-green-500 via-yellow-500 to-purple-500" />
                  {attackPathNodes.map((node: any, idx: number) => (
                    <div key={node.node_id || idx} className="relative mb-6 last:mb-0 pl-16">
                      <div className={`absolute left-2 w-8 h-8 rounded-full border-2 flex items-center justify-center text-xs font-bold ${getStatusBadgeColor(node.status)}`}>
                        {idx + 1}
                      </div>
                      <div className="bg-black/60 border border-gray-700/60 p-4 hover:border-cyan-400/60 transition-colors">
                        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                          <h4 className="text-base font-bold text-white">{node.label}</h4>
                          <div className="flex flex-wrap gap-2 text-xs">
                            <span className={`px-2 py-0.5 border uppercase ${getStatusBadgeColor(node.status)}`}>
                              {node.status || 'inferred'}
                            </span>
                            <span className="px-2 py-0.5 border border-cyan-500/40 text-cyan-300">
                              STAGE: {node.stage}
                            </span>
                            {node.confidence && (
                              <span className="px-2 py-0.5 border border-gray-600 text-gray-300">
                                CONF: {String(node.confidence).toUpperCase()}
                              </span>
                            )}
                          </div>
                        </div>
                        {node.notes && <p className="text-gray-300 text-xs mb-2">{node.notes}</p>}
                        <div className="flex flex-wrap gap-2 text-xs">
                          {(node.knowledge_source_ids || []).map((kid: string) => (
                            <span key={kid} className="px-2 py-0.5 bg-red-900/20 border border-red-500/40 text-red-300">
                              {kid}
                            </span>
                          ))}
                          {(node.event_ids || []).map((eid: string) => (
                            <span key={eid} className="px-2 py-0.5 bg-green-900/20 border border-green-500/40 text-green-300">
                              {eid}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {((attackPath?.missing_evidence && attackPath.missing_evidence.length > 0) ||
                  (attackPath?.alternative_hypotheses && attackPath.alternative_hypotheses.length > 0)) && (
                  <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                    {attackPath?.missing_evidence && attackPath.missing_evidence.length > 0 && (
                      <div className="bg-yellow-950/20 border border-yellow-500/40 p-4">
                        <h4 className="text-yellow-400 font-semibold text-sm mb-2 flex items-center gap-2">
                          <AlertCircle className="h-4 w-4" />
                          [MISSING_EVIDENCE]
                        </h4>
                        <ul className="space-y-1 text-xs text-gray-300 list-disc list-inside">
                          {attackPath.missing_evidence.map((gap: string, idx: number) => (
                            <li key={idx}>{gap}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {attackPath?.alternative_hypotheses && attackPath.alternative_hypotheses.length > 0 && (
                      <div className="bg-purple-950/20 border border-purple-500/40 p-4">
                        <h4 className="text-purple-300 font-semibold text-sm mb-2 flex items-center gap-2">
                          <HelpCircle className="h-4 w-4" />
                          [ALTERNATIVE_HYPOTHESES]
                        </h4>
                        <ul className="space-y-1 text-xs text-gray-300 list-disc list-inside">
                          {attackPath.alternative_hypotheses.map((alt: string, idx: number) => (
                            <li key={idx}>{alt}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Attack kill-chain phases flow */}
            <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-6">
              <h3 className="text-xl font-semibold mb-6 flex items-center text-purple-400">
                <GitBranch className="h-5 w-5 mr-3" />
                [ATTACK_KILL_CHAIN_PROGRESSION]
              </h3>

              {threatJourney.length === 0 ? (
                <p className="text-gray-400 text-sm">No MITRE ATT&amp;CK kill-chain phases mapped for this analysis.</p>
              ) : (
                <div className="relative">
                  <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gradient-to-b from-purple-500 via-red-500 to-orange-500" />
                  {threatJourney.map((node, index) => (
                    <div key={node.id} className="relative mb-8 last:mb-0">
                      <div className={`absolute left-4 w-8 h-8 rounded-full border-4 flex items-center justify-center ${getRiskColor(node.risk_level)}`}>
                        <span className="text-xs font-bold">{index + 1}</span>
                      </div>

                      <div className="ml-20 bg-black/60 border border-gray-600/30 p-6 hover:border-purple-400 transition-colors">
                        <div className="flex justify-between items-start mb-4">
                          <div>
                            <h4 className="text-lg font-bold text-purple-400">{node.phase}</h4>
                            <p className="text-gray-400 text-sm mt-1">{node.description}</p>
                          </div>
                          <button
                            onClick={() => togglePhase(node.id)}
                            className="text-purple-400 hover:text-purple-300"
                          >
                            {expandedPhases.has(node.id) ? <ChevronDown /> : <ChevronRight />}
                          </button>
                        </div>

                        <div className="flex items-center gap-4 mb-3">
                          <span className={`px-3 py-1 border text-xs font-mono ${getRiskColor(node.risk_level)}`}>
                            [{node.risk_level.toUpperCase()}_RISK]
                          </span>
                          <span className="text-gray-400 text-xs">
                            {node.techniques.length} technique(s) detected
                          </span>
                        </div>

                        {expandedPhases.has(node.id) && (
                          <div className="mt-4 pt-4 border-t border-gray-600/30">
                            <h5 className="text-cyan-400 font-semibold mb-2">Associated Techniques:</h5>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                              {node.techniques.map((technique, idx) => (
                                <div key={idx} className="bg-black/50 border border-cyan-500/20 p-2 text-sm">
                                  <span className="text-cyan-300">{technique}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Progression Analysis View */}
        {selectedView === 'progression' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              {/* Attack progression timeline */}
              <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-6">
                <h3 className="text-lg font-semibold mb-4 text-green-400">ATTACK_PROGRESSION_TIMELINE</h3>
                {attackProgression.length === 0 ? (
                  <div className="h-[300px] flex items-center justify-center text-gray-500 text-sm">
                    No progression steps available for this analysis.
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={attackProgression}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                      <XAxis dataKey="timestamp" stroke="#00ff96" fontSize={11} />
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
                      <Line
                        type="monotone"
                        dataKey="risk"
                        stroke="#ff6b6b"
                        strokeWidth={3}
                        dot={{ fill: '#ff6b6b', strokeWidth: 2, r: 6 }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </div>

              {/* Risk by phase */}
              <div className="bg-black/80 backdrop-blur-sm border border-yellow-500/30 p-6">
                <h3 className="text-lg font-semibold mb-4 text-yellow-400">RISK_DISTRIBUTION_BY_PHASE</h3>
                {phaseRiskData.length === 0 ? (
                  <div className="h-[300px] flex items-center justify-center text-gray-500 text-sm">
                    No phase risk distribution available for this analysis.
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={phaseRiskData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                      <XAxis dataKey="phase" stroke="#00ff96" fontSize={10} angle={-45} textAnchor="end" height={80} />
                      <YAxis stroke="#00ff96" fontSize={12} domain={[0, 100]} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: 'black',
                          border: '1px solid #00ff96',
                          fontFamily: 'monospace'
                        }}
                      />
                      <Bar dataKey="risk" fill="#ffd93d" stroke="#00ff96" strokeWidth={1} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Detailed progression steps */}
            <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-6">
              <h3 className="text-lg font-semibold mb-4 text-cyan-400">STEP_BY_STEP_PROGRESSION</h3>
              {attackProgression.length === 0 ? (
                <p className="text-gray-400 text-sm">No progression steps recorded.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm font-mono">
                    <thead>
                      <tr className="border-b border-cyan-500/50">
                        <th className="text-left py-3 text-cyan-400">STEP</th>
                        <th className="text-left py-3 text-cyan-400">TECHNIQUE / ACTION</th>
                        <th className="text-left py-3 text-cyan-400">PHASE</th>
                        <th className="text-left py-3 text-cyan-400">STATUS</th>
                        <th className="text-left py-3 text-cyan-400">RISK</th>
                        <th className="text-left py-3 text-cyan-400">TIMESTAMP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attackProgression.map((step, index) => (
                        <tr key={index} className="border-b border-gray-700/50 hover:bg-cyan-500/10 transition-colors">
                          <td className="py-3 text-cyan-300">#{step.step}</td>
                          <td className="py-3 text-white">{step.shortLabel}</td>
                          <td className="py-3 text-yellow-400">{step.phase}</td>
                          <td className="py-3">
                            <span className={`px-2 py-0.5 border text-xs uppercase ${getStatusBadgeColor(step.status)}`}>
                              {step.status || 'inferred'}
                            </span>
                          </td>
                          <td className="py-3">
                            <div className={`inline-flex items-center px-2 py-1 border text-xs ${
                              step.risk > 80 ? 'text-red-400 border-red-500' :
                              step.risk > 60 ? 'text-orange-400 border-orange-500' :
                              step.risk > 40 ? 'text-yellow-400 border-yellow-500' :
                              'text-green-400 border-green-500'
                            }`}>
                              {step.risk}%
                            </div>
                          </td>
                          <td className="py-3 text-gray-400">{step.timestamp}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Sophistication Radar View */}
        {selectedView === 'sophistication' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              {/* Radar chart */}
              <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-6">
                <h3 className="text-lg font-semibold mb-4 text-purple-400">THREAT_SOPHISTICATION_ANALYSIS</h3>
                <ResponsiveContainer width="100%" height={400}>
                  <RadarChart data={sophisticationData}>
                    <PolarGrid stroke="#9333ea" opacity={0.3} />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: '#a855f7', fontSize: 12 }} />
                    <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#a855f7', fontSize: 10 }} />
                    <Radar
                      name="Sophistication"
                      dataKey="value"
                      stroke="#ff6b6b"
                      fill="#ff6b6b"
                      fillOpacity={0.3}
                      strokeWidth={3}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'black',
                        border: '1px solid #9333ea',
                        fontFamily: 'monospace'
                      }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              {/* Threat assessment summary */}
              <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 p-6">
                <h3 className="text-lg font-semibold mb-4 text-red-400">THREAT_ASSESSMENT_SUMMARY</h3>
                <div className="space-y-4">
                  <div className="bg-black/50 border border-red-500/20 p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-red-400 font-semibold">Overall Threat Level</h4>
                      <span className={`px-2 py-0.5 border text-xs font-bold ${getRiskColor(overallThreatLevel)}`}>
                        {overallThreatLevel}
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-3 bg-gray-800 border border-red-500/30">
                        <div
                          className="h-full bg-gradient-to-r from-yellow-500 to-red-500"
                          style={{ width: `${overallRiskScore}%` }}
                        />
                      </div>
                      <span className="text-red-400 font-bold">{overallRiskScore}%</span>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {threatAssessmentBars.map((metric, index) => (
                      <div key={index} className="bg-black/30 p-3 border border-gray-600/30">
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-sm text-gray-300">{metric.label}</span>
                          <span className={`text-sm font-bold ${metric.color}`}>{metric.value}%</span>
                        </div>
                        <div className="w-full h-2 bg-gray-800 border border-gray-600/30">
                          <div
                            className={`h-full ${metric.color.replace('text-', 'bg-').replace('400', '500')}`}
                            style={{ width: `${metric.value}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Investigation Intel View (Structured Multi-Agent Output) */}
        {selectedView === 'intel' && (
          <InvestigationReportPanel
            investigation={analysisData.investigation}
            visualizationMetrics={analysisData.visualization_metrics}
          />
        )}

        {/* Structured Event Timeline Dashboard View */}
        {selectedView === 'timeline' && (
          <SecurityLogDashboard analysisData={analysisData} />
        )}

        {/* Executive Threat Summary View */}
        {selectedView === 'executive' && (
          <ExecutiveThreatSummary data={analysisData} />
        )}
      </div>
    </div>
  );
};

export default EnhancedThreatDashboard;
