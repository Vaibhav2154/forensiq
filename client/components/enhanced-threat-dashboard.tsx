'use client'
import React, { useState, useEffect, useMemo } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, 
  BarChart, Bar, PieChart, Pie, Cell, Sankey, Radar, RadarChart, PolarGrid, 
  PolarAngleAxis, PolarRadiusAxis, ScatterChart, Scatter, FunnelChart, Funnel, LabelList
} from 'recharts';
import { 
  AlertTriangle, Shield, Activity, Clock, Database, Network, AlertCircle, 
  Eye, TrendingUp, MapPin, Target, Zap, Brain, Search, FileText, 
  ChevronRight, ChevronDown, Layers, GitBranch
} from 'lucide-react';
import ThreatNarrativeEngine from './threat-narrative-engine';

interface EnhancedAnalysisData {
  summary: string;
  matched_techniques: Array<{
    technique_id: string;
    name: string;
    description: string;
    kill_chain_phases: string[];
    platforms: string[];
    relevance_score: number;
  }>;
  enhanced_analysis: string;
  analysis_timestamp: string;
  processing_time_ms: number;
}

interface ThreatJourneyNode {
  id: string;
  phase: string;
  techniques: string[];
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  timestamp?: string;
  description: string;
}

const EnhancedThreatDashboard: React.FC<{ analysisData: EnhancedAnalysisData }> = ({ analysisData }) => {
  const [selectedView, setSelectedView] = useState('narrative');
  const [expandedPhases, setExpandedPhases] = useState<Set<string>>(new Set());
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  // Transform your analysis data into narrative journey
  const threatJourney: ThreatJourneyNode[] = useMemo(() => {
    const phases = analysisData.matched_techniques.reduce((acc, tech) => {
      tech.kill_chain_phases.forEach(phase => {
        if (!acc[phase]) {
          acc[phase] = {
            techniques: [],
            maxRisk: 0,
            descriptions: []
          };
        }
        acc[phase].techniques.push(tech.name);
        acc[phase].maxRisk = Math.max(acc[phase].maxRisk, tech.relevance_score);
        acc[phase].descriptions.push(tech.description);
      });
      return acc;
    }, {} as Record<string, any>);

    return Object.entries(phases).map(([phase, data], index) => ({
      id: `phase-${index}`,
      phase: phase.replace(/-/g, ' ').toUpperCase(),
      techniques: data.techniques,
      risk_level: data.maxRisk > 0.8 ? 'critical' : data.maxRisk > 0.6 ? 'high' : data.maxRisk > 0.4 ? 'medium' : 'low',
      description: data.descriptions[0] || 'No description available'
    }));
  }, [analysisData]);

  // Attack progression visualization data
  const attackProgression = useMemo(() => {
    return analysisData.matched_techniques.map((tech, index) => ({
      step: index + 1,
      technique: tech.name.substring(0, 15) + '...',
      risk: Math.round(tech.relevance_score * 100),
      phase: tech.kill_chain_phases[0] || 'unknown',
      timestamp: `T+${index * 5}min`
    }));
  }, [analysisData]);

  // Risk distribution by kill chain phase
  const phaseRiskData = useMemo(() => {
    const phaseRisks = analysisData.matched_techniques.reduce((acc, tech) => {
      tech.kill_chain_phases.forEach(phase => {
        if (!acc[phase]) acc[phase] = { total: 0, count: 0 };
        acc[phase].total += tech.relevance_score;
        acc[phase].count += 1;
      });
      return acc;
    }, {} as Record<string, { total: number; count: number }>);

    return Object.entries(phaseRisks).map(([phase, data]) => ({
      phase: phase.replace(/-/g, ' '),
      risk: Math.round((data.total / data.count) * 100),
      techniques: data.count
    }));
  }, [analysisData]);

  // Technique sophistication radar
  const sophisticationData = useMemo(() => {
    const sophistication = {
      'Technical Complexity': Math.random() * 100,
      'Evasion Capability': Math.random() * 100,
      'Impact Potential': Math.random() * 100,
      'Detection Difficulty': Math.random() * 100,
      'Persistence Level': Math.random() * 100,
      'Lateral Movement': Math.random() * 100
    };

    return Object.entries(sophistication).map(([subject, value]) => ({
      subject,
      value: Math.round(value),
      fullMark: 100
    }));
  }, [analysisData]);

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-400 bg-red-900/30 border-red-500';
      case 'high': return 'text-orange-400 bg-orange-900/30 border-orange-500';
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500';
      case 'low': return 'text-blue-400 bg-blue-900/30 border-blue-500';
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500';
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
        className="absolute inset-0 opacity-5"
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
            <div className="flex items-center gap-4 mb-4">
              <AlertTriangle className="h-8 w-8 text-red-400" />
              <div>
                <h1 className="text-3xl font-bold text-red-400 tracking-wider">[THREAT_INTELLIGENCE_DASHBOARD]</h1>
                <p className="text-cyan-400 text-sm">Advanced threat narrative and attack progression analysis</p>
              </div>
            </div>
            
            {/* Quick threat metrics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
              <div className="bg-black/60 border border-red-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-red-400">{analysisData.matched_techniques.length}</div>
                <div className="text-xs text-gray-400">TECHNIQUES_DETECTED</div>
              </div>
              <div className="bg-black/60 border border-orange-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-orange-400">
                  {Math.round(Math.max(...analysisData.matched_techniques.map(t => t.relevance_score)) * 100)}%
                </div>
                <div className="text-xs text-gray-400">MAX_CONFIDENCE</div>
              </div>
              <div className="bg-black/60 border border-yellow-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-yellow-400">
                  {new Set(analysisData.matched_techniques.flatMap(t => t.kill_chain_phases)).size}
                </div>
                <div className="text-xs text-gray-400">ATTACK_PHASES</div>
              </div>
              <div className="bg-black/60 border border-green-500/30 p-4 text-center">
                <div className="text-2xl font-bold text-green-400">
                  {Math.round(analysisData.processing_time_ms)}ms
                </div>
                <div className="text-xs text-gray-400">ANALYSIS_TIME</div>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation tabs */}
        <div className="flex flex-wrap gap-4 mb-8">
          {[
            { id: 'narrative', label: 'THREAT_NARRATIVE', icon: FileText },
            { id: 'journey', label: 'ATTACK_JOURNEY', icon: GitBranch },
            { id: 'progression', label: 'PROGRESSION_ANALYSIS', icon: TrendingUp },
            { id: 'sophistication', label: 'SOPHISTICATION_RADAR', icon: Target }
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setSelectedView(id)}
              className={`px-4 py-2 border-2 font-mono uppercase tracking-wider transition-all duration-300 text-sm flex items-center gap-2 ${
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
            {/* Attack phases flow */}
            <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-6">
              <h3 className="text-xl font-semibold mb-6 flex items-center text-purple-400">
                <GitBranch className="h-5 w-5 mr-3" />
                [ATTACK_KILL_CHAIN_PROGRESSION]
              </h3>
              
              <div className="relative">
                {/* Timeline line */}
                <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gradient-to-b from-purple-500 via-red-500 to-orange-500"></div>
                
                {threatJourney.map((node, index) => (
                  <div key={node.id} className="relative mb-8 last:mb-0">
                    {/* Phase node */}
                    <div className={`absolute left-4 w-8 h-8 rounded-full border-4 flex items-center justify-center ${getRiskColor(node.risk_level)}`}>
                      <span className="text-xs font-bold">{index + 1}</span>
                    </div>
                    
                    {/* Phase content */}
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
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={attackProgression}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                    <XAxis dataKey="timestamp" stroke="#00ff96" fontSize={12} />
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
              </div>

              {/* Risk by phase */}
              <div className="bg-black/80 backdrop-blur-sm border border-yellow-500/30 p-6">
                <h3 className="text-lg font-semibold mb-4 text-yellow-400">RISK_DISTRIBUTION_BY_PHASE</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={phaseRiskData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                    <XAxis dataKey="phase" stroke="#00ff96" fontSize={10} angle={-45} textAnchor="end" height={80} />
                    <YAxis stroke="#00ff96" fontSize={12} />
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
              </div>
            </div>

            {/* Detailed progression steps */}
            <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-6">
              <h3 className="text-lg font-semibold mb-4 text-cyan-400">STEP_BY_STEP_PROGRESSION</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm font-mono">
                  <thead>
                    <tr className="border-b border-cyan-500/50">
                      <th className="text-left py-3 text-cyan-400">STEP</th>
                      <th className="text-left py-3 text-cyan-400">TECHNIQUE</th>
                      <th className="text-left py-3 text-cyan-400">PHASE</th>
                      <th className="text-left py-3 text-cyan-400">RISK</th>
                      <th className="text-left py-3 text-cyan-400">TIMESTAMP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attackProgression.map((step, index) => (
                      <tr key={index} className="border-b border-gray-700/50 hover:bg-cyan-500/10 transition-colors">
                        <td className="py-3 text-cyan-300">#{step.step}</td>
                        <td className="py-3 text-white">{step.technique}</td>
                        <td className="py-3 text-yellow-400">{step.phase}</td>
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
                    <h4 className="text-red-400 font-semibold mb-2">Overall Threat Level</h4>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-3 bg-gray-800 border border-red-500/30">
                        <div 
                          className="h-full bg-gradient-to-r from-yellow-500 to-red-500"
                          style={{ width: `${Math.round(Math.max(...analysisData.matched_techniques.map(t => t.relevance_score)) * 100)}%` }}
                        ></div>
                      </div>
                      <span className="text-red-400 font-bold">
                        {Math.round(Math.max(...analysisData.matched_techniques.map(t => t.relevance_score)) * 100)}%
                      </span>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {[
                      { label: 'Attack Complexity', value: 75, color: 'text-orange-400' },
                      { label: 'Stealth Level', value: 60, color: 'text-yellow-400' },
                      { label: 'Persistence Capability', value: 85, color: 'text-red-400' },
                      { label: 'Lateral Movement Risk', value: 45, color: 'text-blue-400' }
                    ].map((metric, index) => (
                      <div key={index} className="bg-black/30 p-3 border border-gray-600/30">
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-sm text-gray-300">{metric.label}</span>
                          <span className={`text-sm font-bold ${metric.color}`}>{metric.value}%</span>
                        </div>
                        <div className="w-full h-2 bg-gray-800 border border-gray-600/30">
                          <div 
                            className={`h-full ${metric.color.replace('text-', 'bg-').replace('400', '500')}`}
                            style={{ width: `${metric.value}%` }}
                          ></div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EnhancedThreatDashboard;
