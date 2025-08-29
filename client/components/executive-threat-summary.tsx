'use client'
import React, { useState, useMemo } from 'react';
import {
  TrendingUp, AlertTriangle, Shield, Clock, DollarSign, Users,
  Building, ChevronRight, Download, Share, Printer, Eye,
  BarChart3, PieChart, Activity, Target, Zap, Lock
} from 'lucide-react';
import { 
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, PieChart as RechartsPieChart, Pie, Cell, LineChart, Line, Area, AreaChart
} from 'recharts';

interface ExecutiveSummaryData {
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

interface RiskMetric {
  category: string;
  current: number;
  target: number;
  trend: 'up' | 'down' | 'stable';
  impact: 'high' | 'medium' | 'low';
}

interface BusinessImpact {
  area: string;
  risk_level: number;
  financial_impact: string;
  operational_impact: string;
  reputation_impact: string;
}

const ExecutiveThreatSummary: React.FC<{ data: ExecutiveSummaryData }> = ({ data }) => {
  const [selectedMetric, setSelectedMetric] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'overview' | 'details' | 'recommendations'>('overview');

  // Calculate executive metrics
  const executiveMetrics = useMemo(() => {
    const avgConfidence = data.matched_techniques.reduce((sum, t) => sum + t.relevance_score, 0) / data.matched_techniques.length;
    const maxRisk = Math.max(...data.matched_techniques.map(t => t.relevance_score));
    const uniquePhases = new Set(data.matched_techniques.flatMap(t => t.kill_chain_phases));
    
    return {
      overall_risk: Math.round(maxRisk * 100),
      confidence_level: Math.round(avgConfidence * 100),
      attack_phases: uniquePhases.size,
      techniques_detected: data.matched_techniques.length,
      analysis_time: Math.round(data.processing_time_ms / 1000),
      threat_sophistication: Math.round(avgConfidence * 100)
    };
  }, [data]);

  // Business impact assessment
  const businessImpacts: BusinessImpact[] = useMemo(() => [
    {
      area: 'Data Security',
      risk_level: executiveMetrics.overall_risk,
      financial_impact: executiveMetrics.overall_risk > 70 ? 'High ($100K+)' : executiveMetrics.overall_risk > 40 ? 'Medium ($10K-100K)' : 'Low (<$10K)',
      operational_impact: executiveMetrics.overall_risk > 70 ? 'Critical Systems at Risk' : 'Limited Impact',
      reputation_impact: executiveMetrics.overall_risk > 70 ? 'Significant Brand Risk' : 'Minimal Impact'
    },
    {
      area: 'System Availability',
      risk_level: Math.round(executiveMetrics.overall_risk * 0.8),
      financial_impact: 'Potential Downtime Costs',
      operational_impact: 'Service Disruption Risk',
      reputation_impact: 'Customer Trust Impact'
    },
    {
      area: 'Compliance',
      risk_level: Math.round(executiveMetrics.overall_risk * 0.6),
      financial_impact: 'Regulatory Fines Risk',
      operational_impact: 'Audit Implications',
      reputation_impact: 'Stakeholder Confidence'
    }
  ], [executiveMetrics]);

  // Risk trend data (simulated based on analysis)
  const riskTrends = useMemo(() => {
    const baseRisk = executiveMetrics.overall_risk;
    return Array.from({ length: 7 }, (_, i) => ({
      day: `Day ${i - 6}`,
      risk: Math.max(0, Math.min(100, baseRisk + (Math.random() - 0.5) * 20)),
      incidents: Math.floor(Math.random() * 5) + 1
    }));
  }, [executiveMetrics]);

  // MITRE technique distribution
  const techniqueDistribution = useMemo(() => {
    const phaseCount = data.matched_techniques.reduce((acc, tech) => {
      tech.kill_chain_phases.forEach(phase => {
        acc[phase] = (acc[phase] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(phaseCount).map(([phase, count]) => ({
      phase: phase.replace(/-/g, ' ').toUpperCase(),
      count,
      percentage: Math.round((count / data.matched_techniques.length) * 100)
    }));
  }, [data]);

  const getSeverityColor = (risk: number) => {
    if (risk >= 80) return 'text-red-400 bg-red-900/30 border-red-500';
    if (risk >= 60) return 'text-orange-400 bg-orange-900/30 border-orange-500';
    if (risk >= 40) return 'text-yellow-400 bg-yellow-900/30 border-yellow-500';
    return 'text-green-400 bg-green-900/30 border-green-500';
  };

  const getRiskLevel = (risk: number) => {
    if (risk >= 80) return 'CRITICAL';
    if (risk >= 60) return 'HIGH';
    if (risk >= 40) return 'MEDIUM';
    return 'LOW';
  };

  const generateRecommendations = () => {
    const risk = executiveMetrics.overall_risk;
    const recommendations = [];

    if (risk >= 70) {
      recommendations.push({
        priority: 'IMMEDIATE',
        action: 'Activate Incident Response Team',
        timeline: '1-2 hours',
        owner: 'CISO/Security Team'
      });
      recommendations.push({
        priority: 'URGENT',
        action: 'Isolate Affected Systems',
        timeline: '2-4 hours',
        owner: 'IT Operations'
      });
    }

    recommendations.push({
      priority: risk >= 50 ? 'HIGH' : 'MEDIUM',
      action: 'Enhance Monitoring & Logging',
      timeline: '1-3 days',
      owner: 'Security Operations'
    });

    recommendations.push({
      priority: 'MEDIUM',
      action: 'Review Security Policies',
      timeline: '1-2 weeks',
      owner: 'Risk Management'
    });

    return recommendations;
  };

  return (
    <div className="bg-black min-h-screen text-white font-sans">
      <div className="container mx-auto px-6 py-8 max-w-7xl">
        {/* Executive Header */}
        <div className="mb-8">
          <div className="bg-gradient-to-r from-gray-900 to-black border border-cyan-500/30 rounded-lg p-8">
            <div className="flex justify-between items-start mb-6">
              <div>
                <h1 className="text-4xl font-bold text-white mb-2">Executive Threat Summary</h1>
                <p className="text-gray-300 text-lg">Critical security intelligence for leadership decision-making</p>
                <p className="text-gray-400 text-sm mt-2">
                  Generated: {new Date(data.analysis_timestamp).toLocaleString()} | 
                  Analysis Time: {executiveMetrics.analysis_time}s
                </p>
              </div>
              <div className="flex gap-3">
                <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors">
                  <Download className="h-4 w-4" />
                  Export PDF
                </button>
                <button className="flex items-center gap-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded transition-colors">
                  <Share className="h-4 w-4" />
                  Share
                </button>
              </div>
            </div>

            {/* Key Risk Indicators */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              <div className="text-center">
                <div className={`text-3xl font-bold mb-1 ${executiveMetrics.overall_risk >= 70 ? 'text-red-400' : executiveMetrics.overall_risk >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>
                  {getRiskLevel(executiveMetrics.overall_risk)}
                </div>
                <div className="text-gray-400 text-sm">Overall Risk Level</div>
                <div className="text-2xl font-bold text-white">{executiveMetrics.overall_risk}%</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-1 text-orange-400">{executiveMetrics.techniques_detected}</div>
                <div className="text-gray-400 text-sm">Threat Techniques</div>
                <div className="text-sm text-orange-300">Detected</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-1 text-purple-400">{executiveMetrics.attack_phases}</div>
                <div className="text-gray-400 text-sm">Attack Phases</div>
                <div className="text-sm text-purple-300">Identified</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold mb-1 text-cyan-400">{executiveMetrics.confidence_level}%</div>
                <div className="text-gray-400 text-sm">Analysis Confidence</div>
                <div className="text-sm text-cyan-300">AI Validated</div>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex gap-4 mb-8">
          {[
            { id: 'overview', label: 'Executive Overview', icon: Eye },
            { id: 'details', label: 'Risk Analysis', icon: BarChart3 },
            { id: 'recommendations', label: 'Action Items', icon: Target }
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setViewMode(id as any)}
              className={`flex items-center gap-2 px-6 py-3 rounded transition-all ${
                viewMode === id
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              <Icon className="h-5 w-5" />
              {label}
            </button>
          ))}
        </div>

        {/* Overview Mode */}
        {viewMode === 'overview' && (
          <div className="space-y-8">
            {/* Business Impact Assessment */}
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <Building className="h-6 w-6 mr-3 text-blue-400" />
                Business Impact Assessment
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {businessImpacts.map((impact, index) => (
                  <div key={index} className="bg-black/50 border border-gray-600 rounded p-4">
                    <div className="flex justify-between items-start mb-4">
                      <h4 className="text-lg font-semibold text-white">{impact.area}</h4>
                      <span className={`px-3 py-1 rounded text-sm font-medium ${getSeverityColor(impact.risk_level)}`}>
                        {getRiskLevel(impact.risk_level)}
                      </span>
                    </div>
                    <div className="space-y-3 text-sm">
                      <div>
                        <span className="text-gray-400">Financial:</span>
                        <span className="text-white ml-2">{impact.financial_impact}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Operational:</span>
                        <span className="text-white ml-2">{impact.operational_impact}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Reputation:</span>
                        <span className="text-white ml-2">{impact.reputation_impact}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Risk Trend Visualization */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
              <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
                <h4 className="text-xl font-bold text-white mb-4">Risk Trend (7 Days)</h4>
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={riskTrends}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="day" stroke="#9CA3AF" fontSize={12} />
                    <YAxis stroke="#9CA3AF" fontSize={12} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1F2937', 
                        border: '1px solid #4B5563',
                        borderRadius: '8px',
                        color: '#F9FAFB'
                      }} 
                    />
                    <Area 
                      type="monotone" 
                      dataKey="risk" 
                      stroke="#EF4444" 
                      fill="#EF4444" 
                      fillOpacity={0.3}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
                <h4 className="text-xl font-bold text-white mb-4">Attack Technique Distribution</h4>
                <ResponsiveContainer width="100%" height={250}>
                  <RechartsPieChart>
                    <Pie
                      data={techniqueDistribution}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ phase, percentage }) => `${phase}: ${percentage}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="count"
                    >
                      {techniqueDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={`hsl(${index * 45}, 70%, 60%)`} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </RechartsPieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Executive Summary Text */}
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
              <h3 className="text-2xl font-bold text-white mb-4">Executive Summary</h3>
              <div className="prose prose-invert max-w-none">
                <p className="text-gray-300 leading-relaxed text-lg mb-4">
                  Our security analysis has identified a <strong className={executiveMetrics.overall_risk >= 70 ? 'text-red-400' : executiveMetrics.overall_risk >= 40 ? 'text-yellow-400' : 'text-green-400'}>
                    {getRiskLevel(executiveMetrics.overall_risk)} risk</strong> security incident affecting your organization. 
                  The threat demonstrates <strong className="text-orange-400">{executiveMetrics.threat_sophistication >= 70 ? 'high' : executiveMetrics.threat_sophistication >= 40 ? 'moderate' : 'low'} sophistication</strong> and 
                  has triggered <strong className="text-purple-400">{executiveMetrics.techniques_detected} distinct threat indicators</strong> across 
                  <strong className="text-cyan-400"> {executiveMetrics.attack_phases} attack phases</strong>.
                </p>
                <p className="text-gray-300 leading-relaxed text-lg">
                  Based on our AI-powered analysis with <strong className="text-green-400">{executiveMetrics.confidence_level}% confidence</strong>, 
                  immediate attention is {executiveMetrics.overall_risk >= 70 ? 'critical' : executiveMetrics.overall_risk >= 40 ? 'recommended' : 'advisable'} to 
                  prevent potential business impact and ensure continued operational security.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Details Mode */}
        {viewMode === 'details' && (
          <div className="space-y-8">
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
              <h3 className="text-2xl font-bold text-white mb-6">Detailed Risk Analysis</h3>
              <div className="space-y-6">
                {data.matched_techniques.map((technique, index) => (
                  <div key={technique.technique_id} className="bg-black/50 border border-gray-600 rounded p-6">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h4 className="text-lg font-semibold text-white">{technique.name}</h4>
                        <p className="text-gray-400 text-sm">{technique.technique_id}</p>
                      </div>
                      <div className="text-right">
                        <div className={`text-2xl font-bold ${technique.relevance_score >= 0.7 ? 'text-red-400' : technique.relevance_score >= 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {Math.round(technique.relevance_score * 100)}%
                        </div>
                        <div className="text-gray-400 text-sm">Confidence</div>
                      </div>
                    </div>
                    <p className="text-gray-300 mb-4">{technique.description}</p>
                    <div className="flex gap-2">
                      {technique.kill_chain_phases.map(phase => (
                        <span key={phase} className="px-3 py-1 bg-blue-900/30 text-blue-300 text-sm rounded border border-blue-500/50">
                          {phase.replace(/-/g, ' ').toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Recommendations Mode */}
        {viewMode === 'recommendations' && (
          <div className="space-y-8">
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <Target className="h-6 w-6 mr-3 text-green-400" />
                Recommended Actions
              </h3>
              <div className="space-y-4">
                {generateRecommendations().map((rec, index) => (
                  <div key={index} className="bg-black/50 border border-gray-600 rounded p-4 flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className={`px-3 py-1 rounded text-sm font-medium ${
                          rec.priority === 'IMMEDIATE' ? 'bg-red-600 text-white' :
                          rec.priority === 'URGENT' ? 'bg-orange-600 text-white' :
                          rec.priority === 'HIGH' ? 'bg-yellow-600 text-black' :
                          'bg-blue-600 text-white'
                        }`}>
                          {rec.priority}
                        </span>
                        <h4 className="text-lg font-semibold text-white">{rec.action}</h4>
                      </div>
                      <div className="text-gray-400 text-sm">
                        Timeline: {rec.timeline} | Owner: {rec.owner}
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-gray-400" />
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ExecutiveThreatSummary;
