'use client'
import React, { useState, useEffect, useMemo } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell
} from 'recharts';
import { Shield, AlertCircle, Clock } from 'lucide-react';
import type { LogAnalysisResponse } from '@/lib/types';

interface SecurityLogDashboardProps {
  analysisData?: LogAnalysisResponse | null;
}

const SEVERITY_RISK_MAP: Record<string, number> = {
  critical: 95,
  high: 75,
  medium: 55,
  low: 30,
  informational: 15,
};

const PIE_COLORS = ['#00ff96', '#22d3ee', '#ffd93d', '#ff6b6b', '#a855f7', '#fb923c'];

const SecurityLogDashboard: React.FC<SecurityLogDashboardProps> = ({ analysisData }) => {
  const [selectedView, setSelectedView] = useState('overview');
  const [isVisible, setIsVisible] = useState(false);
  const [terminalText, setTerminalText] = useState('');
  const [showCursor, setShowCursor] = useState(true);
  const [isMobile, setIsMobile] = useState(false);

  const investigation = analysisData?.investigation || null;
  const invId = investigation?.investigation_id || 'NO_INVESTIGATION';
  const fullTerminalText = `> SECURITY_LOG_ANALYZER.EXE --INVESTIGATION=${invId} --MODE=TIMELINE`;

  useEffect(() => {
    const checkMobile = () => setIsMobile(window.innerWidth < 768);
    checkMobile();
    window.addEventListener('resize', checkMobile);
    setIsVisible(true);

    let i = 0;
    const typeInterval = setInterval(() => {
      if (i <= fullTerminalText.length) {
        setTerminalText(fullTerminalText.slice(0, i));
        i++;
      } else {
        clearInterval(typeInterval);
      }
    }, 35);

    const cursorInterval = setInterval(() => setShowCursor(prev => !prev), 500);

    return () => {
      clearInterval(typeInterval);
      clearInterval(cursorInterval);
      window.removeEventListener('resize', checkMobile);
    };
  }, [fullTerminalText]);

  const timelineEvents = useMemo(() => {
    const rawTimeline = Array.isArray(investigation?.timeline) ? investigation.timeline : [];
    if (rawTimeline.length > 0) {
      return rawTimeline.map((entry) => {
        const sev = (entry.significance || 'medium').toLowerCase();
        return {
          eventId: entry.event_id,
          timestamp: entry.timestamp_ist || entry.timestamp_utc,
          timestampUtc: entry.timestamp_utc,
          event: entry.event_type ? entry.event_type.replace(/_/g, ' ') : 'Log Event',
          eventType: entry.event_type || 'system_log_event',
          severity: sev,
          riskScore: SEVERITY_RISK_MAP[sev] ?? 50,
          actor: entry.actor || 'unknown',
          host: entry.host || '-',
          sourceIp: entry.source_ip || '-',
          summary: entry.summary,
          scopeKey: entry.scope_key,
        };
      });
    }

    const obs = Array.isArray(investigation?.observations) ? investigation.observations : [];
    return obs.map((o) => {
      const sev = (o.severity || 'medium').toLowerCase();
      return {
        eventId: o.event_id,
        timestamp: o.timestamp_utc,
        timestampUtc: o.timestamp_utc,
        event: o.is_anomalous ? 'Anomalous Observation' : 'Observed Event',
        eventType: o.is_anomalous ? 'anomalous_event' : 'observed_event',
        severity: sev,
        riskScore: SEVERITY_RISK_MAP[sev] ?? 50,
        actor: o.entities?.[0] || 'unknown',
        host: '-',
        sourceIp: '-',
        summary: o.summary,
        scopeKey: o.scope_key,
      };
    });
  }, [investigation]);

  const severityData = useMemo(() => {
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    timelineEvents.forEach((ev) => {
      const s = ev.severity.toUpperCase();
      if (s === 'INFORMATIONAL') {
        counts.INFO += 1;
      } else if (s in counts) {
        counts[s] += 1;
      }
    });
    return Object.entries(counts).map(([severity, count]) => ({ severity, count }));
  }, [timelineEvents]);

  const hourlyActivity = useMemo(() => {
    if (timelineEvents.length === 0) return [];
    const buckets: Record<string, number> = {};
    timelineEvents.forEach((ev) => {
      const match = (ev.timestamp || '').match(/\b(\d{2}):\d{2}/);
      const hour = match ? `${match[1]}:00` : '00:00';
      buckets[hour] = (buckets[hour] || 0) + 1;
    });
    return Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, events]) => ({ hour, events }));
  }, [timelineEvents]);

  const riskDistribution = useMemo(() => {
    if (timelineEvents.length > 0) {
      const byType: Record<string, number> = {};
      timelineEvents.forEach((ev) => {
        const key = ev.eventType || 'event';
        byType[key] = (byType[key] || 0) + 1;
      });
      const total = timelineEvents.length;
      return Object.entries(byType).map(([name, count], idx) => ({
        name,
        value: Math.round((count / total) * 100),
        color: PIE_COLORS[idx % PIE_COLORS.length],
      }));
    }

    const techs = Array.isArray(analysisData?.matched_techniques) ? analysisData.matched_techniques : [];
    if (techs.length === 0) return [];
    const byPhase: Record<string, number> = {};
    techs.forEach((t) => {
      (t.kill_chain_phases || []).forEach((p) => {
        byPhase[p] = (byPhase[p] || 0) + 1;
      });
    });
    const total = Object.values(byPhase).reduce((a, b) => a + b, 0) || 1;
    return Object.entries(byPhase).map(([name, count], idx) => ({
      name,
      value: Math.round((count / total) * 100),
      color: PIE_COLORS[idx % PIE_COLORS.length],
    }));
  }, [timelineEvents, analysisData]);

  const findings = Array.isArray(investigation?.findings) ? investigation.findings : [];
  const recommendations = Array.isArray(investigation?.recommendations) ? investigation.recommendations : [];
  const iocs = Array.isArray(investigation?.iocs) ? investigation.iocs : [];
  const maxRiskScore = timelineEvents.length > 0
    ? Math.max(...timelineEvents.map((e) => e.riskScore))
    : analysisData?.visualization_metrics?.overall_risk_score ?? 0;

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-900/30 border-red-500/50';
      case 'high': return 'text-orange-400 bg-orange-900/30 border-orange-500/50';
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/50';
      case 'low': return 'text-blue-400 bg-blue-900/30 border-blue-500/50';
      default: return 'text-green-400 bg-green-900/30 border-green-500/50';
    }
  };

  return (
    <div className='relative bg-black min-h-screen w-full text-white overflow-x-hidden font-mono'>
      <div className="relative container mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 md:py-8 max-w-full">
        {/* Terminal Header */}
        <div className={`mb-6 sm:mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-3 sm:p-4 overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
              <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
              <span className="ml-2 text-green-400 text-xs sm:text-sm truncate">
                {isMobile ? terminalText.slice(0, 35) : terminalText}
                {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-green-400 mb-1 tracking-wider">
              [SECURITY_LOG_TIMELINE_DASHBOARD.SYS]
            </h2>
            <p className="text-cyan-400 text-xs sm:text-sm">
              &gt; INVESTIGATION_ID: {invId} · THREAT_LEVEL: {(investigation?.overall_threat_level || 'unknown').toUpperCase()}
            </p>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex flex-wrap gap-2 sm:gap-4 mb-6">
          {['overview', 'timeline', 'events', 'analysis'].map((view) => (
            <button
              key={view}
              type="button"
              onClick={() => setSelectedView(view)}
              className={`px-3 sm:px-4 py-2 border-2 font-mono uppercase tracking-wider transition-all duration-300 text-xs sm:text-sm ${
                selectedView === view
                  ? 'bg-green-500/20 text-green-400 border-green-500 shadow-[0_0_10px_rgba(0,255,150,0.3)]'
                  : 'bg-black/80 text-green-600 border-green-500/30 hover:border-green-400 hover:text-green-400'
              }`}
            >
              [{view}]
            </button>
          ))}
        </div>

        {timelineEvents.length === 0 ? (
          <div className="bg-black/80 border border-gray-700/60 p-8 text-center">
            <Clock className="h-10 w-10 text-green-400 mx-auto mb-3" />
            <h3 className="text-lg font-bold text-green-400 mb-2">[NO_STRUCTURED_TIMELINE_EVENTS]</h3>
            <p className="text-gray-400 text-sm">
              This analysis does not contain a structured `investigation.timeline` payload. Run an AI-enhanced log analysis or batch investigation to populate event timelines, hourly charts, and IOC breakdowns.
            </p>
          </div>
        ) : (
          <>
            {/* Overview Dashboard */}
            {selectedView === 'overview' && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6 mb-6 sm:mb-8">
                <div className="bg-black/80 border border-red-500/30 p-4 sm:p-6">
                  <h3 className="text-sm sm:text-lg font-semibold text-red-400 mb-2">[SECURITY_RISK]</h3>
                  <p className="text-red-300 text-xs sm:text-sm mb-1">
                    {findings[0]?.title || 'Observed log timeline events'}
                  </p>
                  <p className="text-xs text-gray-400 mb-2">{findings.length} finding(s) synthesized</p>
                  <div className="text-xl sm:text-2xl font-bold text-red-400">RISK_SCORE: {maxRiskScore}</div>
                </div>

                <div className="bg-black/80 border border-cyan-500/30 p-4 sm:p-6">
                  <h3 className="text-sm sm:text-lg font-semibold text-cyan-400 mb-2">[TIMELINE_ACTIVITY]</h3>
                  <p className="text-cyan-300 text-xs sm:text-sm mb-1">NORMALIZED_KCP_EVENTS</p>
                  <p className="text-xs text-gray-400 mb-2">{timelineEvents.length} chronological event(s)</p>
                  <div className="text-xl sm:text-2xl font-bold text-cyan-400">EVENTS: {timelineEvents.length}</div>
                </div>

                <div className="bg-black/80 border border-green-500/30 p-4 sm:p-6">
                  <h3 className="text-sm sm:text-lg font-semibold text-green-400 mb-2">[OBSERVED_IOCS]</h3>
                  <p className="text-green-300 text-xs sm:text-sm mb-1">
                    {iocs.length > 0 ? `${iocs.length} INDICATOR(S) RECORDED` : 'NO_IOCS_FLAGGED'}
                  </p>
                  <p className="text-xs text-gray-400 mb-2 truncate">
                    {iocs.slice(0, 3).map((i) => `${i.ioc_type}:${i.value}`).join(', ') || 'None'}
                  </p>
                  <div className="text-xl sm:text-2xl font-bold text-green-400">IOCS: {iocs.length}</div>
                </div>
              </div>
            )}

            {/* Timeline View */}
            {selectedView === 'timeline' && (
              <div className="bg-black/80 border border-green-500/30 p-4 sm:p-6 mb-6">
                <h3 className="text-lg sm:text-xl font-semibold mb-4 text-green-400">[EVENT_TIMELINE]</h3>
                <div className="relative">
                  <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-green-500/50" />
                  {timelineEvents.map((event, index) => (
                    <div key={event.eventId || index} className="relative flex items-center mb-6">
                      <div className={`absolute left-2 w-4 h-4 rounded-full border-2 ${
                        event.severity === 'critical' || event.severity === 'high'
                          ? 'bg-red-500 border-red-400'
                          : event.severity === 'medium'
                          ? 'bg-yellow-500 border-yellow-400'
                          : 'bg-green-500 border-green-400'
                      }`} />
                      <div className="ml-10 bg-black/70 border border-green-500/30 p-3 sm:p-4 flex-1">
                        <div className="flex flex-col sm:flex-row justify-between items-start mb-2 gap-2">
                          <h4 className="font-semibold text-green-400 text-sm sm:text-base">&gt; {event.summary}</h4>
                          <span className={`px-2 py-1 border text-xs ${getSeverityColor(event.severity)}`}>
                            [{event.severity.toUpperCase()}]
                          </span>
                        </div>
                        <p className="text-cyan-300 text-xs mb-1">
                          {event.eventType} · actor: {event.actor} · host: {event.host}
                        </p>
                        <p className="text-gray-400 text-xs">[TIMESTAMP]: {event.timestamp}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Events Detail View */}
            {selectedView === 'events' && (
              <div className="bg-black/80 border border-green-500/30 p-4 sm:p-6 mb-6 space-y-4">
                <h3 className="text-lg sm:text-xl font-semibold text-green-400">[DETAILED_EVENT_ANALYSIS.LOG]</h3>
                {timelineEvents.map((event, index) => (
                  <div key={event.eventId || index} className="bg-black/70 border border-red-500/30 border-l-4 border-l-red-500 p-4">
                    <div className="flex flex-col sm:flex-row justify-between items-start mb-3 gap-2">
                      <h4 className="font-semibold text-green-400 text-sm sm:text-base">&gt; {event.summary}</h4>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 border text-xs ${getSeverityColor(event.severity)}`}>
                          [{event.severity.toUpperCase()}]
                        </span>
                        <span className="text-red-400 font-bold text-xs">RISK: {event.riskScore}</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                      <div>
                        <span className="text-cyan-400">[TIMESTAMP]:</span>
                        <p className="text-white">{event.timestamp}</p>
                      </div>
                      <div>
                        <span className="text-cyan-400">[ACTOR / IP]:</span>
                        <p className="text-white">{event.actor} ({event.sourceIp})</p>
                      </div>
                      <div>
                        <span className="text-cyan-400">[SCOPE]:</span>
                        <p className="text-white break-all">{event.scopeKey}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Analysis View */}
            {selectedView === 'analysis' && (
              <div className="bg-black/80 border border-red-500/30 p-4 sm:p-6 mb-6">
                <h3 className="text-lg sm:text-xl font-semibold mb-4 text-red-400">[THREAT_ASSESSMENT.DB]</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
                  <div>
                    <h4 className="text-sm sm:text-base font-medium mb-3 text-red-400">[FINDINGS_IDENTIFIED]:</h4>
                    <ul className="space-y-2 text-xs">
                      {findings.length === 0 ? (
                        <li className="text-gray-400">No material findings recorded.</li>
                      ) : findings.map((f, idx) => (
                        <li key={f.finding_id || idx} className="flex items-start bg-black/50 border border-red-500/20 p-2 sm:p-3">
                          <AlertCircle className="h-4 w-4 text-red-400 mr-2 mt-0.5 flex-shrink-0" />
                          <span className="text-gray-300">{f.title}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4 className="text-sm sm:text-base font-medium mb-3 text-green-400">[APPROVAL_GATED_ACTIONS]:</h4>
                    <ul className="space-y-2 text-xs">
                      {recommendations.length === 0 ? (
                        <li className="text-gray-400">No remediation actions drafted.</li>
                      ) : recommendations.map((rec, idx) => (
                        <li key={rec.recommendation_id || idx} className="flex items-start bg-black/50 border border-green-500/20 p-2 sm:p-3">
                          <Shield className="h-4 w-4 text-green-400 mr-2 mt-0.5 flex-shrink-0" />
                          <span className="text-gray-300">{rec.title}: {rec.action}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Charts Section */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6">
              <div className="bg-black/80 border border-green-500/30 p-4 sm:p-6">
                <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400">[SEVERITY_DISTRIBUTION.CHART]</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={severityData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                    <XAxis dataKey="severity" stroke="#00ff96" fontSize={12} />
                    <YAxis stroke="#00ff96" fontSize={12} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: 'black', border: '1px solid #00ff96', color: '#00ff96', fontFamily: 'monospace' }}
                    />
                    <Bar dataKey="count" fill="#22d3ee" stroke="#00ff96" strokeWidth={1} />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-black/80 border border-green-500/30 p-4 sm:p-6">
                <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400">[EVENT_TYPE_DISTRIBUTION.CHART]</h3>
                {riskDistribution.length === 0 ? (
                  <div className="h-[250px] flex items-center justify-center text-gray-500 text-xs">No distribution data</div>
                ) : (
                  <>
                    <ResponsiveContainer width="100%" height={250}>
                      <PieChart>
                        <Pie
                          data={riskDistribution}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, value }) => `${(name ?? '').replace(/_/g, ' ')}: ${value}%`}
                          outerRadius={70}
                          fill="#8884d8"
                          stroke="#00ff96"
                          strokeWidth={2}
                          dataKey="value"
                        >
                          {riskDistribution.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: 'black', border: '1px solid #00ff96', color: '#00ff96', fontFamily: 'monospace' }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="flex flex-wrap justify-center gap-3 mt-2">
                      {riskDistribution.map((entry, index) => (
                        <div key={index} className="flex items-center text-xs">
                          <div className="w-3 h-3 mr-1.5 border border-green-500/50" style={{ backgroundColor: entry.color }} />
                          <span className="text-green-400">{entry.name.replace(/_/g, ' ')}: {entry.value}%</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>

              <div className="bg-black/80 border border-green-500/30 p-4 sm:p-6">
                <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400">[HOURLY_ACTIVITY.CHART]</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={hourlyActivity}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                    <XAxis dataKey="hour" stroke="#00ff96" fontSize={12} />
                    <YAxis stroke="#00ff96" fontSize={12} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: 'black', border: '1px solid #00ff96', color: '#00ff96', fontFamily: 'monospace' }}
                    />
                    <Line type="monotone" dataKey="events" stroke="#22d3ee" strokeWidth={3} dot={{ fill: '#22d3ee', strokeWidth: 2, r: 5 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-black/80 border border-green-500/30 p-4 sm:p-6">
                <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400">[EVENT_SUMMARY.TABLE]</h3>
                <div className="overflow-x-auto max-h-[250px] overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-green-500/50 text-cyan-400">
                        <th className="text-left py-2">[TIME]</th>
                        <th className="text-left py-2">[EVENT]</th>
                        <th className="text-left py-2">[RISK]</th>
                      </tr>
                    </thead>
                    <tbody>
                      {timelineEvents.map((event, index) => (
                        <tr key={event.eventId || index} className="border-b border-gray-800">
                          <td className="py-2 pr-2 text-gray-400 whitespace-nowrap">{event.timestamp}</td>
                          <td className="py-2 pr-2">
                            <div className="text-white">{event.summary}</div>
                            <div className="text-gray-500">{event.eventType}</div>
                          </td>
                          <td className="py-2">
                            <span className={`px-2 py-0.5 border text-xs ${getSeverityColor(event.severity)}`}>
                              [{event.riskScore}]
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default SecurityLogDashboard;
