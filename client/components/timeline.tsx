'use client'
import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { AlertTriangle, Shield, Activity, Clock, Database, Network, AlertCircle } from 'lucide-react';

const SecurityLogDashboard = () => {
  const [selectedView, setSelectedView] = useState('overview');
  const [isVisible, setIsVisible] = useState(false);
  const [terminalText, setTerminalText] = useState('');
  const [showCursor, setShowCursor] = useState(true);
  const [isMobile, setIsMobile] = useState(false);

  const fullTerminalText = '> SECURITY_LOG_ANALYZER.EXE --INCIDENT=2025-08-07 --MODE=THREAT_HUNT';

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    
    checkMobile();
    window.addEventListener('resize', checkMobile);
    
    setIsVisible(true);
    
    // Terminal typing effect
    let i = 0;
    const typeInterval = setInterval(() => {
      if (i <= fullTerminalText.length) {
        setTerminalText(fullTerminalText.slice(0, i));
        i++;
      } else {
        clearInterval(typeInterval);
      }
    }, 50);

    // Cursor blinking
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 500);

    return () => {
      clearInterval(typeInterval);
      clearInterval(cursorInterval);
      window.removeEventListener('resize', checkMobile);
    };
  }, []);

  // Sample data based on your log analysis
  const securityEvents = [
    {
      timestamp: '2025-08-07T13:01:50Z',
      event: 'Registry Query',
      severity: 'Medium',
      command: 'reg.exe query HKEY_USERS\\S-1-5-21-382297125-3180263876-1941408969-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
      riskScore: 65,
      category: 'Suspicious Registry Access'
    }
  ];

  const timelineData = [
    {
      time: '13:01:50',
      event: 'reg.exe execution',
      type: 'Registry Query',
      severity: 'Medium'
    }
  ];

  const riskDistribution = [
    { name: 'Registry_Access', value: 65, color: '#FF6B6B' },
    { name: 'Normal_Activity', value: 35, color: '#00ff96' }
  ];

  const severityData = [
    { severity: 'HIGH', count: 0 },
    { severity: 'MEDIUM', count: 1 },
    { severity: 'LOW', count: 0 },
    { severity: 'INFO', count: 0 }
  ];

  const hourlyActivity = [
    { hour: '12:00', events: 0 },
    { hour: '13:00', events: 1 },
    { hour: '14:00', events: 0 },
    { hour: '15:00', events: 0 }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'High': return 'text-red-400 bg-red-900/30 border-red-500/50';
      case 'Medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/50';
      case 'Low': return 'text-blue-400 bg-blue-900/30 border-blue-500/50';
      default: return 'text-green-400 bg-green-900/30 border-green-500/50';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className='relative bg-black min-h-screen w-full text-white overflow-x-hidden font-mono'>
      {/* Terminal grid overlay */}
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
      
      {/* Matrix-style overlay */}
      <div className="absolute inset-0 bg-gradient-to-b from-black/60 via-transparent to-black/80" />
      
      <div className="relative container mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 md:py-8 max-w-full">
        {/* Terminal Header */}
        <div className={`mb-6 sm:mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-2 sm:p-3 mb-4 overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-red-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-yellow-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-green-500"></div>
              <span className="ml-2 sm:ml-4 text-green-400 text-xs sm:text-sm">admin@forensiq:~/security_analysis#</span>
              <div className="text-green-400 text-xs sm:text-sm overflow-hidden">
                <div className="whitespace-nowrap overflow-hidden">
                  {isMobile ? terminalText.slice(0, 30) + (terminalText.length > 30 ? '...' : '') : terminalText}
                  {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
                </div>
              </div>
            </div>
            <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-green-400 mb-2 tracking-wider break-words">
              [SECURITY_LOG_DASHBOARD.SYS]
            </h1>
            <div className="text-cyan-400 text-xs sm:text-sm overflow-hidden">
              <div className="whitespace-nowrap overflow-x-auto">
                &gt; INCIDENT_ID: 2025-08-07_REG_QUERY_ANOMALY --STATUS: ANALYZING
              </div>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div className={`flex flex-wrap gap-2 sm:gap-4 mb-6 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {['overview', 'timeline', 'events', 'analysis'].map((view) => (
            <button
              key={view}
              onClick={() => setSelectedView(view)}
              className={`px-3 sm:px-4 py-2 border-2 font-mono uppercase tracking-wider transition-all duration-300 text-xs sm:text-sm ${
                selectedView === view 
                  ? 'bg-green-500/20 text-green-400 border-green-500 shadow-[0_0_10px_rgba(0,255,150,0.3)]' 
                  : 'bg-black/80 text-green-600 border-green-500/30 hover:border-green-400 hover:text-green-400 hover:shadow-[0_0_5px_rgba(0,255,150,0.2)]'
              }`}
            >
              [{view}]
            </button>
          ))}
        </div>

        {/* Overview Dashboard */}
        {selectedView === 'overview' && (
          <div className={`grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6 mb-6 sm:mb-8 transform transition-all duration-1000 delay-300 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            {/* Security Alert Card */}
            <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 p-4 sm:p-6 hover:border-red-400 transition-colors">
              <div className="flex items-center mb-4">
                <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                <h3 className="text-sm sm:text-lg font-semibold text-red-400 font-mono">[SECURITY_ALERT]</h3>
              </div>
              <div className="space-y-2">
                <p className="text-red-300 text-xs sm:text-sm font-mono">SUSPICIOUS_REGISTRY_ACCESS_DETECTED</p>
                <p className="text-xs text-gray-400">RunMRU key query via reg.exe</p>
                <div className="text-xl sm:text-2xl font-bold text-red-400 font-mono">RISK_SCORE: 65</div>
              </div>
            </div>

            {/* System Activity Card */}
            <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-4 sm:p-6 hover:border-cyan-400 transition-colors">
              <div className="flex items-center mb-4">
                <div className="w-2 h-2 bg-cyan-500 rounded-full mr-3"></div>
                <h3 className="text-sm sm:text-lg font-semibold text-cyan-400 font-mono">[SYSTEM_ACTIVITY]</h3>
              </div>
              <div className="space-y-2">
                <p className="text-cyan-300 text-xs sm:text-sm font-mono">REGISTRY_OPERATIONS</p>
                <p className="text-xs text-gray-400">1 event detected</p>
                <div className="text-xl sm:text-2xl font-bold text-cyan-400 font-mono">EVENTS: 1</div>
              </div>
            </div>

            {/* Network Status Card */}
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 hover:border-green-400 transition-colors">
              <div className="flex items-center mb-4">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                <h3 className="text-sm sm:text-lg font-semibold text-green-400 font-mono">[NETWORK_STATUS]</h3>
              </div>
              <div className="space-y-2">
                <p className="text-green-300 text-xs sm:text-sm font-mono">NO_NETWORK_EVENTS</p>
                <p className="text-xs text-gray-400">Clean network activity</p>
                <div className="text-xl sm:text-2xl font-bold text-green-400 font-mono">STATUS: CLEAN</div>
              </div>
            </div>
          </div>
        )}

        {/* Timeline View */}
        {selectedView === 'timeline' && (
          <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 mb-6 sm:mb-8 transform transition-all duration-1000 delay-300 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            <h3 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6 flex items-center text-green-400 font-mono">
              <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3"></span>
              [EVENT_TIMELINE] - 2025.08.07
            </h3>
            <div className="relative">
              <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-green-500/50"></div>
              {timelineData.map((event, index) => (
                <div key={index} className="relative flex items-center mb-6">
                  <div className={`absolute left-2 w-4 h-4 rounded-full border-2 ${
                    event.severity === 'Medium' ? 'bg-yellow-500 border-yellow-400' : 'bg-green-500 border-green-400'
                  }`}></div>
                  <div className="ml-10 bg-black/70 border border-green-500/30 p-3 sm:p-4 flex-1 hover:border-cyan-400 transition-colors">
                    <div className="flex flex-col sm:flex-row justify-between items-start mb-2 gap-2">
                      <h4 className="font-semibold text-green-400 font-mono text-sm sm:text-base">&gt; {event.event}</h4>
                      <span className={`px-2 py-1 border text-xs font-mono ${
                        event.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50' : 'bg-green-500/20 text-green-400 border-green-500/50'
                      }`}>
                        [{event.severity.toUpperCase()}]
                      </span>
                    </div>
                    <p className="text-cyan-300 text-xs sm:text-sm font-mono mb-1">{event.type}</p>
                    <p className="text-gray-400 text-xs font-mono">[TIMESTAMP]: {event.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Events Detail View */}
        {selectedView === 'events' && (
          <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 mb-6 sm:mb-8 transform transition-all duration-1000 delay-300 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            <h3 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6 flex items-center text-green-400 font-mono">
              <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3"></span>
              [DETAILED_EVENT_ANALYSIS.LOG]
            </h3>
            <div className="space-y-4">
              {securityEvents.map((event, index) => (
                <div key={index} className="bg-black/70 border border-red-500/30 border-l-4 border-l-red-500 p-4 hover:border-red-400 transition-colors">
                  <div className="flex flex-col sm:flex-row justify-between items-start mb-3 gap-3">
                    <h4 className="font-semibold text-green-400 text-base sm:text-lg font-mono break-words">
                      &gt; {event.event}
                    </h4>
                    <div className="flex items-center space-x-2">
                      <span className="px-2 sm:px-3 py-1 border text-xs font-mono bg-yellow-500/20 text-yellow-400 border-yellow-500/50">
                        [{event.severity.toUpperCase()}]
                      </span>
                      <span className="text-red-400 font-bold font-mono text-xs sm:text-sm">RISK: {event.riskScore}</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs sm:text-sm">
                    <div>
                      <span className="text-cyan-400 font-mono">[TIMESTAMP]:</span>
                      <p className="text-white font-mono">{formatTimestamp(event.timestamp)}</p>
                    </div>
                    <div>
                      <span className="text-cyan-400 font-mono">[CATEGORY]:</span>
                      <p className="text-white font-mono break-words">{event.category}</p>
                    </div>
                  </div>
                  <div className="mt-3">
                    <span className="text-cyan-400 font-mono">[COMMAND_EXECUTED]:</span>
                    <div className="text-green-400 bg-black border border-green-500/30 p-2 sm:p-3 mt-1 font-mono text-xs break-all overflow-x-auto">
                      {event.command}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Analysis View */}
        {selectedView === 'analysis' && (
          <div className={`space-y-4 sm:space-y-6 transform transition-all duration-1000 delay-300 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            {/* Risk Assessment */}
            <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 p-4 sm:p-6">
              <h3 className="text-lg sm:text-xl font-semibold mb-4 flex items-center text-red-400 font-mono">
                <span className="w-2 h-2 bg-red-500 rounded-full mr-2 sm:mr-3"></span>
                [THREAT_ASSESSMENT.DB]
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
                <div>
                  <h4 className="text-sm sm:text-lg font-medium mb-3 text-red-400 font-mono">[THREATS_IDENTIFIED]:</h4>
                  <ul className="space-y-2 text-xs sm:text-sm">
                    <li className="flex items-start bg-black/50 border border-red-500/20 p-2 sm:p-3">
                      <AlertCircle className="h-3 w-3 sm:h-4 sm:w-4 text-red-400 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300 font-mono break-words">Registry manipulation via reg.exe - common malware persistence technique</span>
                    </li>
                    <li className="flex items-start bg-black/50 border border-red-500/20 p-2 sm:p-3">
                      <AlertCircle className="h-3 w-3 sm:h-4 sm:w-4 text-red-400 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300 font-mono break-words">RunMRU key access - potential auto-run entry modification</span>
                    </li>
                    <li className="flex items-start bg-black/50 border border-red-500/20 p-2 sm:p-3">
                      <AlertCircle className="h-3 w-3 sm:h-4 sm:w-4 text-red-400 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300 font-mono break-words">Direct command-line registry access bypassing standard APIs</span>
                    </li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-sm sm:text-lg font-medium mb-3 text-green-400 font-mono">[RECOMMENDED_ACTIONS]:</h4>
                  <ul className="space-y-2 text-xs sm:text-sm">
                    <li className="flex items-start bg-black/50 border border-green-500/20 p-2 sm:p-3">
                      <Shield className="h-3 w-3 sm:h-4 sm:w-4 text-green-400 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300 font-mono break-words">Monitor for subsequent registry modifications</span>
                    </li>
                    <li className="flex items-start bg-black/50 border border-green-500/20 p-2 sm:p-3">
                      <Shield className="h-3 w-3 sm:h-4 sm:w-4 text-green-400 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300 font-mono break-words">Check user profile for unauthorized applications</span>
                    </li>
                    <li className="flex items-start bg-black/50 border border-green-500/20 p-2 sm:p-3">
                      <Shield className="h-3 w-3 sm:h-4 sm:w-4 text-green-400 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300 font-mono break-words">Audit current RunMRU entries for anomalies</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Charts Section */}
        <div className={`grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {/* Severity Distribution */}
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 hover:border-cyan-400 transition-colors">
            <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400 font-mono">[SEVERITY_DISTRIBUTION.CHART]</h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                <XAxis dataKey="severity" stroke="#00ff96" fontSize={12} />
                <YAxis stroke="#00ff96" fontSize={12} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: 'black', 
                    border: '1px solid #00ff96',
                    borderRadius: '0px',
                    color: '#00ff96',
                    fontFamily: 'monospace'
                  }} 
                />
                <Bar dataKey="count" fill="#22d3ee" stroke="#00ff96" strokeWidth={1} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Risk Score Pie Chart */}
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 hover:border-cyan-400 transition-colors">
            <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400 font-mono">[RISK_DISTRIBUTION.CHART]</h3>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={riskDistribution}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name.replace('_', ' ')}: ${value}%`}
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
                  contentStyle={{ 
                    backgroundColor: 'black', 
                    border: '1px solid #00ff96',
                    borderRadius: '0px',
                    color: '#00ff96',
                    fontFamily: 'monospace'
                  }}
                  formatter={(value, name) => [`${value}%`, typeof name === 'string' ? name.replace('_', ' ') : String(name)]}
                />
              </PieChart>
            </ResponsiveContainer>
            
            {/* Legend */}
            <div className="flex justify-center gap-4 mt-2">
              {riskDistribution.map((entry, index) => (
                <div key={index} className="flex items-center text-xs font-mono">
                  <div 
                    className="w-3 h-3 mr-2 border border-green-500/50"
                    style={{ backgroundColor: entry.color }}
                  ></div>
                  <span className="text-green-400">{entry.name.replace('_', ' ')}: {entry.value}%</span>
                </div>
              ))}
            </div>
          </div>

          {/* Hourly Activity */}
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 hover:border-cyan-400 transition-colors">
            <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400 font-mono">[HOURLY_ACTIVITY.CHART]</h3>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={hourlyActivity}>
                <CartesianGrid strokeDasharray="3 3" stroke="#00ff96" opacity={0.2} />
                <XAxis dataKey="hour" stroke="#00ff96" fontSize={12} />
                <YAxis stroke="#00ff96" fontSize={12} />
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
                  dataKey="events" 
                  stroke="#22d3ee" 
                  strokeWidth={3}
                  dot={{ fill: '#22d3ee', strokeWidth: 2, r: 6 }}
                  activeDot={{ r: 8, stroke: '#00ff96', strokeWidth: 2, fill: '#22d3ee' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Event Details Table */}
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 hover:border-cyan-400 transition-colors">
            <h3 className="text-sm sm:text-lg font-semibold mb-4 text-green-400 font-mono">[EVENT_SUMMARY.TABLE]</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs sm:text-sm font-mono">
                <thead>
                  <tr className="border-b border-green-500/50">
                    <th className="text-left py-2 text-cyan-400">[TIME]</th>
                    <th className="text-left py-2 text-cyan-400">[EVENT]</th>
                    <th className="text-left py-2 text-cyan-400">[RISK]</th>
                  </tr>
                </thead>
                <tbody>
                  {securityEvents.map((event, index) => (
                    <tr key={index} className="border-b border-gray-700/50 hover:bg-green-500/10 transition-colors">
                      <td className="py-3 text-gray-400">{event.timestamp.split('T')[1].split('Z')[0]}</td>
                      <td className="py-3">
                        <div>
                          <div className="font-medium text-white break-words">{event.event}</div>
                          <div className="text-xs text-gray-400 break-words">{event.category}</div>
                        </div>
                      </td>
                      <td className="py-3">
                        <span className={`px-2 py-1 border text-xs font-mono ${getSeverityColor(event.severity)}`}>
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

        {/* Detailed Analysis Section */}
        <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 mt-6 transform transition-all duration-1000 delay-500 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <h3 className="text-lg sm:text-xl font-semibold mb-4 flex items-center text-green-400 font-mono">
            <span className="w-2 h-2 bg-red-500 rounded-full mr-2 sm:mr-3"></span>
            [SECURITY_ANALYSIS_SUMMARY.RPT]
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
            <div>
              <h4 className="text-sm sm:text-lg font-medium mb-3 text-red-400 font-mono">[KEY_FINDINGS.DAT]:</h4>
              <div className="space-y-3 text-xs sm:text-sm">
                <div className="bg-black/50 border border-red-500/20 p-3">
                  <span className="font-medium text-green-400 font-mono">&gt; Registry_Access_Pattern:</span>
                  <p className="text-gray-300 mt-1 font-mono break-words">Direct reg.exe usage targeting RunMRU key suggests potential persistence mechanism setup.</p>
                </div>
                <div className="bg-black/50 border border-red-500/20 p-3">
                  <span className="font-medium text-green-400 font-mono">&gt; User_Profile_Target:</span>
                  <p className="text-gray-300 mt-1 font-mono break-all">Specific user SID targeted: S-1-5-21-382297125-3180263876-1941408969-1001</p>
                </div>
              </div>
            </div>
            <div>
              <h4 className="text-sm sm:text-lg font-medium mb-3 text-green-400 font-mono">[ADDITIONAL_OBSERVATIONS.DAT]:</h4>
              <div className="space-y-3 text-xs sm:text-sm">
                <div className="bg-black/50 border border-green-500/20 p-3">
                  <span className="font-medium text-green-400 font-mono">&gt; Network_Activity:</span>
                  <p className="text-gray-300 mt-1 font-mono break-words">No network anomalies detected during the analyzed period.</p>
                </div>
                <div className="bg-black/50 border border-green-500/20 p-3">
                  <span className="font-medium text-green-400 font-mono">&gt; Process_Context:</span>
                  <p className="text-gray-300 mt-1 font-mono break-words">Registry query executed via legitimate Windows reg.exe utility.</p>
                </div>
                <div className="bg-black/50 border border-green-500/20 p-3">
                  <span className="font-medium text-green-400 font-mono">&gt; Risk_Assessment:</span>
                  <p className="text-gray-300 mt-1 font-mono break-words">Medium risk - requires further monitoring and investigation.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityLogDashboard;