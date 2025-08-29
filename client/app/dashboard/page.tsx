'use client'
import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import Navbar from '../../components/navbar'

const DashboardPage = () => {
  const [isVisible, setIsVisible] = useState(false)
  const [hoveredFeature, setHoveredFeature] = useState<number | null>(null)
  const [terminalText, setTerminalText] = useState('')
  const [showCursor, setShowCursor] = useState(true)

  const fullTerminalText = '> FORENSIQ_DASHBOARD.EXE --MODE=OPERATIONAL'

  useEffect(() => {
    setIsVisible(true)
    
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
    };
  }, []);

  const features = [
    {
      title: 'LOG_ANALYSIS.SYS',
      description: 'AI-powered analysis of security logs with MITRE ATT&CK technique mapping',
      icon: '🔍',
      href: '/dashboard/analysis',
      color: 'cyan',
      stats: 'REALTIME_ANALYSIS'
    },
    {
      title: 'MITRE_ATTACK.DB',
      description: 'Comprehensive threat intelligence and attack technique database',
      icon: '🛡️',
      href: '/dashboard/mitre',
      color: 'purple',
      stats: 'ENTERPRISE_TECH'
    },
    {
      title: 'THREAT_INTEL.NET',
      description: 'Advanced threat detection and response capabilities',
      icon: '⚠️',
      href: '/dashboard/threats',
      color: 'red',
      stats: 'COMING_SOON'
    },
    {
      title: 'SEC_REPORTS.OUT',
      description: 'Comprehensive security analysis and incident reports',
      icon: '📊',
      href: '/dashboard/reports',
      color: 'green',
      stats: 'COMING_SOON'
    }
  ]

  const recentAnalyses = [
    {
      id: 1,
      type: 'System Break Out',
      timestamp: '2025-08-29 05:08:30',
      techniques: 5,
      severity: 'Critical',
      status: 'Completed'
    },
    {
      id: 2,
      type: 'Login Anomaly',
      timestamp: '2025-08-29 04:15:22',
      techniques: 3,
      severity: 'High',
      status: 'Completed'
    },
    {
      id: 3,
      type: 'Network Intrusion',
      timestamp: '2025-08-29 03:42:11',
      techniques: 7,
      severity: 'Critical',
      status: 'In Progress'
    }
  ]

  const getColorClasses = (color: string) => {
    switch (color) {
      case 'cyan': return 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 bg-cyan-500/10'
      case 'purple': return 'border-purple-500/30 hover:border-purple-400 text-purple-400 bg-purple-500/10'
      case 'red': return 'border-red-500/30 hover:border-red-400 text-red-400 bg-red-500/10'
      case 'green': return 'border-green-500/30 hover:border-green-400 text-green-400 bg-green-500/10'
      default: return 'border-gray-500/30 hover:border-gray-400 text-gray-400 bg-gray-500/10'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-900/30 border-red-500/30'
      case 'high': return 'text-orange-400 bg-orange-900/30 border-orange-500/30'
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/30'
      case 'low': return 'text-green-400 bg-green-900/30 border-green-500/30'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/30'
    }
  }

  return (
    <div className='relative bg-black min-h-screen w-screen text-white overflow-hidden'>
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
      
      <Navbar />
      
      <div className="relative container mx-auto px-6 py-8 font-mono">
        {/* Terminal Header */}
        <div className={`mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-3 mb-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="ml-4 text-green-400 text-sm">admin@forensiq:~/dashboard#</span>
            </div>
            <div className="text-green-400 text-sm">
              {terminalText}
              {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
            </div>
          </div>
          
          <h1 className="text-4xl font-bold text-green-400 mb-2 tracking-wider">
            [SECURITY_OPS_DASHBOARD]
          </h1>
          <p className="text-cyan-400">&gt; CYBER_THREAT_ANALYSIS.PLATFORM --STATUS=OPERATIONAL</p>
        </div>

        {/* Terminal Stats Overview */}
        <div className={`grid grid-cols-1 md:grid-cols-4 gap-4 mb-8 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[TOTAL_ANALYSES]</p>
                <p className="text-2xl font-bold text-cyan-400">1,247</p>
              </div>
              <div className="text-cyan-400 text-xl">📈</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-400 text-xs">[CRITICAL_THREATS]</p>
                <p className="text-2xl font-bold text-red-400">23</p>
              </div>
              <div className="text-red-400 text-xl animate-pulse">🚨</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[MITRE_TECHNIQUES]</p>
                <p className="text-2xl font-bold text-green-400">578</p>
              </div>
              <div className="text-green-400 text-xl">🛡️</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-400 text-xs">[RESPONSE_TIME]</p>
                <p className="text-2xl font-bold text-purple-400">2.3s</p>
              </div>
              <div className="text-purple-400 text-xl">⚡</div>
            </div>
          </div>
        </div>

        {/* Terminal Features Grid */}
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-6 mb-8 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {features.map((feature, index) => (
            <Link key={index} href={feature.href}>
              <div 
                className={`relative bg-black/80 backdrop-blur-sm border ${getColorClasses(feature.color)} p-6 transition-all duration-300 group cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,150,0.3)]`}
                onMouseEnter={() => setHoveredFeature(index)}
                onMouseLeave={() => setHoveredFeature(null)}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className={`w-12 h-12 ${getColorClasses(feature.color)} flex items-center justify-center text-2xl group-hover:scale-110 transition-transform duration-300`}>
                    {feature.icon}
                  </div>
                  <span className={`text-xs px-2 py-1 border ${getColorClasses(feature.color)}`}>
                    [{feature.stats}]
                  </span>
                </div>
                
                <h3 className="text-xl font-semibold text-green-400 mb-2 group-hover:text-cyan-400 transition-colors">
                  &gt; {feature.title}
                </h3>
                <p className="text-gray-300 leading-relaxed text-sm">
                  {feature.description}
                </p>
                
                <div className="mt-4 flex items-center text-cyan-400 text-sm font-medium">
                  <span>&gt; EXEC_MODULE --RUN</span>
                </div>
                
                {hoveredFeature === index && (
                  <>
                    <div className={`absolute inset-0 ${getColorClasses(feature.color)} animate-pulse`} />
                    <div className={`absolute -inset-1 border ${getColorClasses(feature.color)} animate-pulse`} />
                  </>
                )}
              </div>
            </Link>
          ))}
        </div>

        {/* Terminal Recent Analyses */}
        <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 p-6 transform transition-all duration-1000 delay-600 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <h2 className="text-xl font-semibold mb-6 flex items-center text-green-400">
            <span className="w-2 h-2 bg-green-500 rounded-full mr-3 animate-pulse"></span>
            [RECENT_ANALYSES.LOG]
          </h2>
          
          <div className="space-y-3">
            {recentAnalyses.map((analysis) => (
              <div key={analysis.id} className="flex items-center justify-between p-4 bg-black/50 border border-gray-700/30 hover:border-cyan-500/30 transition-colors font-mono">
                <div className="flex items-center space-x-4">
                  <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse"></div>
                  <div>
                    <h4 className="font-medium text-cyan-400">&gt; {analysis.type}</h4>
                    <p className="text-xs text-gray-400">[{analysis.timestamp}]</p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-4 text-sm">
                  <span className="text-gray-300">
                    [{analysis.techniques}_TECH]
                  </span>
                  <span className={`px-3 py-1 text-xs font-medium border ${getSeverityColor(analysis.severity)}`}>
                    {analysis.severity.toUpperCase()}
                  </span>
                  <span className="text-green-400">
                    [{analysis.status.toUpperCase()}]
                  </span>
                </div>
              </div>
            ))}
          </div>
          
          <div className="mt-6 text-center">
            <Link href="/dashboard/analysis" className="inline-flex items-center px-6 py-3 bg-black border-2 border-green-500 hover:border-cyan-400 text-green-400 hover:text-cyan-400 font-medium transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,150,0.5)] font-mono">
              &gt; NEW_ANALYSIS.EXE --EXECUTE
            </Link>
          </div>
        </div>

        {/* Floating ASCII elements */}
        <div className="absolute top-32 left-10 text-green-500/20 font-mono text-xs animate-pulse">
          {`{
  "mode": "dashboard",
  "status": "active"
}`}
        </div>
        
        <div className="absolute top-48 right-12 text-green-500/20 font-mono text-xs animate-pulse delay-1000">
          &gt; ./security_ops.exe
        </div>
        
        <div className="absolute bottom-32 left-16 text-green-500/20 font-mono text-xs animate-pulse delay-2000">
          [ADMIN@FORENSIQ]#
        </div>
      </div>

      <style jsx>{`
        .glitch-text {
          position: relative;
        }
        
        @keyframes glitch {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-2px); }
          75% { transform: translateX(2px); }
        }
        
        .glitch-text:hover {
          animation: glitch 0.3s;
        }
      `}</style>
    </div>
  )
}

export default DashboardPage
