'use client'
import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import Navbar from '../../components/navbar'

const DashboardPage = () => {
  const [isVisible, setIsVisible] = useState(false)
  const [hoveredFeature, setHoveredFeature] = useState<number | null>(null)
  const [terminalText, setTerminalText] = useState('')
  const [showCursor, setShowCursor] = useState(true)
  const [isMobile, setIsMobile] = useState(false)

  const fullTerminalText = '> FORENSIQ_DASHBOARD.EXE --MODE=OPERATIONAL'

  useEffect(() => {
    // Check if mobile on mount
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768)
    }
    
    checkMobile()
    window.addEventListener('resize', checkMobile)
    
    setIsVisible(true)
    
    // Terminal typing effect
    let i = 0
    const typeInterval = setInterval(() => {
      if (i <= fullTerminalText.length) {
        setTerminalText(fullTerminalText.slice(0, i))
        i++
      } else {
        clearInterval(typeInterval)
      }
    }, 50)

    // Cursor blinking
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev)
    }, 500)

    return () => {
      clearInterval(typeInterval)
      clearInterval(cursorInterval)
      window.removeEventListener('resize', checkMobile)
    }
  }, [])

  const features = [
    {
      title: 'LOG_ANALYSIS.SYS',
      shortTitle: 'LOG_ANALYSIS',
      description: 'AI-powered analysis of security logs with MITRE ATT&CK technique mapping',
      shortDescription: 'AI-powered log analysis with MITRE mapping',
      icon: '🔍',
      href: '/dashboard/analysis',
      color: 'cyan',
      stats: 'REALTIME_ANALYSIS'
    },
    {
      title: 'MITRE_ATTACK.DB',
      shortTitle: 'MITRE_ATTACK',
      description: 'Comprehensive threat intelligence and attack technique database',
      shortDescription: 'Threat intelligence and attack technique database',
      icon: '🛡️',
      href: '/dashboard/mitre',
      color: 'purple',
      stats: 'ENTERPRISE_TECH'
    },
    {
      title: 'THREAT_INTEL.NET',
      shortTitle: 'THREAT_INTEL',
      description: 'Advanced threat detection and response capabilities',
      shortDescription: 'Advanced threat detection and response',
      icon: '⚠️',
      href: '/dashboard/threats',
      color: 'red',
      stats: 'COMING_SOON'
    },
    {
      title: 'SEC_REPORTS.OUT',
      shortTitle: 'SEC_REPORTS',
      description: 'Comprehensive security analysis and incident reports',
      shortDescription: 'Security analysis and incident reports',
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
      shortType: 'System Break',
      timestamp: '2025-08-29 05:08:30',
      shortTimestamp: '08-29 05:08',
      techniques: 5,
      severity: 'Critical',
      status: 'Completed'
    },
    {
      id: 2,
      type: 'Login Anomaly',
      shortType: 'Login Anomaly',
      timestamp: '2025-08-29 04:15:22',
      shortTimestamp: '08-29 04:15',
      techniques: 3,
      severity: 'High',
      status: 'Completed'
    },
    {
      id: 3,
      type: 'Network Intrusion',
      shortType: 'Net Intrusion',
      timestamp: '2025-08-29 03:42:11',
      shortTimestamp: '08-29 03:42',
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
    <div className='relative bg-black min-h-screen w-full text-white overflow-x-hidden'>
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
      
      <div className="relative container mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 md:py-8 font-mono max-w-full">
        {/* Terminal Header */}
        <div className={`mb-6 sm:mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-2 sm:p-3 mb-4 overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-red-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-yellow-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-green-500"></div>
              <span className="ml-2 sm:ml-4 text-green-400 text-xs sm:text-sm">admin@forensiq:~/dashboard#</span>
            </div>
            <div className="text-green-400 text-xs sm:text-sm overflow-hidden">
              <div className="whitespace-nowrap overflow-hidden">
                {isMobile ? terminalText.slice(0, 30) + (terminalText.length > 30 ? '...' : '') : terminalText}
                {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
              </div>
            </div>
          </div>
          
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-green-400 mb-2 tracking-wider break-words">
            [SECURITY_OPS_DASHBOARD]
          </h1>
          <div className="text-cyan-400 text-xs sm:text-sm overflow-hidden">
            <div className="whitespace-nowrap overflow-x-auto">
              &gt; CYBER_THREAT_ANALYSIS.PLATFORM --STATUS=OPERATIONAL
            </div>
          </div>
        </div>

        {/* Terminal Stats Overview */}
        <div className={`grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 mb-6 sm:mb-8 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[TOTAL_ANALYSES]</p>
                <p className="text-xl sm:text-2xl font-bold text-cyan-400">1,247</p>
              </div>
              <div className="text-cyan-400 text-lg sm:text-xl">📈</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-400 text-xs">[CRITICAL_THREATS]</p>
                <p className="text-xl sm:text-2xl font-bold text-red-400">23</p>
              </div>
              <div className="text-red-400 text-lg sm:text-xl animate-pulse">🚨</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[MITRE_TECHNIQUES]</p>
                <p className="text-xl sm:text-2xl font-bold text-green-400">578</p>
              </div>
              <div className="text-green-400 text-lg sm:text-xl">🛡️</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-400 text-xs">[RESPONSE_TIME]</p>
                <p className="text-xl sm:text-2xl font-bold text-purple-400">2.3s</p>
              </div>
              <div className="text-purple-400 text-lg sm:text-xl">⚡</div>
            </div>
          </div>
        </div>

        {/* Terminal Features Grid */}
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6 mb-6 sm:mb-8 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {features.map((feature, index) => (
            <Link key={index} href={feature.href}>
              <div 
                className={`relative bg-black/80 backdrop-blur-sm border ${getColorClasses(feature.color)} p-4 sm:p-6 transition-all duration-300 group cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,150,0.3)]`}
                onMouseEnter={() => setHoveredFeature(index)}
                onMouseLeave={() => setHoveredFeature(null)}
              >
                <div className="flex items-start justify-between mb-3 sm:mb-4">
                  <div className={`w-10 h-10 sm:w-12 sm:h-12 ${getColorClasses(feature.color)} flex items-center justify-center text-xl sm:text-2xl group-hover:scale-110 transition-transform duration-300`}>
                    {feature.icon}
                  </div>
                  <span className={`text-xs px-2 py-1 border ${getColorClasses(feature.color)} whitespace-nowrap`}>
                    [{feature.stats}]
                  </span>
                </div>
                
                <h3 className="text-lg sm:text-xl font-semibold text-green-400 mb-2 group-hover:text-cyan-400 transition-colors break-words">
                  <span className="hidden sm:inline">&gt; {feature.title}</span>
                  <span className="sm:hidden">&gt; {feature.shortTitle}</span>
                </h3>
                <p className="text-gray-300 leading-relaxed text-xs sm:text-sm break-words">
                  <span className="hidden sm:inline">{feature.description}</span>
                  <span className="sm:hidden">{feature.shortDescription}</span>
                </p>
                
                <div className="mt-3 sm:mt-4 flex items-center text-cyan-400 text-xs sm:text-sm font-medium">
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
        <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 sm:p-6 transform transition-all duration-1000 delay-600 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6 flex items-center text-green-400">
            <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
            <span className="break-words">[RECENT_ANALYSES.LOG]</span>
          </h2>
          
          <div className="space-y-2 sm:space-y-3">
            {recentAnalyses.map((analysis) => (
              <div key={analysis.id} className="flex flex-col sm:flex-row sm:items-center justify-between p-3 sm:p-4 bg-black/50 border border-gray-700/30 hover:border-cyan-500/30 transition-colors font-mono gap-3 sm:gap-0">
                <div className="flex items-center space-x-3 sm:space-x-4">
                  <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse flex-shrink-0"></div>
                  <div>
                    <h4 className="font-medium text-cyan-400 text-sm sm:text-base break-words">
                      <span className="hidden sm:inline">&gt; {analysis.type}</span>
                      <span className="sm:hidden">&gt; {analysis.shortType}</span>
                    </h4>
                    <p className="text-xs text-gray-400">
                      <span className="hidden sm:inline">[{analysis.timestamp}]</span>
                      <span className="sm:hidden">[{analysis.shortTimestamp}]</span>
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center justify-between sm:justify-end space-x-2 sm:space-x-4 text-xs sm:text-sm pl-5 sm:pl-0">
                  <span className="text-gray-300 flex-shrink-0">
                    [{analysis.techniques}_TECH]
                  </span>
                  <span className={`px-2 sm:px-3 py-1 text-xs font-medium border ${getSeverityColor(analysis.severity)} whitespace-nowrap`}>
                    {analysis.severity.toUpperCase()}
                  </span>
                  <span className="text-green-400 whitespace-nowrap">
                    [{analysis.status.toUpperCase()}]
                  </span>
                </div>
              </div>
            ))}
          </div>
          
          <div className="mt-4 sm:mt-6 text-center">
            <Link href="/dashboard/analysis" className="inline-flex items-center px-4 sm:px-6 py-2 sm:py-3 bg-black border-2 border-green-500 hover:border-cyan-400 text-green-400 hover:text-cyan-400 font-medium transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,150,0.5)] font-mono text-sm">
              <span className="hidden sm:inline">&gt; NEW_ANALYSIS.EXE --EXECUTE</span>
              <span className="sm:hidden">&gt; NEW_ANALYSIS</span>
            </Link>
          </div>
        </div>

        {/* Floating ASCII elements - hidden on mobile for cleaner look */}
        <div className="hidden md:block absolute top-32 left-10 text-green-500/20 font-mono text-xs animate-pulse">
          {`{
  "mode": "dashboard",
  "status": "active"
}`}
        </div>
        
        <div className="hidden md:block absolute top-48 right-12 text-green-500/20 font-mono text-xs animate-pulse delay-1000">
          &gt; ./security_ops.exe
        </div>
        
        <div className="hidden sm:block absolute bottom-32 left-16 text-green-500/20 font-mono text-xs animate-pulse delay-2000">
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

        @media (max-width: 640px) {
          .container {
            max-width: 100%;
          }
        }
      `}</style>
    </div>
  )
}

export default DashboardPage