'use client'
import Navbar from '@/components/navbar'
import React, { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'

const DashboardPage = () => {
  const [isVisible, setIsVisible] = useState(false)
  const [hoveredFeature, setHoveredFeature] = useState<number | null>(null)
  const [terminalText, setTerminalText] = useState('')
  const [showCursor, setShowCursor] = useState(true)
  const [isMobile, setIsMobile] = useState(false)
  const [recentAnalyses, setRecentAnalyses] = useState<any[]>([])
  const [allSingleAnalysis, setAllSingleAnalysis] = useState<any[]>([])
  const [singleAnalysis, setSingleAnalysis] = useState<any | null>(null)
  const [selectedAnalysis, setSelectedAnalysis] = useState<any | null>(null)
  const [showModal, setShowModal] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fullTerminalText = '> FORENSIQ_DASHBOARD.EXE --MODE=OPERATIONAL'

  // Memoized mobile check function
  const checkMobile = useCallback(() => {
    setIsMobile(window.innerWidth < 768)
  }, [])

  useEffect(() => {
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
  }, [checkMobile])

  
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
      title: 'THREAT_VISUALIZATION.EXE',
      shortTitle: 'VISUALIZATION',
      description: 'Enhanced threat visualization dashboard with advanced analytics',
      shortDescription: 'Enhanced threat visualization dashboard',
      icon: '�',
      href: '/dashboard/visualization',
      color: 'purple',
      stats: 'INTERACTIVE_CHARTS'
    },
    {
      title: 'MITRE_ATTACK.DB',
      shortTitle: 'MITRE_ATTACK',
      description: 'Comprehensive threat intelligence and attack technique database',
      shortDescription: 'Threat intelligence and attack technique database',
      icon: '🛡',
      href: '/dashboard/mitre',
      color: 'green',
      stats: 'ENTERPRISE_TECH'
    },
    {
      title: 'THREAT_INTEL.NET',
      shortTitle: 'THREAT_INTEL',
      description: 'Advanced threat detection and response capabilities for modern security operations',
      shortDescription: 'Advanced threat detection and response',
      icon: '⚠',
      href: '/dashboard',
      color: 'red',
      stats: 'THREAT_INTEL'
    }
  ]


  
  const handleRecentAnalyses = async()=>{
    setLoading(true);
    setError(null);
    try{
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/v1/history?limit=10&offset=0`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch recent analyses: ${response.statusText}`);
      }
      const data = await response.json();
      setRecentAnalyses(data);
      console.log(data);
    }catch(err){
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch recent analyses';
      console.log(errorMessage);
    }
  }
  useEffect(()=>{
    handleRecentAnalyses();
  },[])

const recentSingleAnalyses  = async(elementId:string)=>{
    try{
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/v1/history/${elementId}`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch recent single analysis: ${response.statusText}`);
      }
      const data = await response.json();
      setSingleAnalysis(data);
      console.log(data);
    }catch(err){
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch recent single analysis';
      console.log(errorMessage);
    }
  }
  const allAnalysis = async () => {
    setLoading(true);
    setError(null);
  try {

    if (recentAnalyses.length === 0) return;

    const results = await Promise.all(
      recentAnalyses.map(async (item) => {
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/v1/history/${item.id}`,
          {
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${localStorage.getItem("token")}`,
            },
            
          }
        );
        if (!response.ok) throw new Error(`Failed to fetch analysis ${item.id}`);
        return response.json();
      })
    );

   setAllSingleAnalysis((prev) => [...prev, ...results]); // update state once
    console.log("All single analyses:", results);
    console.log("All single analyses final:", allSingleAnalysis);
  } catch (err) {
    console.log(err);
  }
};

  useEffect(()=>{
    allAnalysis();
  },[recentAnalyses])

  const handleAnalysisClick = useCallback((analysis: any) => {
    setSelectedAnalysis(analysis)
    setShowModal(true)
  }, [])

  const closeModal = useCallback(() => {
    setShowModal(false)
    setSelectedAnalysis(null)
  }, [])

  useEffect(() => {
  console.log("Updated allSingleAnalysis:", allSingleAnalysis)
}, [allSingleAnalysis])

  // Escape key handler for modal
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showModal) {
        closeModal()
      }
    }

    if (showModal) {
      document.addEventListener('keydown', handleEscape)
      document.body.style.overflow = 'hidden'
    }

    return () => {
      document.removeEventListener('keydown', handleEscape)
      document.body.style.overflow = 'unset'
    }
  }, [showModal, closeModal])

  

  const getColorClasses = useCallback((color: string) => {
    switch (color) {
      case 'cyan': return 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 bg-cyan-500/10'
      case 'purple': return 'border-purple-500/30 hover:border-purple-400 text-purple-400 bg-purple-500/10'
      case 'red': return 'border-red-500/30 hover:border-red-400 text-red-400 bg-red-500/10'
      case 'green': return 'border-green-500/30 hover:border-green-400 text-green-400 bg-green-500/10'
      default: return 'border-gray-500/30 hover:border-gray-400 text-gray-400 bg-gray-500/10'
    }
  }, [])

  const getSeverityColor = useCallback((severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-900/30 border-red-500/30'
      case 'high': return 'text-orange-400 bg-orange-900/30 border-orange-500/30'
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/30'
      case 'low': return 'text-green-400 bg-green-900/30 border-green-500/30'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/30'
    }
  }, [])

  const getActivityTypeColor = useCallback((type: string) => {
    switch (type.toLowerCase()) {
      case 'auth': return 'text-green-400 bg-green-900/30 border-green-500/30'
      case 'analysis': return 'text-cyan-400 bg-cyan-900/30 border-cyan-500/30'
      case 'query': return 'text-purple-400 bg-purple-900/30 border-purple-500/30'
      case 'visualization': return 'text-blue-400 bg-blue-900/30 border-blue-500/30'
      case 'access': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/30'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/30'
    }
  }, [])

  const getActivityIcon = useCallback((type: string) => {
    switch (type.toLowerCase()) {
      case 'auth': return '🔐'
      case 'analysis': return '🔍'
      case 'query': return '📊'
      case 'visualization': return '📈'
      case 'access': return '🖥️'
      default: return '⚡'
    }
  }, [])

  const formatTimestamp = useCallback((timestamp: string) => {
    if (!timestamp) return 'N/A'
    try {
      const date = new Date(timestamp)
      return date.toLocaleString()
    } catch {
      return 'Invalid Date'
    }
  }, [])

  const extractSummaryPreview = useCallback((summary: string) => {
    if (!summary) return 'No summary available'
    const lines = summary.replace(/```/g, '').split('\n').filter(line => line.trim())
    return lines.slice(0, 3).join(' ').substring(0, 150) + '...'
  }, [])

  const getSeverityFromSummary = useCallback((summary: string) => {
    if (!summary) return 'unknown'
    const summaryLower = summary.toLowerCase()
    if (summaryLower.includes('critical') || summaryLower.includes('high priority')) return 'critical'
    if (summaryLower.includes('high') || summaryLower.includes('moderate')) return 'high'
    if (summaryLower.includes('medium')) return 'medium'
    if (summaryLower.includes('low')) return 'low'
    return 'medium'
  }, [])

  // Mock navigation function since we don't have Next.js router
  const navigate = useCallback((href: string) => {
    console.log(`Navigating to: ${href}`)
    // In a real app, this would use Next.js router
  }, [])

  const FeatureCard = React.memo(({ feature, index }: { feature: any, index: number }) => (
    <div 
      className={`relative bg-black/80 backdrop-blur-sm border rounded-2xl ${getColorClasses(feature.color)} p-4 sm:p-6 transition-all duration-300 group cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,150,0.3)]`}
      onMouseEnter={() => setHoveredFeature(index)}
      onMouseLeave={() => setHoveredFeature(null)}
      onClick={() => navigate(feature.href)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          
        }
      }}
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
          <div className={`absolute inset-0 ${getColorClasses(feature.color)} animate-pulse rounded-2xl`} />
          <div className={`absolute -inset-1 border ${getColorClasses(feature.color)} animate-pulse rounded-2xl`} />
        </>
      )}
    </div>
  ))

  // Calculate total techniques correctly
  const totalTechniques = allSingleAnalysis.reduce((total, analysis) => {
    return total + (Array.isArray(analysis?.matched_techniques) ? analysis.matched_techniques.length : 0)
  }, 0)

  return (
    <div className='relative bg-black min-h-screen w-full text-white overflow-x-hidden'>
      {/* Terminal grid overlay */}
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
      
      {/* Matrix-style overlay */}
      <div className="absolute inset-0 bg-gradient-to-b from-black/60 via-transparent to-black/80 pointer-events-none" />
      
      {/* Navbar placeholder */}
      <Navbar/>
      
      <div className="relative container mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 md:py-8 font-mono max-w-full">
        {/* Error Display */}
        {error && (
          <div className="mb-6 bg-red-900/30 border border-red-500/50 rounded-lg p-4 text-red-400">
            <div className="flex items-center space-x-2">
              <span className="text-xl">⚠️</span>
              <span>[ERROR]: {error}</span>
            </div>
          </div>
        )}

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
                <p className="text-xl sm:text-2xl font-bold text-cyan-400">
                  {loading ? '...' : recentAnalyses.length}
                </p>
              </div>
              <div className="text-cyan-400 text-lg sm:text-xl">📈</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[MITRE_TECHNIQUES]</p>
                <p className="text-xl sm:text-2xl font-bold text-green-400">
                  {loading ? '...' : totalTechniques}
                </p>
              </div>
              <div className="text-green-400 text-lg sm:text-xl">🛡️</div>
            </div>
          </div>

          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[THREATS_ACTIVE]</p>
                <p className="text-xl sm:text-2xl font-bold text-red-400">3</p>
              </div>
              <div className="text-red-400 text-lg sm:text-xl">⚠️</div>
            </div>
          </div>

          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[SYSTEM_STATUS]</p>
                <p className="text-sm sm:text-base font-bold text-green-400">ONLINE</p>
              </div>
              <div className="text-green-400 text-lg sm:text-xl">✅</div>
            </div>
          </div>
        </div>

        {/* Terminal Features Grid */}
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6 mb-6 sm:mb-8 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {features.map((feature, index) => (
            <Link key={index} href={feature.href}>
              <div 
                className={`relative bg-black/80 backdrop-blur-sm border rounded-2xl ${getColorClasses(feature.color)} p-4 sm:p-6 transition-all duration-300 group cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,150,0.3)]`}
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


        {/* Terminal Recent Analyses and User Activity */}
       {/*} <div className={`flex flex-col-1 w-full gap-4 sm:gap-6 transform transition-all duration-1000 delay-600 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {/* Recent Analyses */}
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-2xl p-4 sm:p-6">
            <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6 flex items-center text-green-400">
              <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
              <span className="break-words">[RECENT_ANALYSES.LOG]</span>
            </h2>
            
     { allSingleAnalysis.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                No analyses available
              </div>
            ) : (
              <div className="space-y-2 sm:space-y-3">
                {allSingleAnalysis.map((analysis, index) => (
                  <div 
                    key={analysis?.id || index} 
                    className="flex flex-col p-3 bg-black/50 border border-gray-700/30 hover:border-cyan-500/30 transition-colors font-mono cursor-pointer"
                    onClick={() => handleAnalysisClick(analysis)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        handleAnalysisClick(analysis)
                      }
                    }}
                  >
                    <div className="flex items-center space-x-3 mb-2">
                      <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse flex-shrink-0"></div>
                      <div className="flex-1 min-w-0">
                        <h4 className="font-medium text-cyan-400 text-sm break-words">
                          &gt; ANALYSIS_#{index + 1}
                        </h4>
                        <p className="text-xs text-gray-400">
                          [{formatTimestamp(analysis?.analysis_timestamp)}]
                        </p>
                      </div>
                    </div>
                    
                    <div className="pl-5 text-xs text-gray-300 mb-2">
                      {extractSummaryPreview(analysis?.summary)}
                    </div>
                    
                    <div className="flex items-center justify-between text-xs pl-5">
                      <div className="flex items-center space-x-2">
                        <span className="text-gray-300">
                          [{Array.isArray(analysis?.matched_techniques) ? analysis.matched_techniques.length : 0}_TECH]
                        </span>
                        <span className={`px-2 py-1 text-xs font-medium border ${getSeverityColor(getSeverityFromSummary(analysis?.summary))}`}>
                          {getSeverityFromSummary(analysis?.summary).toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-green-400">
                          [COMPLETED]
                        </span>
                        <span className="px-2 py-1 bg-purple-900/30 border border-purple-500/30 hover:border-purple-400 hover:bg-purple-500/20 text-purple-400 hover:text-purple-300 transition-colors text-xs">
                          [VIEW]
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )
          }
            <div className="mt-4 text-center">
              <button 
                onClick={() => navigate('/dashboard/analysis')}
                className="inline-flex items-center px-4 py-2 bg-black border-2 border-green-500 hover:border-cyan-400 text-green-400 hover:text-cyan-400 font-medium transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,150,0.5)] font-mono text-sm"
              >
                <span className="hidden sm:inline">&gt; NEW_ANALYSIS.EXE</span>
                <span className="sm:hidden">&gt; NEW_ANALYSIS</span>
              </button>
            </div>
          </div>

          {/* User Activity */}
          
       {/* </div>*/}

        {/* Analysis Detail Modal */}
        {showModal && selectedAnalysis && (
          <div 
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={(e) => {
              if (e.target === e.currentTarget) {
                closeModal()
              }
            }}
          >
            <div className="bg-black border-2 border-green-500/50 rounded-2xl max-w-6xl max-h-[90vh] overflow-hidden font-mono w-full">
              {/* Modal Header */}
              <div className="bg-black/80 backdrop-blur-sm border-b border-green-500/30 p-4 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                  <h3 className="text-lg font-semibold text-green-400">
                    [ANALYSIS_DETAILS.EXE]
                  </h3>
                </div>
                <button 
                  onClick={closeModal}
                  className="text-red-400 hover:text-red-300 text-xl font-bold transition-colors w-8 h-8 flex items-center justify-center hover:bg-red-900/20 rounded"
                  aria-label="Close modal"
                >
                  ×
                </button>
              </div>

              {/* Modal Content */}
              <div className="p-6 overflow-y-auto max-h-[70vh]">
                {/* Analysis Timestamp */}
                <div className="mb-6">
                  <div className="text-cyan-400 text-sm mb-2">[ANALYSIS_TIMESTAMP]</div>
                  <div className="bg-black/50 border border-gray-700/30 p-3 text-green-400">
                    &gt; {formatTimestamp(selectedAnalysis.analysis_timestamp)}
                  </div>
                </div>

                {/* Processing Time */}
                <div className="mb-6">
                  <div className="text-cyan-400 text-sm mb-2">[PROCESSING_TIME_MS]</div>
                  <div className="bg-black/50 border border-gray-700/30 p-3 text-green-400">
                    &gt; {selectedAnalysis.processing_time_ms?.toFixed(2) || 'N/A'} ms
                  </div>
                </div>

                {/* Summary */}
                <div className="mb-6">
                  <div className="text-cyan-400 text-sm mb-2">[THREAT_SUMMARY.LOG]</div>
                  <div className="bg-black/50 border border-gray-700/30 p-4 text-green-400 whitespace-pre-wrap text-sm max-h-64 overflow-y-auto">
                    {selectedAnalysis.summary || 'No summary available'}
                  </div>
                </div>

                {/* Matched Techniques */}
                <div className="mb-6">
                  <div className="text-cyan-400 text-sm mb-2">[MITRE_TECHNIQUES.DB]</div>
                  <div className="space-y-3">
                    {Array.isArray(selectedAnalysis.matched_techniques) && selectedAnalysis.matched_techniques.length > 0 ? (
                      selectedAnalysis.matched_techniques.map((technique: any, index: number) => (
                        <div key={index} className="bg-black/50 border border-gray-700/30 p-4">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center space-x-3">
                              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                              <h4 className="text-red-400 font-semibold">
                                [{technique.technique_id}] {technique.name}
                              </h4>
                            </div>
                            <span className="text-xs px-2 py-1 border border-orange-500/30 text-orange-400">
                              {technique.tactic || 'UNKNOWN'}
                            </span>
                          </div>
                          {technique.description && (
                            <p className="text-gray-300 text-sm pl-5">
                              {technique.description}
                            </p>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="bg-black/50 border border-gray-700/30 p-4 text-gray-400 text-center">
                        No MITRE techniques identified
                      </div>
                    )}
                  </div>
                </div>

                {/* Modal Actions */}
                <div className="flex justify-end space-x-4 pt-4 border-t border-gray-700/30">
                  <button
                    onClick={closeModal}
                    className="px-4 py-2 bg-black border-2 border-gray-500 hover:border-gray-400 text-gray-400 hover:text-gray-300 font-medium transition-all duration-300 font-mono text-sm"
                  >
                    [CLOSE]
                  </button>
                  <button
                    onClick={() => {
                      console.log('Export analysis:', selectedAnalysis)
                      // In a real app, this would trigger an export function
                    }}
                    className="px-4 py-2 bg-black border-2 border-cyan-500 hover:border-cyan-400 text-cyan-400 hover:text-cyan-300 font-medium transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,255,0.5)] font-mono text-sm"
                  >
                    [EXPORT]
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default DashboardPage