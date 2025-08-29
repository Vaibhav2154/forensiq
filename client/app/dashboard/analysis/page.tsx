'use client'
import React, { useState, useEffect } from 'react'
import Navbar from '../../../components/navbar'

interface ThreatTechnique {
  technique_id: string;
  name: string;
  description: string;
  kill_chain_phases: string[];
  platforms: string[];
  relevance_score: number;
}

interface AnalysisResponse {
  summary: string;
  matched_techniques: ThreatTechnique[];
  enhanced_analysis: string;
  analysis_timestamp: string;
  processing_time_ms: number;
}

const AnalysisPage = () => {
  const [logs, setLogs] = useState('');
  const [enhanceWithAI, setEnhanceWithAI] = useState(true);
  const [maxResults, setMaxResults] = useState(5);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [terminalText, setTerminalText] = useState('');
  const [showCursor, setShowCursor] = useState(true);
  const [isMobile, setIsMobile] = useState(false);

  const fullTerminalText = '> LOG_ANALYZER.EXE --MODE=THREAT_DETECTION --FRAMEWORK=MITRE';

  useEffect(() => {
    // Check if mobile on mount
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

  const handleAnalysis = async () => {
    if (!logs.trim()) {
      setError('Please enter logs to analyze');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8000/api/v1/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          logs: logs,
          enhance_with_ai: enhanceWithAI,
          max_results: maxResults
        })
      });

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`);
      }

      const result: AnalysisResponse = await response.json();
      setAnalysis(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze logs');
    } finally {
      setLoading(false);
    }
  };

  const formatMarkdown = (text: string) => {
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/#{1,6}\s(.*?)$/gm, '<h3 class="text-base sm:text-lg font-bold mt-4 mb-2 text-blue-400">$1</h3>')
      .replace(/^\* (.*?)$/gm, '<li class="ml-4 mb-1">• $1</li>')
      .replace(/\n\n/g, '<br/><br/>');
  };

  const getThreatLevelColor = (score: number) => {
    if (score >= 0.7) return 'bg-red-500/20 text-red-400 border-red-500/50';
    if (score >= 0.5) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
    return 'bg-green-500/20 text-green-400 border-green-500/50';
  };

  const getPhaseColor = (phase: string) => {
    const colors: { [key: string]: string } = {
      'initial-access': 'bg-red-900/30 text-red-400 border-red-500/30',
      'execution': 'bg-orange-900/30 text-orange-400 border-orange-500/30',
      'persistence': 'bg-yellow-900/30 text-yellow-400 border-yellow-500/30',
      'privilege-escalation': 'bg-pink-900/30 text-pink-400 border-pink-500/30',
      'defense-evasion': 'bg-purple-900/30 text-purple-400 border-purple-500/30',
      'credential-access': 'bg-indigo-900/30 text-indigo-400 border-indigo-500/30',
      'discovery': 'bg-blue-900/30 text-blue-400 border-blue-500/30',
      'lateral-movement': 'bg-cyan-900/30 text-cyan-400 border-cyan-500/30',
      'collection': 'bg-teal-900/30 text-teal-400 border-teal-500/30',
      'command-and-control': 'bg-green-900/30 text-green-400 border-green-500/30',
      'exfiltration': 'bg-lime-900/30 text-lime-400 border-lime-500/30',
      'impact': 'bg-red-900/50 text-red-400 border-red-500/50'
    };
    return colors[phase] || 'bg-gray-900/30 text-gray-400 border-gray-500/30';
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
      
      <Navbar />
      
      <div className="relative container mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 md:py-8 max-w-full">
        {/* Terminal Header */}
        <div className={`mb-6 sm:mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-2 sm:p-3 mb-4 overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-red-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-yellow-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-green-500"></div>
              <span className="ml-2 sm:ml-4 text-green-400 text-xs sm:text-sm">admin@forensiq:~/analysis#</span>
            </div>
            <div className="text-green-400 text-xs sm:text-sm overflow-hidden">
              <div className="whitespace-nowrap overflow-hidden">
                {isMobile ? terminalText.slice(0, 30) + (terminalText.length > 30 ? '...' : '') : terminalText}
                {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
              </div>
            </div>
          </div>
          
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-green-400 mb-2 tracking-wider break-words">
            [LOG_ANALYSIS_PLATFORM]
          </h1>
          <div className="text-cyan-400 text-xs sm:text-sm overflow-hidden">
            <div className="whitespace-nowrap overflow-x-auto">
              &gt; AI_THREAT_DETECTION.SYS --FRAMEWORK=MITRE_ATTACK
            </div>
          </div>
        </div>

        <div className={`flex flex-col lg:grid lg:grid-cols-3 gap-4 sm:gap-6 md:gap-8 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {/* Input Panel */}
          <div className="w-full lg:col-span-1 order-1 lg:order-none">
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 md:p-6 w-full">
              <h2 className="text-lg sm:text-xl font-semibold mb-3 sm:mb-4 flex items-center text-green-400 break-words">
                <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
                <span className="text-sm sm:text-base">[ANALYSIS_CONFIG.SYS]</span>
              </h2>
              
              <div className="space-y-3 sm:space-y-4">
                <div>
                  <label className="block text-xs sm:text-sm font-medium text-cyan-400 mb-2">
                    &gt; LOG_DATA_INPUT:
                  </label>
                  <textarea
                    value={logs}
                    onChange={(e) => setLogs(e.target.value)}
                    placeholder="// Enter your log data here...
// Example: System break out
// Failed login attempts detected
// Suspicious network activity..."
                    className="w-full h-32 sm:h-40 bg-black/70 border border-green-500/30 p-2 sm:p-3 text-green-400 placeholder-green-600/50 focus:ring-2 focus:ring-cyan-500 focus:border-cyan-400 resize-none text-xs sm:text-sm hover:border-green-400 transition-colors"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <label className="text-xs sm:text-sm font-medium text-cyan-400">
                    [AI_ENHANCEMENT]: 
                  </label>
                  <button
                    onClick={() => setEnhanceWithAI(!enhanceWithAI)}
                    className={`relative inline-flex h-5 w-9 sm:h-6 sm:w-11 items-center border transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
                      enhanceWithAI ? 'bg-green-600/30 border-green-400' : 'bg-gray-900/50 border-gray-600'
                    }`}
                  >
                    <span className={`inline-block h-3 w-3 sm:h-4 sm:w-4 transform bg-green-400 transition-transform ${
                      enhanceWithAI ? 'translate-x-5 sm:translate-x-6' : 'translate-x-1'
                    }`} />
                  </button>
                </div>

                <div>
                  <label className="block text-xs sm:text-sm font-medium text-cyan-400 mb-2">
                    [MAX_RESULTS]: {maxResults}
                  </label>
                  <input
                    type="range"
                    min="1"
                    max="20"
                    value={maxResults}
                    onChange={(e) => setMaxResults(parseInt(e.target.value))}
                    className="w-full h-2 bg-gray-900 border border-green-500/30 appearance-none cursor-pointer slider"
                  />
                </div>

                <button
                  onClick={handleAnalysis}
                  disabled={loading || !logs.trim()}
                  className="w-full bg-black border-2 border-green-500 hover:border-cyan-400 disabled:border-gray-600 disabled:cursor-not-allowed text-green-400 hover:text-cyan-400 disabled:text-gray-600 font-medium py-2 sm:py-3 px-3 sm:px-4 transition-all duration-300 flex items-center justify-center hover:shadow-[0_0_20px_rgba(0,255,150,0.3)] text-xs sm:text-sm"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 sm:h-5 sm:w-5 border-b-2 border-cyan-400 mr-2"></div>
                      <span className="hidden sm:inline">[ANALYZING...]</span>
                      <span className="sm:hidden">[ANALYZING]</span>
                    </>
                  ) : (
                    <>
                      <span className="hidden sm:inline">&gt; EXECUTE_ANALYSIS.EXE</span>
                      <span className="sm:hidden">&gt; ANALYZE</span>
                    </>
                  )}
                </button>

                {error && (
                  <div className="bg-red-900/30 border border-red-500/50 p-2 sm:p-3 text-red-400 text-xs sm:text-sm break-words">
                    [ERROR]: {error}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Results Panel */}
          <div className="w-full lg:col-span-2 order-2 lg:order-none">
            {analysis ? (
              <div className="space-y-4 sm:space-y-6">
                {/* Header */}
                <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-3 sm:p-4 md:p-6">
                  <div className="flex flex-col sm:flex-row justify-between items-start mb-4 gap-3 sm:gap-0">
                    <h2 className="text-lg sm:text-xl font-semibold text-cyan-400 break-words">[ANALYSIS_RESULTS.LOG]</h2>
                    <div className="text-left sm:text-right text-xs sm:text-sm text-green-400 font-mono">
                      <div>[PROCESSED_IN]: {(analysis.processing_time_ms / 1000).toFixed(2)}s</div>
                      <div className="break-all">[TIMESTAMP]: {new Date(analysis.analysis_timestamp).toLocaleString()}</div>
                    </div>
                  </div>
                  
                  <div className="flex flex-wrap items-center gap-2 sm:space-x-4">
                    <div className="bg-cyan-900/30 border border-cyan-500/30 px-2 sm:px-3 py-1 text-cyan-400 text-xs sm:text-sm">
                      [{analysis.matched_techniques.length}_TECHNIQUES_FOUND]
                    </div>
                    <div className="bg-green-900/30 border border-green-500/30 px-2 sm:px-3 py-1 text-green-400 text-xs sm:text-sm">
                      [STATUS: COMPLETE]
                    </div>
                  </div>
                </div>

                {/* Summary */}
                <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 md:p-6">
                  <h3 className="text-base sm:text-lg font-semibold mb-3 sm:mb-4 flex items-center text-green-400">
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
                    <span className="break-words text-sm sm:text-base">[EXECUTIVE_SUMMARY.TXT]</span>
                  </h3>
                  <div 
                    className="prose prose-invert max-w-none text-gray-300 leading-relaxed text-sm sm:text-base"
                    dangerouslySetInnerHTML={{ __html: formatMarkdown(analysis.summary) }}
                  />
                </div>

                {/* MITRE ATT&CK Techniques */}
                <div className="bg-black/80 backdrop-blur-sm border border-red-500/30 p-3 sm:p-4 md:p-6">
                  <h3 className="text-base sm:text-lg font-semibold mb-3 sm:mb-4 flex items-center text-red-400">
                    <span className="w-2 h-2 bg-red-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
                    <span className="break-words text-sm sm:text-base">[MITRE_ATTACK_TECHNIQUES.DB]</span>
                  </h3>
                  
                  <div className="space-y-3 sm:space-y-4">
                    {analysis.matched_techniques.map((technique, index) => (
                      <div key={index} className="border border-gray-700/50 bg-black/50 p-3 sm:p-4 hover:border-cyan-500/50 transition-colors">
                        <div className="flex flex-col sm:flex-row justify-between items-start mb-3 gap-2">
                          <div className="w-full">
                            <h4 className="font-semibold text-cyan-400 font-mono text-sm sm:text-base break-words">
                              &gt; {technique.technique_id}: {technique.name}
                            </h4>
                            <div className={`inline-block px-2 py-1 text-xs font-medium border mt-2 ${getThreatLevelColor(technique.relevance_score)}`}>
                              [RELEVANCE: {(technique.relevance_score * 100).toFixed(1)}%]
                            </div>
                          </div>
                        </div>
                        
                        <p className="text-gray-300 text-xs sm:text-sm mb-3 leading-relaxed break-words">
                          {technique.description.length > (isMobile ? 200 : 300)
                            ? `${technique.description.substring(0, isMobile ? 200 : 300)}...` 
                            : technique.description
                          }
                        </p>
                        
                        <div className="flex flex-wrap gap-1 sm:gap-2 mb-2">
                          <span className="text-xs text-cyan-400 font-mono flex-shrink-0">[KILL_CHAIN]:</span>
                          {technique.kill_chain_phases.map((phase, i) => (
                            <span key={i} className={`px-1 sm:px-2 py-1 text-xs font-medium border ${getPhaseColor(phase)} break-words`}>
                              {phase.replace('-', '_').toUpperCase()}
                            </span>
                          ))}
                        </div>
                        
                        <div className="flex flex-wrap gap-1 sm:gap-2">
                          <span className="text-xs text-cyan-400 font-mono flex-shrink-0">[PLATFORMS]:</span>
                          {technique.platforms.map((platform, i) => (
                            <span key={i} className="bg-gray-700/50 border border-gray-600/50 text-gray-300 px-1 sm:px-2 py-1 text-xs">
                              {platform.toUpperCase()}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Enhanced Analysis */}
                {enhanceWithAI && analysis.enhanced_analysis && (
                  <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-3 sm:p-4 md:p-6">
                    <h3 className="text-base sm:text-lg font-semibold mb-3 sm:mb-4 flex items-center text-purple-400">
                      <span className="w-2 h-2 bg-purple-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
                      <span className="break-words text-sm sm:text-base">[AI_ENHANCED_THREAT_ANALYSIS.AI]</span>
                    </h3>
                    <div 
                      className="prose prose-invert max-w-none text-gray-300 leading-relaxed text-sm sm:text-base"
                      dangerouslySetInnerHTML={{ __html: formatMarkdown(analysis.enhanced_analysis) }}
                    />
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-6 sm:p-8 md:p-12 text-center">
                <div className="w-12 h-12 sm:w-16 sm:h-16 mx-auto mb-4 bg-black border-2 border-green-500 flex items-center justify-center">
                  <svg className="w-6 h-6 sm:w-8 sm:h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <h3 className="text-lg sm:text-xl font-semibold text-green-400 mb-2 font-mono break-words">[ANALYSIS_ENGINE_READY]</h3>
                <p className="text-gray-500 font-mono text-xs sm:text-sm break-words">
                  &gt; Enter log data and execute analysis to begin threat detection.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Floating ASCII elements - hidden on mobile for cleaner look */}
        <div className="hidden md:block absolute top-32 left-10 text-green-500/20 font-mono text-xs animate-pulse">
          {`{
  "mode": "analysis",
  "ai_engine": "active",
  "framework": "mitre_attack"
}`}
        </div>
        
        <div className="hidden md:block absolute top-48 right-12 text-green-500/20 font-mono text-xs animate-pulse delay-1000">
          &gt; ./threat_detector.exe --verbose
        </div>
        
        <div className="hidden sm:block absolute bottom-32 left-16 text-green-500/20 font-mono text-xs animate-pulse delay-2000">
          [ANALYSIS@FORENSIQ]#
        </div>
      </div>

      <style jsx>{`
        .slider::-webkit-slider-thumb {
          appearance: none;
          height: 14px;
          width: 14px;
          background: #00ff96;
          cursor: pointer;
          border: 2px solid #00ff96;
        }
        
        @media (min-width: 640px) {
          .slider::-webkit-slider-thumb {
            height: 16px;
            width: 16px;
          }
        }
        
        .slider::-moz-range-thumb {
          height: 14px;
          width: 14px;
          background: #00ff96;
          cursor: pointer;
          border: 2px solid #00ff96;
        }
        
        @media (min-width: 640px) {
          .slider::-moz-range-thumb {
            height: 16px;
            width: 16px;
          }
        }

        .prose h3 {
          color: #22d3ee !important;
          font-family: monospace !important;
        }

        .prose strong {
          color: #00ff96 !important;
        }

        .prose em {
          color: #a78bfa !important;
        }

        .prose li {
          color: #d1d5db !important;
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

export default AnalysisPage