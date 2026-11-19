'use client'
import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Navbar from '../../../components/navbar'
import Chatbot from '@/components/chatbot-simple';
import ThemedMitreSearch from '@/components/themed-mitre-search';

interface Technique {
  id: string;
  name: string;
  description: string;
  phase: string;
  platforms: string[];
}

const MitrePage = () => {
  const router = useRouter();
  const [selectedPhase, setSelectedPhase] = useState<string>('all');
  const [isVisible, setIsVisible] = useState(false);
  const [terminalText, setTerminalText] = useState('');
  const [showCursor, setShowCursor] = useState(true);
  const [isMobile, setIsMobile] = useState(false);
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalTechniques: 0,
    totalTactics: 0,
    totalPlatforms: 0
  });
  const [killChainPhases, setKillChainPhases] = useState([
    { id: 'all', name: 'ALL_PHASES', shortName: 'ALL', color: 'border-gray-500/50 text-gray-400', bgColor: 'bg-gray-900/30' }
  ]);

  const handleTechniqueClick = (technique: Technique) => {
    // Navigate to chat page with the technique as a pre-filled query
    const techniqueQuery = `Tell me about ${technique.id}: ${technique.name}`;
    router.push(`/chat?query=${encodeURIComponent(techniqueQuery)}`);
  };

  const fullTerminalText = '> MITRE_ATTACK.DB --LOAD_FRAMEWORK --MODE=ENTERPRISE';

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

  // Fetch MITRE data from backend
  useEffect(() => {
    const fetchMitreData = async () => {
      try {
        setLoading(true);
        const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
        
        const [techniquesRes, statsRes, tacticsRes, platformsRes] = await Promise.all([
          fetch(`${BACKEND_URL}/api/mitre/techniques?limit=200`),
          fetch(`${BACKEND_URL}/api/mitre/stats`),
          fetch(`${BACKEND_URL}/api/mitre/tactics`),
          fetch(`${BACKEND_URL}/api/mitre/platforms`)
        ]);

        if (techniquesRes.ok) {
          const techniquesData = await techniquesRes.json();
          setTechniques(techniquesData);
        }

        if (statsRes.ok) {
          const statsData = await statsRes.json();
          setStats(prev => ({ ...prev, totalTechniques: statsData.total_techniques }));
        }

        if (tacticsRes.ok) {
          const tacticsData = await tacticsRes.json();
          setStats(prev => ({ ...prev, totalTactics: tacticsData.length }));
          
          // Build dynamic kill chain phases
          const phases = [
            { id: 'all', name: 'ALL_PHASES', shortName: 'ALL', color: 'border-gray-500/50 text-gray-400', bgColor: 'bg-gray-900/30' },
            ...tacticsData.map((tactic: string, index: number) => ({
              id: tactic.toLowerCase().replace(/\s+/g, '-'),
              name: tactic.toUpperCase(),
              shortName: tactic.substring(0, 4).toUpperCase(),
              color: `border-${['red', 'orange', 'yellow', 'pink', 'purple', 'indigo', 'blue', 'cyan', 'teal', 'green', 'lime'][index % 11]}-500/50 text-${['red', 'orange', 'yellow', 'pink', 'purple', 'indigo', 'blue', 'cyan', 'teal', 'green', 'lime'][index % 11]}-400`,
              bgColor: `bg-${['red', 'orange', 'yellow', 'pink', 'purple', 'indigo', 'blue', 'cyan', 'teal', 'green', 'lime'][index % 11]}-900/30`
            }))
          ];
          setKillChainPhases(phases);
        }

        if (platformsRes.ok) {
          const platformsData = await platformsRes.json();
          setStats(prev => ({ ...prev, totalPlatforms: platformsData.length }));
        }
      } catch (error) {
        console.error('Error fetching MITRE data:', error);
        // Fallback to sample data if API fails
        setTechniques(sampleTechniques);
        setStats({
          totalTechniques: sampleTechniques.length,
          totalTactics: 12,
          totalPlatforms: 8
        });
      } finally {
        setLoading(false);
      }
    };

    fetchMitreData();
  }, []);

  const sampleTechniques: Technique[] = [
    {
      id: 'T1562.002',
      name: 'Disable Windows Event Logging',
      description: 'Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits.',
      phase: 'defense-evasion',
      platforms: ['Windows']
    },
    {
      id: 'T1654',
      name: 'Log Enumeration',
      description: 'Adversaries may enumerate system and service logs to find useful data.',
      phase: 'discovery',
      platforms: ['Linux', 'macOS', 'Windows', 'IaaS', 'ESXi']
    },
    {
      id: 'T1063',
      name: 'Security Software Discovery',
      description: 'Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors.',
      phase: 'discovery',
      platforms: ['macOS', 'Windows']
    },
    {
      id: 'T1070',
      name: 'Indicator Removal',
      description: 'Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.',
      phase: 'defense-evasion',
      platforms: ['Linux', 'macOS', 'Windows', 'Containers', 'Network Devices']
    }
  ];

  const filteredTechniques = selectedPhase === 'all' 
    ? techniques 
    : techniques.filter(tech => tech.phase === selectedPhase);

  const getPhaseStyle = (phaseId: string) => {
    const phase = killChainPhases.find(p => p.id === phaseId);
    return phase ? { color: phase.color, bgColor: phase.bgColor } : { color: 'border-gray-500/50 text-gray-400', bgColor: 'bg-gray-900/30' };
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
              <span className="ml-2 sm:ml-4 text-green-400 text-xs sm:text-sm">admin@logiq:~/mitre#</span>
            </div>
            <div className="text-green-400 text-xs sm:text-sm overflow-hidden">
              <div className="whitespace-nowrap overflow-hidden">
                {isMobile ? terminalText.slice(0, 35) + (terminalText.length > 35 ? '...' : '') : terminalText}
                {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
              </div>
            </div>
          </div>
          
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-green-400 mb-2 tracking-wider break-words">
            [MITRE_ATTACK_FRAMEWORK]
          </h1>
          <div className="text-cyan-400 text-xs sm:text-sm overflow-hidden">
            <div className="whitespace-nowrap overflow-x-auto">
              &gt; ADVERSARIAL_TACTICS.DB --TECHNIQUES=ENTERPRISE --PROCEDURES=ACTIVE
            </div>
          </div>
        </div>

        {/* Kill Chain Phase Filter */}
        <div className={`mb-6 sm:mb-8 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <h3 className="text-base sm:text-lg font-semibold mb-3 sm:mb-4 text-cyan-400 break-words">[KILL_CHAIN_FILTER.SYS]</h3>
          <div className="flex flex-wrap gap-2 sm:gap-3">
            {killChainPhases
            .filter((phase)=> phase.name != 'EXFILTRATION')
            .map((phase) => (
              <button
                key={phase.id}
                onClick={() => setSelectedPhase(phase.id)}
                className={`px-2 sm:px-3 md:px-4 py-1 sm:py-2 text-xs sm:text-sm font-medium transition-all duration-200 border hover:shadow-[0_0_10px_rgba(0,255,150,0.3)] whitespace-nowrap ${
                  selectedPhase === phase.id
                    ? `${phase.color} ${phase.bgColor} border-current shadow-[0_0_15px_rgba(0,255,150,0.4)]`
                    : 'bg-black/50 border-green-500/30 text-green-500 hover:text-green-400 hover:border-green-400'
                }`}
              >
                {
                  phase.name === 'EXFILTRATION' ? ' ':<span className="hidden sm:inline">&gt; {phase.name}</span>
                }
                <span className="sm:hidden">&gt; {phase.shortName}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Terminal Statistics */}
        <div className={`grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 mb-6 sm:mb-8 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[TOTAL_TECHNIQUES]</p>
                <p className="text-xl sm:text-2xl font-bold text-cyan-400">
                  {loading ? '...' : stats.totalTechniques}
                </p>
              </div>
              <div className="text-cyan-400 text-lg sm:text-xl">🛡️</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-3 sm:p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-400 text-xs">[KILL_CHAIN_PHASES]</p>
                <p className="text-xl sm:text-2xl font-bold text-purple-400">
                  {loading ? '...' : stats.totalTactics}
                </p>
              </div>
              <div className="text-purple-400 text-lg sm:text-xl">⚔️</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[PLATFORMS]</p>
                <p className="text-xl sm:text-2xl font-bold text-green-400">
                  {loading ? '...' : stats.totalPlatforms}
                </p>
              </div>
              <div className="text-green-400 text-lg sm:text-xl">💻</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-3 sm:p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-cyan-400 text-xs">[ACTIVE_FILTER]</p>
                <p className="text-xl sm:text-2xl font-bold text-cyan-400">{filteredTechniques.length}</p>
              </div>
              <div className="text-cyan-400 text-lg sm:text-xl">🔍</div>
            </div>
          </div>
        </div>

        {/* Terminal Techniques List */}
        <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 md:p-6 transform transition-all duration-1000 delay-600 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6 flex flex-col sm:flex-row items-start sm:items-center text-green-400 gap-2 sm:gap-0">
            <div className="flex items-center">
              <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
              <span className="break-words">[ATTACK_TECHNIQUES.DB]</span>
            </div>
            {selectedPhase !== 'all' && (
              <span className="ml-0 sm:ml-3 text-xs sm:text-sm text-cyan-400 break-words">
                --FILTER={killChainPhases.find(p => p.id === selectedPhase)?.name}
              </span>
            )}
          </h2>
          
          {loading ? (
            <div className="text-center py-8">
              <div className="w-12 h-12 mx-auto mb-4 bg-black border-2 border-green-500 flex items-center justify-center animate-spin">
                <span className="text-green-400">⟳</span>
              </div>
              <p className="text-green-400 font-mono">[LOADING_MITRE_DATA]</p>
            </div>
          ) : (
            <div className="space-y-3 sm:space-y-4">
              {filteredTechniques.map((technique) => {
              const phaseStyle = getPhaseStyle(technique.phase);
              return (
                <div 
                  key={technique.id} 
                  className="border border-gray-700/50 bg-black/50 p-3 sm:p-4 md:p-6 hover:border-cyan-500/50 transition-colors cursor-pointer"
                  onClick={() => handleTechniqueClick(technique)}
                >
                  <div className="flex flex-col sm:flex-row justify-between items-start mb-3 sm:mb-4 gap-3 sm:gap-0">
                    <div className="w-full">
                      <h3 className="text-base sm:text-lg font-semibold text-cyan-400 mb-2 break-words">
                        &gt; {technique.id}: {technique.name}
                      </h3>
                      <div className={`inline-block px-2 sm:px-3 py-1 text-xs font-medium border ${phaseStyle.color} ${phaseStyle.bgColor} break-words`}>
                        <span className="hidden sm:inline">[{killChainPhases.find(p => p.id === technique.phase)?.name || technique.phase.toUpperCase()}]</span>
                        <span className="sm:hidden">[{killChainPhases.find(p => p.id === technique.phase)?.shortName || technique.phase.toUpperCase()}]</span>
                      </div>
                    </div>
                  </div>
                  
                  <p className="text-gray-300 mb-3 sm:mb-4 leading-relaxed text-sm sm:text-base break-words">
                    {isMobile && technique.description.length > 150
                      ? `${technique.description.substring(0, 150)}...`
                      : technique.description
                    }
                  </p>
                  
                  <div className="flex flex-wrap gap-1 sm:gap-2">
                    <span className="text-xs sm:text-sm text-cyan-400 mr-1 sm:mr-2 font-mono flex-shrink-0">[PLATFORMS]:</span>
                    {technique.platforms.map((platform, index) => (
                      <span key={index} className="bg-gray-700/50 border border-gray-600/50 text-gray-300 px-1 sm:px-2 py-1 text-xs break-words">
                        {platform.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
              );
              })}
            </div>
          )}
          
          {!loading && filteredTechniques.length === 0 && (
            <div className="text-center py-8 sm:py-12">
              <div className="w-12 h-12 sm:w-16 sm:h-16 mx-auto mb-4 bg-black border-2 border-green-500 flex items-center justify-center">
                <span className="text-xl sm:text-2xl text-green-400">🔍</span>
              </div>
              <h3 className="text-base sm:text-lg font-semibold text-green-400 mb-2 font-mono break-words">[NO_TECHNIQUES_FOUND]</h3>
              <p className="text-gray-500 font-mono text-xs sm:text-sm break-words">
                &gt; Try selecting a different kill chain phase filter.
              </p>
            </div>
          )}
        </div>

        {/* AI-Powered MITRE Search Section */}
        <div className={`mt-8 sm:mt-12 transform transition-all duration-1000 delay-800 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="mb-6">
            <h2 className="text-xl sm:text-2xl font-bold text-cyan-400 mb-2 tracking-wider break-words font-mono">
              [AI_ENHANCED_THREAT_ANALYSIS.SYS]
            </h2>
            <div className="text-green-400 text-xs sm:text-sm overflow-hidden">
              <div className="whitespace-nowrap overflow-x-auto">
                &gt; AWS_TITAN_EMBEDDINGS --SEMANTIC_SEARCH --REAL_TIME_ANALYSIS
              </div>
            </div>
          </div>
          
          <ThemedMitreSearch isVisible={isVisible} />
        </div>

        {/* Floating ASCII elements - hidden on mobile for cleaner look */}
        <div className="hidden md:block absolute top-32 left-10 text-green-500/20 font-mono text-xs animate-pulse">
          {`{
  "framework": "mitre_attack",
  "version": "v16.1",
  "enterprise": true
}`}
        </div>
        
        <div className="hidden md:block absolute top-48 right-12 text-green-500/20 font-mono text-xs animate-pulse delay-1000">
          &gt; ./attack_navigator.exe
        </div>
        <Chatbot /> 
        <div className="hidden sm:block absolute bottom-32 left-16 text-green-500/20 font-mono text-xs animate-pulse delay-2000">
          [MITRE@FORENSIQ]#
        </div>
      </div>
    </div>
  )
}

export default MitrePage