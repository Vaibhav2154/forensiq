'use client'
import React, { useState, useEffect } from 'react'
import Navbar from '../../../components/navbar'

interface Technique {
  id: string;
  name: string;
  description: string;
  phase: string;
  platforms: string[];
}

const MitrePage = () => {
  const [selectedPhase, setSelectedPhase] = useState<string>('all');
  const [isVisible, setIsVisible] = useState(false);
  const [terminalText, setTerminalText] = useState('');
  const [showCursor, setShowCursor] = useState(true);

  const fullTerminalText = '> MITRE_ATTACK.DB --LOAD_FRAMEWORK --MODE=ENTERPRISE';

  useEffect(() => {
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
    };
  }, []);
  
  const killChainPhases = [
    { id: 'all', name: 'ALL_PHASES', color: 'border-gray-500/50 text-gray-400', bgColor: 'bg-gray-900/30' },
    { id: 'initial-access', name: 'INITIAL_ACCESS', color: 'border-red-500/50 text-red-400', bgColor: 'bg-red-900/30' },
    { id: 'execution', name: 'EXECUTION', color: 'border-orange-500/50 text-orange-400', bgColor: 'bg-orange-900/30' },
    { id: 'persistence', name: 'PERSISTENCE', color: 'border-yellow-500/50 text-yellow-400', bgColor: 'bg-yellow-900/30' },
    { id: 'privilege-escalation', name: 'PRIV_ESCALATION', color: 'border-pink-500/50 text-pink-400', bgColor: 'bg-pink-900/30' },
    { id: 'defense-evasion', name: 'DEFENSE_EVASION', color: 'border-purple-500/50 text-purple-400', bgColor: 'bg-purple-900/30' },
    { id: 'credential-access', name: 'CRED_ACCESS', color: 'border-indigo-500/50 text-indigo-400', bgColor: 'bg-indigo-900/30' },
    { id: 'discovery', name: 'DISCOVERY', color: 'border-blue-500/50 text-blue-400', bgColor: 'bg-blue-900/30' },
    { id: 'lateral-movement', name: 'LATERAL_MOVEMENT', color: 'border-cyan-500/50 text-cyan-400', bgColor: 'bg-cyan-900/30' },
    { id: 'collection', name: 'COLLECTION', color: 'border-teal-500/50 text-teal-400', bgColor: 'bg-teal-900/30' },
    { id: 'command-and-control', name: 'C2_COMMAND', color: 'border-green-500/50 text-green-400', bgColor: 'bg-green-900/30' },
    { id: 'exfiltration', name: 'EXFILTRATION', color: 'border-lime-500/50 text-lime-400', bgColor: 'bg-lime-900/30' },
    { id: 'impact', name: 'IMPACT', color: 'border-red-600/50 text-red-400', bgColor: 'bg-red-900/50' }
  ];

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
    ? sampleTechniques 
    : sampleTechniques.filter(tech => tech.phase === selectedPhase);

  const getPhaseStyle = (phaseId: string) => {
    const phase = killChainPhases.find(p => p.id === phaseId);
    return phase ? { color: phase.color, bgColor: phase.bgColor } : { color: 'border-gray-500/50 text-gray-400', bgColor: 'bg-gray-900/30' };
  };

  return (
    <div className='relative bg-black min-h-screen w-screen text-white overflow-hidden font-mono'>
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
      
      <div className="relative container mx-auto px-6 py-8">
        {/* Terminal Header */}
        <div className={`mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-3 mb-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="ml-4 text-green-400 text-sm">admin@forensiq:~/mitre#</span>
            </div>
            <div className="text-green-400 text-sm">
              {terminalText}
              {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
            </div>
          </div>
          
          <h1 className="text-4xl font-bold text-green-400 mb-2 tracking-wider">
            [MITRE_ATTACK_FRAMEWORK]
          </h1>
          <p className="text-cyan-400">&gt; ADVERSARIAL_TACTICS.DB --TECHNIQUES=ENTERPRISE --PROCEDURES=ACTIVE</p>
        </div>

        {/* Kill Chain Phase Filter */}
        <div className={`mb-8 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <h3 className="text-lg font-semibold mb-4 text-cyan-400">[KILL_CHAIN_FILTER.SYS]</h3>
          <div className="flex flex-wrap gap-3">
            {killChainPhases.map((phase) => (
              <button
                key={phase.id}
                onClick={() => setSelectedPhase(phase.id)}
                className={`px-4 py-2 text-sm font-medium transition-all duration-200 border hover:shadow-[0_0_10px_rgba(0,255,150,0.3)] ${
                  selectedPhase === phase.id
                    ? `${phase.color} ${phase.bgColor} border-current shadow-[0_0_15px_rgba(0,255,150,0.4)]`
                    : 'bg-black/50 border-green-500/30 text-green-500 hover:text-green-400 hover:border-green-400'
                }`}
              >
                &gt; {phase.name}
              </button>
            ))}
          </div>
        </div>
      

        {/* Terminal Statistics */}
        <div className={`grid grid-cols-1 md:grid-cols-4 gap-4 mb-8 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[TOTAL_TECHNIQUES]</p>
                <p className="text-2xl font-bold text-cyan-400">{sampleTechniques.length}</p>
              </div>
              <div className="text-cyan-400 text-xl">🛡️</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-400 text-xs">[KILL_CHAIN_PHASES]</p>
                <p className="text-2xl font-bold text-purple-400">{killChainPhases.length - 1}</p>
              </div>
              <div className="text-purple-400 text-xl">⚔️</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[PLATFORMS]</p>
                <p className="text-2xl font-bold text-green-400">8</p>
              </div>
              <div className="text-green-400 text-xl">💻</div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-cyan-400 text-xs">[ACTIVE_FILTER]</p>
                <p className="text-2xl font-bold text-cyan-400">{filteredTechniques.length}</p>
              </div>
              <div className="text-cyan-400 text-xl">🔍</div>
            </div>
          </div>
        </div>

        {/* Terminal Techniques List */}
        <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 p-6 transform transition-all duration-1000 delay-600 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <h2 className="text-xl font-semibold mb-6 flex items-center text-green-400">
            <span className="w-2 h-2 bg-green-500 rounded-full mr-3 animate-pulse"></span>
            [ATTACK_TECHNIQUES.DB]
            {selectedPhase !== 'all' && (
              <span className="ml-3 text-sm text-cyan-400">
                --FILTER={killChainPhases.find(p => p.id === selectedPhase)?.name}
              </span>
            )}
          </h2>
          
          <div className="space-y-4">
            {filteredTechniques.map((technique) => {
              const phaseStyle = getPhaseStyle(technique.phase);
              return (
                <div key={technique.id} className="border border-gray-700/50 bg-black/50 p-6 hover:border-cyan-500/50 transition-colors">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-cyan-400 mb-2">
                        &gt; {technique.id}: {technique.name}
                      </h3>
                      <div className={`inline-block px-3 py-1 text-xs font-medium border ${phaseStyle.color} ${phaseStyle.bgColor}`}>
                        [{killChainPhases.find(p => p.id === technique.phase)?.name || technique.phase.toUpperCase()}]
                      </div>
                    </div>
                  </div>
                  
                  <p className="text-gray-300 mb-4 leading-relaxed">
                    {technique.description}
                  </p>
                  
                  <div className="flex flex-wrap gap-2">
                    <span className="text-sm text-cyan-400 mr-2 font-mono">[PLATFORMS]:</span>
                    {technique.platforms.map((platform, index) => (
                      <span key={index} className="bg-gray-700/50 border border-gray-600/50 text-gray-300 px-2 py-1 text-sm">
                        {platform.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
          
          {filteredTechniques.length === 0 && (
            <div className="text-center py-12">
              <div className="w-16 h-16 mx-auto mb-4 bg-black border-2 border-green-500 flex items-center justify-center">
                <span className="text-2xl text-green-400">🔍</span>
              </div>
              <h3 className="text-lg font-semibold text-green-400 mb-2 font-mono">[NO_TECHNIQUES_FOUND]</h3>
              <p className="text-gray-500 font-mono">&gt; Try selecting a different kill chain phase filter.</p>
            </div>
          )}
        </div>

        {/* Floating ASCII elements */}
        <div className="absolute top-32 left-10 text-green-500/20 font-mono text-xs animate-pulse">
          {`{
  "framework": "mitre_attack",
  "version": "v16.1",
  "enterprise": true
}`}
        </div>
        
        <div className="absolute top-48 right-12 text-green-500/20 font-mono text-xs animate-pulse delay-1000">
          &gt; ./attack_navigator.exe
        </div>
        
        <div className="absolute bottom-32 left-16 text-green-500/20 font-mono text-xs animate-pulse delay-2000">
          [MITRE@FORENSIQ]#
        </div>
      </div>
    </div>
  )
}

export default MitrePage
