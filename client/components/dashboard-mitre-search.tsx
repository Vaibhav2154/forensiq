'use client';

import React, { useState, useEffect } from 'react';
const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
import { Search, AlertTriangle, Shield, Cpu, Server, Loader2, ExternalLink, BarChart3, TrendingUp, Users } from 'lucide-react';

interface MitreTechnique {
  technique_id: string;
  name: string;
  description: string;
  kill_chain_phases: string[];
  platforms: string[];
  relevance_score: number;
  embedding_model: string;
}

interface MitreSearchResponse {
  query: string;
  relevant_techniques: MitreTechnique[];
  summary: string;
  context: string;
  embedding_model: string;
  total_techniques: number;
  top_match?: {
    technique_id: string;
    name: string;
    relevance_score: number;
    description: string;
  };
  common_tactics?: string[];
  common_platforms?: string[];
}

interface MitreStats {
  total_techniques: number;
  collection_name: string;
  embedding_model: string;
  embedding_dimension: number;
}

const DashboardMitreSearch: React.FC = () => {
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [searchResults, setSearchResults] = useState<MitreSearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [maxResults, setMaxResults] = useState(5);
  const [stats, setStats] = useState<MitreStats | null>(null);
  const [tactics, setTactics] = useState<string[]>([]);
  const [platforms, setPlatforms] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<'search' | 'explore' | 'stats'>('search');
  const [isVisible, setIsVisible] = useState(false);
  const [terminalText, setTerminalText] = useState('');
  const [showCursor, setShowCursor] = useState(true);

  const fullTerminalText = '> MITRE_ATTACK_FRAMEWORK.DB --MODE=ACTIVE --AI=TITAN_V2';

  useEffect(() => {
    setIsVisible(true);
    fetchInitialData();
    
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

  const fetchInitialData = async () => {
    try {
      const [statsRes, tacticsRes, platformsRes] = await Promise.all([
        fetch(`${BACKEND_URL}/api/mitre/stats`),
        fetch(`${BACKEND_URL}/api/mitre/tactics`),
        fetch(`${BACKEND_URL}/api/mitre/platforms`)
      ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      if (tacticsRes.ok) {
        const tacticsData = await tacticsRes.json();
        setTactics(tacticsData);
      }

      if (platformsRes.ok) {
        const platformsData = await platformsRes.json();
        setPlatforms(platformsData);
      }
    } catch (error) {
      console.error('Error fetching MITRE data:', error);
    }
  };

  const handleSearch = async () => {
    if (!query.trim()) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
  const response = await fetch(`${BACKEND_URL}/api/mitre/search?q=${encodeURIComponent(query)}&max_results=${maxResults}`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data: MitreSearchResponse = await response.json();
      setSearchResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred while searching');
      setSearchResults(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const getTacticColor = (tactic: string) => {
    const colors: { [key: string]: string } = {
      'initial-access': 'border-red-500/30 text-red-400 bg-red-500/10',
      'execution': 'border-orange-500/30 text-orange-400 bg-orange-500/10',
      'persistence': 'border-yellow-500/30 text-yellow-400 bg-yellow-500/10',
      'privilege-escalation': 'border-green-500/30 text-green-400 bg-green-500/10',
      'defense-evasion': 'border-blue-500/30 text-blue-400 bg-blue-500/10',
      'credential-access': 'border-indigo-500/30 text-indigo-400 bg-indigo-500/10',
      'discovery': 'border-purple-500/30 text-purple-400 bg-purple-500/10',
      'lateral-movement': 'border-pink-500/30 text-pink-400 bg-pink-500/10',
      'collection': 'border-gray-500/30 text-gray-400 bg-gray-500/10',
      'command-and-control': 'border-cyan-500/30 text-cyan-400 bg-cyan-500/10',
      'exfiltration': 'border-teal-500/30 text-teal-400 bg-teal-500/10',
      'impact': 'border-rose-500/30 text-rose-400 bg-rose-500/10',
    };
    return colors[tactic] || 'border-gray-500/30 text-gray-400 bg-gray-500/10';
  };

  const getPlatformIcon = (platform: string) => {
    if (platform.toLowerCase().includes('windows')) return <Server className="w-4 h-4" />;
    if (platform.toLowerCase().includes('linux')) return <Cpu className="w-4 h-4" />;
    if (platform.toLowerCase().includes('macos')) return <Shield className="w-4 h-4" />;
    return <AlertTriangle className="w-4 h-4" />;
  };

  return (
    <div className="relative bg-black min-h-screen w-full text-white overflow-x-hidden">
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
      
      <div className="relative container mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 md:py-8 font-mono max-w-full">
        {/* Terminal Header */}
        <div className={`mb-6 sm:mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-2 sm:p-3 mb-4 overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-red-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-yellow-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-green-500"></div>
              <span className="ml-2 sm:ml-4 text-green-400 text-xs sm:text-sm">admin@forensiq:~/mitre#</span>
            </div>
            <div className="text-green-400 text-xs sm:text-sm overflow-hidden">
              <div className="whitespace-nowrap overflow-hidden">
                {terminalText}
                {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
              </div>
            </div>
          </div>
          
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-green-400 mb-2 tracking-wider break-words flex items-center gap-3">
            <Shield className="w-8 h-8 text-cyan-400" />
            [MITRE_ATT&CK_FRAMEWORK]
          </h1>
          <div className="text-cyan-400 text-xs sm:text-sm overflow-hidden">
            <div className="whitespace-nowrap overflow-x-auto">
              &gt; AI_POWERED_THREAT_INTELLIGENCE --EMBEDDING=AWS_TITAN_V2 --STATUS=OPERATIONAL
            </div>
          </div>
        </div>

        {/* Stats Overview */}
        {stats && (
          <div className={`grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 mb-6 sm:mb-8 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-green-400 text-xs">[TOTAL_TECHNIQUES]</p>
                  <p className="text-xl sm:text-2xl font-bold text-cyan-400">{stats.total_techniques}</p>
                </div>
                <BarChart3 className="w-6 h-6 text-cyan-400" />
              </div>
            </div>
            
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-green-400 text-xs">[TACTICS]</p>
                  <p className="text-xl sm:text-2xl font-bold text-green-400">{tactics.length}</p>
                </div>
                <Shield className="w-6 h-6 text-green-400" />
              </div>
            </div>
            
            <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-3 sm:p-4 font-mono">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-purple-400 text-xs">[PLATFORMS]</p>
                  <p className="text-xl sm:text-2xl font-bold text-purple-400">{platforms.length}</p>
                </div>
                <Server className="w-6 h-6 text-purple-400" />
              </div>
            </div>
            
            <div className="bg-black/80 backdrop-blur-sm border border-orange-500/30 p-3 sm:p-4 font-mono">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-orange-400 text-xs">[AI_MODEL]</p>
                  <p className="text-sm font-bold text-orange-400">TITAN_V2</p>
                  <p className="text-xs text-gray-400">{stats.embedding_dimension}D</p>
                </div>
                <TrendingUp className="w-6 h-6 text-orange-400" />
              </div>
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-lg mb-6 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="border-b border-green-500/20">
            <nav className="-mb-px flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab('search')}
                className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'search'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-green-400 hover:border-green-500/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Search className="w-4 h-4" />
                  [AI_SEARCH]
                </div>
              </button>
              <button
                onClick={() => setActiveTab('explore')}
                className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'explore'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-green-400 hover:border-green-500/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  [FRAMEWORK]
                </div>
              </button>
              <button
                onClick={() => setActiveTab('stats')}
                className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'stats'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-green-400 hover:border-green-500/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-4 h-4" />
                  [STATISTICS]
                </div>
              </button>
            </nav>
          </div>

          <div className="p-6">
            {/* Search Tab */}
            {activeTab === 'search' && (
              <div className="space-y-6">
                {/* Search Interface */}
                <div className="space-y-4">
                  <div className="flex gap-4 flex-wrap">
                    <div className="flex-1 min-w-0">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-green-400 w-5 h-5" />
                        <input
                          type="text"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                          onKeyPress={handleKeyPress}
                          placeholder="Enter threat query (e.g., 'credential dumping', 'lateral movement')"
                          className="w-full pl-10 pr-4 py-3 bg-black/60 border border-green-500/30 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 text-green-400 placeholder-gray-500 font-mono"
                        />
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <label className="text-sm text-green-400 font-mono">[RESULTS]:</label>
                      <select
                        value={maxResults}
                        onChange={(e) => setMaxResults(Number(e.target.value))}
                        className="bg-black/60 border border-green-500/30 rounded px-3 py-2 text-sm text-green-400 font-mono focus:ring-2 focus:ring-cyan-500"
                      >
                        <option value={3}>3</option>
                        <option value={5}>5</option>
                        <option value={10}>10</option>
                        <option value={15}>15</option>
                      </select>
                    </div>
                    <button
                      onClick={handleSearch}
                      disabled={isLoading || !query.trim()}
                      className="px-6 py-3 bg-green-600/20 border border-green-500/50 text-green-400 rounded-lg hover:bg-green-600/30 hover:border-green-400 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-all font-mono"
                    >
                      {isLoading ? (
                        <Loader2 className="w-5 h-5 animate-spin" />
                      ) : (
                        <Search className="w-5 h-5" />
                      )}
                      [EXECUTE]
                    </button>
                  </div>
                </div>

                {/* Error Display */}
                {error && (
                  <div className="bg-red-900/30 border border-red-500/30 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-red-400">
                      <AlertTriangle className="w-5 h-5" />
                      <span className="font-medium font-mono">[ERROR_DETECTED]:</span>
                    </div>
                    <p className="text-red-300 mt-1 font-mono text-sm">{error}</p>
                  </div>
                )}

                {/* Search Results */}
                {searchResults && (
                  <div className="space-y-6">
                    {/* Summary */}
                    <div className="bg-cyan-900/20 border border-cyan-500/30 rounded-lg p-4">
                      <h3 className="font-semibold text-cyan-400 mb-2 font-mono">[SEARCH_SUMMARY]</h3>
                      <p className="text-cyan-300 font-mono text-sm">{searchResults.summary}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-cyan-400 font-mono">
                        <span>MODEL: {searchResults.embedding_model}</span>
                        <span>RESULTS: {searchResults.total_techniques}</span>
                      </div>
                    </div>

                    {/* Top Match Highlight */}
                    {searchResults.top_match && (
                      <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
                        <h3 className="font-semibold text-green-400 mb-2 flex items-center gap-2 font-mono">
                          <AlertTriangle className="w-5 h-5" />
                          [BEST_MATCH]
                        </h3>
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-green-300 font-mono">
                            {searchResults.top_match.name} ({searchResults.top_match.technique_id})
                          </span>
                          <span className="bg-green-500/20 text-green-400 px-2 py-1 rounded text-sm font-mono border border-green-500/30">
                            {(searchResults.top_match.relevance_score * 100).toFixed(1)}%
                          </span>
                        </div>
                        <p className="text-green-200 text-sm font-mono">{searchResults.top_match.description}</p>
                      </div>
                    )}

                    {/* Common Tactics and Platforms */}
                    {(searchResults.common_tactics || searchResults.common_platforms) && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {searchResults.common_tactics && (
                          <div className="bg-black/60 border border-gray-500/30 rounded-lg p-4">
                            <h4 className="font-semibold text-gray-300 mb-2 font-mono">[COMMON_TACTICS]</h4>
                            <div className="flex flex-wrap gap-2">
                              {searchResults.common_tactics.map((tactic, index) => (
                                <span
                                  key={index}
                                  className={`px-2 py-1 rounded text-xs font-medium font-mono border ${getTacticColor(tactic)}`}
                                >
                                  {tactic.replace('-', '_').toUpperCase()}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        {searchResults.common_platforms && (
                          <div className="bg-black/60 border border-gray-500/30 rounded-lg p-4">
                            <h4 className="font-semibold text-gray-300 mb-2 font-mono">[COMMON_PLATFORMS]</h4>
                            <div className="flex flex-wrap gap-2">
                              {searchResults.common_platforms.map((platform, index) => (
                                <span
                                  key={index}
                                  className="flex items-center gap-1 px-2 py-1 bg-gray-500/20 text-gray-300 rounded text-xs font-medium font-mono border border-gray-500/30"
                                >
                                  {getPlatformIcon(platform)}
                                  {platform.toUpperCase()}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Detailed Results */}
                    <div>
                      <h3 className="font-semibold text-green-400 mb-4 font-mono">[DETAILED_RESULTS]</h3>
                      <div className="space-y-4">
                        {searchResults.relevant_techniques.map((technique, index) => (
                          <div key={index} className="bg-black/60 border border-green-500/30 rounded-lg p-4 hover:border-cyan-500/50 transition-all">
                            <div className="flex items-start justify-between mb-3">
                              <div className="flex-1">
                                <h4 className="font-semibold text-green-300 mb-1 flex items-center gap-2 font-mono">
                                  {technique.name}
                                  <span className="bg-gray-500/20 text-gray-300 px-2 py-1 rounded text-sm font-normal border border-gray-500/30">
                                    {technique.technique_id}
                                  </span>
                                  <a
                                    href={`https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-cyan-400 hover:text-cyan-300"
                                  >
                                    <ExternalLink className="w-4 h-4" />
                                  </a>
                                </h4>
                                <p className="text-gray-300 text-sm mb-3 font-mono">
                                  {technique.description.length > 200
                                    ? `${technique.description.substring(0, 200)}...`
                                    : technique.description}
                                </p>
                              </div>
                              <div className="text-right">
                                <span className="bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded text-sm font-medium font-mono border border-cyan-500/30">
                                  {(technique.relevance_score * 100).toFixed(1)}%
                                </span>
                              </div>
                            </div>

                            <div className="flex flex-wrap gap-4 text-sm">
                              {technique.kill_chain_phases.length > 0 && (
                                <div>
                                  <span className="font-medium text-green-400 font-mono">TACTICS: </span>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {technique.kill_chain_phases.map((tactic, tacticIndex) => (
                                      <span
                                        key={tacticIndex}
                                        className={`px-2 py-1 rounded text-xs font-medium font-mono border ${getTacticColor(tactic)}`}
                                      >
                                        {tactic.replace('-', '_').toUpperCase()}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {technique.platforms.length > 0 && (
                                <div>
                                  <span className="font-medium text-green-400 font-mono">PLATFORMS: </span>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {technique.platforms.map((platform, platformIndex) => (
                                      <span
                                        key={platformIndex}
                                        className="flex items-center gap-1 px-2 py-1 bg-gray-500/20 text-gray-300 rounded text-xs font-medium font-mono border border-gray-500/30"
                                      >
                                        {getPlatformIcon(platform)}
                                        {platform.toUpperCase()}
                                      </span>
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
              </div>
            )}

            {/* Explore Tab */}
            {activeTab === 'explore' && (
              <div className="space-y-8">
                {/* MITRE ATT&CK Tactics */}
                <div>
                  <h3 className="text-xl font-semibold text-green-400 mb-4 font-mono">[MITRE_ATTACK_TACTICS]</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {tactics.map((tactic, index) => (
                      <div
                        key={index}
                        className={`bg-black/60 border rounded-lg p-4 cursor-pointer transition-all duration-200 transform hover:scale-105 hover:border-cyan-500/50 ${getTacticColor(tactic)}`}
                      >
                        <div className="flex items-center gap-3 mb-2">
                          <Shield className="w-5 h-5" />
                          <h4 className="font-semibold font-mono">
                            {tactic.replace('-', '_').toUpperCase()}
                          </h4>
                        </div>
                        <p className="text-sm opacity-90 font-mono">
                          {`TACTIC.${tactic.replace('-', '_').toUpperCase()}`}
                        </p>
                        <div className="mt-3 flex justify-end">
                          <ExternalLink className="w-4 h-4 opacity-75" />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Platforms */}
                <div>
                  <h3 className="text-xl font-semibold text-green-400 mb-4 font-mono">[SUPPORTED_PLATFORMS]</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                    {platforms.map((platform, index) => (
                      <div
                        key={index}
                        className="bg-black/60 border border-gray-500/30 rounded-lg p-3 text-center hover:border-green-500/50 transition-colors cursor-pointer"
                      >
                        <div className="flex justify-center mb-2">
                          {getPlatformIcon(platform)}
                        </div>
                        <p className="text-sm font-medium text-gray-300 font-mono">{platform.toUpperCase()}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Stats Tab */}
            {activeTab === 'stats' && stats && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-gradient-to-r from-cyan-900/30 to-cyan-800/20 border border-cyan-500/30 rounded-lg p-6">
                    <h4 className="font-semibold text-cyan-400 mb-4 font-mono">[DATABASE_INFO]</h4>
                    <div className="space-y-2 text-sm font-mono">
                      <div className="flex justify-between">
                        <span className="text-cyan-300">COLLECTION:</span>
                        <span className="font-medium text-cyan-100">{stats.collection_name}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-cyan-300">TECHNIQUES:</span>
                        <span className="font-medium text-cyan-100">{stats.total_techniques}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-cyan-300">EMBEDDING:</span>
                        <span className="font-medium text-cyan-100">{stats.embedding_model}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-cyan-300">DIMENSIONS:</span>
                        <span className="font-medium text-cyan-100">{stats.embedding_dimension}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-r from-green-900/30 to-green-800/20 border border-green-500/30 rounded-lg p-6">
                    <h4 className="font-semibold text-green-400 mb-4 font-mono">[FRAMEWORK_COVERAGE]</h4>
                    <div className="space-y-2 text-sm font-mono">
                      <div className="flex justify-between">
                        <span className="text-green-300">TACTICS:</span>
                        <span className="font-medium text-green-100">{tactics.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-green-300">PLATFORMS:</span>
                        <span className="font-medium text-green-100">{platforms.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-green-300">SEARCH_MODE:</span>
                        <span className="font-medium text-green-100">AI_ENHANCED</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-green-300">RESPONSE:</span>
                        <span className="font-medium text-green-100">REALTIME</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-gradient-to-r from-purple-900/30 to-purple-800/20 border border-purple-500/30 rounded-lg p-6">
                  <h4 className="font-semibold text-purple-400 mb-4 font-mono">[AI_ENHANCEMENT_FEATURES]</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm font-mono">
                    <div>
                      <h5 className="font-medium text-purple-300 mb-2">AWS_TITAN_EMBEDDINGS</h5>
                      <ul className="space-y-1 text-purple-200">
                        <li>• 1024D_VECTOR_EMBEDDINGS</li>
                        <li>• SEMANTIC_SIMILARITY_SEARCH</li>
                        <li>• CONTEXT_AWARE_RETRIEVAL</li>
                        <li>• REALTIME_PROCESSING</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium text-purple-300 mb-2">ENHANCED_SEARCH</h5>
                      <ul className="space-y-1 text-purple-200">
                        <li>• NATURAL_LANGUAGE_QUERIES</li>
                        <li>• RELEVANCE_SCORING</li>
                        <li>• CONTEXTUAL_RESULTS</li>
                        <li>• BATCH_PROCESSING</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardMitreSearch;
