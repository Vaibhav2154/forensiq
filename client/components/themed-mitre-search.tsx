'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
import { Search, AlertTriangle, Shield, Cpu, Server, Loader2, ExternalLink, Database, Activity } from 'lucide-react';

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

interface RagQueryResponse {
  query: string;
  response: string;
  relevant_techniques: MitreTechnique[];
  confidence_score: number;
  processing_time_ms: number;
  embedding_model: string;
  total_techniques_found: number;
}

interface MitreStats {
  total_techniques: number;
  collection_name: string;
  embedding_model: string;
  embedding_dimension: number;
}

interface ThemedMitreSearchProps {
  isVisible: boolean;
}

const ThemedMitreSearch: React.FC<ThemedMitreSearchProps> = ({ isVisible }) => {
  const router = useRouter();
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [searchResults, setSearchResults] = useState<MitreSearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [maxResults, setMaxResults] = useState(5);
  const [stats, setStats] = useState<MitreStats | null>(null);
  const [tactics, setTactics] = useState<string[]>([]);
  const [platforms, setPlatforms] = useState<string[]>([]);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [searchHistory, setSearchHistory] = useState<string[]>([]);
  const [searchMode, setSearchMode] = useState<'regular' | 'rag'>('regular');
  const [ragResults, setRagResults] = useState<RagQueryResponse | null>(null);

  const handleTechniqueClick = (technique: MitreTechnique) => {
    // Navigate to chat page with the technique as a pre-filled query
    const techniqueQuery = `Tell me about ${technique.technique_id}: ${technique.name}`;
    router.push(`/chat?query=${encodeURIComponent(techniqueQuery)}`);
  };

  useEffect(() => {
    fetchMitreStats();
  }, []);

  useEffect(() => {
    addToTerminal(`[MODE] Switched to ${searchMode.toUpperCase()} search mode`);
  }, [searchMode]);

  const fetchMitreStats = async () => {
    try {
      const [statsRes, tacticsRes, platformsRes] = await Promise.all([
          fetch(`${BACKEND_URL}/api/mitre/stats`),
          fetch(`${BACKEND_URL}/api/mitre/tactics`),
          fetch(`${BACKEND_URL}/api/mitre/platforms`)
        ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
        addToTerminal(`[INFO] Database loaded: ${statsData.total_techniques} techniques`);
      }

      if (tacticsRes.ok) {
        const tacticsData = await tacticsRes.json();
        setTactics(tacticsData);
        addToTerminal(`[INFO] Tactics loaded: ${tacticsData.length} categories`);
      }

      if (platformsRes.ok) {
        const platformsData = await platformsRes.json();
        setPlatforms(platformsData);
        addToTerminal(`[INFO] Platforms loaded: ${platformsData.length} systems`);
      }
    } catch (error) {
      console.error('Error fetching MITRE data:', error);
      addToTerminal(`[ERROR] Failed to load MITRE data: ${error}`);
    }
  };

  const addToTerminal = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setTerminalOutput(prev => [...prev.slice(-4), `[${timestamp}] ${message}`]);
  };

  const handleSearch = async () => {
    if (!query.trim()) return;
    
    setIsLoading(true);
    setError(null);
    addToTerminal(`[${searchMode.toUpperCase()}_SEARCH] Querying: "${query}"`);
    setSearchHistory(prev => [query, ...prev.slice(0, 4)]);
    
    try {
      if (searchMode === 'rag') {
        await handleRagSearch();
      } else {
        await handleRegularSearch();
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'An error occurred while searching';
      setError(errorMsg);
      addToTerminal(`[ERROR] Search failed: ${errorMsg}`);
      setSearchResults(null);
      setRagResults(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegularSearch = async () => {
  const response = await fetch(`${BACKEND_URL}/api/mitre/search?q=${encodeURIComponent(query)}&max_results=${maxResults}`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data: MitreSearchResponse = await response.json();
    setSearchResults(data);
    setRagResults(null);
    addToTerminal(`[SUCCESS] Found ${data.total_techniques} matching techniques`);
  };

  const handleRagSearch = async () => {
  const response = await fetch(`${BACKEND_URL}/api/mitre/rag-query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: query,
        max_context_techniques: maxResults,
        include_source_techniques: true
      }),
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data: RagQueryResponse = await response.json();
    setRagResults(data);
    setSearchResults(null);
    addToTerminal(`[SUCCESS] RAG analysis complete - ${data.total_techniques_found} techniques analyzed`);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const getTacticColor = (tactic: string) => {
    const colors: { [key: string]: string } = {
      'initial-access': 'border-red-500/50 text-red-400 bg-red-900/30',
      'execution': 'border-orange-500/50 text-orange-400 bg-orange-900/30',
      'persistence': 'border-yellow-500/50 text-yellow-400 bg-yellow-900/30',
      'privilege-escalation': 'border-green-500/50 text-green-400 bg-green-900/30',
      'defense-evasion': 'border-blue-500/50 text-blue-400 bg-blue-900/30',
      'credential-access': 'border-indigo-500/50 text-indigo-400 bg-indigo-900/30',
      'discovery': 'border-purple-500/50 text-purple-400 bg-purple-900/30',
      'lateral-movement': 'border-pink-500/50 text-pink-400 bg-pink-900/30',
      'collection': 'border-gray-500/50 text-gray-400 bg-gray-900/30',
      'command-and-control': 'border-cyan-500/50 text-cyan-400 bg-cyan-900/30',
      'exfiltration': 'border-teal-500/50 text-teal-400 bg-teal-900/30',
      'impact': 'border-rose-500/50 text-rose-400 bg-rose-900/30',
    };
    return colors[tactic] || 'border-gray-500/50 text-gray-400 bg-gray-900/30';
  };

  return (
    <div className={`space-y-6 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
      {/* AI-Enhanced Search Terminal */}
      <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4 md:p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
          <h3 className="text-lg font-semibold text-green-400 font-mono">[AI_SEARCH_ENGINE.EXE]</h3>
          <div className="flex-1 text-right">
            <span className="text-xs text-cyan-400 font-mono">AWS_TITAN_V2 --EMBEDDINGS=1024D</span>
          </div>
        </div>

        {/* Search Interface */}
        <div className="mb-6">
          <div className="flex gap-2 mb-4">
            <div className="flex-1 relative">
              <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-green-400 font-mono">&gt;</span>
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Enter threat intelligence query..."
                className="w-full pl-8 pr-4 py-3 bg-black/50 border border-green-500/30 text-green-400 font-mono text-sm focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 placeholder:text-green-500/50"
              />
            </div>
            <select
              value={maxResults}
              onChange={(e) => setMaxResults(Number(e.target.value))}
              className="bg-black/50 border border-green-500/30 text-green-400 px-3 py-3 text-sm font-mono focus:ring-2 focus:ring-cyan-500/50"
            >
              <option value={3}>3</option>
              <option value={5}>5</option>
              <option value={10}>10</option>
              <option value={15}>15</option>
            </select>
            <button
              onClick={handleSearch}
              disabled={isLoading || !query.trim()}
              className="px-6 py-3 bg-green-600/20 border border-green-500/50 text-green-400 hover:bg-green-500/30 hover:shadow-[0_0_10px_rgba(0,255,150,0.3)] disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 font-mono text-sm transition-all"
            >
              {isLoading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              {isLoading ? 'PROCESSING...' : 'EXECUTE'}
            </button>
          </div>

          {/* Search Mode Toggle */}
          <div className="mb-4">
            <div className="flex gap-2 items-center">
              <span className="text-xs text-cyan-400 font-mono">[SEARCH_MODE]:</span>
              <div className="flex gap-1">
                <button
                  onClick={() => setSearchMode('regular')}
                  className={`px-3 py-1 text-xs font-mono border transition-all ${
                    searchMode === 'regular'
                      ? 'border-cyan-500/50 text-cyan-400 bg-cyan-900/30 shadow-[0_0_5px_rgba(0,255,150,0.3)]'
                      : 'border-gray-500/30 text-gray-400 hover:border-gray-400/50'
                  }`}
                >
                  VECTOR_SEARCH
                </button>
                <button
                  onClick={() => setSearchMode('rag')}
                  className={`px-3 py-1 text-xs font-mono border transition-all ${
                    searchMode === 'rag'
                      ? 'border-green-500/50 text-green-400 bg-green-900/30 shadow-[0_0_5px_rgba(0,255,150,0.3)]'
                      : 'border-gray-500/30 text-gray-400 hover:border-gray-400/50'
                  }`}
                >
                  RAG_ANALYSIS
                </button>
              </div>
              <div className="flex-1 text-right">
                <span className="text-xs text-gray-500 font-mono">
                  {searchMode === 'regular' ? 'Fast semantic search' : 'AI-powered analysis'}
                </span>
              </div>
            </div>
          </div>

          {/* Search History */}
          {searchHistory.length > 0 && (
            <div className="mb-4">
              <div className="text-xs text-cyan-400 mb-2 font-mono">[SEARCH_HISTORY]:</div>
              <div className="flex flex-wrap gap-2">
                {searchHistory.map((hist, index) => (
                  <button
                    key={index}
                    onClick={() => setQuery(hist)}
                    className="px-2 py-1 bg-cyan-900/30 border border-cyan-500/30 text-cyan-400 text-xs font-mono hover:bg-cyan-800/40 transition-colors"
                  >
                    {hist.length > 20 ? `${hist.slice(0, 20)}...` : hist}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Terminal Output */}
        <div className="bg-black/70 border border-gray-700/50 p-3 h-24 overflow-y-auto font-mono text-xs">
          {terminalOutput.map((line, index) => (
            <div key={index} className="text-green-400 mb-1">
              {line}
            </div>
          ))}
          {terminalOutput.length === 0 && (
            <div className="text-gray-500">Waiting for search query...</div>
          )}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-900/30 border border-red-500/50 p-4">
          <div className="flex items-center gap-2 text-red-400 font-mono">
            <AlertTriangle className="w-5 h-5" />
            <span className="font-medium">[SYSTEM_ERROR]</span>
          </div>
          <p className="text-red-300 mt-1 font-mono text-sm">{error}</p>
        </div>
      )}

      {/* Stats Display */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-cyan-400 text-xs font-mono">[DB_SIZE]</p>
                <p className="text-xl font-bold text-cyan-400 font-mono">{stats.total_techniques}</p>
              </div>
              <Database className="w-6 h-6 text-cyan-400" />
            </div>
          </div>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs font-mono">[TACTICS]</p>
                <p className="text-xl font-bold text-green-400 font-mono">{tactics.length}</p>
              </div>
              <Shield className="w-6 h-6 text-green-400" />
            </div>
          </div>
          <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-400 text-xs font-mono">[PLATFORMS]</p>
                <p className="text-xl font-bold text-purple-400 font-mono">{platforms.length}</p>
              </div>
              <Server className="w-6 h-6 text-purple-400" />
            </div>
          </div>
          <div className="bg-black/80 backdrop-blur-sm border border-orange-500/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-orange-400 text-xs font-mono">[AI_MODEL]</p>
                <p className="text-sm font-bold text-orange-400 font-mono">TITAN_V2</p>
              </div>
              <Activity className="w-6 h-6 text-orange-400" />
            </div>
          </div>
        </div>
      )}

      {/* Search Results */}
      {searchResults && (
        <div className="space-y-6">
          {/* Summary Terminal */}
          <div className="bg-black/80 backdrop-blur-sm border border-blue-500/30 p-4">
            <h3 className="font-semibold text-blue-400 mb-2 font-mono flex items-center gap-2">
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
              [SEARCH_SUMMARY.LOG]
            </h3>
            <p className="text-blue-300 font-mono text-sm">{searchResults.summary}</p>
            <div className="flex items-center gap-4 mt-2 text-xs text-blue-400 font-mono">
              <span>MODEL: {searchResults.embedding_model}</span>
              <span>RESULTS: {searchResults.total_techniques}</span>
              <span>STATUS: ACTIVE</span>
            </div>
          </div>

          {/* Top Match Highlight */}
          {searchResults.top_match && (
            <div 
              className="bg-green-900/30 border border-green-500/50 p-4 cursor-pointer hover:bg-green-900/40 transition-colors"
              onClick={() => handleTechniqueClick({
                technique_id: searchResults.top_match!.technique_id,
                name: searchResults.top_match!.name,
                description: searchResults.top_match!.description,
                kill_chain_phases: [],
                platforms: [],
                relevance_score: searchResults.top_match!.relevance_score,
                embedding_model: searchResults.embedding_model
              })}
            >
              <h3 className="font-semibold text-green-400 mb-2 flex items-center gap-2 font-mono">
                <AlertTriangle className="w-5 h-5" />
                [PRIMARY_MATCH.DAT]
              </h3>
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-green-300 font-mono">
                  {searchResults.top_match.name} ({searchResults.top_match.technique_id})
                </span>
                <span className="bg-green-500/20 border border-green-500/50 text-green-400 px-2 py-1 text-xs font-mono">
                  {(searchResults.top_match.relevance_score * 100).toFixed(1)}% MATCH
                </span>
              </div>
              <p className="text-green-200 text-sm font-mono">{searchResults.top_match.description}</p>
            </div>
          )}

          {/* Common Tactics and Platforms */}
          {(searchResults.common_tactics || searchResults.common_platforms) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {searchResults.common_tactics && (
                <div className="bg-black/80 backdrop-blur-sm border border-gray-500/30 p-4">
                  <h4 className="font-semibold text-gray-300 mb-2 font-mono">[COMMON_TACTICS.CFG]</h4>
                  <div className="flex flex-wrap gap-2">
                    {searchResults.common_tactics.map((tactic, index) => (
                      <span
                        key={index}
                        className={`px-2 py-1 text-xs font-medium border font-mono ${getTacticColor(tactic)}`}
                      >
                        {tactic.toUpperCase().replace('-', '_')}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {searchResults.common_platforms && (
                <div className="bg-black/80 backdrop-blur-sm border border-gray-500/30 p-4">
                  <h4 className="font-semibold text-gray-300 mb-2 font-mono">[COMMON_PLATFORMS.CFG]</h4>
                  <div className="flex flex-wrap gap-2">
                    {searchResults.common_platforms.map((platform, index) => (
                      <span
                        key={index}
                        className="flex items-center gap-1 px-2 py-1 bg-gray-700/50 border border-gray-600/50 text-gray-300 text-xs font-mono"
                      >
                        <Cpu className="w-3 h-3" />
                        {platform.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Detailed Results */}
          <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-4">
            <h3 className="font-semibold text-cyan-400 mb-4 font-mono flex items-center gap-2">
              <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse"></div>
              [TECHNIQUE_ANALYSIS.DB]
            </h3>
            <div className="space-y-4">
              {searchResults.relevant_techniques.map((technique, index) => (
                <div 
                  key={index} 
                  className="border border-gray-700/50 bg-black/50 p-4 hover:border-cyan-500/50 transition-colors cursor-pointer"
                  onClick={() => handleTechniqueClick(technique)}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <h4 className="font-semibold text-cyan-400 mb-1 flex items-center gap-2 font-mono">
                        &gt; {technique.technique_id}: {technique.name}
                        <a
                          href={`https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:text-blue-300"
                          onClick={(e) => e.stopPropagation()}
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
                      <span className="bg-blue-500/20 border border-blue-500/50 text-blue-400 px-2 py-1 text-xs font-mono">
                        {(technique.relevance_score * 100).toFixed(1)}% REL
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-4 text-sm">
                    {technique.kill_chain_phases.length > 0 && (
                      <div>
                        <span className="font-medium text-gray-400 font-mono">TACTICS: </span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {technique.kill_chain_phases.map((tactic, tacticIndex) => (
                            <span
                              key={tacticIndex}
                              className={`px-2 py-1 text-xs font-medium border font-mono ${getTacticColor(tactic)}`}
                            >
                              {tactic.toUpperCase().replace('-', '_')}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {technique.platforms.length > 0 && (
                      <div>
                        <span className="font-medium text-gray-400 font-mono">PLATFORMS: </span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {technique.platforms.map((platform, platformIndex) => (
                            <span
                              key={platformIndex}
                              className="flex items-center gap-1 px-2 py-1 bg-gray-700/50 border border-gray-600/50 text-gray-300 text-xs font-mono"
                            >
                              <Server className="w-3 h-3" />
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

      {/* RAG Analysis Results */}
      {ragResults && (
        <div className="space-y-6">
          {/* RAG Response Header */}
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
              <h3 className="text-lg font-semibold text-green-400 font-mono">[AI_ANALYSIS_REPORT.EXE]</h3>
              <div className="flex-1 text-right">
                <span className="text-xs text-cyan-400 font-mono">
                  CONFIDENCE: {(ragResults.confidence_score * 100).toFixed(1)}% | 
                  TIME: {ragResults.processing_time_ms.toFixed(0)}ms
                </span>
              </div>
            </div>

            {/* AI Response */}
            <div className="bg-black/50 border border-green-500/20 p-4 mb-4">
              <div className="text-green-300 leading-relaxed whitespace-pre-wrap font-mono text-sm">
                {ragResults.response}
              </div>
            </div>

            {/* Query Info */}
            <div className="text-xs text-gray-500 font-mono">
              [QUERY]: "{ragResults.query}" | 
              [MODEL]: {ragResults.embedding_model.toUpperCase()} | 
              [TECHNIQUES_FOUND]: {ragResults.total_techniques_found}
            </div>
          </div>

          {/* Source Techniques */}
          {ragResults.relevant_techniques.length > 0 && (
            <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-4">
              <h3 className="font-semibold text-cyan-400 mb-4 font-mono flex items-center gap-2">
                <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse"></div>
                [SOURCE_TECHNIQUES.DB]
              </h3>
              <div className="space-y-3">
                {ragResults.relevant_techniques.map((technique, index) => (
                  <div key={index} className="border border-gray-700/50 bg-black/50 p-3 hover:border-cyan-500/50 transition-colors">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <h4 className="font-semibold text-cyan-400 mb-1 flex items-center gap-2 font-mono text-sm">
                          &gt; {technique.technique_id}: {technique.name}
                          <a
                            href={`https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:text-cyan-300 transition-colors"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </h4>
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-xs text-gray-500 font-mono">
                            RELEVANCE: {(technique.relevance_score * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    </div>
                    
                    <p className="text-gray-300 mb-2 leading-relaxed text-sm">
                      {technique.description.length > 200 
                        ? `${technique.description.substring(0, 200)}...`
                        : technique.description
                      }
                    </p>
                    
                    {technique.kill_chain_phases.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {technique.kill_chain_phases.map((tactic, tacticIndex) => (
                          <span
                            key={tacticIndex}
                            className={`px-2 py-1 text-xs font-medium border font-mono ${getTacticColor(tactic)}`}
                          >
                            {tactic.toUpperCase().replace('-', '_')}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ThemedMitreSearch;
