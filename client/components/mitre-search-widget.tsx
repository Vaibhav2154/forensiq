'use client';

import React, { useState, useEffect } from 'react';
const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
import { Search, AlertTriangle, Shield, Cpu, Server, Loader2, ExternalLink } from 'lucide-react';

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

const MitreSearchWidget: React.FC = () => {
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [searchResults, setSearchResults] = useState<MitreSearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [maxResults, setMaxResults] = useState(5);

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
      'initial-access': 'bg-red-100 text-red-800',
      'execution': 'bg-orange-100 text-orange-800',
      'persistence': 'bg-yellow-100 text-yellow-800',
      'privilege-escalation': 'bg-green-100 text-green-800',
      'defense-evasion': 'bg-blue-100 text-blue-800',
      'credential-access': 'bg-indigo-100 text-indigo-800',
      'discovery': 'bg-purple-100 text-purple-800',
      'lateral-movement': 'bg-pink-100 text-pink-800',
      'collection': 'bg-gray-100 text-gray-800',
      'command-and-control': 'bg-cyan-100 text-cyan-800',
      'exfiltration': 'bg-teal-100 text-teal-800',
      'impact': 'bg-rose-100 text-rose-800',
    };
    return colors[tactic] || 'bg-gray-100 text-gray-800';
  };

  const getPlatformIcon = (platform: string) => {
    if (platform.toLowerCase().includes('windows')) return <Server className="w-4 h-4" />;
    if (platform.toLowerCase().includes('linux')) return <Cpu className="w-4 h-4" />;
    if (platform.toLowerCase().includes('macos')) return <Shield className="w-4 h-4" />;
    return <AlertTriangle className="w-4 h-4" />;
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6 max-w-4xl mx-auto">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2 flex items-center gap-2">
          <Shield className="w-6 h-6 text-blue-600" />
          MITRE ATT&CK Framework Search
        </h2>
        <p className="text-gray-600">
          Search MITRE ATT&CK techniques using AWS Titan embeddings for enhanced context retrieval
        </p>
      </div>

      {/* Search Interface */}
      <div className="mb-6">
        <div className="flex gap-4 mb-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Enter your search query (e.g., 'credential dumping', 'lateral movement')"
                className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-600">Results:</label>
            <select
              value={maxResults}
              onChange={(e) => setMaxResults(Number(e.target.value))}
              className="border border-gray-300 rounded px-3 py-2 text-sm"
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
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isLoading ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <Search className="w-5 h-5" />
            )}
            Search
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center gap-2 text-red-800">
            <AlertTriangle className="w-5 h-5" />
            <span className="font-medium">Error occurred:</span>
          </div>
          <p className="text-red-700 mt-1">{error}</p>
        </div>
      )}

      {/* Search Results */}
      {searchResults && (
        <div className="space-y-6">
          {/* Summary */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h3 className="font-semibold text-blue-900 mb-2">Search Summary</h3>
            <p className="text-blue-800">{searchResults.summary}</p>
            <div className="flex items-center gap-4 mt-2 text-sm text-blue-700">
              <span>Model: {searchResults.embedding_model}</span>
              <span>Total Results: {searchResults.total_techniques}</span>
            </div>
          </div>

          {/* Top Match Highlight */}
          {searchResults.top_match && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <h3 className="font-semibold text-green-900 mb-2 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Best Match
              </h3>
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-green-800">
                  {searchResults.top_match.name} ({searchResults.top_match.technique_id})
                </span>
                <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-sm">
                  {(searchResults.top_match.relevance_score * 100).toFixed(1)}% match
                </span>
              </div>
              <p className="text-green-700 text-sm">{searchResults.top_match.description}</p>
            </div>
          )}

          {/* Common Tactics and Platforms */}
          {(searchResults.common_tactics || searchResults.common_platforms) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {searchResults.common_tactics && (
                <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                  <h4 className="font-semibold text-gray-900 mb-2">Common Tactics</h4>
                  <div className="flex flex-wrap gap-2">
                    {searchResults.common_tactics.map((tactic, index) => (
                      <span
                        key={index}
                        className={`px-2 py-1 rounded text-xs font-medium ${getTacticColor(tactic)}`}
                      >
                        {tactic.replace('-', ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {searchResults.common_platforms && (
                <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                  <h4 className="font-semibold text-gray-900 mb-2">Common Platforms</h4>
                  <div className="flex flex-wrap gap-2">
                    {searchResults.common_platforms.map((platform, index) => (
                      <span
                        key={index}
                        className="flex items-center gap-1 px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs font-medium"
                      >
                        {getPlatformIcon(platform)}
                        {platform}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Detailed Results */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-4">Detailed Results</h3>
            <div className="space-y-4">
              {searchResults.relevant_techniques.map((technique, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <h4 className="font-semibold text-gray-900 mb-1 flex items-center gap-2">
                        {technique.name}
                        <span className="bg-gray-100 text-gray-700 px-2 py-1 rounded text-sm font-normal">
                          {technique.technique_id}
                        </span>
                        <a
                          href={`https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      </h4>
                      <p className="text-gray-600 text-sm mb-3">
                        {technique.description.length > 200
                          ? `${technique.description.substring(0, 200)}...`
                          : technique.description}
                      </p>
                    </div>
                    <div className="text-right">
                      <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-sm font-medium">
                        {(technique.relevance_score * 100).toFixed(1)}% relevance
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-4 text-sm">
                    {technique.kill_chain_phases.length > 0 && (
                      <div>
                        <span className="font-medium text-gray-700">Tactics: </span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {technique.kill_chain_phases.map((tactic, tacticIndex) => (
                            <span
                              key={tacticIndex}
                              className={`px-2 py-1 rounded text-xs font-medium ${getTacticColor(tactic)}`}
                            >
                              {tactic.replace('-', ' ')}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {technique.platforms.length > 0 && (
                      <div>
                        <span className="font-medium text-gray-700">Platforms: </span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {technique.platforms.map((platform, platformIndex) => (
                            <span
                              key={platformIndex}
                              className="flex items-center gap-1 px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs font-medium"
                            >
                              {getPlatformIcon(platform)}
                              {platform}
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
  );
};

export default MitreSearchWidget;
