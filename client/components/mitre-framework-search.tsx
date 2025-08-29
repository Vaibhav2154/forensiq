'use client';

import React, { useState, useEffect } from 'react';
import { Shield, Search, BarChart3, Users, Server, AlertTriangle, TrendingUp, ExternalLink } from 'lucide-react';
import MitreSearchWidget from './mitre-search-widget';
const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface MitreStats {
  total_techniques: number;
  collection_name: string;
  embedding_model: string;
  embedding_dimension: number;
}

const MitreFrameworkSearch: React.FC = () => {
  const [stats, setStats] = useState<MitreStats | null>(null);
  const [tactics, setTactics] = useState<string[]>([]);
  const [platforms, setPlatforms] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'search' | 'explore' | 'stats'>('search');

  useEffect(() => {
    fetchInitialData();
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
    } finally {
      setLoading(false);
    }
  };

  const getTacticDescription = (tactic: string) => {
    const descriptions: { [key: string]: string } = {
      'initial-access': 'Techniques used to gain an initial foothold within a network',
      'execution': 'Techniques that result in adversary-controlled code running on a local or remote system',
      'persistence': 'Techniques that adversaries use to keep access to systems across restarts',
      'privilege-escalation': 'Techniques that adversaries use to gain higher-level permissions',
      'defense-evasion': 'Techniques that adversaries use to avoid detection',
      'credential-access': 'Techniques for stealing credentials like account names and passwords',
      'discovery': 'Techniques an adversary may use to gain knowledge about the system',
      'lateral-movement': 'Techniques that adversaries use to move through your environment',
      'collection': 'Techniques adversaries may use to gather information',
      'command-and-control': 'Techniques that adversaries may use to communicate with systems',
      'exfiltration': 'Techniques that adversaries may use to steal data',
      'impact': 'Techniques that adversaries use to disrupt availability or compromise integrity'
    };
    return descriptions[tactic] || 'MITRE ATT&CK tactic';
  };

  const getTacticIcon = (tactic: string) => {
    const icons: { [key: string]: React.ReactNode } = {
      'initial-access': <AlertTriangle className="w-5 h-5" />,
      'execution': <Server className="w-5 h-5" />,
      'persistence': <Shield className="w-5 h-5" />,
      'privilege-escalation': <TrendingUp className="w-5 h-5" />,
      'defense-evasion': <Shield className="w-5 h-5" />,
      'credential-access': <Users className="w-5 h-5" />,
      'discovery': <Search className="w-5 h-5" />,
      'lateral-movement': <Server className="w-5 h-5" />,
      'collection': <BarChart3 className="w-5 h-5" />,
      'command-and-control': <Server className="w-5 h-5" />,
      'exfiltration': <TrendingUp className="w-5 h-5" />,
      'impact': <AlertTriangle className="w-5 h-5" />
    };
    return icons[tactic] || <Shield className="w-5 h-5" />;
  };

  const getTacticColor = (tactic: string) => {
    const colors: { [key: string]: string } = {
      'initial-access': 'bg-red-500 hover:bg-red-600',
      'execution': 'bg-orange-500 hover:bg-orange-600',
      'persistence': 'bg-yellow-500 hover:bg-yellow-600',
      'privilege-escalation': 'bg-green-500 hover:bg-green-600',
      'defense-evasion': 'bg-blue-500 hover:bg-blue-600',
      'credential-access': 'bg-indigo-500 hover:bg-indigo-600',
      'discovery': 'bg-purple-500 hover:bg-purple-600',
      'lateral-movement': 'bg-pink-500 hover:bg-pink-600',
      'collection': 'bg-gray-500 hover:bg-gray-600',
      'command-and-control': 'bg-cyan-500 hover:bg-cyan-600',
      'exfiltration': 'bg-teal-500 hover:bg-teal-600',
      'impact': 'bg-rose-500 hover:bg-rose-600'
    };
    return colors[tactic] || 'bg-gray-500 hover:bg-gray-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-8 h-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-900">MITRE ATT&CK Framework</h1>
          </div>
          <p className="text-lg text-gray-600">
            Explore cybersecurity threats and techniques with AI-powered search using AWS Titan embeddings
          </p>
        </div>

        {/* Stats Overview */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Techniques</p>
                  <p className="text-2xl font-bold text-blue-600">{stats.total_techniques}</p>
                </div>
                <BarChart3 className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Tactics</p>
                  <p className="text-2xl font-bold text-green-600">{tactics.length}</p>
                </div>
                <Shield className="w-8 h-8 text-green-600" />
              </div>
            </div>
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Platforms</p>
                  <p className="text-2xl font-bold text-purple-600">{platforms.length}</p>
                </div>
                <Server className="w-8 h-8 text-purple-600" />
              </div>
            </div>
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">AI Model</p>
                  <p className="text-sm font-bold text-orange-600">AWS Titan V2</p>
                  <p className="text-xs text-gray-500">{stats.embedding_dimension}D embeddings</p>
                </div>
                <TrendingUp className="w-8 h-8 text-orange-600" />
              </div>
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab('search')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'search'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Search className="w-4 h-4" />
                  AI-Powered Search
                </div>
              </button>
              <button
                onClick={() => setActiveTab('explore')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'explore'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Explore Framework
                </div>
              </button>
              <button
                onClick={() => setActiveTab('stats')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'stats'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-4 h-4" />
                  Statistics
                </div>
              </button>
            </nav>
          </div>

          <div className="p-6">
            {/* Search Tab */}
            {activeTab === 'search' && (
              <div>
                <MitreSearchWidget />
              </div>
            )}

            {/* Explore Tab */}
            {activeTab === 'explore' && (
              <div className="space-y-8">
                {/* MITRE ATT&CK Tactics */}
                <div>
                  <h3 className="text-xl font-semibold text-gray-900 mb-4">MITRE ATT&CK Tactics</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {tactics.map((tactic, index) => (
                      <div
                        key={index}
                        className={`${getTacticColor(tactic)} text-white rounded-lg p-4 cursor-pointer transition-all duration-200 transform hover:scale-105`}
                      >
                        <div className="flex items-center gap-3 mb-2">
                          {getTacticIcon(tactic)}
                          <h4 className="font-semibold capitalize">
                            {tactic.replace('-', ' ')}
                          </h4>
                        </div>
                        <p className="text-sm opacity-90">
                          {getTacticDescription(tactic)}
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
                  <h3 className="text-xl font-semibold text-gray-900 mb-4">Supported Platforms</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                    {platforms.map((platform, index) => (
                      <div
                        key={index}
                        className="bg-gray-100 rounded-lg p-3 text-center hover:bg-gray-200 transition-colors cursor-pointer"
                      >
                        <div className="flex justify-center mb-2">
                          <Server className="w-6 h-6 text-gray-600" />
                        </div>
                        <p className="text-sm font-medium text-gray-800">{platform}</p>
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
                  <div className="bg-gradient-to-r from-blue-50 to-blue-100 rounded-lg p-6">
                    <h4 className="font-semibold text-blue-900 mb-4">Database Information</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-blue-700">Collection Name:</span>
                        <span className="font-medium text-blue-900">{stats.collection_name}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-blue-700">Total Techniques:</span>
                        <span className="font-medium text-blue-900">{stats.total_techniques}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-blue-700">Embedding Model:</span>
                        <span className="font-medium text-blue-900">{stats.embedding_model}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-blue-700">Embedding Dimension:</span>
                        <span className="font-medium text-blue-900">{stats.embedding_dimension}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-r from-green-50 to-green-100 rounded-lg p-6">
                    <h4 className="font-semibold text-green-900 mb-4">Framework Coverage</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-green-700">Tactics Covered:</span>
                        <span className="font-medium text-green-900">{tactics.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-green-700">Platforms Supported:</span>
                        <span className="font-medium text-green-900">{platforms.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-green-700">Search Capability:</span>
                        <span className="font-medium text-green-900">AI-Enhanced</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-green-700">Response Time:</span>
                        <span className="font-medium text-green-900">Real-time</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-gradient-to-r from-purple-50 to-purple-100 rounded-lg p-6">
                  <h4 className="font-semibold text-purple-900 mb-4">AI Enhancement Features</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <h5 className="font-medium text-purple-800 mb-2">AWS Titan Embeddings</h5>
                      <ul className="space-y-1 text-purple-700">
                        <li>• 1024-dimensional vector embeddings</li>
                        <li>• Semantic similarity search</li>
                        <li>• Context-aware retrieval</li>
                        <li>• Real-time processing</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-medium text-purple-800 mb-2">Enhanced Search</h5>
                      <ul className="space-y-1 text-purple-700">
                        <li>• Natural language queries</li>
                        <li>• Relevance scoring</li>
                        <li>• Contextual results</li>
                        <li>• Batch processing</li>
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

export default MitreFrameworkSearch;
