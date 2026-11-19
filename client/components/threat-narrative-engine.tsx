'use client'
import React, { useState, useEffect, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { 
  Clock, AlertTriangle, Shield, Eye, Target, Zap, Brain, 
  FileText, Search, TrendingUp, GitBranch, MapPin, Users,
  Server, Network, Lock, Unlock, Activity, ChevronRight,
  Play, Pause, RotateCcw, FastForward
} from 'lucide-react';

interface ThreatStoryData {
  summary: string;
  matched_techniques: Array<{
    technique_id: string;
    name: string;
    description: string;
    kill_chain_phases: string[];
    platforms: string[];
    relevance_score: number;
  }>;
  enhanced_analysis?: string | null;
  analysis_timestamp: string;
  processing_time_ms: number;
}

interface StoryChapter {
  id: string;
  title: string;
  icon: React.ComponentType<any>;
  content: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp?: string;
  techniques: Array<{ id: string; name: string; score: number; phases: string[] }>;
  body: string;
}

interface ThreatActor {
  name: string;
  sophistication: number;
  motivation: string;
  tactics: string[];
}

// Phase metadata for icons and labels
const PHASE_META: Record<string, { label: string; icon: React.ComponentType<any>; severity: StoryChapter['severity'] }> = {
  'reconnaissance':       { label: 'Reconnaissance',         icon: Search,    severity: 'low'      },
  'discovery':            { label: 'Discovery',              icon: Eye,       severity: 'low'      },
  'initial-access':       { label: 'Initial Access',         icon: Unlock,    severity: 'high'     },
  'execution':            { label: 'Execution',              icon: Zap,       severity: 'high'     },
  'persistence':          { label: 'Persistence',            icon: Lock,      severity: 'high'     },
  'privilege-escalation': { label: 'Privilege Escalation',   icon: TrendingUp, severity: 'critical'},
  'defense-evasion':      { label: 'Defense Evasion',        icon: Shield,    severity: 'critical' },
  'credential-access':    { label: 'Credential Access',      icon: Users,     severity: 'critical' },
  'lateral-movement':     { label: 'Lateral Movement',       icon: Network,   severity: 'high'     },
  'collection':           { label: 'Collection',             icon: Server,    severity: 'medium'   },
  'command-and-control':  { label: 'C2 Communication',       icon: Activity,  severity: 'critical' },
  'exfiltration':         { label: 'Exfiltration',           icon: MapPin,    severity: 'critical' },
  'impact':               { label: 'Impact',                 icon: AlertTriangle, severity: 'critical' },
};

const PHASE_ORDER = [
  'reconnaissance', 'initial-access', 'execution', 'persistence',
  'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact'
];

const ThreatNarrativeEngine: React.FC<{ data: ThreatStoryData }> = ({ data }) => {
  const [currentChapter, setCurrentChapter] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);

  // Build chapters dynamically from actual data
  const storyChapters: StoryChapter[] = useMemo(() => {
    const chapters: StoryChapter[] = [];

    // Chapter 1: Overview — always present, uses the real AI summary
    chapters.push({
      id: 'overview',
      title: 'Threat Overview',
      icon: FileText,
      content: 'AI-generated log analysis summary',
      severity: 'medium',
      timestamp: data.analysis_timestamp,
      techniques: [],
      body: data.summary || 'No summary available for this analysis.',
    });

    // Chapters 2+: One per detected kill chain phase, ordered logically
    const phaseMap: Record<string, ThreatStoryData['matched_techniques']> = {};
    for (const tech of data.matched_techniques) {
      for (const phase of tech.kill_chain_phases) {
        if (!phaseMap[phase]) phaseMap[phase] = [];
        phaseMap[phase].push(tech);
      }
    }

    // Sort phases by the canonical MITRE kill-chain order
    const detectedPhases = Object.keys(phaseMap).sort((a, b) => {
      const ai = PHASE_ORDER.indexOf(a);
      const bi = PHASE_ORDER.indexOf(b);
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    });

    for (const phase of detectedPhases) {
      const techs = phaseMap[phase];
      const meta = PHASE_META[phase] ?? { label: phase.replace(/-/g, ' ').toUpperCase(), icon: Activity, severity: 'medium' as const };

      // Build a list of the techniques in this phase with real data
      const techniquesSummary = techs
        .map(t => `### ${t.technique_id}: ${t.name}\n> Relevance Score: **${(t.relevance_score * 100).toFixed(1)}%**\n\n${t.description}`)
        .join('\n\n---\n\n');

      chapters.push({
        id: `phase-${phase}`,
        title: meta.label,
        icon: meta.icon,
        content: `${techs.length} technique(s) detected in this phase`,
        severity: meta.severity,
        techniques: techs.map(t => ({
          id: t.technique_id,
          name: t.name,
          score: t.relevance_score,
          phases: t.kill_chain_phases,
        })),
        body: `## ${meta.label} Phase\n\n${techniquesSummary}`,
      });
    }

    // Final chapter: Enhanced AI analysis — always present
    if (data.enhanced_analysis) {
      chapters.push({
        id: 'enhanced',
        title: 'Full Threat Analysis',
        icon: Brain,
        content: 'Complete AI-powered enhanced threat assessment',
        severity: 'low',
        techniques: [],
        body: data.enhanced_analysis,
      });
    }

    return chapters;
  }, [data]);

  // Threat actor profile from real data
  const threatActorProfile: ThreatActor = useMemo(() => {
    const count = data.matched_techniques.length;
    if (count === 0) return { name: 'Unknown Actor', sophistication: 0, motivation: 'Unknown', tactics: [] };
    const avg = data.matched_techniques.reduce((s, t) => s + t.relevance_score, 0) / count;
    const uniquePhases = [...new Set(data.matched_techniques.flatMap(t => t.kill_chain_phases))];
    return {
      name: avg > 0.7 ? 'Advanced Persistent Threat' : avg > 0.5 ? 'Skilled Adversary' : 'Opportunistic Attacker',
      sophistication: Math.round(avg * 100),
      motivation: uniquePhases.includes('exfiltration') ? 'Data Exfiltration'
        : uniquePhases.includes('persistence') ? 'Long-term Access'
        : uniquePhases.includes('impact') ? 'Destructive Attack'
        : uniquePhases.includes('discovery') ? 'Intelligence Gathering'
        : 'System Compromise',
      tactics: uniquePhases,
    };
  }, [data]);

  // Auto-play
  useEffect(() => {
    if (isPlaying && currentChapter < storyChapters.length - 1) {
      const timer = setTimeout(() => setCurrentChapter(prev => prev + 1), 5000 / playbackSpeed);
      return () => clearTimeout(timer);
    } else if (isPlaying && currentChapter >= storyChapters.length - 1) {
      setIsPlaying(false);
    }
  }, [isPlaying, currentChapter, storyChapters.length, playbackSpeed]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 border-red-500 bg-red-900/20';
      case 'high':     return 'text-orange-400 border-orange-500 bg-orange-900/20';
      case 'medium':   return 'text-yellow-400 border-yellow-500 bg-yellow-900/20';
      case 'low':      return 'text-blue-400 border-blue-500 bg-blue-900/20';
      default:         return 'text-gray-400 border-gray-500 bg-gray-900/20';
    }
  };

  const mdComponents: React.ComponentProps<typeof ReactMarkdown>['components'] = {
    h1: ({ children }) => <h1 className="text-3xl font-bold text-cyan-400 mb-6">{children}</h1>,
    h2: ({ children }) => <h2 className="text-2xl font-bold text-purple-400 mb-4 mt-6">{children}</h2>,
    h3: ({ children }) => <h3 className="text-xl font-semibold text-green-400 mb-3 mt-4">{children}</h3>,
    h4: ({ children }) => <h4 className="text-lg font-semibold text-yellow-400 mb-2 mt-3">{children}</h4>,
    p:  ({ children }) => <p className="text-gray-300 mb-4 leading-relaxed">{children}</p>,
    strong: ({ children }) => <strong className="text-green-400 font-bold">{children}</strong>,
    em:     ({ children }) => <em className="text-cyan-300 italic">{children}</em>,
    ul: ({ children }) => <ul className="list-disc list-inside mb-4 space-y-2 text-gray-300">{children}</ul>,
    ol: ({ children }) => <ol className="list-decimal list-inside mb-4 space-y-2 text-gray-300">{children}</ol>,
    li: ({ children }) => <li className="text-gray-300 ml-4">{children}</li>,
    hr: () => <hr className="border-gray-700 my-6" />,
    blockquote: ({ children }) => (
      <blockquote className="border-l-4 border-cyan-500 bg-cyan-900/20 pl-4 py-2 my-4 italic text-cyan-200">
        {children}
      </blockquote>
    ),
    code: ({ children }) => (
      <code className="bg-black/50 text-green-400 px-2 py-1 rounded font-mono text-sm border border-green-500/30">
        {children}
      </code>
    ),
    pre: ({ children }) => (
      <pre className="bg-black/70 border border-gray-600 p-4 rounded overflow-x-auto mb-4">
        {children}
      </pre>
    ),
    table: ({ children }) => (
      <table className="min-w-full border border-gray-600 mb-4">{children}</table>
    ),
    th: ({ children }) => (
      <th className="border border-gray-600 px-4 py-2 bg-gray-800 text-cyan-400 font-semibold">{children}</th>
    ),
    td: ({ children }) => (
      <td className="border border-gray-600 px-4 py-2 text-gray-300">{children}</td>
    ),
  };

  return (
    <div className="relative bg-black min-h-screen w-full text-white overflow-x-hidden font-mono">
      {/* Background effects */}
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

      <div className="relative container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <div className="mb-8">
          <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 rounded-lg p-6">
            <div className="flex items-center gap-4 mb-4">
              <FileText className="h-8 w-8 text-cyan-400" />
              <div>
                <h1 className="text-3xl font-bold text-cyan-400 tracking-wider">[THREAT_INTELLIGENCE_NARRATIVE]</h1>
                <p className="text-gray-400 text-sm">
                  {storyChapters.length} chapters generated from your analysis ·{' '}
                  {data.matched_techniques.length} technique(s) detected ·{' '}
                  Analyzed at {new Date(data.analysis_timestamp).toLocaleTimeString()}
                </p>
              </div>
            </div>

            {/* Playback controls */}
            <div className="flex items-center gap-4 mt-6">
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className="flex items-center gap-2 px-4 py-2 border border-cyan-500 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
              >
                {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                {isPlaying ? 'PAUSE' : 'PLAY'}
              </button>

              <button
                onClick={() => { setCurrentChapter(0); setIsPlaying(false); }}
                className="flex items-center gap-2 px-4 py-2 border border-gray-500 text-gray-400 hover:bg-gray-500/20 transition-colors"
              >
                <RotateCcw className="h-4 w-4" />
                RESTART
              </button>

              <div className="flex items-center gap-2">
                <span className="text-gray-400 text-sm">SPEED:</span>
                {[0.5, 1, 1.5, 2].map(speed => (
                  <button
                    key={speed}
                    onClick={() => setPlaybackSpeed(speed)}
                    className={`px-2 py-1 border text-xs ${
                      playbackSpeed === speed
                        ? 'border-cyan-500 text-cyan-400'
                        : 'border-gray-600 text-gray-400 hover:border-gray-400'
                    }`}
                  >
                    {speed}x
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
          {/* Sidebar: Chapter navigation */}
          <div className="xl:col-span-1">
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-6 sticky top-8">
              <h3 className="text-lg font-semibold mb-4 text-green-400">STORY_CHAPTERS</h3>

              <div className="space-y-3">
                {storyChapters.map((chapter, index) => {
                  const Icon = chapter.icon;
                  return (
                    <button
                      key={chapter.id}
                      onClick={() => setCurrentChapter(index)}
                      className={`w-full text-left p-4 border transition-all duration-300 ${
                        currentChapter === index
                          ? 'border-cyan-500 bg-cyan-500/10 text-cyan-400'
                          : 'border-gray-600/30 hover:border-gray-400 text-gray-300 hover:text-white'
                      }`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <Icon className="h-5 w-5 flex-shrink-0" />
                        <span className="font-semibold text-sm">{index + 1}. {chapter.title}</span>
                      </div>
                      <div className="text-xs text-gray-500 mb-2">{chapter.content}</div>
                      {chapter.severity !== 'low' && (
                        <div className={`inline-flex items-center px-2 py-1 border text-xs ${getSeverityColor(chapter.severity)}`}>
                          {chapter.severity.toUpperCase()}
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Threat Actor Profile */}
              <div className="mt-8 p-4 bg-black/60 border border-red-500/30">
                <h4 className="text-red-400 font-semibold mb-3">THREAT_ACTOR_PROFILE</h4>
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-gray-400">Classification:</span>
                    <span className="text-red-400 ml-2">{threatActorProfile.name}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Sophistication:</span>
                    <span className="text-yellow-400 ml-2">{threatActorProfile.sophistication}%</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Motivation:</span>
                    <span className="text-orange-400 ml-2">{threatActorProfile.motivation}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Detected Tactics:</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {threatActorProfile.tactics.map(tactic => (
                        <span key={tactic} className="px-2 py-1 bg-red-900/30 text-red-300 text-xs border border-red-500/50">
                          {tactic.replace(/-/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Main content area */}
          <div className="xl:col-span-2">
            <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-8">
              {storyChapters[currentChapter] && (
                <>
                  {/* Chapter header */}
                  <div className="flex items-center gap-4 mb-6">
                    {React.createElement(storyChapters[currentChapter].icon, {
                      className: 'h-8 w-8 text-purple-400'
                    })}
                    <div>
                      <h2 className="text-2xl font-bold text-purple-400">
                        {currentChapter + 1}. {storyChapters[currentChapter].title}
                      </h2>
                      <p className="text-gray-400 text-sm mt-1">{storyChapters[currentChapter].content}</p>
                    </div>
                    {storyChapters[currentChapter].severity !== 'low' && (
                      <span className={`ml-auto px-3 py-1 border text-xs font-mono ${getSeverityColor(storyChapters[currentChapter].severity)}`}>
                        [{storyChapters[currentChapter].severity.toUpperCase()}_RISK]
                      </span>
                    )}
                  </div>

                  {/* Techniques quick-list (for phase chapters) */}
                  {storyChapters[currentChapter].techniques.length > 0 && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
                      {storyChapters[currentChapter].techniques.map(tech => (
                        <div key={tech.id} className="bg-black/50 border border-cyan-500/20 p-3">
                          <div className="flex justify-between items-start">
                            <span className="text-cyan-400 text-xs font-bold">{tech.id}</span>
                            <span className={`text-xs px-2 py-0.5 border ${
                              tech.score > 0.7 ? 'text-red-400 border-red-500' :
                              tech.score > 0.5 ? 'text-orange-400 border-orange-500' :
                              'text-yellow-400 border-yellow-500'
                            }`}>{(tech.score * 100).toFixed(0)}%</span>
                          </div>
                          <div className="text-white text-sm mt-1">{tech.name}</div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Main chapter body (real AI content) */}
                  <div className="prose prose-invert max-w-none mb-8 markdown-content">
                    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                      {storyChapters[currentChapter].body}
                    </ReactMarkdown>
                  </div>

                  {/* Navigation */}
                  <div className="flex justify-between items-center mt-8 pt-4 border-t border-gray-700/50">
                    <button
                      onClick={() => setCurrentChapter(Math.max(0, currentChapter - 1))}
                      disabled={currentChapter === 0}
                      className="flex items-center gap-2 px-4 py-2 border border-gray-500 text-gray-400 hover:bg-gray-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      ← PREVIOUS
                    </button>

                    <div className="text-gray-400 text-sm">
                      {currentChapter + 1} of {storyChapters.length}
                    </div>

                    <button
                      onClick={() => setCurrentChapter(Math.min(storyChapters.length - 1, currentChapter + 1))}
                      disabled={currentChapter === storyChapters.length - 1}
                      className="flex items-center gap-2 px-4 py-2 border border-gray-500 text-gray-400 hover:bg-gray-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      NEXT →
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatNarrativeEngine;
