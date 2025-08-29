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
  enhanced_analysis: string;
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
  techniques: string[];
  narrative: string;
}

interface ThreatActor {
  name: string;
  sophistication: number;
  motivation: string;
  tactics: string[];
}

const ThreatNarrativeEngine: React.FC<{ data: ThreatStoryData }> = ({ data }) => {
  const [currentChapter, setCurrentChapter] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null);

  // Generate narrative chapters from analysis data
  const storyChapters: StoryChapter[] = useMemo(() => {
    const chapters: StoryChapter[] = [];

    // Chapter 1: Initial Discovery
    chapters.push({
      id: 'discovery',
      title: 'The Discovery',
      icon: Eye,
      content: 'Initial system reconnaissance detected',
      severity: 'medium',
      timestamp: data.analysis_timestamp,
      techniques: data.matched_techniques.filter(t => t.kill_chain_phases.includes('discovery')).map(t => t.name),
      narrative: `## Initial Threat Detection

At **${new Date(data.analysis_timestamp).toLocaleTimeString()}**, our advanced threat detection systems identified suspicious activity. 

### Key Observations:
- The attack began with **reconnaissance activities**
- Suggests a *sophisticated threat actor* conducting preliminary intelligence gathering
- The observed techniques indicate an adversary with knowledge of:
  - Windows systems
  - Registry manipulation
  - System utilities

> **Alert Level**: Medium Priority - Requires immediate investigation

### Attack Progression:
1. Initial system scanning
2. Registry enumeration
3. Information gathering phase

The behavior patterns suggest this is not a random attack but a **targeted reconnaissance mission** by an experienced adversary.`
    });

    // Chapter 2: Initial Access (if applicable)
    const initialAccessTechniques = data.matched_techniques.filter(t => 
      t.kill_chain_phases.includes('initial-access') || t.kill_chain_phases.includes('execution')
    );
    if (initialAccessTechniques.length > 0) {
      chapters.push({
        id: 'initial-access',
        title: 'The Breach',
        icon: Unlock,
        content: 'Initial system access achieved',
        severity: 'high',
        techniques: initialAccessTechniques.map(t => t.name),
        narrative: `## System Compromise Detected

Following the reconnaissance phase, the threat actor successfully gained initial access to the target system.

### Breach Details:
- **Sophisticated techniques** employed to bypass security measures
- Initial security perimeter has been **compromised**
- Threat actor has established a **foothold** within the environment

#### Attack Vector Analysis:
The adversary leveraged the following methods:
${initialAccessTechniques.map(t => `- **${t.name}** (Relevance: ${(t.relevance_score * 100).toFixed(1)}%)`).join('\n')}

> **⚠️ Critical Alert**: This marks a significant escalation in the attack progression

### Immediate Actions Required:
1. **Isolate** affected systems
2. **Preserve** forensic evidence
3. **Analyze** attack vectors
4. **Implement** containment measures`
      });
    }

    // Chapter 3: Persistence
    const persistenceTechniques = data.matched_techniques.filter(t => 
      t.kill_chain_phases.includes('persistence') || t.kill_chain_phases.includes('privilege-escalation')
    );
    if (persistenceTechniques.length > 0) {
      chapters.push({
        id: 'persistence',
        title: 'Establishing Foothold',
        icon: Lock,
        content: 'Persistent access mechanisms deployed',
        severity: 'high',
        techniques: persistenceTechniques.map(t => t.name),
        narrative: `## Persistence Mechanisms Deployed

The adversary has moved to establish **persistence** within the compromised environment.

### Persistence Techniques:
${persistenceTechniques.map(t => `- **${t.name}**\n  - *Kill Chain Phase*: ${t.kill_chain_phases.join(', ')}\n  - *Platforms*: ${t.platforms.join(', ')}\n  - *Relevance*: ${(t.relevance_score * 100).toFixed(1)}%`).join('\n\n')}

### Attack Characteristics:
- **Registry modifications** for persistence
- **System utilities** leveraged for stealth
- **Maintains access** even after system reboots
- **Evades** security interventions

> **📊 Threat Assessment**: This behavior is characteristic of **Advanced Persistent Threats (APTs)**

### Defense Recommendations:
1. **Monitor** registry keys for unauthorized changes
2. **Implement** application whitelisting
3. **Deploy** endpoint detection and response (EDR)
4. **Review** system startup programs and services`
      });
    }

    // Chapter 4: Defense Evasion
    const evasionTechniques = data.matched_techniques.filter(t => 
      t.kill_chain_phases.includes('defense-evasion')
    );
    if (evasionTechniques.length > 0) {
      chapters.push({
        id: 'evasion',
        title: 'Staying Hidden',
        icon: Shield,
        content: 'Defensive measures circumvented',
        severity: 'critical',
        techniques: evasionTechniques.map(t => t.name),
        narrative: `## Evasion Tactics Detected

The threat actor is actively working to **evade detection** and analysis.

### Evasion Techniques Observed:
${evasionTechniques.map(t => `#### ${t.name}
- **Description**: ${t.description.substring(0, 200)}...
- **Kill Chain**: ${t.kill_chain_phases.join(', ')}
- **Risk Score**: ${(t.relevance_score * 100).toFixed(1)}%`).join('\n\n')}

### Threat Intelligence:
- **Disabling logging mechanisms** to avoid detection
- **Employing stealth techniques** for persistence
- **Demonstrates awareness** of security monitoring capabilities
- **Taking active steps** to remain undetected

> **🚨 CRITICAL**: Advanced evasion indicates sophisticated threat actor

### Stealth Indicators:
- [x] Log tampering attempts
- [x] Anti-forensics techniques
- [x] Security tool evasion
- [x] Process hiding mechanisms

**Recommendation**: Implement advanced threat hunting and behavioral analysis.`
      });
    }

    // Chapter 5: The Resolution (Recommendations)
    chapters.push({
      id: 'resolution',
      title: 'The Response',
      icon: Target,
      content: 'Security response recommendations',
      severity: 'low',
      techniques: ['Immediate Response', 'Long-term Hardening'],
      narrative: `## Incident Response & Mitigation

Based on the analysis of this incident, **immediate containment** and investigation actions are required.

### Incident Classification:
- **Threat Level**: ${data.matched_techniques.length > 3 ? 'HIGH' : 'MEDIUM'}
- **Attack Sophistication**: ${data.matched_techniques.reduce((sum, t) => sum + t.relevance_score, 0) / data.matched_techniques.length > 0.7 ? 'Advanced' : 'Intermediate'}
- **MITRE ATT&CK Mapping**: ✅ Complete

### Immediate Actions (Next 1-4 Hours):
1. **🚨 Isolate** affected systems from network
2. **🔍 Preserve** all forensic evidence
3. **📊 Document** all findings and timelines
4. **🛡️ Activate** incident response team

### Short-term Response (Next 24-48 Hours):
- **Threat Hunt** for similar indicators across environment
- **Patch** identified vulnerabilities
- **Review** and strengthen access controls
- **Update** security monitoring rules

### Long-term Hardening (Next 30 Days):
- **Implement** additional monitoring for detected techniques
- **Conduct** tabletop exercises based on this incident
- **Review** and update security policies
- **Train** staff on new threat indicators

> **✅ Success Metrics**: No similar attacks detected, improved detection capabilities, reduced mean time to detection (MTTD)`
    });

    return chapters;
  }, [data]);

  // Generate threat actor profile
  const threatActorProfile: ThreatActor = useMemo(() => {
    const avgSophistication = data.matched_techniques.reduce((sum, t) => sum + t.relevance_score, 0) / data.matched_techniques.length;
    const uniquePhases = [...new Set(data.matched_techniques.flatMap(t => t.kill_chain_phases))];
    
    return {
      name: avgSophistication > 0.7 ? 'Advanced Persistent Threat' : avgSophistication > 0.5 ? 'Skilled Adversary' : 'Opportunistic Attacker',
      sophistication: Math.round(avgSophistication * 100),
      motivation: uniquePhases.includes('persistence') ? 'Long-term Access' : uniquePhases.includes('discovery') ? 'Information Gathering' : 'System Compromise',
      tactics: uniquePhases
    };
  }, [data]);

  // Auto-play functionality
  useEffect(() => {
    if (isPlaying && currentChapter < storyChapters.length - 1) {
      const timer = setTimeout(() => {
        setCurrentChapter(prev => prev + 1);
      }, 5000 / playbackSpeed);
      return () => clearTimeout(timer);
    } else if (isPlaying && currentChapter >= storyChapters.length - 1) {
      setIsPlaying(false);
    }
  }, [isPlaying, currentChapter, storyChapters.length, playbackSpeed]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 border-red-500 bg-red-900/20';
      case 'high': return 'text-orange-400 border-orange-500 bg-orange-900/20';
      case 'medium': return 'text-yellow-400 border-yellow-500 bg-yellow-900/20';
      case 'low': return 'text-blue-400 border-blue-500 bg-blue-900/20';
      default: return 'text-gray-400 border-gray-500 bg-gray-900/20';
    }
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
                <p className="text-gray-400 text-sm">AI-powered storytelling for cybersecurity incidents</p>
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
          {/* Story Navigation */}
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
                        <Icon className="h-5 w-5" />
                        <span className="font-semibold">{index + 1}. {chapter.title}</span>
                      </div>
                      <div className="text-xs text-gray-400 mb-2">{chapter.content}</div>
                      <div className={`inline-flex items-center px-2 py-1 border text-xs ${getSeverityColor(chapter.severity)}`}>
                        {chapter.severity.toUpperCase()}
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Threat Actor Profile */}
              <div className="mt-8 p-4 bg-black/60 border border-red-500/30">
                <h4 className="text-red-400 font-semibold mb-3">THREAT_ACTOR_PROFILE</h4>
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-gray-400">Name:</span>
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
                    <span className="text-gray-400">Tactics:</span>
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

          {/* Main Story Content */}
          <div className="xl:col-span-2">
            <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-8">
              {storyChapters[currentChapter] && (
                <>
                  <div className="flex items-center gap-4 mb-6">
                    {React.createElement(storyChapters[currentChapter].icon, {
                      className: "h-8 w-8 text-purple-400"
                    })}
                    <div>
                      <h2 className="text-2xl font-bold text-purple-400">
                        Chapter {currentChapter + 1}: {storyChapters[currentChapter].title}
                      </h2>
                      <p className="text-gray-400 text-sm mt-1">{storyChapters[currentChapter].content}</p>
                    </div>
                  </div>

                  {/* Chapter narrative */}
                  <div className="prose prose-invert max-w-none mb-8 markdown-content">
                    <ReactMarkdown 
                      remarkPlugins={[remarkGfm]}
                      components={{
                        h1: ({ children }) => <h1 className="text-3xl font-bold text-cyan-400 mb-6">{children}</h1>,
                        h2: ({ children }) => <h2 className="text-2xl font-bold text-purple-400 mb-4 mt-6">{children}</h2>,
                        h3: ({ children }) => <h3 className="text-xl font-semibold text-green-400 mb-3 mt-4">{children}</h3>,
                        h4: ({ children }) => <h4 className="text-lg font-semibold text-yellow-400 mb-2 mt-3">{children}</h4>,
                        p: ({ children }) => <p className="text-gray-300 mb-4 leading-relaxed">{children}</p>,
                        strong: ({ children }) => <strong className="text-green-400 font-bold">{children}</strong>,
                        em: ({ children }) => <em className="text-cyan-300 italic">{children}</em>,
                        ul: ({ children }) => <ul className="list-disc list-inside mb-4 space-y-2 text-gray-300">{children}</ul>,
                        ol: ({ children }) => <ol className="list-decimal list-inside mb-4 space-y-2 text-gray-300">{children}</ol>,
                        li: ({ children }) => <li className="text-gray-300 ml-4">{children}</li>,
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
                          <table className="min-w-full border border-gray-600 mb-4">
                            {children}
                          </table>
                        ),
                        th: ({ children }) => (
                          <th className="border border-gray-600 px-4 py-2 bg-gray-800 text-cyan-400 font-semibold">
                            {children}
                          </th>
                        ),
                        td: ({ children }) => (
                          <td className="border border-gray-600 px-4 py-2 text-gray-300">
                            {children}
                          </td>
                        )
                      }}
                    >
                      {storyChapters[currentChapter].narrative}
                    </ReactMarkdown>
                  </div>

                  {/* Technical details */}
                  <div className="bg-black/60 border border-gray-600/30 p-6 mb-6">
                    <h4 className="text-cyan-400 font-semibold mb-3">TECHNICAL_DETAILS</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <span className="text-gray-400 text-sm">Associated Techniques:</span>
                        <div className="mt-2 space-y-1">
                          {storyChapters[currentChapter].techniques.map((technique, idx) => (
                            <div key={idx} className="text-cyan-300 text-sm bg-black/40 p-2 border border-cyan-500/20">
                              {technique}
                            </div>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-gray-400 text-sm">Severity Assessment:</span>
                        <div className={`mt-2 p-3 border ${getSeverityColor(storyChapters[currentChapter].severity)}`}>
                          <div className="text-lg font-bold">{storyChapters[currentChapter].severity.toUpperCase()}</div>
                          <div className="text-xs opacity-75">Risk Level</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Enhanced analysis for current chapter */}
                  {currentChapter === storyChapters.length - 1 && (
                    <div className="bg-black/60 border border-green-500/30 p-6">
                      <h4 className="text-green-400 font-semibold mb-4">DETAILED_ANALYSIS_REPORT</h4>
                      <div className="markdown-content">
                        <ReactMarkdown 
                          remarkPlugins={[remarkGfm]}
                          components={{
                            h1: ({ children }) => <h1 className="text-2xl font-bold text-cyan-400 mb-4">{children}</h1>,
                            h2: ({ children }) => <h2 className="text-xl font-bold text-green-400 mb-3">{children}</h2>,
                            h3: ({ children }) => <h3 className="text-lg font-semibold text-yellow-400 mb-2">{children}</h3>,
                            h4: ({ children }) => <h4 className="text-base font-semibold text-purple-400 mb-2">{children}</h4>,
                            p: ({ children }) => <p className="text-gray-300 mb-3 leading-relaxed text-sm">{children}</p>,
                            strong: ({ children }) => <strong className="text-green-400 font-bold">{children}</strong>,
                            em: ({ children }) => <em className="text-cyan-300 italic">{children}</em>,
                            ul: ({ children }) => <ul className="list-disc list-inside mb-3 space-y-1 text-gray-300 text-sm">{children}</ul>,
                            ol: ({ children }) => <ol className="list-decimal list-inside mb-3 space-y-1 text-gray-300 text-sm">{children}</ol>,
                            li: ({ children }) => <li className="text-gray-300 ml-2">{children}</li>,
                            blockquote: ({ children }) => (
                              <blockquote className="border-l-4 border-cyan-500 bg-cyan-900/20 pl-3 py-2 my-3 italic text-cyan-200 text-sm">
                                {children}
                              </blockquote>
                            ),
                            code: ({ children }) => (
                              <code className="bg-black/50 text-green-400 px-1 py-0.5 rounded font-mono text-xs border border-green-500/30">
                                {children}
                              </code>
                            )
                          }}
                        >
                          {data.enhanced_analysis}
                        </ReactMarkdown>
                      </div>
                    </div>
                  )}

                  {/* Navigation */}
                  <div className="flex justify-between items-center mt-8">
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
