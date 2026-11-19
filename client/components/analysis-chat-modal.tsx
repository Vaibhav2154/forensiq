'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Bot, Send, Sparkles, User, X, Layers, AlertTriangle, ShieldCheck } from 'lucide-react';
import { chatWithAnalysisHistory, chatWithStoredAnalysis } from '@/lib/api';
import type { AnalysisChatTurn, LogAnalysisResponse } from '@/lib/types';

export interface StoredAnalysisOption {
  id: string;
  label: string;
  severity?: string;
  timestamp?: string;
  techniquesCount?: number;
  analysis?: LogAnalysisResponse;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  referencedEventIds?: string[];
  referencedKnowledgeIds?: string[];
  followUpQuestions?: string[];
  evidenceCaveats?: string[];
  analysesConsulted?: string[];
  modelUsed?: string;
  processingTimeMs?: number;
  isError?: boolean;
}

interface AnalysisChatModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Primary stored MongoDB analysis ID, or null to chat across recent history */
  initialAnalysisId: string | null;
  /** Optional list of stored analyses for quick switching inside the chatbot */
  availableAnalyses?: StoredAnalysisOption[];
}

const SINGLE_ANALYSIS_PROMPTS = [
  'Explain the attack path and distinguish observed facts from inferences.',
  'What evidence or telemetry is still missing or unconfirmed?',
  'Walk through the immediate recommended actions and rollback considerations.',
  'Summarize the key IOCs and which log events triggered each MITRE ATT&CK match.',
];

const HISTORY_PROMPTS = [
  'Summarize the highest-severity incidents across my recent stored analyses.',
  'Which MITRE ATT&CK techniques or IOCs appear repeatedly across my history?',
  'What are the top immediate defensive actions prioritized across recent analyses?',
];

const AnalysisChatModal: React.FC<AnalysisChatModalProps> = ({
  isOpen,
  onClose,
  initialAnalysisId,
  availableAnalyses = [],
}) => {
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(initialAnalysisId);
  const [includeRecentContext, setIncludeRecentContext] = useState(false);
  const [messagesByScope, setMessagesByScope] = useState<Record<string, ChatMessage[]>>({});
  const [inputValue, setInputValue] = useState('');
  const [sending, setSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scopeKey = activeAnalysisId ?? '__ALL_HISTORY__';

  const activeOption = useMemo(
    () => availableAnalyses.find((item) => item.id === activeAnalysisId) || null,
    [availableAnalyses, activeAnalysisId]
  );

  // Sync active analysis whenever modal is opened for a new selection
  useEffect(() => {
    if (isOpen) {
      setActiveAnalysisId(initialAnalysisId);
    }
  }, [isOpen, initialAnalysisId]);

  // Escape key closes modal
  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = prevOverflow || 'unset';
    };
  }, [isOpen, onClose]);

  const messages = useMemo<ChatMessage[]>(() => {
    const existing = messagesByScope[scopeKey];
    if (existing && existing.length > 0) return existing;

    const introContent = activeAnalysisId
      ? `Connected to stored analysis **${activeOption?.label || activeAnalysisId}** (decrypted from MongoDB). Ask me about its findings, observed vs. inferred attack path, timeline events, IOCs, verified MITRE ATT&CK/CVE context, evidence gaps, or approval-gated remediation steps.`
      : `Connected to your recent stored analyses in MongoDB (${availableAnalyses.length || 'up to 5'} recent records). Ask me to compare incidents, highlight recurring techniques/IOCs, or prioritize defensive actions across your history.`;

    return [
      {
        id: `welcome-${scopeKey}`,
        role: 'assistant',
        content: introContent,
        timestamp: new Date(),
        followUpQuestions: activeAnalysisId ? SINGLE_ANALYSIS_PROMPTS : HISTORY_PROMPTS,
      },
    ];
  }, [messagesByScope, scopeKey, activeAnalysisId, activeOption, availableAnalyses.length]);

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, sending, isOpen]);

  const sendMessage = async (textOverride?: string) => {
    const question = (textOverride ?? inputValue).trim();
    if (!question || sending) return;

    const currentScope = scopeKey;
    const priorStored = messagesByScope[currentScope] || [];

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: question,
      timestamp: new Date(),
    };

    const conversationHistory: AnalysisChatTurn[] = priorStored
      .filter((m) => !m.isError)
      .slice(-10)
      .map((m) => ({
        role: m.role,
        content: m.content,
      }));

    setMessagesByScope((prev) => ({
      ...prev,
      [currentScope]: [...(prev[currentScope] || []), userMsg],
    }));
    if (!textOverride) {
      setInputValue('');
    }
    setSending(true);

    try {
      const response = activeAnalysisId
        ? await chatWithStoredAnalysis(activeAnalysisId, {
            message: question,
            conversation_history: conversationHistory,
            include_recent_context: includeRecentContext,
          })
        : await chatWithAnalysisHistory({
            message: question,
            limit: 5,
            conversation_history: conversationHistory,
          });

      const botMsg: ChatMessage = {
        id: `bot-${Date.now() + 1}`,
        role: 'assistant',
        content: response.answer,
        timestamp: new Date(),
        referencedEventIds: response.referenced_event_ids,
        referencedKnowledgeIds: response.referenced_knowledge_ids,
        followUpQuestions: response.follow_up_questions,
        evidenceCaveats: response.evidence_caveats,
        analysesConsulted: response.analyses_consulted,
        modelUsed: response.model_used,
        processingTimeMs: response.processing_time_ms,
      };

      setMessagesByScope((prev) => ({
        ...prev,
        [currentScope]: [...(prev[currentScope] || []), botMsg],
      }));
    } catch (err) {
      const errText = err instanceof Error ? err.message : 'Failed to reach analysis chatbot';
      const errMsg: ChatMessage = {
        id: `err-${Date.now() + 1}`,
        role: 'assistant',
        content: `**[ERROR]** Unable to complete your query: ${errText}`,
        timestamp: new Date(),
        isError: true,
      };
      setMessagesByScope((prev) => ({
        ...prev,
        [currentScope]: [...(prev[currentScope] || []), errMsg],
      }));
    } finally {
      setSending(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-[60] bg-black/85 backdrop-blur-sm flex items-center justify-center p-2 sm:p-4 font-mono"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-black border-2 border-cyan-500/60 rounded-2xl w-full max-w-4xl h-[88vh] flex flex-col overflow-hidden shadow-[0_0_35px_rgba(0,255,255,0.2)]">
        {/* Header */}
        <div className="bg-black/95 border-b border-cyan-500/30 px-4 py-3 flex flex-col gap-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 border border-cyan-400/60 bg-cyan-950/30 flex items-center justify-center flex-shrink-0">
                <Bot className="w-5 h-5 text-cyan-400" />
              </div>
              <div className="min-w-0">
                <h3 className="text-sm sm:text-base font-bold text-cyan-400 truncate">
                  [FORENSIQ_ANALYSIS_CHATBOT.GEMINI]
                </h3>
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-green-400">
                  <span className="inline-flex items-center gap-1">
                    <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                    MONGODB_DECRYPTED
                  </span>
                  {activeOption?.severity && (
                    <span className="px-1.5 py-0.5 border border-orange-500/40 text-orange-300 uppercase">
                      {activeOption.severity}
                    </span>
                  )}
                  {activeOption?.techniquesCount !== undefined && (
                    <span className="px-1.5 py-0.5 border border-purple-500/40 text-purple-300">
                      {activeOption.techniquesCount} TECH
                    </span>
                  )}
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={onClose}
              aria-label="Close analysis chatbot"
              className="p-1.5 border border-red-500/40 text-red-400 hover:bg-red-900/30 hover:text-red-300 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Context Scope Switcher & Cross-History Toggle */}
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-xs">
            <div className="flex items-center gap-2 flex-1 min-w-[200px]">
              <span className="text-gray-400 whitespace-nowrap">[SCOPE]:</span>
              <select
                value={activeAnalysisId ?? '__ALL__'}
                onChange={(e) =>
                  setActiveAnalysisId(e.target.value === '__ALL__' ? null : e.target.value)
                }
                className="flex-1 max-w-md bg-black border border-cyan-500/40 text-cyan-300 px-2 py-1 text-xs focus:outline-none focus:border-green-400"
              >
                <option value="__ALL__">ALL RECENT STORED ANALYSES (CROSS-HISTORY)</option>
                {availableAnalyses.map((opt) => (
                  <option key={opt.id} value={opt.id}>
                    {opt.label}
                    {opt.severity ? ` [${opt.severity.toUpperCase()}]` : ''}
                    {opt.timestamp ? ` · ${opt.timestamp}` : ''}
                  </option>
                ))}
                {activeAnalysisId &&
                  !availableAnalyses.some((opt) => opt.id === activeAnalysisId) && (
                    <option value={activeAnalysisId}>STORED ANALYSIS ({activeAnalysisId})</option>
                  )}
              </select>
            </div>

            {activeAnalysisId && (
              <label className="inline-flex items-center gap-1.5 text-xs text-gray-300 cursor-pointer select-none border border-gray-700/70 px-2 py-1 hover:border-cyan-500/40">
                <input
                  type="checkbox"
                  checked={includeRecentContext}
                  onChange={(e) => setIncludeRecentContext(e.target.checked)}
                  className="accent-cyan-400"
                />
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>Compare w/ recent history</span>
              </label>
            )}
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'assistant' && (
                <div className="w-8 h-8 border border-green-500/60 bg-black flex items-center justify-center flex-shrink-0 mt-1">
                  <Bot className="w-4 h-4 text-green-400" />
                </div>
              )}

              <div className={`max-w-[85%] ${msg.role === 'user' ? 'order-2' : ''}`}>
                <div
                  className={`p-3 border text-xs sm:text-sm ${
                    msg.role === 'user'
                      ? 'bg-blue-950/30 border-blue-500/50 text-blue-200'
                      : msg.isError
                      ? 'bg-red-950/30 border-red-500/50 text-red-300'
                      : 'bg-green-950/15 border-green-500/30 text-green-200'
                  }`}
                >
                  {msg.role === 'assistant' ? (
                    <div className="prose prose-invert prose-sm max-w-none prose-headings:text-cyan-300 prose-strong:text-green-300 prose-code:text-cyan-200">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.content}</ReactMarkdown>
                    </div>
                  ) : (
                    <p className="whitespace-pre-wrap">{msg.content}</p>
                  )}

                  {/* Grounded Citations */}
                  {((msg.referencedKnowledgeIds && msg.referencedKnowledgeIds.length > 0) ||
                    (msg.referencedEventIds && msg.referencedEventIds.length > 0)) && (
                    <div className="mt-3 pt-2 border-t border-green-500/20 space-y-1.5 text-[11px]">
                      {msg.referencedKnowledgeIds && msg.referencedKnowledgeIds.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="inline-flex items-center gap-1 text-purple-300 font-semibold">
                            <ShieldCheck className="w-3.5 h-3.5" /> OKF_REFS:
                          </span>
                          {msg.referencedKnowledgeIds.map((kid) => (
                            <span
                              key={kid}
                              className="px-1.5 py-0.5 border border-purple-500/40 bg-purple-950/30 text-purple-200"
                            >
                              {kid}
                            </span>
                          ))}
                        </div>
                      )}
                      {msg.referencedEventIds && msg.referencedEventIds.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-cyan-300 font-semibold">EVENT_REFS:</span>
                          {msg.referencedEventIds.map((eid) => (
                            <span
                              key={eid}
                              className="px-1.5 py-0.5 border border-cyan-500/40 bg-cyan-950/30 text-cyan-200"
                            >
                              {eid}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Evidence Caveats */}
                  {msg.evidenceCaveats && msg.evidenceCaveats.length > 0 && (
                    <div className="mt-2 p-2 border border-yellow-500/30 bg-yellow-950/20 text-[11px] text-yellow-200">
                      <div className="flex items-center gap-1.5 font-semibold text-yellow-300 mb-1">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>[EVIDENCE_CAVEATS]</span>
                      </div>
                      <ul className="list-disc ml-4 space-y-0.5">
                        {msg.evidenceCaveats.map((cav, idx) => (
                          <li key={idx}>{cav}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Clickable Follow-Up Questions */}
                  {msg.followUpQuestions && msg.followUpQuestions.length > 0 && (
                    <div className="mt-3 pt-2 border-t border-cyan-500/20">
                      <div className="flex items-center gap-1 text-[11px] text-cyan-400 mb-1.5">
                        <Sparkles className="w-3 h-3" />
                        <span>[SUGGESTED_QUESTIONS]</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {msg.followUpQuestions.map((q, idx) => (
                          <button
                            key={idx}
                            type="button"
                            disabled={sending}
                            onClick={() => sendMessage(q)}
                            className="text-left text-[11px] px-2 py-1 border border-cyan-500/40 bg-black/70 text-cyan-300 hover:bg-cyan-900/30 hover:border-cyan-300 transition-colors disabled:opacity-50 cursor-pointer"
                          >
                            &gt; {q}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div
                  className={`text-[10px] text-gray-500 mt-1 flex flex-wrap items-center gap-2 ${
                    msg.role === 'user' ? 'justify-end' : 'justify-start'
                  }`}
                >
                  <span>
                    {msg.role === 'user' ? '[ANALYST]' : '[GEMINI_ANALYSIS_BOT]'}{' '}
                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                  {msg.modelUsed && <span>· {msg.modelUsed}</span>}
                  {msg.processingTimeMs !== undefined && (
                    <span>· {(msg.processingTimeMs / 1000).toFixed(2)}s</span>
                  )}
                  {msg.analysesConsulted && msg.analysesConsulted.length > 1 && (
                    <span>· {msg.analysesConsulted.length} analyses</span>
                  )}
                </div>
              </div>

              {msg.role === 'user' && (
                <div className="w-8 h-8 border border-blue-500/60 bg-black flex items-center justify-center flex-shrink-0 mt-1 order-3">
                  <User className="w-4 h-4 text-blue-400" />
                </div>
              )}
            </div>
          ))}

          {sending && (
            <div className="flex gap-3 justify-start">
              <div className="w-8 h-8 border border-green-500/60 bg-black flex items-center justify-center flex-shrink-0 mt-1">
                <Bot className="w-4 h-4 text-green-400" />
              </div>
              <div className="bg-green-950/20 border border-green-500/30 text-green-300 px-3 py-2 text-xs flex items-center gap-2">
                <span>[QUERYING_GEMINI_OVER_STORED_ANALYSIS]</span>
                <span className="inline-flex gap-1">
                  <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce" />
                  <span
                    className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce"
                    style={{ animationDelay: '0.15s' }}
                  />
                  <span
                    className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce"
                    style={{ animationDelay: '0.3s' }}
                  />
                </span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-3 sm:p-4 bg-black/95 border-t border-cyan-500/30">
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <span className="absolute left-3 top-2.5 text-cyan-400 text-xs sm:text-sm">&gt;</span>
              <textarea
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                  }
                }}
                placeholder={
                  activeAnalysisId
                    ? 'Ask Gemini about findings, IOCs, attack path, evidence gaps, or remediation...'
                    : 'Ask Gemini across your recent stored analyses...'
                }
                rows={1}
                disabled={sending}
                className="w-full bg-black border border-green-500/40 pl-8 pr-3 py-2 text-green-300 placeholder-green-600/60 focus:outline-none focus:border-cyan-400 resize-none text-xs sm:text-sm"
              />
            </div>
            <button
              type="button"
              onClick={() => sendMessage()}
              disabled={!inputValue.trim() || sending}
              className="px-4 py-2 bg-black border-2 border-cyan-500 hover:border-green-400 text-cyan-400 hover:text-green-400 disabled:border-gray-700 disabled:text-gray-600 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5 text-xs sm:text-sm cursor-pointer"
            >
              <Send className="w-4 h-4" />
              <span className="hidden sm:inline">[SEND]</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AnalysisChatModal;
