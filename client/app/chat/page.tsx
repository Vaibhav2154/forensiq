"use client"

import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'next/navigation';
import { ArrowLeft, Send, Bot, User, ChevronDown, ChevronRight } from 'lucide-react';
import Link from 'next/link';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface Message {
  id: string;
  type: 'user' | 'bot';
  content: string;
  jsonData?: any;
  timestamp: Date;
}

interface JsonResponseData {
  answer?: string;
  summary?: string;
  top_findings?: Array<{
    finding?: string;
    description?: string;
    severity?: string;
    priority?: string;
    technique_id?: string;
    name?: string;
    relevance_score?: number;
    impact?: string;
    recommended_detections?: string[];
    recommended_mitigations?: string[];
  }>;
  detection_queries?: {
    guidance?: string;
    queries?: Array<{
      source?: string;
      description?: string;
      example_query?: string;
      name?: string;
      query?: string;
      log_source?: string;
      priority?: string;
    }>;
  };
  recommendations?: Array<{
    category?: string;
    items?: string[];
  }> | string[];
  references?: string[];
  follow_up_questions?: string[];
  confidence?: number;
}

const CollapsibleSection = ({ title, children, defaultExpanded = false }: { title: string, children: React.ReactNode, defaultExpanded?: boolean }) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  
  return (
    <div className="border-l-2 border-green-500/30 pl-3 my-2">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="flex items-center gap-2 text-cyan-400 hover:text-cyan-300 transition-colors font-mono text-sm font-bold"
      >
        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        {title}
      </button>
      {isExpanded && (
        <div className="mt-2 ml-6">
          {children}
        </div>
      )}
    </div>
  );
};

const JsonResponseRenderer = ({ jsonData, fallbackText }: { jsonData?: JsonResponseData, fallbackText: string }) => {
  if (!jsonData) {
    return <p className="whitespace-pre-wrap font-mono text-green-300">{fallbackText}</p>;
  }

  // Helper function to safely render any value as string
  const safeRender = (value: any): string => {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number') return value.toString();
    if (typeof value === 'boolean') return value.toString();
    if (typeof value === 'object') {
      try {
        return JSON.stringify(value, null, 2);
      } catch {
        return '[Object]';
      }
    }
    return String(value);
  };

  return (
    <div className="space-y-3 font-mono">
      {/* Answer */}
      {jsonData.answer && (
        <div>
          <h4 className="text-cyan-400 font-bold text-sm mb-2">[ANALYSIS_RESPONSE]</h4>
          <p className="text-green-300 text-sm leading-relaxed">{safeRender(jsonData.answer)}</p>
        </div>
      )}

      {/* Summary */}
      {jsonData.summary && (
        <div>
          <h4 className="text-cyan-400 font-bold text-sm mb-2">[EXECUTIVE_SUMMARY]</h4>
          <p className="text-green-300 text-sm bg-black/30 border border-green-500/20 p-2">{safeRender(jsonData.summary)}</p>
        </div>
      )}

      {/* Top Findings */}
      {jsonData.top_findings && jsonData.top_findings.length > 0 && (
        <CollapsibleSection title="[TOP_FINDINGS]" defaultExpanded={true}>
          <div className="space-y-2">
            {jsonData.top_findings.map((finding, index) => (
              <div key={index} className="bg-black/30 border border-yellow-500/20 p-3">
                <div className="flex justify-between items-start mb-2">
                  <h5 className="text-yellow-400 font-bold text-xs">
                    {finding.technique_id && `[${safeRender(finding.technique_id)}] `}
                    {safeRender(finding.finding || finding.name || `Finding ${index + 1}`)}
                  </h5>
                  {finding.severity && (
                    <span className={`text-xs px-2 py-1 border ${
                      safeRender(finding.severity).toLowerCase() === 'high' ? 'text-red-400 border-red-500/30' :
                      safeRender(finding.severity).toLowerCase() === 'medium' ? 'text-yellow-400 border-yellow-500/30' :
                      'text-green-400 border-green-500/30'
                    }`}>
                      {safeRender(finding.severity)}
                    </span>
                  )}
                </div>
                {finding.description && (
                  <p className="text-green-300 text-xs mb-2">{safeRender(finding.description)}</p>
                )}
                {finding.priority && (
                  <p className="text-cyan-400 text-xs">Priority: {safeRender(finding.priority)}</p>
                )}
                {finding.relevance_score && (
                  <p className="text-cyan-400 text-xs">Relevance: {(Number(finding.relevance_score) * 100).toFixed(1)}%</p>
                )}
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Detection Queries */}
      {jsonData.detection_queries && (
        <CollapsibleSection title="[DETECTION_QUERIES]">
          {jsonData.detection_queries.guidance && (
            <p className="text-green-300 text-xs mb-3 italic">{jsonData.detection_queries.guidance}</p>
          )}
          {jsonData.detection_queries.queries && jsonData.detection_queries.queries.length > 0 && (
            <div className="space-y-2">
              {jsonData.detection_queries.queries.map((query, index) => (
                <div key={index} className="bg-black/50 border border-blue-500/30 p-3">
                  <h6 className="text-blue-400 font-bold text-xs mb-1">
                    {query.name || query.source || `Query ${index + 1}`}
                  </h6>
                  {query.description && (
                    <p className="text-green-300 text-xs mb-2">{query.description}</p>
                  )}
                  {(query.example_query || query.query) && (
                    <div className="bg-gray-900/50 border border-gray-600/30 p-2 mt-2">
                      <code className="text-cyan-300 text-xs block whitespace-pre-wrap">
                        {query.example_query || query.query}
                      </code>
                    </div>
                  )}
                  {query.log_source && (
                    <p className="text-yellow-400 text-xs mt-1">Source: {query.log_source}</p>
                  )}
                  {query.priority && (
                    <p className="text-yellow-400 text-xs">Priority: {query.priority}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </CollapsibleSection>
      )}

      {/* Recommendations */}
      {jsonData.recommendations && jsonData.recommendations.length > 0 && (
        <CollapsibleSection title="[RECOMMENDATIONS]">
          <div className="space-y-2">
            {jsonData.recommendations.map((rec, index) => (
              <div key={index}>
                {typeof rec === 'string' ? (
                  <p className="text-green-300 text-xs">• {rec}</p>
                ) : rec.category ? (
                  <div className="bg-black/30 border border-purple-500/20 p-2">
                    <h6 className="text-purple-400 font-bold text-xs mb-1">{safeRender(rec.category)}</h6>
                    {rec.items && rec.items.map((item, itemIndex) => (
                      <p key={itemIndex} className="text-green-300 text-xs ml-2">• {safeRender(item)}</p>
                    ))}
                  </div>
                ) : (
                  <p className="text-green-300 text-xs">• {safeRender(rec)}</p>
                )}
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Follow-up Questions */}
      {jsonData.follow_up_questions && jsonData.follow_up_questions.length > 0 && (
        <CollapsibleSection title="[FOLLOW_UP_QUESTIONS]">
          <div className="space-y-1">
            {jsonData.follow_up_questions.map((question, index) => (
              <p key={index} className="text-cyan-300 text-xs">
                <span className="text-cyan-400">Q{index + 1}:</span> {safeRender(question)}
              </p>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* References */}
      {jsonData.references && jsonData.references.length > 0 && (
        <CollapsibleSection title="[REFERENCES]">
          <div className="space-y-1">
            {jsonData.references.map((ref, index) => (
              <p key={index} className="text-blue-400 text-xs break-all">
                • {safeRender(ref)}
              </p>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Confidence */}
      {jsonData.confidence !== undefined && (
        <div className="border-t border-green-500/20 pt-2 mt-3">
          <div className="flex items-center gap-2">
            <span className="text-cyan-400 text-xs font-bold">[CONFIDENCE]</span>
            <div className="flex-1 bg-gray-800 border border-gray-600 h-2">
              <div 
                className={`h-full ${
                  jsonData.confidence > 0.7 ? 'bg-green-500' :
                  jsonData.confidence > 0.4 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${jsonData.confidence * 100}%` }}
              />
            </div>
            <span className="text-green-400 text-xs">
              {(jsonData.confidence * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

const ChatPage = () => {
  const searchParams = useSearchParams();
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      type: 'bot',
      content: 'MITRE ATT&CK RAG Assistant initialized. I can help you understand attack techniques, tactics, and procedures using the MITRE ATT&CK framework with AI-powered responses. Ask me about specific threats, detection strategies, or mitigation approaches.',
      timestamp: new Date()
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Check for query parameter and pre-fill the input
    const query = searchParams.get('query');
    if (query) {
      setInputValue(decodeURIComponent(query));
    }
  }, [searchParams]);

  useEffect(() => {
    // Auto-scroll to bottom
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const parseJsonResponse = (responseText: string): JsonResponseData | null => {
    try {
      return JSON.parse(responseText);
    } catch (error) {
      // Try to extract JSON from text if it's wrapped in other content
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try {
          return JSON.parse(jsonMatch[0]);
        } catch (e) {
          return null;
        }
      }
      return null;
    }
  };

  const handleSendMessage = async () => {
    if (!inputValue.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      type: 'user',
      content: inputValue,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setIsTyping(true);

    try {
      // Call the MITRE RAG API on backend server
      console.log('Chat: Making API call to backend rag-query');
      console.log('Chat: Backend URL:', BACKEND_URL);
      console.log('Chat: Query:', inputValue);

      const response = await fetch(`${BACKEND_URL}/api/mitre/rag-query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query: inputValue,
          max_context_techniques: 5,
          include_source_techniques: false
        }),
      });

      console.log('Chat: Response status:', response.status);
      console.log('Chat: Response ok:', response.ok);

      if (response.ok) {
        const data = await response.json();
        console.log('Chat: Response data:', data);

        // Parse JSON response if available
        const jsonData = parseJsonResponse(data.response || '');
        
        const botResponse: Message = {
          id: (Date.now() + 1).toString(),
          type: 'bot',
          content: data.response || 'I received your message but couldn\'t generate a proper response.',
          jsonData: jsonData,
          timestamp: new Date()
        };

        setMessages(prev => [...prev, botResponse]);
      } else {
        const errorText = await response.text();
        console.error('Chat: API error response:', errorText);
        
        const errorMessage: Message = {
          id: (Date.now() + 1).toString(),
          type: 'bot',
          content: `Sorry, I encountered an error while processing your request. (Status: ${response.status})`,
          timestamp: new Date()
        };
        setMessages(prev => [...prev, errorMessage]);
      }
    } catch (error) {
      console.error('Chat: Network error:', error);
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'bot',
        content: 'Sorry, I\'m having trouble connecting to the server. Please check your connection and try again.',
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatTimestamp = (date: Date) => {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      {/* Background Grid */}
      <div
        className="fixed inset-0 opacity-5"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0, 255, 150, 0.3) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 150, 0.3) 1px, transparent 1px)
          `,
          backgroundSize: '30px 30px'
        }}
      />

      {/* Header */}
      <div className="relative z-10 border-b border-green-500/30 bg-black/90 backdrop-blur-sm">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center gap-4">
          <Link 
            href="/dashboard"
            className="p-2 hover:bg-green-900/20 border border-green-500/30 transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-green-400 hover:text-cyan-400" />
          </Link>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-black border-2 border-green-500 flex items-center justify-center">
              <Bot className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-cyan-400">[MITRE_RAG.TERMINAL]</h1>
              <div className="flex items-center gap-2 text-sm text-green-400">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span>AI_ENHANCED | JSON_STRUCTURED</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Chat Container */}
      <div className="relative z-10 max-w-4xl mx-auto h-[calc(100vh-80px)] flex flex-col">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex gap-3 ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {message.type === 'bot' && (
                <div className="w-8 h-8 bg-black border-2 border-green-500 flex items-center justify-center flex-shrink-0 mt-1">
                  <Bot className="w-4 h-4 text-green-400" />
                </div>
              )}
              
              <div className={`max-w-[80%] ${message.type === 'user' ? 'order-2' : ''}`}>
                <div
                  className={`p-3 border ${
                    message.type === 'user'
                      ? 'bg-blue-900/30 border-blue-500/50 text-blue-300 ml-auto'
                      : 'bg-green-900/20 border-green-500/30 text-green-300'
                  }`}
                >
                  {message.type === 'bot' ? (
                    <JsonResponseRenderer jsonData={message.jsonData} fallbackText={message.content} />
                  ) : (
                    <p className="whitespace-pre-wrap font-mono">{message.content}</p>
                  )}
                </div>
                <p className={`text-xs text-gray-500 mt-1 font-mono ${message.type === 'user' ? 'text-right' : ''}`}>
                  {message.type === 'user' ? '[USER]' : '[MITRE_AI]'} {formatTimestamp(message.timestamp)}
                </p>
              </div>

              {message.type === 'user' && (
                <div className="w-8 h-8 bg-black border-2 border-blue-500 flex items-center justify-center flex-shrink-0 mt-1 order-3">
                  <User className="w-4 h-4 text-blue-400" />
                </div>
              )}
            </div>
          ))}

          {isTyping && (
            <div className="flex gap-3 justify-start">
              <div className="w-8 h-8 bg-black border-2 border-green-500 flex items-center justify-center flex-shrink-0 mt-1">
                <Bot className="w-4 h-4 text-green-400" />
              </div>
              <div className="bg-green-900/20 border border-green-500/30 text-green-300 p-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono">[PROCESSING_QUERY]</span>
                  <div className="flex gap-1">
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-bounce"></div>
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                  </div>
                </div>
              </div>
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-4 bg-black/90 border-t border-green-500/30">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <span className="absolute left-4 top-3 text-cyan-400 text-sm font-mono">&gt;</span>
              <textarea
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Enter MITRE ATT&CK query..."
                className="w-full bg-black/70 border border-green-500/30 pl-10 pr-4 py-3 text-green-400 placeholder-green-600/50 focus:ring-2 focus:ring-cyan-500 focus:border-cyan-400 resize-none text-sm font-mono hover:border-green-400 transition-colors"
                rows={1}
                disabled={isTyping}
              />
            </div>
            <button
              onClick={handleSendMessage}
              disabled={!inputValue.trim() || isTyping}
              className="bg-black border-2 border-green-500 hover:border-cyan-400 disabled:border-gray-600 disabled:cursor-not-allowed text-green-400 hover:text-cyan-400 disabled:text-gray-600 px-4 py-3 transition-all duration-300 hover:shadow-[0_0_15px_rgba(0,255,150,0.3)] disabled:shadow-none"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
          
          {/* Quick Actions */}
          <div className="flex flex-wrap gap-2 mt-3">
            <button
              onClick={() => setInputValue('What is MITRE ATT&CK framework?')}
              className="text-xs px-3 py-1 bg-gray-900/50 border border-gray-600/50 text-gray-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors font-mono"
            >
              [MITRE_OVERVIEW]
            </button>
            <button
              onClick={() => setInputValue('What are common phishing techniques?')}
              className="text-xs px-3 py-1 bg-gray-900/50 border border-gray-600/50 text-gray-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors font-mono"
            >
              [PHISHING]
            </button>
            <button
              onClick={() => setInputValue('How to detect lateral movement?')}
              className="text-xs px-3 py-1 bg-gray-900/50 border border-gray-600/50 text-gray-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors font-mono"
            >
              [LATERAL_MOVEMENT]
            </button>
          </div>
        </div>
      </div>

      {/* Custom Styles */}
      <style jsx>{`
        .custom-scrollbar {
          scrollbar-width: thin;
          scrollbar-color: #00ff96 #1a1a1a;
        }

        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }

        .custom-scrollbar::-webkit-scrollbar-track {
          background: #1a1a1a;
          border-radius: 4px;
        }

        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #00ff96;
          border-radius: 4px;
          border: 2px solid #1a1a1a;
        }

        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #00ffaa;
        }
      `}</style>
    </div>
  );
};

export default ChatPage;
