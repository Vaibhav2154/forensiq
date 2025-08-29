import React, { useState, useEffect, useRef } from 'react';

interface Message {
  id: string;
  type: 'user' | 'bot';
  content: string;
  timestamp: Date;
}

const Chatbot = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      type: 'bot',
      content: 'THREAT_ANALYSIS_BOT.AI initialized. Ready to assist with cybersecurity queries.',
      timestamp: new Date()
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [showCursor, setShowCursor] = useState(true);
  const [terminalText, setTerminalText] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const fullTerminalText = '> FORENSIQ_ASSISTANT.EXE --MODE=INTERACTIVE';

  useEffect(() => {
    // Terminal typing effect when chat opens
    if (isOpen && terminalText === '') {
      let i = 0;
      const typeInterval = setInterval(() => {
        if (i <= fullTerminalText.length) {
          setTerminalText(fullTerminalText.slice(0, i));
          i++;
        } else {
          clearInterval(typeInterval);
        }
      }, 50);
      return () => clearInterval(typeInterval);
    }
  }, [isOpen]);

  useEffect(() => {
    // Cursor blinking
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 500);
    return () => clearInterval(cursorInterval);
  }, []);

  useEffect(() => {
    // Auto-scroll to bottom
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

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

    // Simulate bot response
    setTimeout(() => {
      const botResponse: Message = {
        id: (Date.now() + 1).toString(),
        type: 'bot',
        content: getBotResponse(inputValue),
        timestamp: new Date()
      };
      setMessages(prev => [...prev, botResponse]);
      setIsTyping(false);
    }, 1000 + Math.random() * 1500);
  };

  const getBotResponse = (input: string) => {
    const lowerInput = input.toLowerCase();
    
    if (lowerInput.includes('threat') || lowerInput.includes('attack')) {
      return 'Analyzing threat patterns in your query. **MITRE ATT&CK** framework suggests monitoring for indicators of compromise. Would you like me to run a deep scan analysis?';
    }
    
    if (lowerInput.includes('log') || lowerInput.includes('analyze')) {
      return 'Log analysis protocols activated. Please upload your log files to the main analysis panel for comprehensive **MITRE ATT&CK** technique mapping and AI enhancement.';
    }
    
    if (lowerInput.includes('help')) {
      return `Available commands:
      
**> analyze [logs]** - Run threat detection
**> scan [system]** - Perform security scan  
**> mitre [technique]** - Query MITRE database
**> status** - Check system status

How can I assist with your cybersecurity needs?`;
    }
    
    if (lowerInput.includes('status')) {
      return 'System status: **OPERATIONAL**. All threat detection modules active. AI enhancement: **ENABLED**. Last scan: 00:42:17 ago.';
    }

    return 'Query processed. For advanced threat analysis, please use the main analysis interface. Type **help** for available commands.';
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatBotMessage = (text: string) => {
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong class="text-green-400">$1</strong>')
      .replace(/\*(.*?)\*/g, '<em class="text-cyan-400">$1</em>')
      .replace(/\n/g, '<br/>');
  };

  return (
    <>
      {/* Floating Chat Icon */}
      <div className="fixed bottom-6 right-6 z-50">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className={`relative group w-14 h-14 bg-black border-2 hover:border-cyan-400 transition-all duration-300 flex items-center justify-center ${
            isOpen ? 'border-red-500 rotate-45' : 'border-green-500 hover:shadow-[0_0_20px_rgba(0,255,150,0.5)]'
          }`}
        >
          {isOpen ? (
            <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
          )}
          
          {/* Pulse animation */}
          {!isOpen && (
            <div className="absolute inset-0 border-2 border-green-500 animate-ping opacity-30"></div>
          )}
          
          {/* Status indicator */}
          <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
        </button>
      </div>

      {/* Chat Portal */}
      {isOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-40 flex items-center justify-center p-4">
          <div className={`relative w-full max-w-md h-[600px] bg-black border-2 border-cyan-500/50 transform transition-all duration-500 ${
            isOpen ? 'scale-100 opacity-100' : 'scale-95 opacity-0'
          }`}>
            {/* Grid overlay */}
            <div 
              className="absolute inset-0 opacity-10"
              style={{
                backgroundImage: `
                  linear-gradient(rgba(0, 255, 150, 0.3) 1px, transparent 1px),
                  linear-gradient(90deg, rgba(0, 255, 150, 0.3) 1px, transparent 1px)
                `,
                backgroundSize: '15px 15px'
              }}
            />

            {/* Terminal Header */}
            <div className="bg-black/90 border-b border-green-500/30 p-3">
              
              <div className="text-green-400 text-sm font-mono overflow-hidden">
                <div className="whitespace-nowrap overflow-hidden">
                  {terminalText}
                  {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
                </div>
              </div>
            </div>

            {/* Chat Header */}
            <div className="bg-black/80 border-b border-cyan-500/30 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-cyan-400 font-mono">[THREAT_ASSISTANT.AI]</h3>
                  <div className="flex items-center gap-2 text-xs text-green-400">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span>ONLINE | AI_ENHANCED</span>
                  </div>
                </div>
                <button
                  onClick={() => setIsOpen(false)}
                  className="text-red-400 hover:text-red-300 transition-colors"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Messages Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 h-96 custom-scrollbar">
              {messages.map((message) => (
                <div key={message.id} className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-xs lg:max-w-md px-3 py-2 text-sm ${
                    message.type === 'user'
                      ? 'bg-blue-900/30 border border-blue-500/50 text-blue-300'
                      : 'bg-green-900/20 border border-green-500/30 text-green-300'
                  }`}>
                    {message.type === 'bot' ? (
                      <div 
                        className="font-mono"
                        dangerouslySetInnerHTML={{ __html: formatBotMessage(message.content) }}
                      />
                    ) : (
                      <div className="font-mono">{message.content}</div>
                    )}
                    <div className="text-xs text-gray-500 mt-1 font-mono">
                      {message.timestamp.toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
              
              {isTyping && (
                <div className="flex justify-start">
                  <div className="bg-green-900/20 border border-green-500/30 px-3 py-2 text-green-300 font-mono text-sm">
                    <div className="flex items-center gap-1">
                      <span>[PROCESSING]</span>
                      <div className="flex gap-1">
                        <div className="w-1 h-1 bg-green-400 rounded-full animate-bounce"></div>
                        <div className="w-1 h-1 bg-green-400 rounded-full animate-bounce delay-100"></div>
                        <div className="w-1 h-1 bg-green-400 rounded-full animate-bounce delay-200"></div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="bg-black/90 border-t border-cyan-500/30 p-4">
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <span className="absolute left-3 top-2 text-cyan-400 text-sm font-mono">&gt;</span>
                  <textarea
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="Enter your query..."
                    className="w-full bg-black/70 border border-green-500/30 pl-8 pr-3 py-2 text-green-400 placeholder-green-600/50 focus:ring-2 focus:ring-cyan-500 focus:border-cyan-400 resize-none text-sm font-mono hover:border-green-400 transition-colors"
                    rows={2}
                  />
                </div>
                <button
                  onClick={handleSendMessage}
                  disabled={!inputValue.trim() || isTyping}
                  className="bg-black border-2 border-green-500 hover:border-cyan-400 disabled:border-gray-600 disabled:cursor-not-allowed text-green-400 hover:text-cyan-400 disabled:text-gray-600 px-3 py-2 transition-all duration-300 hover:shadow-[0_0_15px_rgba(0,255,150,0.3)] disabled:shadow-none"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                  </svg>
                </button>
              </div>
              
              {/* Quick Actions */}
              <div className="flex flex-wrap gap-1 mt-3">
                <button
                  onClick={() => setInputValue('What threats should I look for?')}
                  className="text-xs px-2 py-1 bg-gray-900/50 border border-gray-600/50 text-gray-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors font-mono"
                >
                  [THREATS]
                </button>
                <button
                  onClick={() => setInputValue('How do I analyze logs?')}
                  className="text-xs px-2 py-1 bg-gray-900/50 border border-gray-600/50 text-gray-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors font-mono"
                >
                  [LOGS]
                </button>
                <button
                  onClick={() => setInputValue('Explain MITRE ATT&CK')}
                  className="text-xs px-2 py-1 bg-gray-900/50 border border-gray-600/50 text-gray-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors font-mono"
                >
                  [MITRE]
                </button>
              </div>
            </div>

            {/* Floating Terminal Info */}
            <div className="absolute -top-8 left-0 text-green-500/40 font-mono text-xs animate-pulse">
              [CHAT_PROTOCOL_ACTIVE]
            </div>
            <div className="absolute -bottom-8 right-0 text-green-500/40 font-mono text-xs animate-pulse delay-1000">
              [SECURE_CHANNEL]
            </div>
          </div>
        </div>
      )}

      {/* Notification Badge */}
      {!isOpen && messages.length > 1 && (
        <div className="fixed bottom-20 right-6 z-50">
          <div className="bg-red-500 text-white text-xs font-bold px-2 py-1 rounded-full animate-bounce">
            {messages.filter(m => m.type === 'bot').length}
          </div>
        </div>
      )}

      <style jsx>{`
        /* Custom scrollbar for chat */
        .custom-scrollbar {
          scrollbar-width: thin;
          scrollbar-color: #00ff96 #1a1a1a;
        }

        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }

        .custom-scrollbar::-webkit-scrollbar-track {
          background: #1a1a1a;
          border-radius: 3px;
        }

        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #00ff96;
          border-radius: 3px;
          border: 1px solid #000;
        }

        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #22d3ee;
        }

        /* Chat portal animation */
        @keyframes portalOpen {
          0% {
            transform: scale(0) rotate(180deg);
            opacity: 0;
          }
          50% {
            transform: scale(1.1) rotate(90deg);
            opacity: 0.8;
          }
          100% {
            transform: scale(1) rotate(0deg);
            opacity: 1;
          }
        }

        .chat-portal {
          animation: portalOpen 0.6s ease-out;
        }

        /* Glow effect for active elements */
        .glow {
          box-shadow: 0 0 10px rgba(0, 255, 150, 0.3);
        }

        .glow:hover {
          box-shadow: 0 0 20px rgba(0, 255, 150, 0.5);
        }
      `}</style>
    </>
  );
};

export default Chatbot;