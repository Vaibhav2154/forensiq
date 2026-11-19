import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const Chatbot = () => {
  const [showCursor, setShowCursor] = useState(true);
  const router = useRouter();

  useEffect(() => {
    // Cursor blinking
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 500);
    return () => clearInterval(cursorInterval);
  }, []);

  const handleChatClick = () => {
    router.push('/chat');
  };

  return (
    <>
      {/* Floating Chat Icon */}
      <div className="fixed bottom-6 right-6 z-50">
        <button
          onClick={handleChatClick}
          className="relative group w-14 h-14 bg-black border-2 border-green-500 hover:border-cyan-400 transition-all duration-300 flex items-center justify-center hover:shadow-[0_0_20px_rgba(0,255,150,0.5)]"
        >
          <svg className="w-6 h-6 text-green-400 group-hover:text-cyan-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>

          {/* Pulse animation */}
          <div className="absolute inset-0 border-2 border-green-500 animate-ping opacity-30"></div>

          {/* Status indicator */}
          <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
        </button>

        {/* Tooltip */}
        <div className="absolute bottom-full right-0 mb-2 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
          <div className="bg-black border border-green-500/50 text-green-400 text-xs px-2 py-1 whitespace-nowrap font-mono">
            [MITRE_CHAT_TERMINAL]
            {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
          </div>
        </div>
      </div>

      {/* Floating Terminal Info */}
      <div className="fixed bottom-20 right-6 z-40 text-green-500/40 font-mono text-xs animate-pulse">
        [CHAT_READY]
      </div>
    </>
  );
};

export default Chatbot;
