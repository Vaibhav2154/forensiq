"use client"

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

  const handleOpenChat = () => {
    router.push('/chat');
  };

  return (
    <>
      {/* Floating Chat Icon */}
      <div className="fixed bottom-6 right-6 z-50">
        <button
          onClick={handleOpenChat}
          className="relative group w-14 h-14 bg-black border-2 border-green-500 hover:border-cyan-400 hover:shadow-[0_0_20px_rgba(0,255,150,0.5)] transition-all duration-300 flex items-center justify-center"
        >
          <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>

          {/* Pulse animation */}
          <div className="absolute inset-0 border-2 border-green-500 animate-ping opacity-30"></div>

          {/* Status indicator */}
          <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
        </button>

        {/* Tooltip */}
        <div className="absolute bottom-full right-0 mb-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
          <div className="bg-black border border-green-500/30 text-green-400 text-sm px-3 py-2 rounded font-mono whitespace-nowrap">
            Open MITRE Assistant
            {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
          </div>
        </div>
      </div>
    </>
  );
};

export default Chatbot;
