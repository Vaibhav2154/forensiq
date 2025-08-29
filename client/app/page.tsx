'use client'

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const Hyperspeed = () => {
  return <div className="absolute inset-0 bg-black" />;
};

const LandingPage = () => {
  const router = useRouter();
  const [isVisible, setIsVisible] = useState(false);
  const [hoveredButton, setHoveredButton] = useState<'login' | 'signup' | null>(null);
  const [terminalText, setTerminalText] = useState('');
  const [showCursor, setShowCursor] = useState(true);

  const fullTerminalText = '> Initializing FORENSIQ Systems...';

  useEffect(() => {
    setIsVisible(true);
    
    // Terminal typing effect
    let i = 0;
    const typeInterval = setInterval(() => {
      if (i <= fullTerminalText.length) {
        setTerminalText(fullTerminalText.slice(0, i));
        i++;
      } else {
        clearInterval(typeInterval);
      }
    }, 100);

    // Cursor blinking
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 500);

    return () => {
      clearInterval(typeInterval);
      clearInterval(cursorInterval);
    };
  }, []);

  return (
    <div>
      <div className='relative h-screen w-screen overflow-hidden'>
        <Hyperspeed />
        
        {/* Terminal grid overlay */}
        <div 
          className="absolute inset-0 opacity-10"
          style={{
            backgroundImage: `
              linear-gradient(rgba(0, 255, 150, 0.1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(0, 255, 150, 0.1) 1px, transparent 1px)
            `,
            backgroundSize: '20px 20px'
          }}
        />
        
        {/* Matrix-style overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-black/60 via-transparent to-black/80" />
        
        <div className='absolute inset-0 flex flex-col items-center justify-center gap-8 font-mono'>
          
          {/* Terminal Header */}
          <div className={`w-full max-w-4xl mx-auto px-4 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-3">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
                <span className="ml-4 text-green-400 text-sm">root@forensiq:~#</span>
              </div>
              <div className="text-green-400 text-sm">
                {terminalText}
                {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
              </div>
            </div>
          </div>

          {/* TrackBack Title */}
          <div className={`text-center transform transition-all duration-1000 delay-300 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
            <div className="relative">
              <h2 className='text-4xl md:text-8xl font-black mb-4 text-green-400 tracking-wider filter  glitch-text'>
                ForensIQ
              </h2>
              {/* Glitch lines */}
              
            </div>
            
            <div className="bg-black/60 backdrop-blur-sm border border-green-500/30 rounded-lg p-4 max-w-2xl mx-auto">
              <p className="text-green-300 text-lg font-mono">
                <span className="text-cyan-400">[STATUS]</span> NEURAL NETWORK INTERFACE ACTIVE
              </p>
              <p className="text-slate-300 font-mono text-sm mt-1">
                &gt; Advanced tracking protocols initialized
              </p>
            </div>
          </div>

          {/* Terminal-style Buttons Container */}
          <div className={`flex flex-col sm:flex-row items-center gap-6 transform transition-all duration-1000 delay-500 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            
            {/* Login Button */}
            <div className="relative group">
              <button 
                className='group relative bg-black border-2 border-green-500 hover:border-cyan-400 text-green-400 hover:text-cyan-400 font-bold font-mono text-lg px-8 py-4 rounded-none transition-all duration-300 hover:shadow-[0_0_20px_rgba(34,197,94,0.5)] hover:shadow-cyan-400/50 min-w-[180px] glitch-btn'
                onMouseEnter={() => setHoveredButton('login')}
                onClick={() => router.push('/login')}
              >
                <span className="relative z-10 flex items-center justify-center gap-3">
                  <span className="text-cyan-400">&gt;</span>
                  ACCESS_LOGIN
                  <span className="text-green-400">_</span>
                </span>
                {hoveredButton === 'login' && (
                  <>
                    <div className="absolute inset-0 bg-green-500/10 animate-pulse" />
                    <div className="absolute -inset-1 border border-cyan-400/50 animate-pulse" />
                  </>
                )}
              </button>
            </div>

            {/* Sign Up Button */}
            <div className="relative group">
              <button 
                className='group relative bg-black border-2 border-green-500 hover:border-purple-400 text-green-400 hover:text-purple-400 font-bold font-mono text-lg px-8 py-4 rounded-none transition-all duration-300 hover:shadow-[0_0_20px_rgba(34,197,94,0.5)] hover:shadow-purple-400/50 min-w-[180px] glitch-btn'
                onMouseEnter={() => setHoveredButton('signup')}
                onMouseLeave={() => setHoveredButton(null)}
                onClick={() => router.push('/signup')}
              >
                <span className="relative z-10 flex items-center justify-center gap-3">
                  <span className="text-purple-400">&gt;</span>
                  REGISTER_USER
                  <span className="text-green-400">_</span>
                </span>
                {hoveredButton === 'signup' && (
                  <>
                    <div className="absolute inset-0 bg-purple-500/10 animate-pulse" />
                    <div className="absolute -inset-1 border border-purple-400/50 animate-pulse" />
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Terminal Status Pills */}
          <div className={`flex flex-wrap justify-center gap-4 mt-6 max-w-4xl mx-auto transform transition-all duration-1000 delay-700 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            <div className="px-4 py-2 bg-black/80 border border-green-500/50 font-mono text-green-400 text-sm hover:border-cyan-400 hover:text-cyan-400 transition-all duration-300 cursor-default">
              [SPEED: 99.9%]
            </div>
            <div className="px-4 py-2 bg-black/80 border border-green-500/50 font-mono text-green-400 text-sm hover:border-yellow-400 hover:text-yellow-400 transition-all duration-300 cursor-default">
              [SECURITY: MAX]
            </div>
            <div className="px-4 py-2 bg-black/80 border border-green-500/50 font-mono text-green-400 text-sm hover:border-purple-400 hover:text-purple-400 transition-all duration-300 cursor-default">
              [ANALYTICS: ON]
            </div>
            <div className="px-4 py-2 bg-black/80 border border-green-500/50 font-mono text-green-400 text-sm hover:border-red-400 hover:text-red-400 transition-all duration-300 cursor-default">
              [REALTIME: LIVE]
            </div>
          </div>

          {/* Terminal Footer */}
          <div className={`absolute bottom-6 left-1/2 transform -translate-x-1/2 transition-all duration-1000 delay-900 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded px-6 py-3">
              <div className="flex items-center gap-4 text-green-400 font-mono text-sm">
                <span className="animate-pulse">●</span>
                <span>SYSTEM_STATUS: ONLINE</span>
                <span className="text-slate-500">|</span>
                <span>CONN: SECURE</span>
                <span className="text-slate-500">|</span>
                <span className="text-cyan-400">SCROLL_DOWN &gt;</span>
              </div>
            </div>
          </div>

          {/* Floating ASCII elements */}
          <div className="absolute top-20 left-10 text-green-500/20 font-mono text-xs animate-pulse">
            {`{
  "status": "active",
  "mode": "hacker"
}`}
          </div>
          
          <div className="absolute top-32 right-12 text-green-500/20 font-mono text-xs animate-pulse delay-1000">
            &gt; ./trackback.exe
          </div>
          
          <div className="absolute bottom-32 left-16 text-green-500/20 font-mono text-xs animate-pulse delay-2000">
            [ROOT@SYSTEM]#
          </div>
        </div>
      </div>

      <style jsx>{`
        .glitch-text {
          position: relative;
        }
        .glitch-1 {
          animation: glitch1 2s infinite;
        }
        .glitch-2 {
          animation: glitch2 2s infinite;
        }
        .glitch-btn:hover .glitch-text {
          animation: glitch3 0.3s;
        }

        @keyframes glitch1 {
          0%, 100% { transform: translateX(0); }
          20% { transform: translateX(-2px) translateY(1px); }
          40% { transform: translateX(-1px) translateY(-1px); }
          60% { transform: translateX(1px) translateY(1px); }
          80% { transform: translateX(1px) translateY(-1px); }
        }

        @keyframes glitch2 {
          0%, 100% { transform: translateX(0); }
          10% { transform: translateX(2px) translateY(-1px); }
          30% { transform: translateX(-1px) translateY(2px); }
          50% { transform: translateX(1px) translateY(-2px); }
          70% { transform: translateX(-2px) translateY(1px); }
        }

        @keyframes glitch3 {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-2px); }
          75% { transform: translateX(2px); }
        }
      `}</style>
    </div>
  );
};

export default LandingPage;