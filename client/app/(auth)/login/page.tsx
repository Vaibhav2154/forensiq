'use client'
import React, { useState, useEffect, useRef } from 'react';
import {useRouter} from 'next/navigation'


interface TerminalLine {
  id: number;
  text: string;
  type: 'system' | 'user' | 'success' | 'error' | 'info' | 'prompt';
  timestamp?: string;
}

interface LoginFormData {
  username: string;
  password: string;
}


const ProfessionalTerminalLogin: React.FC = () => {
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
  const [currentInput, setCurrentInput] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loginStep, setLoginStep] = useState<'username' | 'password' | 'complete'>('username');
  const [formData, setFormData] = useState<LoginFormData>({ username: '', password: '' });
  const [client, setClient] = useState(false);
  const [showCursor, setShowCursor] = useState(true);
  const [showPrompt, setShowPrompt] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const getTimestamp = () => {
    return new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
  };

  const addTerminalLine = (text: string, type: TerminalLine['type'] = 'system') => {
    const newLine: TerminalLine = {
      id: Date.now() + Math.random(),
      text,
      type,
      timestamp: getTimestamp()
    };
    
    setTerminalLines(prev => [...prev, newLine]);
  };

  // Initialize terminal
  useEffect(() => {
    const initMessages = [
      '',
      'Establishing secure connection...',
      '',
      'Authentication required for system access.',
      ''
    ];

    let delay = 0;
    initMessages.forEach((message, index) => {
      setTimeout(() => {
        addTerminalLine(message, 'info');
        if (index === initMessages.length - 1) {
          setTimeout(() => {
            setShowPrompt(true);
          }, 500);
        }
      }, delay);
      delay += message.length > 30 ? 200 : 100;
    });

    // Cursor blinking
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 500);

    return () => clearInterval(cursorInterval);
  }, []);
  useEffect(()=>{
    setClient(true)
  },[])
  // Auto scroll to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines, showPrompt, currentInput]);

  // Focus input when component mounts or login step changes
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, [loginStep, showPrompt]);

  const handleInputSubmit = () => {
    if (!currentInput.trim()) return;

    if (loginStep === 'username') {
      addTerminalLine(`Username: ${currentInput}`, 'user');
      setFormData(prev => ({ ...prev, username: currentInput }));
      setCurrentInput('');
      setLoginStep('password');
    } else if (loginStep === 'password') {
      addTerminalLine(`Password: ${'•'.repeat(currentInput.length)}`, 'user');
      const username = formData.username;
      setFormData(prev => ({ ...prev, password: currentInput }));
      setCurrentInput('');
      setShowPrompt(false);

      addTerminalLine('', 'system');
      addTerminalLine('Authenticating...', 'info');
      console.log(username, currentInput);
      //console.log(process.env.NEXT_PUBLIC_API_BASE_URL);
      fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password: currentInput }),
      })
        .then(async (res) => {
          if (res.ok) {
            const data = await res.json();
            localStorage.setItem('token', data.access_token);
            localStorage.setItem('user.username', username);
            addTerminalLine('[OK] User credentials verified', 'success');
            addTerminalLine('[OK] Access permissions loaded', 'success');
            addTerminalLine('[OK] Session initialized', 'success');
            addTerminalLine('', 'system');
            addTerminalLine(`Welcome, ${username}`, 'success');
            addTerminalLine(`Last login: ${new Date().toLocaleString()}`, 'info');
            addTerminalLine('Type "help" for available commands.', 'info');
            addTerminalLine('', 'system');
            setIsAuthenticated(true);
            setLoginStep('complete');
            router.push('/dashboard');
          } else {
            const error = await res.text();
            addTerminalLine(`[ERROR] ${error || 'Invalid credentials'}`, 'error');
            setShowPrompt(true);
            setLoginStep('username');
          }
        })
        .catch(() => {
          addTerminalLine('[ERROR] Network error', 'error');
          setShowPrompt(true);
          setLoginStep('username');
        });
    }
  };

  const router = useRouter();
  const handleCommandSubmit = () => {
    if (!currentInput.trim()) return;
    
    // Add the command with prompt
    addTerminalLine(`user@secure-system:~$ ${currentInput}`, 'user');
    
    // Simple command handling
    const command = currentInput.toLowerCase().trim();
    setCurrentInput('');
    
    setTimeout(() => {
      switch(command) {
        case 'help':
          addTerminalLine('Available commands:', 'info');
          addTerminalLine('  help     - Show this help message', 'system');
          addTerminalLine('  clear    - Clear terminal', 'system');
          addTerminalLine('  whoami   - Display current user', 'system');
          addTerminalLine('  date     - Show current date and time', 'system');
          addTerminalLine('  exit     - Logout', 'system');
          break;
        case 'clear':
          setTerminalLines([]);
          break;
        case 'whoami':
          addTerminalLine(formData.username, 'info');
          break;
        case 'date':
          addTerminalLine(new Date().toString(), 'info');
          break;
        case 'exit':
          addTerminalLine('Logging out...', 'info');
          setTimeout(() => {
            window.location.reload();
          }, 1000);
          break;
        default:
          addTerminalLine(`Command not found: ${command}`, 'error');
          addTerminalLine('Type "help" for available commands.', 'info');
      }
    }, 100);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      if (isAuthenticated) {
        handleCommandSubmit();
      } else {
        handleInputSubmit();
      }
    }
  };

  const getLineColor = (type: TerminalLine['type']) => {
    switch (type) {
      case 'system': return 'text-green-400';
      case 'user': return 'text-white';
      case 'success': return 'text-green-300';
      case 'error': return 'text-red-400';
      case 'info': return 'text-gray-300';
      case 'prompt': return 'text-green-400';
      default: return 'text-gray-300';
    }
  };

  const handleTerminalClick = () => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  const getCurrentPrompt = () => {
    if (loginStep === 'username') return 'Username: ';
    if (loginStep === 'password') return 'Password: ';
    return '';
  };

  return (
    client && 
    <div className="h-screen w-screen bg-black text-green-400 font-mono overflow-hidden flex flex-col suppressHydrationWarning={true}">
      {/* Terminal Header */}
      <div className="flex items-center justify-between border-b border-gray-700 px-4 py-2 bg-gray-900 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
          </div>
          <span className="text-gray-300 text-sm">secure-terminal</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-gray-400">
          <span>{getTimestamp()}</span>
          <span className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></div>
            CONNECTED
          </span>
        </div>
      </div>

      {/* Terminal Content */}
      <div 
        ref={terminalRef}
        className="flex-1 p-6 overflow-y-auto cursor-text"
        onClick={handleTerminalClick}
        style={{ scrollBehavior: 'smooth' }}
      >
        <div className="space-y-1">
          {terminalLines.map((line) => (
            <div key={line.id} className="flex items-start gap-2">
              {line.timestamp && line.type !== 'system' && line.type !== 'info' && (
                <span className="text-gray-600 text-xs mt-0.5 min-w-[60px]">
                  {line.timestamp}
                </span>
              )}
              <pre className={`${getLineColor(line.type)} leading-relaxed whitespace-pre-wrap break-words flex-1`}>
                {line.text}
              </pre>
            </div>
          ))}
          
          {/* Login Prompt */}
          {showPrompt && !isAuthenticated && loginStep !== 'complete' && (
            <div className="flex items-start gap-2">
              <span className="text-green-400">{getCurrentPrompt()}</span>
              <div className="flex items-center flex-1">
                <input
                  ref={inputRef}
                  type={loginStep === 'password' ? 'password' : 'text'}
                  value={currentInput}
                  onChange={(e) => setCurrentInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  className="bg-transparent text-white outline-none border-none flex-1"
                  style={{ caretColor: 'transparent' }}
                />
                
                {showCursor && (
                  <span className="bg-green-400 text-black">█</span>
                )}
              </div>
            </div>
          )}

          {/* Authenticated Command Line */}
          {isAuthenticated && (
            <div className="flex items-start gap-2">
              <span className="text-green-400">user@secure-system:~$</span>
              <div className="flex items-center flex-1">

                {showCursor && (
                  <span className="bg-green-400 text-black">█</span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Status Bar */}
      <div className="border-t border-gray-700 px-4 py-2 bg-gray-900 flex-shrink-0">
        <div className="flex justify-between items-center text-xs text-gray-400">
          <div className="flex gap-6">
            <span>Lines: {terminalLines.length}</span>
          </div>
          <div className="flex gap-4">
            {!isAuthenticated && loginStep !== 'complete' && (
              <span className="text-yellow-400">
                {loginStep === 'username' ? 'Enter username' : 'Enter password'}
              </span>
            )}
            {isAuthenticated && (
              <span className="text-green-400">Ready</span>
            )}
            
          </div>
        </div>
      </div>
    </div>
        
  );

};


export default ProfessionalTerminalLogin;