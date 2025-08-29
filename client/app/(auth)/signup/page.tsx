'use client'
import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';

interface TerminalLine {
  id: number;
  text: string;
  type: 'system' | 'user' | 'success' | 'error' | 'info' | 'prompt';
  timestamp?: string;
}

interface SignUpFormData {
  username: string;
  email: string;
  password: string;
}


const ProfessionalTerminalSignUp: React.FC = () => {
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
  const [currentInput, setCurrentInput] = useState('');
  const [isRegistered, setIsRegistered] = useState(false);
  const [signUpStep, setSignUpStep] = useState<'username' | 'email' | 'password' | 'complete'>('username');
  const [formData, setFormData] = useState<SignUpFormData>({ 
    email:'',
    username: '', 
    password: '', 
  });
  const [showCursor, setShowCursor] = useState(true);
  const [showPrompt, setShowPrompt] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  
const router = useRouter();
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
      'Initializing secure registration process...',
      '[OK] Registration service ready',
      '',
      'Welcome to ForensIQ! Let\'s create your account.',
      'Please provide the following information:',
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

  // Auto scroll to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines, showPrompt, currentInput]);

  // Focus input when component mounts or signup step changes
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, [signUpStep, showPrompt]);

  const validateInput = (step: string, value: string): string[] => {
    const validationErrors: string[] = [];
    
    switch (step) {
      case 'username':
        if (!value.trim()) validationErrors.push('Username is required');
        else if (value.length < 3) validationErrors.push('Username must be at least 3 characters');
        else if (!/^[a-zA-Z0-9_-]+$/.test(value)) validationErrors.push('Username can only contain letters, numbers, hyphens, and underscores');
        break;
      case 'email':
        if (!value.trim()) validationErrors.push('Email is required');
        else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) validationErrors.push('Please enter a valid email address');
        break;
      case 'password':
        if (!value) validationErrors.push('Password is required');
        else if (value.length < 8) validationErrors.push('Password must be at least 8 characters');
        else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value)) validationErrors.push('Password must contain at least one uppercase letter, one lowercase letter, and one number');
        break;
    }
    
    return validationErrors;
  };

  const handleInputSubmit = () => {
    if (!currentInput.trim()) return;

    const validationErrors = validateInput(signUpStep, currentInput);
    
    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      validationErrors.forEach(error => {
        addTerminalLine(`[ERROR] ${error}`, 'error');
      });
      setCurrentInput('');
      return;
    }

    setErrors([]);

    // Process each step
    switch (signUpStep) {
      case 'username':
        addTerminalLine(`Username: ${currentInput}`, 'user');
        setFormData(prev => ({ ...prev, username: currentInput }));
        addTerminalLine('[OK] Username available', 'success');
        setSignUpStep('email');
        break;
      case 'email':
        addTerminalLine(`Email: ${currentInput}`, 'user');
        setFormData(prev => ({ ...prev, email: currentInput }));
        addTerminalLine('[OK] Email format validated', 'success');
        setSignUpStep('password');
        break;
      case 'password':
        addTerminalLine(`Password: ${'•'.repeat(currentInput.length)}`, 'user');
        setFormData(prev => ({ ...prev, password: currentInput }));
        addTerminalLine('[OK] Password meets security requirements', 'success');
        // Automatically process registration after password is entered
        setTimeout(() => {
          processRegistration();
        }, 1000);
        break;
    }
    
    setCurrentInput('');
  };

  const processRegistration = () => {
    setShowPrompt(false);
    addTerminalLine('', 'system');
    addTerminalLine('Processing registration...', 'info');
    
    // Simulate API call - replace with actual endpoint when ready
    /*setTimeout(() => {
      // Simulate successful registration
      addTerminalLine('[OK] Validating user information', 'success');
      addTerminalLine('[OK] Checking username availability', 'success');
      addTerminalLine('[OK] Email verification sent', 'success');
      addTerminalLine('[OK] Account created successfully', 'success');
      addTerminalLine('', 'system');
      addTerminalLine(`Your username: ${formData.username}`, 'info');
      addTerminalLine(`Registration completed at: ${new Date().toLocaleString()}`, 'info');
      addTerminalLine('', 'system');
      addTerminalLine('Please check your email to verify your account.', 'info');
      addTerminalLine('You can now login with your credentials.', 'info');
      setIsRegistered(true);
      setSignUpStep('complete');
    }, 2000);
    
    */
   console.log(formData)
    fetch('http://127.0.0.1:8000/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(formData),
    })
      .then(async (res) => {
        if (res.ok) {
            const data = await res.json();
            localStorage.setItem('user', JSON.stringify(data))
          addTerminalLine('[OK] Validating user information', 'success');
          addTerminalLine('[OK] Checking username availability', 'success');
          addTerminalLine('[OK] Email verification sent', 'success');
          addTerminalLine('[OK] Account created successfully', 'success');
          addTerminalLine('', 'system');
          addTerminalLine(`Your username: ${formData.username}`, 'info');
          addTerminalLine(`Registration completed at: ${new Date().toLocaleString()}`, 'info');
          addTerminalLine('', 'system');
          addTerminalLine('Please check your email to verify your account.', 'info');
          addTerminalLine('You can now login with your credentials.', 'info');
          setIsRegistered(true);
          setSignUpStep('complete');
        } else {
          const error = await res.text();
          addTerminalLine(`[ERROR] ${error || 'Registration failed'}`, 'error');
          setShowPrompt(true);
          setSignUpStep('username');
        }
      })
      .catch((err) => {
        addTerminalLine('[ERROR] Network error', 'error');
        setShowPrompt(true);
        setSignUpStep('username');
      });
    
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isRegistered && signUpStep !== 'complete') {
      handleInputSubmit();
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
    if (inputRef.current && !isRegistered && signUpStep !== 'complete') {
      inputRef.current.focus();
    }
  };

  const getCurrentPrompt = () => {
    switch (signUpStep) {
        case 'email': return 'Email Address: ';
      case 'username': return 'Username: ';
      case 'password': return 'Password: ';
      default: return '';
    }
  };

  const getInputType = () => {
    if (signUpStep === 'password') {
      return 'password';
    }
    if (signUpStep === 'email') {
      return 'email';
    }
    return 'text';
  };

  const getPlaceholder = () => {
    switch (signUpStep) {
      case 'username': return 'Choose a unique username';
      case 'email': return 'Enter your email address';
      case 'password': return 'Create a secure password';
      default: return '';
    }
  };

  const restartRegistration = () => {
    setTerminalLines([]);
    setCurrentInput('');
    setIsRegistered(false);
    setSignUpStep('username');
    setFormData({ email:'',username: '', password: '' });
    setShowPrompt(false)
    setErrors([]);
    
    // Restart initialization
    const initMessages = [
      '',
      'Initializing secure registration process...',
      '[OK] Registration service ready',
      '',
      'Welcome to ForensIQ! Let\'s create your account.',
      'Please provide the following information:',
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
  };

  return (
    <div className="h-screen w-screen bg-black text-green-400 font-mono overflow-hidden flex flex-col">
      {/* Terminal Header */}
      <div className="flex items-center justify-between border-b border-gray-700 px-4 py-2 bg-gray-900 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
          </div>
          <span className="text-gray-300 text-sm">registration-portal</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-gray-400">
          <span>{getTimestamp()}</span>
          <span className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></div>
            SECURE
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
          
          {/* Registration Prompt */}
          {showPrompt && !isRegistered && signUpStep !== 'complete' && (
            <div className="flex items-start gap-2">
              <span className="text-green-400">{getCurrentPrompt()}</span>
              <div className="flex items-center flex-1">
                <input
                  ref={inputRef}
                  type={getInputType()}
                  value={currentInput}
                  placeholder={getPlaceholder()}
                  onChange={(e) => setCurrentInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  className="bg-transparent text-white outline-none border-none flex-1 placeholder-gray-500"
                  style={{ caretColor: 'transparent' }}
                />
                {showCursor && (
                  <span className="bg-green-400 text-black">█</span>
                )}
              </div>
            </div>
          )}

          {/* Registration Complete Actions */}
          {isRegistered && (
            <div className="mt-6 space-y-4">
              <div className="flex gap-4">
                
                <button
                  onClick={() => router.push('/login')}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors font-bold"
                >
                  Go to Login
                </button>
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
            <span>Step: {signUpStep !== 'complete' ? `${['username', 'email', 'password'].indexOf(signUpStep) + 1}/3` : 'Complete'}</span>
          </div>
          <div className="flex gap-4">
            {!isRegistered && signUpStep !== 'complete' && (
              <div className="flex items-center gap-3">
                <span className="text-yellow-400">
                  {getCurrentPrompt().replace(': ', '')}
                </span>
                {errors.length > 0 && (
                  <span className="text-red-400">
                    Validation errors: {errors.length}
                  </span>
                )}
              </div>
            )}
            {isRegistered && (
              <span className="text-green-400">Registration Complete</span>
            )}
            <span className="text-gray-500">Press Enter to continue</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfessionalTerminalSignUp;