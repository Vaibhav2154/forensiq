'use client'
import React, { useState, useEffect, useRef } from 'react';
import {useRouter} from 'next/navigation'

interface TerminalLine {
  id: number;
  text: string;
  type: 'system' | 'user' | 'success' | 'error' | 'info' | 'prompt' | 'warning';
  timestamp?: string;
}

interface UserProfile {
  username: string;
  email: string;
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}


type ProfileField = keyof UserProfile;

const ProfessionalTerminalProfileUpdate: React.FC = () => {
    const router = useRouter();
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
  const [currentInput, setCurrentInput] = useState('');
  const [isUpdateComplete, setIsUpdateComplete] = useState(false);
  const [currentStep, setCurrentStep] = useState<'menu' | ProfileField | 'review' | 'confirm' | 'complete'>('menu');
  const [profile, setProfile] = useState<UserProfile>({
    username:  '',
    email: '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  
  const [originalProfile, setOriginalProfile] = useState<UserProfile>({ ...profile });
  const [changedFields, setChangedFields] = useState<Set<ProfileField>>(new Set());
  const [showCursor, setShowCursor] = useState(true);
  const [showPrompt, setShowPrompt] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [client, setClient] = useState(false);
  const [authToken, setAuthToken] = useState<string | null>(null); // Demo token for display
  const [apiBaseUrl] = useState(process.env.NEXT_PUBLIC_API_BASE_URL);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);


  
 useEffect(() => {
    const storedUsername = localStorage.getItem('user.username');
    const storedEmail = localStorage.getItem('user.email');
    const storedToken = localStorage.getItem('token');

    setProfile(prev => ({
      ...prev,
      username: storedUsername || prev.username,
      email: storedEmail || prev.email,
    }));
    setAuthToken(storedToken);
  }, []);
  const getTimestamp = () => {
    return new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
  };

  useEffect(()=>{
    setClient(true);
  },[])
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
    setOriginalProfile({ ...profile });
    
    const initMessages = [
      'SecureSystem Profile Management v2.1.4',
      'Copyright (c) 2024 SecureSystem Technologies',
      '',
      'Initializing profile update session...',
      '[OK] User session validated',
      '[OK] Profile data loaded',
      '[OK] Security protocols active',
      '[OK] API endpoints connected',
      '',
      `Welcome back, ${profile.username}!`,
      'Your profile is ready for updates.',
      ''
    ];

    let delay = 0;
    initMessages.forEach((message, index) => {
      setTimeout(() => {
        addTerminalLine(message, 'info');
        if (index === initMessages.length - 1) {
          setTimeout(() => {
            showMainMenu();
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

  // Focus input when component mounts or step changes
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, [currentStep, showPrompt]);

  const showMainMenu = () => {
    addTerminalLine('Profile Update Menu:', 'info');
    addTerminalLine('1. Update Username', 'system');
    addTerminalLine('2. Change Password', 'system');
    addTerminalLine('3. Review Current Profile', 'system');
    addTerminalLine('4. Save All Changes', 'system');
    addTerminalLine('5. Delete Account', 'system');
    addTerminalLine('6. Logout', 'system');
    addTerminalLine('7. Cancel and Exit', 'system');
    addTerminalLine('', 'system');
    addTerminalLine('Enter your choice (1-7):', 'prompt');
    setCurrentStep('menu');
    setShowPrompt(true);
  };

  const validateInput = (field: ProfileField, value: string): string[] => {
    const validationErrors: string[] = [];
    
    switch (field) {
      case 'username':
        if (!value.trim()) validationErrors.push('Username is required');
        else if (value.length < 3) validationErrors.push('Username must be at least 3 characters');
        else if (!/^[a-zA-Z0-9_-]+$/.test(value)) validationErrors.push('Username can only contain letters, numbers, hyphens, and underscores');
        break;
      case 'email':
        if (!value.trim()) validationErrors.push('Email is required');
        else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) validationErrors.push('Please enter a valid email address');
        break;
      case 'currentPassword':
        if (!value) validationErrors.push('Current password is required to make changes');
        break;
      case 'newPassword':
        if (value && value.length < 8) validationErrors.push('New password must be at least 8 characters');
        else if (value && !/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value)) validationErrors.push('Password must contain at least one uppercase letter, one lowercase letter, and one number');
        break;
      case 'confirmPassword':
        if (profile.newPassword && value !== profile.newPassword) validationErrors.push('Passwords do not match');
        break;
    }
    
    return validationErrors;
  };

  const handleMenuChoice = (choice: string) => {
    switch (choice) {
      case '1':
        addTerminalLine('Selected: Update Username', 'info');
        addTerminalLine('', 'system');
        promptForField('username');
        break;
      case '2':
        addTerminalLine('Selected: Change Password', 'info');
        addTerminalLine('', 'system');
        changePassword();
        break;
      case '3':
        addTerminalLine('Selected: Review Current Profile', 'info');
        addTerminalLine('', 'system');
        showCurrentProfile();
        break;
      case '4':
        addTerminalLine('Selected: Save All Changes', 'info');
        addTerminalLine('', 'system');
        reviewChanges();
        break;
      case '5':
        addTerminalLine('Selected: Delete Account', 'warning');
        addTerminalLine('', 'system');
        confirmDeleteAccount();
        break;
    case '6':
        addTerminalLine('Selected: Logout', 'info');
        addTerminalLine('','system')
        logout();
        router.push('/');
        break;
      case '7':
        addTerminalLine('Selected: Cancel and Exit', 'warning');
        addTerminalLine('Exiting profile update...', 'info');
        setTimeout(() => {
          addTerminalLine('Session terminated.', 'info');
          addTerminalLine('Thank you for using SecureSystem Profile Manager.', 'success');
        }, 1000);
        router.push('/dashboard');
        break;
      default:
        addTerminalLine(`Invalid choice: ${choice}`, 'error');
        addTerminalLine('Please enter a number between 1 and 7.', 'info');
    }
  };

  const changePassword = () => {
    addTerminalLine('Password Change Process', 'warning');
    addTerminalLine('For security, you must enter your current password first.', 'info');
    addTerminalLine('Enter current password:', 'prompt');
    setCurrentStep('currentPassword');
  };

  const confirmDeleteAccount = () => {
    addTerminalLine('⚠️  ACCOUNT DELETION WARNING ⚠️', 'error');
    addTerminalLine('This action cannot be undone!', 'warning');
    addTerminalLine('All your data will be permanently deleted.', 'warning');
    addTerminalLine('', 'system');
    addTerminalLine('Type "DELETE" to confirm account deletion:', 'prompt');
    setCurrentStep('confirm');
  };

  const promptForField = (field: ProfileField) => {
    const fieldLabels: Record<ProfileField, string> = {
      username: 'Username',
      email: 'Email',
      currentPassword: 'Current Password',
      newPassword: 'New Password',
      confirmPassword: 'Confirm Password'
    };

    const currentValue = profile[field];
    if (field !== 'currentPassword' && field !== 'newPassword' && field !== 'confirmPassword') {
      addTerminalLine(`Current ${fieldLabels[field]}: ${currentValue}`, 'system');
    }
    addTerminalLine(`Enter new ${fieldLabels[field].toLowerCase()}:`, 'prompt');
    setCurrentStep(field);
  };

  const showCurrentProfile = () => {
    addTerminalLine('Current Profile Information:', 'info');
    addTerminalLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'system');
    addTerminalLine(`Username: ${profile.username}`, 'system');
    addTerminalLine(`Email: ${profile.email}`, 'system');
    addTerminalLine(`Account Status: Active`, 'system');
    addTerminalLine(`Last Updated: ${new Date().toLocaleDateString()}`, 'system');
    addTerminalLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'system');
    addTerminalLine('', 'system');
    setTimeout(() => showMainMenu(), 1500);
  };

  const reviewChanges = () => {
    if (changedFields.size === 0) {
      addTerminalLine('No changes have been made to your profile.', 'warning');
      addTerminalLine('', 'system');
      setTimeout(() => showMainMenu(), 1000);
      return;
    }

    addTerminalLine('Review Changes:', 'info');
    addTerminalLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'system');
    
    changedFields.forEach(field => {
      const fieldLabels: Record<ProfileField, string> = {
        username: 'Username',
        email: 'Email',
        currentPassword: 'Current Password',
        newPassword: 'New Password',
        confirmPassword: 'Confirm Password'
      };

      if (field === 'newPassword') {
        addTerminalLine(`${fieldLabels[field]}: [Password will be changed]`, 'warning');
      } else if (field !== 'currentPassword' && field !== 'confirmPassword') {
        addTerminalLine(`${fieldLabels[field]}: ${originalProfile[field]} → ${profile[field]}`, 'info');
      }
    });

    addTerminalLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'system');
    addTerminalLine('', 'system');
    addTerminalLine('Confirm these changes? (y/n):', 'prompt');
    setCurrentStep('confirm');
  };

  const handleInputSubmit = () => {
    if (currentStep === 'menu') {
      if (!currentInput.trim()) return;
      addTerminalLine(`Choice: ${currentInput}`, 'user');
      handleMenuChoice(currentInput.trim());
      setCurrentInput('');
      return;
    }

    if (currentStep === 'confirm') {
      const choice = currentInput.toLowerCase().trim();
      addTerminalLine(`Confirm: ${choice}`, 'user');
      
      if (choice === 'delete') {
        deleteAccount();
      } else if (choice === 'y' || choice === 'yes') {
        saveChanges();
      } else {
        addTerminalLine('Changes cancelled.', 'warning');
        addTerminalLine('', 'system');
        setTimeout(() => showMainMenu(), 1000);
      }
      setCurrentInput('');
      return;
    }

    // Handle field updates
    const value = currentInput.trim();
    const validationErrors = validateInput(currentStep as ProfileField, value);
    
    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      validationErrors.forEach(error => {
        addTerminalLine(`[ERROR] ${error}`, 'error');
      });
      setCurrentInput('');
      return;
    }

    setErrors([]);

    // Process field update
    if (value) {
      if (currentStep === 'username') {
        addTerminalLine(`Username: ${value}`, 'user');
        setProfile(prev => ({ ...prev, username: value }));
        setChangedFields(prev => new Set([...prev, 'username']));
        addTerminalLine('', 'system');
        setTimeout(() => showMainMenu(), 500);
      } else if (currentStep === 'email') {
        addTerminalLine(`Email: ${value}`, 'user');
        setProfile(prev => ({ ...prev, email: value }));
        setChangedFields(prev => new Set([...prev, 'email']));
        addTerminalLine('', 'system');
        setTimeout(() => showMainMenu(), 500);
      } else if (currentStep === 'currentPassword') {
        addTerminalLine(`Current Password: ${'•'.repeat(value.length)}`, 'user');
        setProfile(prev => ({ ...prev, currentPassword: value }));
        addTerminalLine('[OK] Current password verified', 'success');
        addTerminalLine('Enter new password:', 'prompt');
        setCurrentStep('newPassword');
      } else if (currentStep === 'newPassword') {
        addTerminalLine(`New Password: ${'•'.repeat(value.length)}`, 'user');
        setProfile(prev => ({ ...prev, newPassword: value }));
        addTerminalLine('[OK] New password accepted', 'success');
        addTerminalLine('Confirm new password:', 'prompt');
        setCurrentStep('confirmPassword');
      } else if (currentStep === 'confirmPassword') {
        addTerminalLine(`Confirm Password: ${'•'.repeat(value.length)}`, 'user');
        setProfile(prev => ({ ...prev, confirmPassword: value }));
        setChangedFields(prev => new Set([...prev, 'newPassword']));
        addTerminalLine('[OK] Password change queued for update', 'success');
        addTerminalLine('', 'system');
        setTimeout(() => showMainMenu(), 1000);
      }
    } else {
      addTerminalLine('(Keeping current value)', 'info');
      addTerminalLine('', 'system');
      setTimeout(() => showMainMenu(), 1000);
    }

    setCurrentInput('');
  };

  const updateUserProfile = async (updateData: { email?: string; username?: string}) => {
    console.log(updateData)
    try {
     // addTerminalLine(`PUT ${apiBaseUrl}/updateusername`, 'system');
      console.log(authToken)
      const response = await fetch(`${apiBaseUrl}/users/update-username`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify(updateData)
      });

      if (response.ok) {
        const data = await response.json();
        addTerminalLine(`[${response.status}] Profile updated successfully`, 'success');
        return { ok: true, data };
      } else {
        const errorData = await response.json();
        addTerminalLine(`[${response.status}] ${response.statusText}`, 'error');
        return { ok: false, error: errorData.detail || 'Profile update failed' };
      }
    } catch (error) {
      addTerminalLine(`[NETWORK ERROR] Failed to connect to ${apiBaseUrl}`, 'error');
      return { ok: false, error: 'Network error - unable to connect to server' };
    }
  };

  const logout = async () =>{
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('user.email');
    localStorage.removeItem('user.username');
  }
  const changeUserPassword = async (currentPassword: string, newPassword: string) => {
    try {
      addTerminalLine(`PUT ${apiBaseUrl}/users/me/password`, 'system');
      
      const response = await fetch(`${apiBaseUrl}/users/me/password`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });

      if (response.ok) {
        const data = await response.text();
        addTerminalLine(`[${response.status}] Password changed successfully`, 'success');
        return { ok: true, data };
      } else {
        const errorData = await response.json();
        addTerminalLine(`[${response.status}] ${response.statusText}`, 'error');
        return { ok: false, error: errorData.detail || 'Password change failed' };
      }
    } catch (error) {
      addTerminalLine(`[NETWORK ERROR] Failed to connect to ${apiBaseUrl}`, 'error');
      return { ok: false, error: 'Network error - unable to connect to server' };
    }
  };

  const deleteUserAccount = async () => {
    try {
      addTerminalLine(`DELETE ${apiBaseUrl}/users/me`, 'system');
      
      const response = await fetch(`${apiBaseUrl}/users/me`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      if (response.ok) {
        const data = await response.text();
        addTerminalLine(`[${response.status}] Account deleted successfully`, 'success');
        return { ok: true, data };
      } else {
        const errorData = await response.json();
        addTerminalLine(`[${response.status}] ${response.statusText}`, 'error');
        return { ok: false, error: errorData.detail || 'Account deletion failed' };
      }
    } catch (error) {
      addTerminalLine(`[NETWORK ERROR] Failed to connect to ${apiBaseUrl}`, 'error');
      return { ok: false, error: 'Network error - unable to connect to server' };
    }
  };

  const saveChanges = async () => {
    setShowPrompt(false);
    addTerminalLine('', 'system');
    addTerminalLine('Connecting to SecureSystem API...', 'info');
    addTerminalLine(`Base URL: ${apiBaseUrl}`, 'system');
    addTerminalLine(`Authorization: Bearer ${authToken ? authToken.substring(0, 8) + '...' : '[No Token]'}`, 'system');
    addTerminalLine('', 'system');

    try {
      // Handle password change separately
      if (changedFields.has('newPassword')) {
        addTerminalLine('Processing password change...', 'info');
        
        const passwordResponse = await changeUserPassword(profile.currentPassword, profile.newPassword);

        if (passwordResponse.ok) {
          addTerminalLine('[OK] Password changed successfully', 'success');
        } else {
          addTerminalLine(`[ERROR] Password change failed: ${passwordResponse.error}`, 'error');
          addTerminalLine('', 'system');
          setTimeout(() => showMainMenu(), 2000);
          return;
        }
      }

      // Handle profile updates
      const profileChanges = new Set(changedFields);
      profileChanges.delete('currentPassword');
      profileChanges.delete('newPassword');
      profileChanges.delete('confirmPassword');

      if (profileChanges.size > 0) {
        addTerminalLine('Updating profile information...', 'info');
        
        const updateData: { email?: string; username?: string} = {};
       // if (changedFields.has('username')) updateData.full_name = profile.username;
       if (changedFields.has('username')){
        updateData.username = profile.username ;
        updateData.email = localStorage.getItem('user.email') || profile.email;
       } 
if (changedFields.has('email')){
   updateData.email = localStorage.getItem('user.email') || profile.email;
   updateData.username = localStorage.getItem('user.username') || profile.username;
} 


        console.log(updateData);

        const profileResponse = await updateUserProfile(updateData);

        if (profileResponse.ok) {
          addTerminalLine('[OK] Profile updated successfully', 'success');
        } else {
          addTerminalLine(`[ERROR] Profile update failed: ${profileResponse.error}`, 'error');
          addTerminalLine('', 'system');
          setTimeout(() => showMainMenu(), 2000);
          return;
        }
      }

      addTerminalLine('[OK] All changes saved successfully', 'success');
      addTerminalLine('', 'system');
      addTerminalLine(`Profile update completed for ${profile.username}`, 'success');
      addTerminalLine(`Updated at: ${new Date().toLocaleString()}`, 'info');
      addTerminalLine('', 'system');
      addTerminalLine('Your changes have been synchronized with the server.', 'info');
      
      setIsUpdateComplete(true);
      setChangedFields(new Set());
      setOriginalProfile({ ...profile });
      setCurrentStep('complete');
      
    } catch (error) {
      addTerminalLine('[ERROR] Network error occurred', 'error');
      addTerminalLine('Please check your connection and try again.', 'warning');
      setTimeout(() => showMainMenu(), 2000);
    }
  };

  const deleteAccount = async () => {
    setShowPrompt(false);
    addTerminalLine('', 'system');
    addTerminalLine('Connecting to SecureSystem API...', 'warning');
    addTerminalLine('Processing account deletion...', 'warning');

    try {
      const response = await deleteUserAccount();

      if (response.ok) {
        addTerminalLine('[OK] Account deletion confirmed', 'success');
        addTerminalLine('[OK] All data has been permanently removed', 'success');
        addTerminalLine('[OK] User session invalidated', 'success');
        addTerminalLine('', 'system');
        addTerminalLine('Your account has been successfully deleted.', 'info');
        addTerminalLine('Thank you for using SecureSystem services.', 'info');
        addTerminalLine('', 'system');
        addTerminalLine('Session will terminate in 3 seconds...', 'warning');
        
        setTimeout(() => {
          addTerminalLine('Connection closed.', 'error');
        }, 3000);
      } else {
        addTerminalLine(`[ERROR] Account deletion failed: ${response.error}`, 'error');
        setTimeout(() => showMainMenu(), 2000);
      }
    } catch (error) {
      addTerminalLine('[ERROR] Network error occurred', 'error');
      setTimeout(() => showMainMenu(), 2000);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isUpdateComplete) {
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
      case 'warning': return 'text-yellow-400';
      default: return 'text-gray-300';
    }
  };

  const handleTerminalClick = () => {
    if (inputRef.current && !isUpdateComplete) {
      inputRef.current.focus();
    }
  };

  const getCurrentPrompt = () => {
    if (currentStep === 'menu') return 'Choice: ';
    if (currentStep === 'confirm') return 'Confirm: ';
    return '> ';
  };

  const getInputType = () => {
    if (currentStep === 'currentPassword' || currentStep === 'newPassword' || currentStep === 'confirmPassword') {
      return 'password';
    }
    if (currentStep === 'email') {
      return 'email';
    }
    return 'text';
  };

  const restartUpdate = () => {
    setTerminalLines([]);
    setProfile({
      username: localStorage.getItem('user.username') || '',
      email: localStorage.getItem('user.email') || '',
      currentPassword: '',
      newPassword: '',
      confirmPassword: ''
    });
    setChangedFields(new Set());
    setCurrentStep('menu');
    setIsUpdateComplete(false);
    setShowPrompt(false);
    setErrors([]);
    
    // Re-initialize
    setTimeout(() => {
      const initMessages = [
        'SecureSystem Profile Management v2.1.4',
        'Copyright (c) 2024 SecureSystem Technologies',
        '',
        'Restarting profile update session...',
        '[OK] Session reinitialized',
        ''
      ];

      let delay = 0;
      initMessages.forEach((message, index) => {
        setTimeout(() => {
          addTerminalLine(message, 'info');
          if (index === initMessages.length - 1) {
            setTimeout(() => showMainMenu(), 500);
          }
        }, delay);
        delay += 100;
      });
    }, 100);
  };

  return (
    client &&
    <div className="h-screen w-screen bg-black text-green-400 font-mono overflow-hidden flex flex-col">
      {/* Terminal Header */}
      <div className="flex items-center justify-between border-b border-gray-700 px-4 py-2 bg-gray-900 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
          </div>
          <span className="text-gray-300 text-sm">profile-manager</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-gray-400">
          <span>{getTimestamp()}</span>
          <span className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></div>
            API CONNECTED
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
          
          {/* Input Prompt */}
          {showPrompt && !isUpdateComplete && (
            <div className="flex items-start gap-2">
              <span className="text-green-400">{getCurrentPrompt()}</span>
              <div className="flex items-center flex-1">
                <input
                  ref={inputRef}
                  type={getInputType()}
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

          {/* Update Complete Actions */}
          {isUpdateComplete && (
            <div className="mt-6 space-y-4">
              <div className="flex gap-4">
                <button
                  onClick={() => {
                    setIsUpdateComplete(false);
                    addTerminalLine('', 'system');
                    showMainMenu();
                  }}
                  className="bg-green-600 hover:bg-green-700 text-black px-4 py-2 rounded transition-colors font-bold"
                >
                  Continue Updating
                </button>
                <button
                  onClick={restartUpdate}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors font-bold"
                >
                  Restart Session
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
            <span>Changes: {changedFields.size}</span>
            <span className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-blue-400"></div>
              API: {apiBaseUrl}
            </span>
          </div>
          <div className="flex gap-4">
            {!isUpdateComplete && currentStep !== 'complete' && (
              <div className="flex items-center gap-3">
                <span className="text-yellow-400">
                  {currentStep === 'menu' ? 'Select Option' : 'Update Field'}
                </span>
                {errors.length > 0 && (
                  <span className="text-red-400">
                    Errors: {errors.length}
                  </span>
                )}
              </div>
            )}
            {isUpdateComplete && (
              <span className="text-green-400">Update Complete</span>
            )}
            <span className="text-gray-500">Press Enter to continue</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfessionalTerminalProfileUpdate;