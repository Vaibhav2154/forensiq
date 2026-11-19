'use client'
import React, { useState, useEffect } from 'react';
import { ChevronDown, ChevronRight, Copy, CheckCircle, Terminal, FileText, Play, Settings, Eye, Download, Power, ArrowDown, ArrowRight, Brain, User } from 'lucide-react';

interface Step {
  id: number;
  title: string;
  shortTitle: string;
  description: string;
  shortDescription: string;
  commands?: string[];
  example?: string;
  tips?: string[];
  status: 'completed' | 'current' | 'pending';
  icon: React.ReactNode;
  color: string;
}

const StepGuide: React.FC = () => {
  const [currentStep, setCurrentStep] = useState(1);
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set([1]));
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    // Only run on client side
    if (typeof window === 'undefined') return;

    setIsClient(true);
    
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };

    checkMobile();
    window.addEventListener('resize', checkMobile);
    setIsVisible(true);

    return () => {
      window.removeEventListener('resize', checkMobile);
    };
  }, []);


  const steps: Step[] = [
  {
    id: 1,
    title: 'INSTALL_DEPENDENCIES.SYS',
    shortTitle: 'INSTALL_DEPS',
    description: 'Install Python dependencies and verify CLI tool setup',
    shortDescription: 'Install dependencies',
    commands: [
      'cd aiagent',
      'pip install -r cli_requirements.txt',
      'python cli_tool.py --help'
    ],
    example: `$ pip install -r cli_requirements.txt
Successfully installed aiohttp-3.8.0 cryptography-41.0.0...
$ python cli_tool.py --help
LogIQ CLI Tool for Automated Log Analysis
Usage: python cli_tool.py [command] [options]`,
    tips: [
      'Ensure Python 3.7+ is installed',
      'Use virtual environment for clean installation',
      'Verify all dependencies are installed correctly'
    ],
    status: currentStep >= 1 ? 'completed' : currentStep === 1 ? 'current' : 'pending',
    icon: <Download className="w-5 h-5" />,
    color: 'red'
  },
  {
    id: 2,
    title: 'START_SERVER.SYS',
    shortTitle: 'START_SERVER',
    description: 'Start your LogIQ FastAPI server',
    shortDescription: 'Run LogIQ server',
    commands: [
      'cd server',
      'python main.py'
    ],
    example: `$ python main.py
INFO:     Uvicorn running on http://localhost:8000 (Press CTRL+C to quit)
INFO:     MongoDB connected successfully`,
    tips: [
      'Ensure MongoDB is running and accessible',
      'Check firewall allows access on port 8000',
      'Server must be running before using CLI tool'
    ],
    status: currentStep >= 2 ? 'completed' : currentStep === 2 ? 'current' : 'pending',
    icon: <Power className="w-5 h-5" />,
    color: 'blue'
  },
  {
    id: 3,
    title: 'AUTHENTICATE.USER',
    shortTitle: 'AUTHENTICATE',
    description: 'Login or register using the CLI tool',
    shortDescription: 'Login/Register via CLI',
    commands: [
      'python cli_tool.py auth register --username <username> --email <email>',
      'python cli_tool.py auth login --username <username>',
      'python cli_tool.py auth profile'
    ],
    example: `$ python cli_tool.py auth login --username security_analyst
Password: ********
✅ Authentication successful!
✅ Token stored securely`,
    tips: [
      'Register first if you don\'t have an account',
      'Credentials are encrypted and stored locally',
      'Use --api-url if server not on localhost:8000'
    ],
    status: currentStep >= 3 ? 'completed' : currentStep === 3 ? 'current' : 'pending',
    icon: <User className="w-5 h-5" />,
    color: 'cyan'
  },
  {
    id: 4,
    title: 'SETUP_PROFILE.CFG',
    shortTitle: 'SETUP_PROFILE',
    description: 'Setup monitoring profile (file-based or dynamic)',
    shortDescription: 'Setup monitoring profile',
    commands: [
      'python cli_tool.py profile setup-dynamic --list-sources',
      'python cli_tool.py profile setup-dynamic --sources security_events,system_events --interval 300',
      'python cli_tool.py profile setup --log-path "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx" --interval 300'
    ],
    example: `$ python cli_tool.py profile setup-dynamic --list-sources
📋 Available Log Sources:
  • security_events: Windows Security Events
  • system_events: Windows System Events
  • process_monitor: Process monitoring
✅ Profile configured successfully`,
    tips: [
      'Choose file-based or dynamic monitoring',
      'Use 300 seconds (5 min) for normal monitoring',
      'Enable AI agent for enhanced analysis'
    ],
    status: currentStep >= 4 ? 'completed' : currentStep === 4 ? 'current' : 'pending',
    icon: <Settings className="w-5 h-5" />,
    color: 'orange'
  },
  {
    id: 5,
    title: 'START_MONITOR.DAEMON',
    shortTitle: 'START_MONITOR',
    description: 'Start automated monitoring session',
    shortDescription: 'Begin monitoring',
    commands: [
      'python cli_tool.py monitor --start',
      'python cli_tool.py monitor --dynamic',
      'python cli_tool.py monitor --schedule'
    ],
    example: `$ python cli_tool.py monitor --dynamic
🚀 Starting dynamic system log monitoring...
📊 Logs will be extracted every 5 minutes
🔄 Data will be automatically sent to LogIQ and stored in MongoDB
🤖 AI Agent will provide enhanced analysis`,
    tips: [
      'Use --dynamic for system log extraction',
      'Use --start for file-based monitoring',
      'Keep terminal running for continuous monitoring'
    ],
    status: currentStep >= 5 ? 'completed' : currentStep === 5 ? 'current' : 'pending',
    icon: <Play className="w-5 h-5" />,
    color: 'purple'
  },
  {
    id: 6,
    title: 'VIEW_RESULTS.OUT',
    shortTitle: 'VIEW_RESULTS',
    description: 'Check analysis results and monitoring data',
    shortDescription: 'View results & data',
    commands: [
      'python cli_tool.py data analysis --limit 10',
      'python cli_tool.py data sessions --limit 5',
      'python cli_tool.py data stats',
      'python cli_tool.py agent status'
    ],
    example: `$ python cli_tool.py data analysis --limit 5
📊 Analysis Results (Last 5):
🔍 Threat Level: MEDIUM
🎯 MITRE Techniques: T1078 (Valid Accounts), T1059.001 (PowerShell)
📈 AI Agent: Learning patterns, confidence: 0.85`,
    tips: [
      'Use --limit to control number of results',
      'Export data with --export option',
      'Check agent status for learning progress'
    ],
    status: currentStep >= 6 ? 'completed' : currentStep === 6 ? 'current' : 'pending',
    icon: <Eye className="w-5 h-5" />,
    color: 'yellow'
  },
  {
    id: 7,
    title: 'CONFIG_AI.CFG',
    shortTitle: 'CONFIG_AI',
    description: 'Configure AI agent for optimal threat detection',
    shortDescription: 'Configure AI agent',
    commands: [
      'python cli_tool.py agent status',
      'python cli_tool.py agent configure --enable --learning-threshold 0.8',
      'python cli_tool.py agent configure --high-threat-interval 60',
      'python cli_tool.py agent reset --confirm'
    ],
    example: `$ python cli_tool.py agent status
🤖 AI Agent Status: ACTIVE
📚 Learning Threshold: 0.8
⚡ High-threat Interval: 60 seconds
📊 Patterns Learned: 15`,
    tips: [
      'Lower thresholds for more aggressive detection',
      'Adjust intervals based on security requirements',
      'Reset agent to clear learning data if needed'
    ],
    status: currentStep >= 7 ? 'completed' : currentStep === 7 ? 'current' : 'pending',
    icon: <Brain className="w-5 h-5" />,
    color: 'green'
  },
  {
    id: 8,
    title: 'ANALYZE_LOGS.DAT',
    shortTitle: 'ANALYZE_LOGS',
    description: 'Perform on-demand log analysis with AI enhancement',
    shortDescription: 'Analyze logs on-demand',
    commands: [
      'python cli_tool.py analyze --file <log_file> --enhanced',
      'python cli_tool.py analyze --file <log_file> --ai-agent --output results.json',
      'python cli_tool.py send --file <log_file>'
    ],
    example: `$ python cli_tool.py analyze --file security.log --enhanced --ai-agent
🔍 Analyzing log file: security.log
🤖 AI Agent: Processing with enhanced analysis
📊 Results: 3 MITRE techniques detected
💾 Results saved to: analysis_results.json`,
    tips: [
      'Use --enhanced for AI-powered analysis',
      'Use --output to save results to file',
      'Combine with --ai-agent for best results'
    ],
    status: currentStep >= 8 ? 'completed' : currentStep === 8 ? 'current' : 'pending',
    icon: <FileText className="w-5 h-5" />,
    color: 'cyan'
  }
];



  const toggleStep = (stepId: number) => {
    const newExpanded = new Set(expandedSteps);
    if (newExpanded.has(stepId)) {
      newExpanded.delete(stepId);
    } else {
      newExpanded.add(stepId);
    }
    setExpandedSteps(newExpanded);
  };

  const copyCommand = async (command: string) => {
    // Only run on client side
    if (typeof window === 'undefined' || !navigator.clipboard) return;
    
    try {
      await navigator.clipboard.writeText(command);
      setCopiedCommand(command);
      setTimeout(() => setCopiedCommand(null), 2000);
    } catch (err) {
      console.error('Failed to copy command:', err);
    }
  };

  const getStepColor = (step: Step) => {
    switch (step.color) {
      case 'cyan': return 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 bg-cyan-500/10';
      case 'green': return 'border-green-500/30 hover:border-green-400 text-green-400 bg-green-500/10';
      case 'purple': return 'border-purple-500/30 hover:border-purple-400 text-purple-400 bg-purple-500/10';
      case 'yellow': return 'border-yellow-500/30 hover:border-yellow-400 text-yellow-400 bg-yellow-500/10';
      case 'orange': return 'border-orange-500/30 hover:border-orange-400 text-orange-400 bg-orange-500/10';
      case 'red': return 'border-red-500/30 hover:border-red-400 text-red-400 bg-red-500/10';
      default: return 'border-gray-500/30 hover:border-gray-400 text-gray-400 bg-gray-500/10';
    }
  };

  const getStatusIndicator = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400 fill-current" />;
      case 'current':
        return <div className="w-5 h-5 border-2 border-cyan-400 rounded-full animate-pulse bg-cyan-400/20 flex items-center justify-center">
          <div className="w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
        </div>;
      case 'pending':
        return <div className="w-5 h-5 border-2 border-gray-600 rounded-full bg-gray-900/30" />;
      default:
        return null;
    }
  };

  const getConnectorClass = (index: number) => {
    const currentStepIndex = steps.findIndex(s => s.status === 'current');
    const isActive = index < currentStepIndex || (index === currentStepIndex);
    return isActive ? 'bg-gradient-to-b from-green-400 via-cyan-400 to-purple-400' : 'bg-gray-600';
  };

  // Show loading state during hydration
  if (!isClient) {
    return (
      <div className="relative bg-black min-h-screen text-white flex items-center justify-center">
        <div className="text-green-400 font-mono text-lg">
          [LOGIQ_CLI.GUIDE] &gt; LOADING...
        </div>
      </div>
    );
  }

  return (
    <div className="relative bg-black min-h-screen text-white">
      {/* Grid overlay */}
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

      <div className="relative container mx-auto px-4 sm:px-6 py-6 sm:py-8 max-w-4xl">
        {/* LogIQ CLI Info Panel */}
        <div className="mb-6">
          <div className="bg-cyan-900/80 border border-cyan-400/40 rounded-lg p-4 sm:p-6 shadow-lg">
            <h2 className="text-lg sm:text-xl font-bold text-cyan-300 mb-2 font-mono flex items-center">
              <Settings className="w-5 h-5 mr-2 text-cyan-400" />
              LogIQ CLI Tool - Complete Setup Guide
            </h2>
            <ul className="list-disc pl-5 text-gray-200 text-sm sm:text-base space-y-1">
              <li><span className="text-cyan-300 font-bold">8-Step Process:</span> From installation to advanced log analysis with AI enhancement</li>
              <li><span className="text-green-300 font-bold">Dynamic Monitoring:</span> Real-time extraction from Windows Event Logs with MongoDB storage</li>
              <li><span className="text-yellow-300 font-bold">AI Agent:</span> Intelligent threat detection with adaptive scheduling and pattern learning</li>
              <li><span className="text-purple-300 font-bold">Data Management:</span> Comprehensive MongoDB data retrieval, export, and analysis capabilities</li>
              <li>For complete documentation, see <span className="text-green-300 font-mono">CLI_USER_GUIDE.md</span> or use <span className="text-green-300 font-mono">python cli_tool.py --help</span></li>
            </ul>
          </div>
        </div>
        {/* Header */}
        <div className={`mb-8 sm:mb-12 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-lg p-4 sm:p-6 mb-6">
            <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-green-400 mb-4 tracking-wider font-mono">
              [LOGIQ_CLI.GUIDE]
            </h1>
            <div className="text-cyan-400 text-sm sm:text-base font-mono">
              &gt; STEP_BY_STEP_EXECUTION_PROTOCOL --MODE=INTERACTIVE
            </div>
            <p className="text-gray-300 mt-4 text-sm sm:text-base">
              Follow this comprehensive 8-step process to deploy the LogIQ CLI tool with dynamic monitoring, AI-powered threat detection, and MongoDB integration for automated security analysis.
            </p>
          </div>

          {/* Progress Overview */}
          <div className="bg-black/60 backdrop-blur-sm border border-gray-700/30 rounded-lg p-4 sm:p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg text-green-400 flex items-center font-mono">
                <Terminal className="w-5 h-5 mr-2" />
                [EXECUTION_PROGRESS]
              </h3>
              <span className="text-cyan-400 text-sm font-mono">
                {currentStep}/8 STEPS_COMPLETE
              </span>
            </div>

            <div className="flex items-center space-x-2 overflow-x-auto pb-2">
              {steps.map((step, index) => (
                <React.Fragment key={step.id}>
                  <div
                    className={`flex-shrink-0 w-8 h-8 sm:w-10 sm:h-10 rounded-full border-2 flex items-center justify-center cursor-pointer transition-all duration-300 font-mono ${step.status === 'completed' ? 'border-green-400 bg-green-400/20 text-green-400 shadow-[0_0_10px_rgba(34,197,94,0.5)]' :
                        step.status === 'current' ? 'border-cyan-400 bg-cyan-400/20 text-cyan-400 animate-pulse shadow-[0_0_15px_rgba(6,182,212,0.8)]' :
                          'border-gray-600 bg-gray-600/10 text-gray-600'
                      }`}
                    onClick={() => setCurrentStep(step.id)}
                  >
                    <span className="text-xs sm:text-sm font-bold">{step.id}</span>
                  </div>
                  {index < steps.length - 1 && (
                    <div className={`flex-shrink-0 h-0.5 w-4 sm:w-8 transition-all duration-500 ${step.status === 'completed' ? 'bg-green-400 shadow-[0_0_5px_rgba(34,197,94,0.8)]' : 'bg-gray-600'
                      }`} />
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>

        {/* Linked List Visualization */}
        <div className="relative">
          {/* Main Linked List Chain */}
          <div className="space-y-0">
            {steps.map((step, index) => (
              <div key={step.id} className="relative">
                {/* Linked List Node */}
                <div className="flex items-center">
                  {/* Left Connection Point */}
                  <div className="hidden lg:flex flex-col items-center mr-6">
                    <div className={`w-4 h-4 rounded-full border-2 ${step.status === 'completed' ? 'bg-green-400 border-green-400 shadow-[0_0_10px_rgba(34,197,94,0.8)]' :
                        step.status === 'current' ? 'bg-cyan-400 border-cyan-400 animate-pulse shadow-[0_0_15px_rgba(6,182,212,1)]' :
                          'bg-gray-600 border-gray-600'
                      }`} />
                    <div className="text-gray-500 text-xs font-mono mt-1">NODE_{step.id}</div>
                  </div>

                  {/* Step Container */}
                  <div
                    className={`flex-1 bg-black/80 backdrop-blur-sm border rounded-2xl transition-all duration-500 transform font-mono ${step.status === 'current' ? 'scale-105 shadow-[0_0_30px_rgba(0,255,150,0.3)] animate-pulse' :
                        step.status === 'completed' ? 'shadow-[0_0_15px_rgba(34,197,94,0.2)]' : ''
                      } ${getStepColor(step)} ${isVisible ? 'translate-x-0 opacity-100' : 'translate-x-10 opacity-0'
                      }`}
                    style={{ transitionDelay: `${index * 150}ms` }}
                  >
                    {/* Step Header */}
                    <div
                      className="flex items-center justify-between p-4 sm:p-6 cursor-pointer"
                      onClick={() => toggleStep(step.id)}
                    >
                      <div className="flex items-center space-x-3 sm:space-x-4 min-w-0 flex-1">
                        {/* Mobile Status Indicator */}
                        <div className="lg:hidden flex-shrink-0">
                          {getStatusIndicator(step.status)}
                        </div>

                        {/* Icon */}
                        <div className={`w-10 h-10 sm:w-12 sm:h-12 rounded-lg ${getStepColor(step)} flex items-center justify-center flex-shrink-0 shadow-inner`}>
                          {step.icon}
                        </div>

                        {/* Content */}
                        <div className="min-w-0 flex-1">
                          <h3 className="text-base sm:text-lg font-semibold text-green-400 mb-1 break-words">
                            <span className="hidden sm:inline">[{step.title}]</span>
                            <span className="sm:hidden">[{step.shortTitle}]</span>
                          </h3>
                          <p className="text-gray-300 text-xs sm:text-sm break-words">
                            <span className="hidden sm:inline">{step.description}</span>
                            <span className="sm:hidden">{step.shortDescription}</span>
                          </p>
                        </div>
                      </div>

                      {/* Expand/Collapse */}
                      <div className="flex-shrink-0 ml-2">
                        {expandedSteps.has(step.id) ? (
                          <ChevronDown className="w-5 h-5 text-gray-400" />
                        ) : (
                          <ChevronRight className="w-5 h-5 text-gray-400" />
                        )}
                      </div>
                    </div>

                    {/* Expanded Content */}
                    {expandedSteps.has(step.id) && (
                      <div className="px-4 sm:px-6 pb-4 sm:pb-6 space-y-4 sm:space-y-6 border-t border-gray-800/50 bg-black/20">
                        {/* Commands Section */}
                        {step.commands && (
                          <div>
                            <h4 className="text-cyan-400 font-semibold mb-3 flex items-center">
                              <Terminal className="w-4 h-4 mr-2" />
                              [TERMINAL_COMMANDS]
                            </h4>
                            <div className="space-y-2">
                              {step.commands.map((command, cmdIndex) => (
                                <div key={cmdIndex} className="bg-black/60 border border-gray-700/30 rounded-lg p-3 flex items-center justify-between hover:border-green-500/30 transition-colors">
                                  <code className="text-green-300 text-sm break-all flex-1 font-mono">
                                    $ {command}
                                  </code>
                                  <button
                                    onClick={() => copyCommand(command)}
                                    className="ml-3 p-1 hover:bg-gray-800 rounded transition-colors flex-shrink-0"
                                    title="Copy command"
                                  >
                                    {copiedCommand === command ? (
                                      <CheckCircle className="w-4 h-4 text-green-400" />
                                    ) : (
                                      <Copy className="w-4 h-4 text-gray-400 hover:text-cyan-400" />
                                    )}
                                  </button>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Example Output */}
                        {step.example && (
                          <div>
                            <h4 className="text-cyan-400 font-semibold mb-3 flex items-center">
                              <FileText className="w-4 h-4 mr-2" />
                              [EXAMPLE_OUTPUT]
                            </h4>
                            <div className="bg-black/60 border border-gray-700/30 rounded-lg p-4 overflow-x-auto">
                              <pre className="text-green-300 text-xs sm:text-sm whitespace-pre-wrap font-mono">
                                {step.example}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* Tips Section */}
                        {step.tips && (
                          <div>
                            <h4 className="text-cyan-400 font-semibold mb-3">
                              [OPERATIONAL_TIPS]
                            </h4>
                            <div className="space-y-2">
                              {step.tips.map((tip, tipIndex) => (
                                <div key={tipIndex} className="flex items-start space-x-3">
                                  <div className="w-1.5 h-1.5 bg-yellow-400 rounded-full mt-2 flex-shrink-0" />
                                  <p className="text-gray-300 text-sm break-words">{tip}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Action Buttons */}
                        <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
                          {step.id < 8 && (
                            <button
                              onClick={() => {
                                setCurrentStep(step.id + 1);
                                setExpandedSteps(new Set([step.id + 1]));
                              }}
                              className="px-4 sm:px-6 py-2 sm:py-3 bg-black border-2 border-green-500 hover:border-cyan-400 text-green-400 hover:text-cyan-400 transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,150,0.5)] text-sm whitespace-nowrap font-mono"
                            >
                              <span className="hidden sm:inline">&gt;&gt; PROCEED_TO_NEXT.STEP</span>
                              <span className="sm:hidden">&gt;&gt; NEXT_STEP</span>
                            </button>
                          )}

                          {step.id === 8 && (
                            <button
                              onClick={() => {
                                setCurrentStep(1);
                                setExpandedSteps(new Set([1]));
                              }}
                              className="px-4 sm:px-6 py-2 sm:py-3 bg-black border-2 border-cyan-500 hover:border-green-400 text-cyan-400 hover:text-green-400 transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,255,0.5)] text-sm whitespace-nowrap font-mono"
                            >
                              <span className="hidden sm:inline">&gt;&gt; RESTART_PROCESS.EXE</span>
                              <span className="sm:hidden">&gt;&gt; RESTART</span>
                            </button>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Right Connection Point (Desktop) */}
                  <div className="hidden lg:flex flex-col items-center ml-6">
                    <div className="text-gray-500 text-xs font-mono mb-1">PTR_{step.id}</div>
                    <ArrowRight className={`w-5 h-5 ${step.status === 'completed' ? 'text-green-400' :
                        step.status === 'current' ? 'text-cyan-400 animate-pulse' :
                          'text-gray-600'
                      }`} />
                  </div>
                </div>

                {/* Vertical Connector Line (Linked List Connection) */}
                {index < steps.length - 1 && (
                  <div className="flex justify-center my-4 sm:my-6">
                    <div className="flex flex-col items-center">
                      {/* Vertical connecting line */}
                      <div className={`w-1 h-8 sm:h-12 transition-all duration-500 ${getConnectorClass(index)}`}
                        style={{
                          boxShadow: step.status !== 'pending' ? '0 0 10px rgba(34, 197, 94, 0.5)' : 'none'
                        }}
                      />

                      {/* Connecting arrow */}
                      <ArrowDown className={`w-4 h-4 mt-1 transition-all duration-500 ${step.status === 'completed' ? 'text-green-400' :
                          step.status === 'current' ? 'text-cyan-400 animate-bounce' :
                            'text-gray-600'
                        }`} />

                      {/* Connection label */}
                      <div className="text-xs text-gray-500 mt-1 font-mono hidden sm:block">
                        LINK_TO_STEP_{step.id + 1}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Footer Terminal */}
        <div className={`mt-8 sm:mt-12 bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-lg p-4 sm:p-6 transform transition-all duration-1000 delay-1000 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'} font-mono`}>
          <div className="flex items-center justify-between">
            <div className="text-green-400 text-sm sm:text-base">
              [SYSTEM_STATUS] &gt; LOGIQ_CLI_READY_FOR_DEPLOYMENT --STEPS=8
            </div>
            <div className="flex items-center space-x-2 text-xs sm:text-sm">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_5px_rgba(34,197,94,1)]" />
              <span className="text-green-400">OPERATIONAL</span>
            </div>
          </div>
        </div>
      </div>

      {/* Floating ASCII elements */}
      <div className="hidden md:block absolute top-32 right-10 text-green-500/10 font-mono text-xs animate-pulse">
        {`┌─────────────────┐
│ LINKED_LIST.DAT │
│ STATUS: ACTIVE  │
│ NODES: 8        │
│ STEPS: COMPLETE │
└─────────────────┘`}
      </div>

      <div className="hidden lg:block absolute bottom-32 left-10 text-green-500/10 font-mono text-xs animate-pulse delay-1000">
        {`> ./traverse_steps.py --direction=forward`}
      </div>

      <div className="hidden lg:block absolute top-1/2 left-10 text-green-500/10 font-mono text-xs animate-pulse delay-2000">
        {`struct Node {
  int step_id;
  Node* next;
};`}
      </div>

      <style jsx>{`
        .container {
          max-width: 100%;
        }
      `}</style>
    </div>
  );
};

export default StepGuide;