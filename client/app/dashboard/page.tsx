'use client'
import Navbar from '@/components/navbar'
import InvestigationReportPanel from '@/components/investigation-report-panel'
import React, { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import MarkdownRenderer from '@/hooks/MarkDownRenderer'
import  {exportMarkdownToPdf} from "../../hooks/MarkDownToPdf"
import { BsGraphUp } from "react-icons/bs";
import { FaShield } from "react-icons/fa6";
import { GrValidate } from "react-icons/gr";
import { FaExclamationTriangle, FaDatabase, FaSearch } from "react-icons/fa";
import { LuScanEye } from "react-icons/lu";
import {
  createMonitoringSession,
  deleteAnalysisById,
  fetchHealth,
  fetchInvestigationConfig,
  fetchMonitoringAnalysisStats,
  fetchMonitoringSessionDetail,
  fetchMonitoringSessions,
  fetchUserAnalytics,
  stopMonitoringSession,
} from '@/lib/api';
import type {
  HealthCheckResponse,
  InvestigationConfig,
  MonitoringAnalysisStats,
  MonitoringSession,
  UserAnalyticsStats,
} from '@/lib/types';


const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  'http://127.0.0.1:8000';

const DashboardPage = () => {
  const router = useRouter()
  const [isVisible, setIsVisible] = useState(false)
  const [hoveredFeature, setHoveredFeature] = useState<number | null>(null)
  const [terminalText, setTerminalText] = useState('')
  const [showCursor, setShowCursor] = useState(true)
  const [isMobile, setIsMobile] = useState(false)
  const [recentAnalyses, setRecentAnalyses] = useState<any[]>([])
  const [allSingleAnalysis, setAllSingleAnalysis] = useState<any[]>([])
  const [singleAnalysis, setSingleAnalysis] = useState<any | null>(null)
  const [selectedAnalysis, setSelectedAnalysis] = useState<any | null>(null)
  const [showModal, setShowModal] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [userProfile, setUserProfile] = useState<any | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [totalAnalysesCount, setTotalAnalysesCount] = useState(0)
  const [health, setHealth] = useState<HealthCheckResponse | null>(null)
  const [healthFailed, setHealthFailed] = useState(false)
  const [invConfig, setInvConfig] = useState<InvestigationConfig | null>(null)
  const [userAnalytics, setUserAnalytics] = useState<UserAnalyticsStats | null>(null)
  const [monitoringSessions, setMonitoringSessions] = useState<MonitoringSession[]>([])
  const [monitoringActiveOnly, setMonitoringActiveOnly] = useState(true)
  const [monitoringStats, setMonitoringStats] = useState<MonitoringAnalysisStats | null>(null)
  const [selectedSession, setSelectedSession] = useState<MonitoringSession | null>(null)
  const [newLogPath, setNewLogPath] = useState('/var/log/auth.log')
  const [newIntervalSec, setNewIntervalSec] = useState(300)
  const [newAiEnabled, setNewAiEnabled] = useState(true)
  const [monitoringBusy, setMonitoringBusy] = useState(false)
  const itemsPerPage = 10

  const fullTerminalText = '> LOGIQ_DASHBOARD.EXE --MODE=OPERATIONAL'

  // Memoized mobile check function
  const checkMobile = useCallback(() => {
    setIsMobile(window.innerWidth < 768)
  }, [])

  useEffect(() => {
    checkMobile()
    window.addEventListener('resize', checkMobile)
    setIsVisible(true)
    
    // Terminal typing effect
    let i = 0
    const typeInterval = setInterval(() => {
      if (i <= fullTerminalText.length) {
        setTerminalText(fullTerminalText.slice(0, i))
        i++
      } else {
        clearInterval(typeInterval)
      }
    }, 50)

    // Cursor blinking
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev)
    }, 500)

    return () => {
      clearInterval(typeInterval)
      clearInterval(cursorInterval)
      window.removeEventListener('resize', checkMobile)
    }
  }, [checkMobile])

  
  const features = [
    {
      title: 'LOG_ANALYSIS.SYS',
      shortTitle: 'LOG_ANALYSIS',
      description: 'AI-powered analysis of security logs with MITRE ATT&CK technique mapping',
      shortDescription: 'AI-powered log analysis with MITRE mapping',
      icon: <FaSearch />,
      href: '/dashboard/analysis',
      color: 'cyan',
      stats: 'REALTIME_ANALYSIS'
    },
    {
      title: 'THREAT_VISUALIZATION.EXE',
      shortTitle: 'VISUALIZATION',
      description: 'Enhanced threat visualization dashboard with advanced analytics',
      shortDescription: 'Enhanced threat visualization dashboard',
      icon: <LuScanEye />,
      href: '/dashboard/visualization',
      color: 'purple',
      stats: 'INTERACTIVE_CHARTS'
    },
    {
      title: 'MITRE_ATTACK.DB',
      shortTitle: 'MITRE_ATTACK',
      description: 'Comprehensive threat intelligence and attack technique database',
      shortDescription: 'Threat intelligence and attack technique database',
      icon: <FaShield />,
      href: '/dashboard/mitre',
      color: 'green',
      stats: 'ENTERPRISE_TECH'
    },
    {
      title: 'KNOWLEDGE_OKF.DB',
      shortTitle: 'KNOWLEDGE',
      description: 'Cognee & KCP unified MITRE Enterprise ATT&CK + CVE knowledge hub and batch sandbox',
      shortDescription: 'MITRE ATT&CK & CVE Cognee OKF Hub',
      icon: <FaDatabase />,
      href: '/dashboard/knowledge',
      color: 'cyan',
      stats: 'OKF_COGNEE'
    },
    {
      title: 'THREAT_INTEL.NET',
      shortTitle: 'THREAT_INTEL',
      description: 'Advanced threat detection and response capabilities for modern security operations',
      shortDescription: 'Advanced threat detection and response',
      icon: <FaExclamationTriangle />,
      href: '/dashboard',
      color: 'red',
      stats: 'THREAT_INTEL'
    }
  ]


  
  const fetchUserProfile = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/me`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch user profile: ${response.statusText}`);
      }
      const data = await response.json();
      setUserProfile(data);
      console.log('User profile:', data);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch user profile';
      console.log(errorMessage);
    }
  }

  const handleRecentAnalyses = async(page: number = 1)=>{
    setLoading(true);
    setError(null);
    try{
      const offset = (page - 1) * itemsPerPage;
      const response = await fetch(`${API_BASE_URL}/api/v1/history?limit=${itemsPerPage}&offset=${offset}`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch recent analyses: ${response.statusText}`);
      }
      const data = await response.json();
      setRecentAnalyses(data);
      
      // Calculate total pages based on response
      // If the API returns total count, use it. Otherwise estimate from data length
      const totalCount = data.total || (data.length === itemsPerPage ? (page + 1) * itemsPerPage : page * itemsPerPage);
      setTotalPages(Math.ceil(totalCount / itemsPerPage));
      
      // Set the total count for display
      if (data.total) {
        setTotalAnalysesCount(data.total);
      }
      
      console.log(data);
    }catch(err){
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch recent analyses';
      console.log(errorMessage);
    } finally {
      setLoading(false);
    }
  }

  // Fetch total count separately if not provided in history endpoint
  const fetchTotalCount = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/history/count`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
      });
      if (response.ok) {
        const data = await response.json();
        const total = data.count || data.total || 0;
        setTotalAnalysesCount(total);
        if (total > 0) {
          setTotalPages(Math.max(1, Math.ceil(total / itemsPerPage)));
        }
      }
    } catch (err) {
      console.log('Could not fetch total count:', err);
    }
  }

  const loadMonitoringData = useCallback(async (activeOnly: boolean) => {
    try {
      const [sessions, stats] = await Promise.all([
        fetchMonitoringSessions(activeOnly),
        fetchMonitoringAnalysisStats(30),
      ]);
      setMonitoringSessions(sessions);
      setMonitoringStats(stats);
    } catch (err) {
      console.log('Could not load monitoring data:', err);
    }
  }, []);

  const loadOperationalData = useCallback(async () => {
    fetchHealth()
      .then((res) => {
        setHealth(res);
        setHealthFailed(false);
      })
      .catch(() => {
        setHealthFailed(true);
      });

    fetchInvestigationConfig()
      .then((cfg) => setInvConfig(cfg))
      .catch(() => {});

    fetchUserAnalytics()
      .then((stats) => setUserAnalytics(stats))
      .catch(() => {});
  }, []);

  useEffect(()=>{
    handleRecentAnalyses(currentPage);
    fetchUserProfile();
    fetchTotalCount(); // Fetch total count on mount
    loadOperationalData();
    loadMonitoringData(monitoringActiveOnly);
    
    // Refresh user profile every 5 seconds to show real-time CLI status
    const interval = setInterval(() => {
      fetchUserProfile();
    }, 5000);
    
    return () => clearInterval(interval);
  },[currentPage, loadOperationalData, loadMonitoringData, monitoringActiveOnly])

const recentSingleAnalyses  = async(elementId:string)=>{
    try{
      const response = await fetch(`${API_BASE_URL}/api/v1/history/${elementId}`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch recent single analysis: ${response.statusText}`);
      }
      const data = await response.json();
      setSingleAnalysis(data);
      console.log(data);
    }catch(err){
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch recent single analysis';
      console.log(errorMessage);
    }
  }
  const allAnalysis = async () => {
    setLoading(true);
    setError(null);
  try {

    if (recentAnalyses.length === 0) {
      setAllSingleAnalysis([]);
      return;
    }

    const results = await Promise.all(
      recentAnalyses.map(async (item) => {
        const response = await fetch(
          `${API_BASE_URL}/api/v1/history/${item.id}`,
          {
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${localStorage.getItem("token")}`,
            },
            
          }
        );
        if (!response.ok) throw new Error(`Failed to fetch analysis ${item.id}`);
        const json = await response.json();
        return { ...json, id: item.id };
      })
    );

   setAllSingleAnalysis(results); // Replace state instead of appending
    console.log("All single analyses:", results);
    console.log("All single analyses final:", allSingleAnalysis);
  } catch (err) {
    console.log(err);
  } finally {
    setLoading(false);
  }
};

  useEffect(()=>{
    allAnalysis();
  },[recentAnalyses])

  const handlePageChange = useCallback((newPage: number) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, [totalPages])

  const handleAnalysisClick = useCallback((analysis: any) => {
    setSelectedAnalysis(analysis)
    setShowModal(true)
  }, [])

  const closeModal = useCallback(() => {
    setShowModal(false)
    setSelectedAnalysis(null)
  }, [])

  const handleDeleteAnalysis = useCallback(async (analysisId?: string) => {
    if (!analysisId) return;
    if (typeof window !== 'undefined' && !window.confirm('Delete this stored analysis permanently?')) {
      return;
    }
    try {
      await deleteAnalysisById(analysisId);
      setAllSingleAnalysis((prev) => prev.filter((item) => item?.id !== analysisId));
      setRecentAnalyses((prev) => prev.filter((item) => item?.id !== analysisId));
      setTotalAnalysesCount((prev) => Math.max(0, prev - 1));
      if (selectedAnalysis?.id === analysisId) {
        closeModal();
      }
      fetchUserAnalytics().then((stats) => setUserAnalytics(stats)).catch(() => {});
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete analysis');
    }
  }, [selectedAnalysis, closeModal]);

  const handleCreateMonitoringSession = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newLogPath.trim()) return;
    try {
      setMonitoringBusy(true);
      await createMonitoringSession({
        log_path: newLogPath.trim(),
        interval_seconds: Number(newIntervalSec) || 300,
        ai_agent_enabled: newAiEnabled,
      });
      await loadMonitoringData(monitoringActiveOnly);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create monitoring session');
    } finally {
      setMonitoringBusy(false);
    }
  };

  const handleStopSession = async (sessionId: string) => {
    try {
      setMonitoringBusy(true);
      await stopMonitoringSession(sessionId);
      if (selectedSession?.session_id === sessionId) {
        setSelectedSession(null);
      }
      await loadMonitoringData(monitoringActiveOnly);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop monitoring session');
    } finally {
      setMonitoringBusy(false);
    }
  };

  const handleInspectSession = async (sessionId: string) => {
    try {
      const detail = await fetchMonitoringSessionDetail(sessionId);
      setSelectedSession(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load monitoring session details');
    }
  };

  const viewInVisualization = useCallback((analysis: any) => {
    // Store selected analysis for visualization and update localStorage cache
    sessionStorage.setItem('selectedAnalysis', JSON.stringify(analysis));
    localStorage.setItem('latestAnalysis', JSON.stringify(analysis));
    // Close the modal and navigate to visualization
    closeModal();
    router.push('/dashboard/visualization');
  }, [router, closeModal])

  useEffect(() => {
  console.log("Updated allSingleAnalysis:", allSingleAnalysis)
}, [allSingleAnalysis])

  // Escape key handler for modal
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showModal) {
        closeModal()
      }
    }

    if (showModal) {
      document.addEventListener('keydown', handleEscape)
      document.body.style.overflow = 'hidden'
    }

    return () => {
      document.removeEventListener('keydown', handleEscape)
      document.body.style.overflow = 'unset'
    }
  }, [showModal, closeModal])

  

  const getColorClasses = useCallback((color: string) => {
    switch (color) {
      case 'cyan': return 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 bg-cyan-500/10'
      case 'purple': return 'border-purple-500/30 hover:border-purple-400 text-purple-400 bg-purple-500/10'
      case 'red': return 'border-red-500/30 hover:border-red-400 text-red-400 bg-red-500/10'
      case 'green': return 'border-green-500/30 hover:border-green-400 text-green-400 bg-green-500/10'
      default: return 'border-gray-500/30 hover:border-gray-400 text-gray-400 bg-gray-500/10'
    }
  }, [])

const convertUSToIST = (timeG: string | Date) => {
  console.log("Original US time : ", timeG);
  const utcDate = new Date(timeG);
  console.log("Converted UTC time : ", utcDate);
const istOffset = 5.5 * 60 * 60 * 1000; // 5 hours 30 mins in ms
const istDate = new Date(utcDate.getTime() + istOffset);
return istDate;
}

  const getSeverityColor = useCallback((severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-900/30 border-red-500/30'
      case 'high': return 'text-orange-400 bg-orange-900/30 border-orange-500/30'
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/30'
      case 'low': return 'text-green-400 bg-green-900/30 border-green-500/30'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/30'
    }
  }, [])

  const getActivityTypeColor = useCallback((type: string) => {
    switch (type.toLowerCase()) {
      case 'auth': return 'text-green-400 bg-green-900/30 border-green-500/30'
      case 'analysis': return 'text-cyan-400 bg-cyan-900/30 border-cyan-500/30'
      case 'query': return 'text-purple-400 bg-purple-900/30 border-purple-500/30'
      case 'visualization': return 'text-blue-400 bg-blue-900/30 border-blue-500/30'
      case 'access': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/30'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/30'
    }
  }, [])

  const renderStructuredLog = (summary: string) => {
    if (!summary) return <div>No summary available</div>;

    // Split the sections by headings
    const sections = summary.split(/\n(?=###?)/); // Split at lines starting with # or ##
    
    return sections.map((section, idx) => {
      // Extract heading
      const headingMatch = section.match(/^(###? ?)(.+)/);
      const content = headingMatch ? section.replace(headingMatch[0], '').trim() : section;

      return (
        <div key={idx} className="mb-4">
          {headingMatch && (
            <h3 className="text-cyan-400 font-semibold mb-2">{headingMatch[2]}</h3>
          )}
          <div className="bg-black/50 border border-gray-700/30 p-4 text-green-400 whitespace-pre-wrap text-sm max-h-64 overflow-y-auto">
            {content}
          </div>
        </div>
      );
    });
  };

  const getActivityIcon = useCallback((type: string) => {
    switch (type.toLowerCase()) {
      case 'auth': return '🔐'
      case 'analysis': return '🔍'
      case 'query': return '📊'
      case 'visualization': return '📈'
      case 'access': return '🖥️'
      default: return '⚡'
    }
  }, [])

  const formatTimestamp = useCallback((timestamp: string) => {
    if (!timestamp) return 'N/A'
    try {
      const date = new Date(timestamp)
      return date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }) + ' IST'
    } catch {
      return 'Invalid Date'
    }
  }, [])

  const extractSummaryPreview = useCallback((summary: string) => {
    if (!summary) return 'No summary available'
    const lines = summary.replace(/```/g, '').split('\n').filter(line => line.trim())
    return lines.slice(0, 3).join(' ').substring(0, 150) + '...'
  }, [])

  const getSeverityFromSummary = useCallback((summary: string) => {
    if (!summary) return 'unknown'
    const summaryLower = summary.toLowerCase()
    if (summaryLower.includes('critical') || summaryLower.includes('high priority')) return 'critical'
    if (summaryLower.includes('high') || summaryLower.includes('moderate')) return 'high'
    if (summaryLower.includes('medium')) return 'medium'
    if (summaryLower.includes('low')) return 'low'
    return 'medium'
  }, [])

  // Navigation function with proper router integration
  const navigate = useCallback((href: string) => {
    if (href === '/dashboard/visualization') {
      // For visualization, fetch latest analysis summary and navigate
      fetchLatestAnalysisSummary();
    } else {
      router.push(href);
    }
  }, [router])

  const fetchLatestAnalysisSummary = async () => {
    try {
      // Try to get the latest analysis from localStorage first
      const storedAnalysis = localStorage.getItem('latestAnalysis');
      if (storedAnalysis) {
        const analysis = JSON.parse(storedAnalysis);
        // Navigate to visualization which will auto-load from localStorage
        router.push('/dashboard/visualization');
        return;
      }

      // If no stored analysis, try to fetch from API
      const response = await fetch(`${API_BASE_URL}/api/v1/latest`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
      });

      if (response.ok) {
        const data = await response.json();
        if (data.analysis) {
          // Store the latest analysis in localStorage
          localStorage.setItem('latestAnalysis', JSON.stringify(data.analysis));
        }
      }
      
      // Navigate to visualization regardless of API response
      router.push('/dashboard/visualization');
    } catch (err) {
      console.error('Error fetching latest analysis:', err);
      // Navigate anyway, visualization page will handle the error state
      router.push('/dashboard/visualization');
    }
  }

  const FeatureCard = React.memo(({ feature, index }: { feature: any, index: number }) => (
    <div 
      className={`relative bg-black/80 backdrop-blur-sm border rounded-2xl ${getColorClasses(feature.color)} p-4 sm:p-6 transition-all duration-300 group cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,150,0.3)]`}
      onMouseEnter={() => setHoveredFeature(index)}
      onMouseLeave={() => setHoveredFeature(null)}
      onClick={() => navigate(feature.href)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          
        }
      }}
    >
      <div className="flex items-start justify-between mb-3 sm:mb-4">
        <div className={`w-10 h-10 sm:w-12 sm:h-12 ${getColorClasses(feature.color)} flex items-center justify-center text-xl sm:text-2xl group-hover:scale-110 transition-transform duration-300`}>
          {feature.icon}
        </div>
        <span className={`text-xs px-2 py-1 border ${getColorClasses(feature.color)} whitespace-nowrap`}>
          [{feature.stats}]
        </span>
      </div>
      
      <h3 className="text-lg sm:text-xl font-semibold text-green-400 mb-2 group-hover:text-cyan-400 transition-colors break-words">
        <span className="hidden sm:inline">&gt; {feature.title}</span>
        <span className="sm:hidden">&gt; {feature.shortTitle}</span>
      </h3>
      <p className="text-gray-300 leading-relaxed text-xs sm:text-sm break-words">
        <span className="hidden sm:inline">{feature.description}</span>
        <span className="sm:hidden">{feature.shortDescription}</span>
      </p>
      
      <div className="mt-3 sm:mt-4 flex items-center text-cyan-400 text-xs sm:text-sm font-medium">
        <span>&gt; EXEC_MODULE --RUN</span>
      </div>
      
      {hoveredFeature === index && (
        <>
          <div className={`absolute inset-0 ${getColorClasses(feature.color)} animate-pulse rounded-2xl`} />
          <div className={`absolute -inset-1 border ${getColorClasses(feature.color)} animate-pulse rounded-2xl`} />
        </>
      )}
    </div>
  ))

  // Calculate total techniques correctly
  const totalTechniques = allSingleAnalysis.reduce((total, analysis) => {
    return total + (Array.isArray(analysis?.matched_techniques) ? analysis.matched_techniques.length : 0)
  }, 0)

  return (
    <div className='relative bg-black min-h-screen w-full text-white overflow-x-hidden'>
      {/* Terminal grid overlay */}
      <div 
        className="absolute inset-0 opacity-5 pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0, 255, 150, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 150, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '20px 20px'
        }}
      />
      
      {/* Matrix-style overlay */}
      <div className="absolute inset-0 bg-gradient-to-b from-black/60 via-transparent to-black/80 pointer-events-none" />
      
      {/* Navbar placeholder */}
      <Navbar/>
      
      <div className="relative container mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 md:py-8 font-mono max-w-full">
        {/* Error Display */}
        {error && (
          <div className="mb-6 bg-red-900/30 border border-red-500/50 rounded-lg p-4 text-red-400">
            <div className="flex items-center space-x-2">
              <span className="text-xl">⚠️</span>
              <span>[ERROR]: {error}</span>
            </div>
          </div>
        )}

        {/* Terminal Header */}
        <div className={`mb-6 sm:mb-8 transform transition-all duration-1000 ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-t-lg p-2 sm:p-3 mb-4 overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-red-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-yellow-500"></div>
              <div className="w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-green-500"></div>
              <span className="ml-2 sm:ml-4 text-green-400 text-xs sm:text-sm">admin@logiq:~/dashboard#</span>
            </div>
            <div className="text-green-400 text-xs sm:text-sm overflow-hidden">
              <div className="whitespace-nowrap overflow-hidden">
                {isMobile ? terminalText.slice(0, 30) + (terminalText.length > 30 ? '...' : '') : terminalText}
                {showCursor && <span className="bg-green-400 text-black ml-1">▊</span>}
              </div>
            </div>
          </div>
          
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-green-400 mb-2 tracking-wider break-words">
            [SECURITY_OPS_DASHBOARD]
          </h1>
          <div className="text-cyan-400 text-xs sm:text-sm overflow-hidden">
            <div className="whitespace-nowrap overflow-x-auto">
              &gt; CYBER_THREAT_ANALYSIS.PLATFORM --STATUS=OPERATIONAL
            </div>
          </div>
        </div>

        {/* Terminal Stats Overview */}
        <div className={`grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 mb-6 sm:mb-8 transform transition-all duration-1000 delay-200 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[TOTAL_ANALYSES]</p>
                <p className="text-xl sm:text-2xl font-bold text-cyan-400">
                  {totalAnalysesCount > 0 ? totalAnalysesCount : recentAnalyses.length}
                </p>
              </div>
              <div className="text-cyan-400 text-lg sm:text-xl"><BsGraphUp /></div>
            </div>
          </div>
          
          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[TOTAL_TECHNIQUES_PROCESSED]</p>
                <p className="text-xl sm:text-2xl font-bold text-green-400">
                  {totalTechniques}
                </p>
              </div>
              <div className="text-green-400 text-lg sm:text-xl"><FaShield /></div>
            </div>
          </div>

          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[CLI_STATUS]</p>
                <p className={`text-xl sm:text-2xl font-bold ${userProfile?.cli_active ? 'text-green-400' : 'text-gray-400'}`}>
                  {userProfile?.cli_active ? 'ACTIVE' : 'INACTIVE'}
                </p>
              </div>
              <div className={`text-lg sm:text-xl ${userProfile?.cli_active ? 'text-green-400' : 'text-gray-400'}`}>
                {userProfile?.cli_active ? '🖥️' : '💤'}
              </div>
            </div>
          </div>

          <div className="bg-black/80 backdrop-blur-sm border border-green-500/30 p-3 sm:p-4 font-mono">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">[SYSTEM_STATUS]</p>
                <p className={`text-sm sm:text-base font-bold ${
                  healthFailed ? 'text-red-400' : health?.status === 'healthy' ? 'text-green-400' : 'text-yellow-400'
                }`}>
                  {healthFailed ? 'OFFLINE' : (health?.status || 'CHECKING').toUpperCase()}
                </p>
              </div>
              <div className={`text-lg sm:text-xl ${healthFailed ? 'text-red-400' : 'text-green-400'}`}><GrValidate/></div>
            </div>
            {health?.services && (
              <div className="mt-2 flex flex-wrap gap-1 text-[10px]">
                {Object.entries(health.services).map(([svc, st]) => (
                  <span
                    key={svc}
                    className={`px-1.5 py-0.5 border ${
                      st === 'healthy'
                        ? 'border-green-500/40 text-green-300'
                        : 'border-yellow-500/40 text-yellow-300'
                    }`}
                  >
                    {svc}: {st}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Multi-Agent Orchestrator & User Analytics Overview */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6 sm:mb-8">
          <div className="bg-black/80 backdrop-blur-sm border border-cyan-500/30 p-4 font-mono">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h3 className="text-sm font-semibold text-cyan-400">[USER_ANALYTICS.STAT]</h3>
              <span className="text-xs text-gray-400">
                AVG_TIME: {userAnalytics ? `${(userAnalytics.avg_processing_time / 1000).toFixed(2)}s` : '-'}
              </span>
            </div>
            <div className="space-y-3 text-xs">
              <div>
                <span className="text-gray-400 block mb-1">TOP_MATCHED_TECHNIQUES:</span>
                {userAnalytics?.most_common_techniques?.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {userAnalytics.most_common_techniques.slice(0, 6).map((t) => (
                      <span key={t.technique_id} className="px-2 py-0.5 border border-red-500/40 bg-red-950/20 text-red-300">
                        {t.technique_id} ({t.count})
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-gray-500">No technique history aggregated yet.</span>
                )}
              </div>
              {userAnalytics?.analysis_timeline?.length ? (
                <div>
                  <span className="text-gray-400 block mb-1">RECENT_ACTIVITY_DAYS:</span>
                  <div className="flex flex-wrap gap-2">
                    {userAnalytics.analysis_timeline.slice(-5).map((pt) => (
                      <span key={pt.date} className="px-2 py-0.5 border border-cyan-500/30 text-cyan-300">
                        {pt.date}: {pt.count} run(s)
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </div>

          <div className="bg-black/80 backdrop-blur-sm border border-purple-500/30 p-4 font-mono">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h3 className="text-sm font-semibold text-purple-400">[ORCHESTRATOR_CONFIG.SYS]</h3>
              <span className="text-xs text-gray-400">
                OKF_TECH: {health?.database_stats?.total_techniques ?? '-'}
              </span>
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="px-2 py-1 border border-purple-500/40 text-purple-300">
                KEY_POOL: {invConfig?.key_pool_size ?? '-'}
              </span>
              <span className="px-2 py-1 border border-cyan-500/40 text-cyan-300">
                REFINEMENT_ROUNDS: {invConfig?.max_refinement_rounds ?? '-'}
              </span>
              <span className={`px-2 py-1 border ${
                invConfig?.lstm_connected
                  ? 'border-green-500/50 text-green-300'
                  : 'border-yellow-500/40 text-yellow-300'
              }`}>
                LSTM_SEQUENCE: {invConfig?.lstm_connected ? 'ACTIVE' : 'STANDBY'}
              </span>
              {health?.database_stats?.collection_name && (
                <span className="px-2 py-1 border border-green-500/40 text-green-300">
                  STORE: {health.database_stats.collection_name}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Terminal Features Grid */}
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6 mb-6 sm:mb-8 transform transition-all duration-1000 delay-400 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          {features.map((feature, index) => (
            <Link key={index} href={feature.href}>
              <div 
                className={`relative bg-black/80 backdrop-blur-sm border rounded-2xl ${getColorClasses(feature.color)} p-4 sm:p-6 transition-all duration-300 group cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,150,0.3)]`}
                onMouseEnter={() => setHoveredFeature(index)}
                onMouseLeave={() => setHoveredFeature(null)}
              >
                <div className="flex items-start justify-between mb-3 sm:mb-4">
                  <div className={`w-10 h-10 sm:w-12 sm:h-12 ${getColorClasses(feature.color)} flex items-center justify-center text-xl sm:text-2xl group-hover:scale-110 transition-transform duration-300`}>
                    {feature.icon}
                  </div>
                  <span className={`text-xs px-2 py-1 border ${getColorClasses(feature.color)} whitespace-nowrap`}>
                    [{feature.stats}]
                  </span>
                </div>
                
                <h3 className="text-lg sm:text-xl font-semibold text-green-400 mb-2 group-hover:text-cyan-400 transition-colors break-words">
                  <span className="hidden sm:inline">&gt; {feature.title}</span>
                  <span className="sm:hidden">&gt; {feature.shortTitle}</span>
                </h3>
                <p className="text-gray-300 leading-relaxed text-xs sm:text-sm break-words">
                  <span className="hidden sm:inline">{feature.description}</span>
                  <span className="sm:hidden">{feature.shortDescription}</span>
                </p>
                
                <div className="mt-3 sm:mt-4 flex items-center text-cyan-400 text-xs sm:text-sm font-medium">
                  <span>&gt; EXEC_MODULE --RUN</span>
                </div>
                
                {hoveredFeature === index && (
                  <>
                    <div className={`absolute inset-0 ${getColorClasses(feature.color)} animate-pulse`} />
                    <div className={`absolute -inset-1 border ${getColorClasses(feature.color)} animate-pulse`} />
                  </>
                )}
              </div>
            </Link>
          ))}
        </div>


        {/* Terminal Recent Analyses with Pagination */}
        <div className={`bg-black/80 backdrop-blur-sm border border-green-500/30 rounded-2xl p-4 sm:p-6 transform transition-all duration-1000 delay-600 ${isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
          <div>
            <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6 flex items-center text-green-400">
              <span className="w-2 h-2 bg-green-500 rounded-full mr-2 sm:mr-3 animate-pulse flex-shrink-0"></span>
              <span className="break-words">[RECENT_ANALYSES.LOG]</span>
              <span className="ml-auto text-sm text-gray-400">
                [PAGE_{currentPage}/{totalPages}]
              </span>
            </h2>
            
            {loading ? (
              <div className="text-center py-8 text-cyan-400">
                <div className="inline-block animate-spin mr-2">⚙️</div>
                Loading analyses...
              </div>
            ) : allSingleAnalysis.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                No analyses available
              </div>
            ) : (
              <div className="space-y-2 sm:space-y-3">
                {allSingleAnalysis.map((analysis, index) => {
                  const realSeverity =
                    analysis?.investigation?.overall_threat_level ||
                    analysis?.visualization_metrics?.overall_threat_level ||
                    getSeverityFromSummary(analysis?.summary);
                  const realConfidence =
                    analysis?.investigation?.overall_confidence ||
                    analysis?.visualization_metrics?.overall_confidence_label;
                  const cveCount =
                    analysis?.visualization_metrics?.summary_counts?.cve_count ??
                    (Array.isArray(analysis?.investigation?.retrieved_knowledge)
                      ? analysis.investigation.retrieved_knowledge.filter(
                          (k: any) => k?.source_type === 'cve'
                        ).length
                      : 0);

                  return (
                  <div 
                    key={analysis?.id || index} 
                    className="flex flex-col p-3 bg-black/50 border border-gray-700/30 hover:border-cyan-500/30 transition-colors font-mono cursor-pointer"
                    onClick={() => handleAnalysisClick(analysis)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        handleAnalysisClick(analysis)
                      }
                    }}
                  >
                    <div className="flex items-center space-x-3 mb-2">
                      <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse flex-shrink-0"></div>
                      <div className="flex-1 min-w-0">
                        <h4 className="font-medium text-cyan-400 text-sm break-words">
                          &gt; ANALYSIS_#{((currentPage - 1) * itemsPerPage) + index + 1}
                        </h4>
                        <p className="text-xs text-gray-400">
                          [{convertUSToIST(analysis.analysis_timestamp).toLocaleString()}]
                        </p>
                      </div>
                    </div>
                    
                    <div className="pl-5 text-xs text-gray-300 mb-2">
                      {extractSummaryPreview(analysis?.summary)}
                    </div>
                    
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs pl-5">
                      <div className="flex flex-wrap items-center space-x-2">
                        <span className="text-gray-300">
                          [{Array.isArray(analysis?.matched_techniques) ? analysis.matched_techniques.length : 0}_TECH]
                        </span>
                        {cveCount > 0 && (
                          <span className="text-orange-300">[{cveCount}_CVE]</span>
                        )}
                        <span className={`px-2 py-1 text-xs font-medium border ${getSeverityColor(realSeverity)}`}>
                          {String(realSeverity).toUpperCase()}
                        </span>
                        {realConfidence && (
                          <span className="px-2 py-1 text-xs border border-cyan-500/30 text-cyan-300">
                            CONF:{String(realConfidence).toUpperCase()}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-green-400">
                          [COMPLETED]
                        </span>
                        <span className="px-2 py-1 bg-purple-900/30 border border-purple-500/30 hover:border-purple-400 hover:bg-purple-500/20 text-purple-400 hover:text-purple-300 transition-colors text-xs">
                          [VIEW]
                        </span>
                        {analysis?.id && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteAnalysis(analysis.id);
                            }}
                            className="px-2 py-1 bg-red-900/20 border border-red-500/40 hover:border-red-400 text-red-400 text-xs cursor-pointer"
                          >
                            [DELETE]
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                  );
                })}
              </div>
            )}

            {/* Pagination Controls */}
            {!loading && allSingleAnalysis.length > 0 && (
              <div className="mt-6 flex flex-col sm:flex-row items-center justify-between gap-4 border-t border-gray-700/30 pt-4">
                <div className="text-xs text-gray-400">
                  Showing {((currentPage - 1) * itemsPerPage) + 1} - {Math.min(currentPage * itemsPerPage, totalAnalysesCount > 0 ? totalAnalysesCount : totalPages * itemsPerPage)} of {totalAnalysesCount > 0 ? totalAnalysesCount : totalPages * itemsPerPage}
                </div>
                
                <div className="flex items-center space-x-2">
                  {/* First Page Button */}
                  <button
                    onClick={() => handlePageChange(1)}
                    disabled={currentPage === 1}
                    className={`px-3 py-1 text-xs border font-mono transition-all ${
                      currentPage === 1
                        ? 'border-gray-700 text-gray-600 cursor-not-allowed'
                        : 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 hover:bg-cyan-500/10'
                    }`}
                  >
                    [&lt;&lt;]
                  </button>

                  {/* Previous Button */}
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage === 1}
                    className={`px-3 py-1 text-xs border font-mono transition-all ${
                      currentPage === 1
                        ? 'border-gray-700 text-gray-600 cursor-not-allowed'
                        : 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 hover:bg-cyan-500/10'
                    }`}
                  >
                    [&lt;_PREV]
                  </button>

                  {/* Page Numbers */}
                  <div className="flex items-center space-x-1">
                    {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                      let pageNum;
                      if (totalPages <= 5) {
                        pageNum = i + 1;
                      } else if (currentPage <= 3) {
                        pageNum = i + 1;
                      } else if (currentPage >= totalPages - 2) {
                        pageNum = totalPages - 4 + i;
                      } else {
                        pageNum = currentPage - 2 + i;
                      }
                      
                      return (
                        <button
                          key={pageNum}
                          onClick={() => handlePageChange(pageNum)}
                          className={`px-3 py-1 text-xs border font-mono transition-all ${
                            currentPage === pageNum
                              ? 'border-green-500 bg-green-500/20 text-green-400'
                              : 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 hover:bg-cyan-500/10'
                          }`}
                        >
                          [{pageNum}]
                        </button>
                      );
                    })}
                  </div>

                  {/* Next Button */}
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className={`px-3 py-1 text-xs border font-mono transition-all ${
                      currentPage === totalPages
                        ? 'border-gray-700 text-gray-600 cursor-not-allowed'
                        : 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 hover:bg-cyan-500/10'
                    }`}
                  >
                    [NEXT_&gt;]
                  </button>

                  {/* Last Page Button */}
                  <button
                    onClick={() => handlePageChange(totalPages)}
                    disabled={currentPage === totalPages}
                    className={`px-3 py-1 text-xs border font-mono transition-all ${
                      currentPage === totalPages
                        ? 'border-gray-700 text-gray-600 cursor-not-allowed'
                        : 'border-cyan-500/30 hover:border-cyan-400 text-cyan-400 hover:bg-cyan-500/10'
                    }`}
                  >
                    [&gt;&gt;]
                  </button>
                </div>
              </div>
            )}

            <div className="mt-4 text-center">
              <button 
                onClick={() => navigate('/dashboard/analysis')}
                className="inline-flex items-center px-4 py-2 bg-black border-2 border-green-500 hover:border-cyan-400 text-green-400 hover:text-cyan-400 font-medium transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,150,0.5)] font-mono text-sm"
              >
                <span className="hidden sm:inline">&gt; NEW_ANALYSIS.EXE</span>
                <span className="sm:hidden">&gt; NEW_ANALYSIS</span>
              </button>
            </div>
          </div>
        </div>

        {/* Monitoring Sessions Panel */}
        <div className="mt-6 sm:mt-8 bg-black/80 backdrop-blur-sm border border-cyan-500/30 rounded-2xl p-4 sm:p-6 font-mono">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div>
              <h2 className="text-lg sm:text-xl font-semibold text-cyan-400">[MONITORING_SESSIONS.SVC]</h2>
              <p className="text-xs text-gray-400">
                30d System Analyses: {monitoringStats?.total_analyses ?? '-'} · Active Sessions: {monitoringStats?.active_sessions ?? '-'}
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <button
                type="button"
                onClick={() => setMonitoringActiveOnly((prev) => !prev)}
                className="px-3 py-1 border border-cyan-500/40 text-cyan-300 cursor-pointer"
              >
                FILTER: {monitoringActiveOnly ? 'ACTIVE_ONLY' : 'ALL_SESSIONS'}
              </button>
              <button
                type="button"
                onClick={() => loadMonitoringData(monitoringActiveOnly)}
                className="px-3 py-1 border border-green-500/40 text-green-400 cursor-pointer"
              >
                [REFRESH]
              </button>
            </div>
          </div>

          <form onSubmit={handleCreateMonitoringSession} className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4 text-xs">
            <input
              value={newLogPath}
              onChange={(e) => setNewLogPath(e.target.value)}
              placeholder="/var/log/auth.log"
              className="md:col-span-2 bg-black border border-gray-700 px-3 py-2 text-white"
            />
            <input
              type="number"
              min={10}
              value={newIntervalSec}
              onChange={(e) => setNewIntervalSec(Number(e.target.value) || 300)}
              placeholder="Interval (sec)"
              className="bg-black border border-gray-700 px-3 py-2 text-white"
            />
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-1.5 text-gray-300">
                <input
                  type="checkbox"
                  checked={newAiEnabled}
                  onChange={(e) => setNewAiEnabled(e.target.checked)}
                />
                AI
              </label>
              <button
                type="submit"
                disabled={monitoringBusy}
                className="flex-1 py-2 border border-green-500 text-green-400 hover:bg-green-500/20 cursor-pointer"
              >
                [+ START_SESSION]
              </button>
            </div>
          </form>

          {monitoringSessions.length === 0 ? (
            <p className="text-xs text-gray-400">No monitoring sessions found for this filter.</p>
          ) : (
            <div className="space-y-2">
              {monitoringSessions.map((sess) => (
                <div
                  key={sess.session_id}
                  className="bg-black/60 border border-gray-700/60 p-3 flex flex-wrap items-center justify-between gap-2 text-xs"
                >
                  <div>
                    <div className="text-white font-semibold">{sess.log_path}</div>
                    <div className="text-gray-400">
                      id: {sess.session_id} · interval: {sess.interval_seconds}s · status: {sess.status}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => handleInspectSession(sess.session_id)}
                      className="px-2 py-1 border border-cyan-500/40 text-cyan-300 cursor-pointer"
                    >
                      [INSPECT]
                    </button>
                    {sess.status === 'active' && (
                      <button
                        type="button"
                        onClick={() => handleStopSession(sess.session_id)}
                        disabled={monitoringBusy}
                        className="px-2 py-1 border border-red-500/50 text-red-400 cursor-pointer"
                      >
                        [STOP]
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {selectedSession && (
            <div className="mt-4 bg-black/70 border border-cyan-500/40 p-3 text-xs">
              <div className="flex justify-between mb-1">
                <span className="text-cyan-300 font-bold">Session Detail: {selectedSession.session_id}</span>
                <button type="button" onClick={() => setSelectedSession(null)} className="text-red-400 cursor-pointer">[CLOSE]</button>
              </div>
              <pre className="text-gray-300 overflow-x-auto">{JSON.stringify(selectedSession, null, 2)}</pre>
            </div>
          )}
        </div>


        {/* Analysis Detail Modal */}
        {showModal && selectedAnalysis && (
          <div 
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={(e) => {
              if (e.target === e.currentTarget) {
                closeModal()
              }
            }}
          >
            <div className="bg-black border-2 border-green-500/50 rounded-2xl max-w-6xl max-h-[90vh] overflow-hidden font-mono w-full">
              {/* Modal Header */}
              <div className="bg-black/80 backdrop-blur-sm border-b border-green-500/30 p-4 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                  <h3 className="text-lg font-semibold text-green-400">
                    [ANALYSIS_DETAILS.EXE]
                  </h3>
                </div>
                <button 
                  onClick={closeModal}
                  className="text-red-400 hover:text-red-300 text-xl font-bold transition-colors w-8 h-8 flex items-center justify-center hover:bg-red-900/20 rounded"
                  aria-label="Close modal"
                >
                  ×
                </button>
              </div>

          
              {/* Modal Content */}
              <div className="p-6 overflow-y-auto max-h-[70vh]">
                {/* Analysis Timestamp */}
                <div className="mb-6">
                  <div className="text-cyan-400 text-sm mb-2">[ANALYSIS_TIMESTAMP]</div>
                  <div className="bg-black/50 border border-gray-700/30 p-3 text-green-400">
                    &gt; 
                    <div>{convertUSToIST(selectedAnalysis.analysis_timestamp).toLocaleString()}</div>
                  </div>
                </div>

                {/* Processing Time */}
                <div className="mb-6">
                  <div className="text-cyan-400 text-sm mb-2">[PROCESSING_TIME_S]</div>
                  <div className="bg-black/50 border border-gray-700/30 p-3 text-green-400">
                    &gt; {(selectedAnalysis.processing_time_ms/1000)?.toFixed(2) || 'N/A'} s
                  </div>
                </div>

                {/* Summary */}
                <div className="mb-6 ">
                  <div className="text-cyan-400 text-sm mb-2">[THREAT_SUMMARY.LOG]</div>
                  <div className="bg-black/50 border border-gray-700/30 p-4 text-green-400 whitespace-pre-wrap text-sm max-h-64 overflow-y-auto">
                     <MarkdownRenderer markdown={selectedAnalysis.summary} />
                    
                  </div>
                </div>

                {/* Matched Techniques */}
                <div className="mb-6">
                  <div className="text-cyan-400 text-sm mb-2">[MITRE_TECHNIQUES.DB]</div>
                  <div className="space-y-3">
                    {Array.isArray(selectedAnalysis.matched_techniques) && selectedAnalysis.matched_techniques.length > 0 ? (
                      selectedAnalysis.matched_techniques.map((technique: any, index: number) => (
                        <div key={index} className="bg-black/50 border border-gray-700/30 p-4">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center space-x-3">
                              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                              <h4 className="text-red-400 font-semibold">
                                [{technique.technique_id}] {technique.name}
                              </h4>
                            </div>
                            <span className="text-xs px-2 py-1 border border-orange-500/30 text-orange-400">
                              {Array.isArray(technique.kill_chain_phases) && technique.kill_chain_phases.length > 0
                                ? technique.kill_chain_phases.join(', ').toUpperCase()
                                : technique.tactic || 'UNKNOWN'}
                            </span>
                          </div>
                          {technique.description && (
                            <p className="text-gray-300 text-sm pl-5">
                              {technique.description}
                            </p>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="bg-black/50 border border-gray-700/30 p-4 text-gray-400 text-center">
                        No MITRE techniques identified
                      </div>
                    )}
                  </div>
                </div>

                {selectedAnalysis.investigation && (
                  <div className="mb-6">
                    <InvestigationReportPanel
                      investigation={selectedAnalysis.investigation}
                      visualizationMetrics={selectedAnalysis.visualization_metrics}
                      compact
                    />
                  </div>
                )}

                {/* Modal Content */}
                {/* Modal Actions */}
                <div className="flex flex-wrap justify-end gap-3 pt-4 border-t border-gray-700/30">
                  {selectedAnalysis?.id && (
                    <button
                      type="button"
                      onClick={() => handleDeleteAnalysis(selectedAnalysis.id)}
                      className="px-4 py-2 bg-black border-2 border-red-500 hover:border-red-400 text-red-400 hover:text-red-300 font-medium transition-all duration-300 font-mono text-sm cursor-pointer"
                    >
                      [DELETE]
                    </button>
                  )}
                  <button
                    onClick={closeModal}
                    className="px-4 py-2 bg-black border-2 border-gray-500 hover:border-gray-400 text-gray-400 hover:text-gray-300 font-medium transition-all duration-300 font-mono text-sm"
                  >
                    [CLOSE]
                  </button>
                  <button
                    onClick={() => viewInVisualization(selectedAnalysis)}
                    className="px-4 py-2 bg-black border-2 border-blue-500 hover:border-blue-400 text-blue-400 hover:text-blue-300 font-medium transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,100,255,0.5)] font-mono text-sm"
                  >
                    [VIEW_VISUALIZATION]
                  </button>
                  
                  <button
                    onClick={() => selectedAnalysis && exportMarkdownToPdf(selectedAnalysis.summary)}
                    className="px-4 py-2 bg-black border-2 border-cyan-500 hover:border-cyan-400 text-cyan-400 hover:text-cyan-300 font-medium transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,255,255,0.5)] font-mono text-sm"
                  >
                    [EXPORT]
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default DashboardPage