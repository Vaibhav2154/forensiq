'use client'
import React, { useState, useEffect } from 'react';
import EnhancedThreatDashboard from '@/components/enhanced-threat-dashboard';
import Navbar from '@/components/navbar';
import ToastNotification from '@/components/toast-notification';
import { useToast } from '@/hooks/useToast';

// Sample data structure matching your API response
const mockAnalysisData = {
  "summary": "## System Log Analysis: 2025-08-07\n\n**1. Security Events:**\n\n* **Potential Event:** The log entry shows the execution of `reg.exe` to query the registry key `hklm\\SOFTWARE\\Classes\\Protocols\\Handler`. While not inherently malicious, querying this key could be used to gather information about registered protocol handlers, potentially leading to manipulation of how the system handles file types or URLs. This requires further investigation to determine intent. Lack of other logs makes this inconclusive.\n\n**2. System Activities:**\n\n* The system executed a registry query using the `reg.exe` command-line tool. This is a standard system utility but its use in this context warrants further investigation.\n\n**3. Network Activities:**\n\n* No network activity is logged in this single entry.\n\n**4. Error Patterns:**\n\n* No errors are reported in this log entry.\n\n**5. Timeline:**\n\n* **2025-08-07T13:02:02Z:** Registry query of `hklm\\SOFTWARE\\Classes\\Protocols\\Handler` using `reg.exe`.\n\n**6. Potential Threats:**\n\n* **Potential Information Gathering:** The registry query could be a preliminary step in an attack to map system configurations before exploiting a vulnerability. This is low confidence without further evidence.\n* **Privilege Escalation Attempt (Low Confidence):** Modification of protocol handlers can be used for privilege escalation, but this log only shows a query, not a modification.",
  "matched_techniques": [
    {
      "technique_id": "T1012",
      "name": "Query Registry",
      "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. The Registry contains a significant amount of information about the operating system, configuration, software, and security. Information can easily be queried using the Reg utility, though other means to access the Registry exist.",
      "kill_chain_phases": ["discovery"],
      "platforms": ["Windows"],
      "relevance_score": 0.6493836045265198
    },
    {
      "technique_id": "T1063",
      "name": "Security Software Discovery",
      "description": "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules and anti-virus.",
      "kill_chain_phases": ["discovery"],
      "platforms": ["macOS", "Windows"],
      "relevance_score": 0.6133055090904236
    },
    {
      "technique_id": "T1057",
      "name": "Process Discovery",
      "description": "Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network.",
      "kill_chain_phases": ["discovery"],
      "platforms": ["Linux", "Network Devices", "Windows", "macOS", "ESXi"],
      "relevance_score": 0.6053206026554108
    },
    {
      "technique_id": "T1562.002",
      "name": "Disable Windows Event Logging",
      "description": "Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more.",
      "kill_chain_phases": ["defense-evasion"],
      "platforms": ["Windows"],
      "relevance_score": 0.5910313725471497
    },
    {
      "technique_id": "T1547.004",
      "name": "Winlogon Helper DLL",
      "description": "Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.",
      "kill_chain_phases": ["persistence", "privilege-escalation"],
      "platforms": ["Windows"],
      "relevance_score": 0.5741837620735168
    }
  ],
  "enhanced_analysis": "## Threat Analysis: Suspicious Registry Query\n\n**1. Threat Assessment:**\n\n* **Overall Threat Level:** Low to Medium. The current evidence suggests a low-level reconnaissance activity. However, the potential for escalation to a higher threat level exists if this is part of a larger attack.\n* **Confidence Level:** Low. The single log entry provides insufficient evidence to definitively classify this event as malicious.\n\n**2. Attack Vector Analysis:**\n\nThe observed `reg.exe` query targeting `hklm\\SOFTWARE\\Classes\\Protocols\\Handler` aligns with the **Query Registry** MITRE ATT&CK technique. This technique is often used during initial reconnaissance to gather information about the system's configuration.\n\n**3. Potential Impact:**\n\nIf this is part of a larger attack, the potential impact could be significant:\n\n* **Data Breach:** Exploiting vulnerabilities discovered through the reconnaissance could lead to data exfiltration.\n* **System Compromise:** Gaining unauthorized access to the system could allow attackers to install malware, steal credentials, or disrupt operations.\n* **Lateral Movement:** The attacker could leverage compromised systems to move further into the network.\n\n**4. Recommended Actions:**\n\n**Immediate Actions:**\n\n* **Enrich the Log:** Obtain the complete `reg.exe` command line from the event log or other sources.\n* **Correlation with other logs:** Examine logs from the same timeframe for correlated events.\n* **User Context:** Identify the user or process that executed the `reg.exe` command.\n\n**5. IOCs to Monitor:**\n\n* **Processes:** Monitor for unusual or unexpected execution of `reg.exe` or other system utilities.\n* **Registry Keys:** Monitor for any changes or modifications to registry keys related to protocol handlers.\n* **Network Connections:** Monitor for any unusual network connections originating from the affected system.",
  "analysis_timestamp": "2025-08-29T12:19:26.998990",
  "processing_time_ms": 11891.557931900024
};

interface AnalysisData {
  summary: string;
  matched_techniques: Array<{
    technique_id: string;
    name: string;
    description: string;
    kill_chain_phases: string[];
    platforms: string[];
    relevance_score: number;
  }>;
  enhanced_analysis: string;
  analysis_timestamp: string;
  processing_time_ms: number;
}

const EnhancedVisualizationPage = () => {
  const { toasts, removeToast, success, info } = useToast()
  const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dataSource, setDataSource] = useState<'latest' | 'sample'>('latest');

  useEffect(() => {
    // Try to load latest analysis from localStorage first
    loadLatestAnalysis();
  }, []);

  const loadLatestAnalysis = () => {
    try {
      const storedAnalysis = localStorage.getItem('latestAnalysis');
      if (storedAnalysis) {
        const analysisResult = JSON.parse(storedAnalysis);
        setAnalysisData(analysisResult);
        setDataSource('latest');
        success('Loaded latest analysis from storage');
      } else {
        // If no stored analysis, load sample data
        setAnalysisData(mockAnalysisData);
        setDataSource('sample');
        info('No recent analysis found, loaded sample data');
      }
    } catch (err) {
      console.error('Error loading analysis from localStorage:', err);
      setAnalysisData(mockAnalysisData);
      setDataSource('sample');
      info('Error loading stored analysis, using sample data');
    }
  };

  const loadFromAnalysis = async () => {
    // Try to fetch the latest analysis from the API first, then fall back to localStorage
    setLoading(true);
    try {
      // Try to fetch from API first
      const response = await fetch('http://localhost:8000/api/v1/latest');
      if (response.ok) {
        const data = await response.json();
        if (data.analysis) {
          setAnalysisData(data.analysis);
          setDataSource('latest');
          return;
        }
      }
      
      // Fall back to localStorage
      loadLatestAnalysis();
    } catch (err) {
      console.error('Error fetching from API, trying localStorage:', err);
      // Fall back to localStorage
      loadLatestAnalysis();
    } finally {
      setLoading(false);
    }
  };

  const loadSampleData = () => {
    setAnalysisData(mockAnalysisData);
    setDataSource('sample');
    info('Sample threat analysis data loaded');
  };

  if (loading) {
    return (
      <div className="bg-black min-h-screen flex items-center justify-center">
        <div className="text-green-400 font-mono">
          <div className="animate-pulse text-xl">[LOADING_THREAT_INTELLIGENCE...]</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-black min-h-screen flex items-center justify-center">
        <div className="text-red-400 font-mono">
          <div className="text-xl">[ERROR]: {error}</div>
          <button 
            onClick={loadFromAnalysis}
            className="mt-4 px-4 py-2 border border-green-500 text-green-400 hover:bg-green-500/20 transition-colors"
          >
            [RETRY]
          </button>
        </div>
      </div>
    );
  }

  if (!analysisData) {
    return (
      <div className="bg-black min-h-screen">
        <Navbar />
        <div className="container mx-auto px-4 py-8">
          <div className="text-center">
            <h1 className="text-3xl font-bold text-green-400 mb-4 font-mono">[NO_ANALYSIS_DATA]</h1>
            <p className="text-gray-400 mb-6">No threat analysis data available. Run an analysis first or load sample data.</p>
            <div className="space-x-4">
              <button 
                onClick={loadFromAnalysis}
                className="px-6 py-3 border-2 border-green-500 text-green-400 hover:bg-green-500/20 transition-colors font-mono"
              >
                [RELOAD_LATEST_ANALYSIS]
              </button>
              <button 
                onClick={loadSampleData}
                className="px-6 py-3 border-2 border-purple-500 text-purple-400 hover:bg-purple-500/20 transition-colors font-mono"
              >
                [LOAD_SAMPLE_DATA]
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-black min-h-screen">
      <ToastNotification toasts={toasts} removeToast={removeToast} />
      <Navbar />
      <div className="container mx-auto px-4 py-4">
        {/* Data source indicator */}
        <div className="mb-4 flex justify-between items-center">
          <div className="text-green-400 font-mono text-sm">
            [DATA_SOURCE]: {dataSource === 'latest' ? 'LATEST_ANALYSIS' : 'SAMPLE_DATA'}
          </div>
          <div className="space-x-2">
            <button 
              onClick={loadFromAnalysis}
              className="px-3 py-1 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-colors font-mono text-xs"
            >
              [RELOAD]
            </button>
            {dataSource === 'latest' && (
              <button 
                onClick={loadSampleData}
                className="px-3 py-1 border border-purple-500/30 text-purple-400 hover:bg-purple-500/20 transition-colors font-mono text-xs"
              >
                [SAMPLE]
              </button>
            )}
          </div>
        </div>
      </div>
      <EnhancedThreatDashboard analysisData={analysisData} />
    </div>
  );
};

export default EnhancedVisualizationPage;
