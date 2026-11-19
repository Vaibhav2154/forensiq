import type {
  AnalysisChatRequest,
  AnalysisChatResponse,
  BatchIngestRequest,
  HealthCheckResponse,
  HistoryChatRequest,
  IngestionRunStatus,
  InvestigationConfig,
  InvestigationInput,
  InvestigationResult,
  KnowledgeRecordDetailResponse,
  KnowledgeSearchParams,
  KnowledgeSearchResponse,
  KnowledgeStoreStats,
  MonitoringAnalysisStats,
  MonitoringSession,
  NormalizedEvent,
  UserAnalyticsStats,
} from './types';

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  'http://127.0.0.1:8000';

export function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('token');
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }
  return headers;
}

async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
  includeAuth: boolean = true
): Promise<T> {
  const baseHeaders = includeAuth
    ? getAuthHeaders()
    : { 'Content-Type': 'application/json' };

  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      ...baseHeaders,
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const payload = await res.json();
      if (payload?.detail) {
        message =
          typeof payload.detail === 'string'
            ? payload.detail
            : JSON.stringify(payload.detail);
      }
    } catch {
      // Fallback to HTTP status message
    }
    throw new Error(message);
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Health & Multi-Agent Investigation Endpoints
// ---------------------------------------------------------------------------

export function fetchHealth(): Promise<HealthCheckResponse> {
  return apiRequest<HealthCheckResponse>('/health', { method: 'GET' }, false);
}

export function fetchInvestigationConfig(): Promise<InvestigationConfig> {
  return apiRequest<InvestigationConfig>(
    '/api/v1/investigations/config',
    { method: 'GET' },
    false
  );
}

export function runInvestigation(
  payload: InvestigationInput
): Promise<InvestigationResult> {
  return apiRequest<InvestigationResult>(
    '/api/v1/investigations/run',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    false
  );
}

export function runInvestigationFromBatch(
  batch: BatchIngestRequest,
  topK: number = 8
): Promise<InvestigationResult> {
  return apiRequest<InvestigationResult>(
    `/api/v1/investigations/from-batch?top_k_knowledge=${encodeURIComponent(topK)}`,
    {
      method: 'POST',
      body: JSON.stringify(batch),
    },
    false
  );
}

// ---------------------------------------------------------------------------
// History Management & User Analytics
// ---------------------------------------------------------------------------

export function fetchUserAnalytics(): Promise<UserAnalyticsStats> {
  return apiRequest<UserAnalyticsStats>('/api/v1/analytics', { method: 'GET' });
}

export function deleteAnalysisById(
  analysisId: string
): Promise<{ message: string }> {
  return apiRequest<{ message: string }>(
    `/api/v1/history/${encodeURIComponent(analysisId)}`,
    { method: 'DELETE' }
  );
}

export function chatWithStoredAnalysis(
  analysisId: string,
  payload: AnalysisChatRequest
): Promise<AnalysisChatResponse> {
  return apiRequest<AnalysisChatResponse>(
    `/api/v1/history/${encodeURIComponent(analysisId)}/chat`,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    }
  );
}

export function chatWithAnalysisHistory(
  payload: HistoryChatRequest
): Promise<AnalysisChatResponse> {
  return apiRequest<AnalysisChatResponse>('/api/v1/history/chat', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// ---------------------------------------------------------------------------
// Monitoring Sessions & Stats
// ---------------------------------------------------------------------------

export function fetchMonitoringSessions(
  activeOnly: boolean = true
): Promise<MonitoringSession[]> {
  return apiRequest<MonitoringSession[]>(
    `/api/v1/monitoring/sessions?active_only=${activeOnly}`,
    { method: 'GET' }
  );
}

export function fetchMonitoringSessionDetail(
  sessionId: string
): Promise<MonitoringSession> {
  return apiRequest<MonitoringSession>(
    `/api/v1/monitoring/sessions/${encodeURIComponent(sessionId)}`,
    { method: 'GET' }
  );
}

export function createMonitoringSession(body: {
  log_path: string;
  interval_seconds: number;
  ai_agent_enabled: boolean;
}): Promise<{ session_id: string; status: string; message: string }> {
  return apiRequest<{ session_id: string; status: string; message: string }>(
    '/api/v1/monitoring/sessions',
    {
      method: 'POST',
      body: JSON.stringify(body),
    }
  );
}

export function stopMonitoringSession(
  sessionId: string
): Promise<{ session_id: string; status: string; message: string }> {
  return apiRequest<{ session_id: string; status: string; message: string }>(
    `/api/v1/monitoring/sessions/${encodeURIComponent(sessionId)}/stop`,
    { method: 'POST' }
  );
}

export function fetchMonitoringAnalysisStats(
  days: number = 30
): Promise<MonitoringAnalysisStats> {
  return apiRequest<MonitoringAnalysisStats>(
    `/api/v1/analysis/stats?days=${encodeURIComponent(days)}`,
    { method: 'GET' }
  );
}

// ---------------------------------------------------------------------------
// Knowledge / KCP / OKF / Cognee Endpoints
// ---------------------------------------------------------------------------

export function fetchKnowledgeStats(): Promise<KnowledgeStoreStats> {
  return apiRequest<KnowledgeStoreStats>(
    '/api/v1/knowledge/stats',
    { method: 'GET' },
    false
  );
}

export function searchKnowledge(
  params: KnowledgeSearchParams
): Promise<KnowledgeSearchResponse> {
  return apiRequest<KnowledgeSearchResponse>(
    '/api/v1/knowledge/search',
    {
      method: 'POST',
      body: JSON.stringify(params),
    },
    false
  );
}

export function fetchKnowledgeRecord(
  recordId: string,
  includeRelated: boolean = true
): Promise<KnowledgeRecordDetailResponse> {
  return apiRequest<KnowledgeRecordDetailResponse>(
    `/api/v1/knowledge/records/${encodeURIComponent(recordId)}?include_related=${includeRelated}`,
    { method: 'GET' },
    false
  );
}

export function fetchKnowledgeBySource(
  sourceType: 'mitre_attack' | 'cve',
  sourceId: string,
  includeRelated: boolean = true
): Promise<KnowledgeRecordDetailResponse> {
  return apiRequest<KnowledgeRecordDetailResponse>(
    `/api/v1/knowledge/source/${encodeURIComponent(sourceType)}/${encodeURIComponent(sourceId)}?include_related=${includeRelated}`,
    { method: 'GET' },
    false
  );
}

export function ingestMitre(
  payload: Record<string, unknown> = {}
): Promise<IngestionRunStatus> {
  return apiRequest<IngestionRunStatus>(
    '/api/v1/knowledge/ingest/mitre',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    false
  );
}

export function ingestCve(
  payload: Record<string, unknown> = {}
): Promise<IngestionRunStatus> {
  return apiRequest<IngestionRunStatus>(
    '/api/v1/knowledge/ingest/cve',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    false
  );
}

export function fetchIngestionStatuses(
  limit: number = 20
): Promise<IngestionRunStatus[]> {
  return apiRequest<IngestionRunStatus[]>(
    `/api/v1/knowledge/ingestion/status?limit=${encodeURIComponent(limit)}`,
    { method: 'GET' },
    false
  );
}

export function fetchIngestionRun(runId: string): Promise<IngestionRunStatus> {
  return apiRequest<IngestionRunStatus>(
    `/api/v1/knowledge/ingestion/status/${encodeURIComponent(runId)}`,
    { method: 'GET' },
    false
  );
}

export function normalizeLogBatch(
  batch: BatchIngestRequest
): Promise<NormalizedEvent[]> {
  return apiRequest<NormalizedEvent[]>(
    '/api/v1/knowledge/normalize/batch',
    {
      method: 'POST',
      body: JSON.stringify(batch),
    },
    false
  );
}

export function prepareInvestigationInput(
  batch: BatchIngestRequest,
  topK: number = 10
): Promise<InvestigationInput> {
  return apiRequest<InvestigationInput>(
    `/api/v1/knowledge/prepare-investigation?top_k_knowledge=${encodeURIComponent(topK)}`,
    {
      method: 'POST',
      body: JSON.stringify(batch),
    },
    false
  );
}

