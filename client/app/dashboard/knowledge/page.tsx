'use client'
import React, { useEffect, useState, useCallback } from 'react';
import Navbar from '@/components/navbar';
import ToastNotification from '@/components/toast-notification';
import InvestigationReportPanel from '@/components/investigation-report-panel';
import { useToast } from '@/hooks/useToast';
import {
  fetchIngestionRun,
  fetchIngestionStatuses,
  fetchKnowledgeBySource,
  fetchKnowledgeRecord,
  fetchKnowledgeStats,
  ingestCve,
  ingestMitre,
  normalizeLogBatch,
  prepareInvestigationInput,
  runInvestigation,
  runInvestigationFromBatch,
  searchKnowledge,
} from '@/lib/api';
import type {
  BatchIngestRequest,
  IngestionRunStatus,
  InvestigationInput,
  InvestigationResult,
  KnowledgeRecordDetailResponse,
  KnowledgeSearchResponse,
  KnowledgeStoreStats,
  NormalizedEvent,
} from '@/lib/types';

const DEFAULT_BATCH_FIXTURE: BatchIngestRequest = {
  schema_version: '1.0',
  batch_id: 'batch-demo-001',
  source: 'cli:workstation-17',
  sent_at: '2026-11-19T14:45:00Z',
  records: [
    {
      record_id: 'raw-demo-0001',
      observed_at: '2026-11-19T14:40:01Z',
      source_type: 'linux-auth',
      message: 'Failed password for alex from 203.0.113.25 port 44120',
      evidence_ref: {
        reference_id: 'ev-demo-0001',
        uri: 'file:///var/log/auth.log',
        line_start: 101,
        line_end: 101,
      },
      metadata: { host: 'workstation-17' },
    },
    {
      record_id: 'raw-demo-0002',
      observed_at: '2026-11-19T14:40:49Z',
      source_type: 'linux-auth',
      message: 'Accepted password for alex from 203.0.113.25 port 44130',
      evidence_ref: {
        reference_id: 'ev-demo-0002',
        uri: 'file:///var/log/auth.log',
        line_start: 103,
        line_end: 103,
      },
      metadata: { host: 'workstation-17' },
    },
    {
      record_id: 'raw-demo-0003',
      observed_at: '2026-11-19T14:41:12Z',
      source_type: 'linux-auth',
      message: 'sudo[5123]: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/bin/cat /etc/shadow',
      evidence_ref: {
        reference_id: 'ev-demo-0003',
        uri: 'file:///var/log/auth.log',
        line_start: 104,
        line_end: 104,
      },
      metadata: { host: 'workstation-17' },
    },
  ],
};

type KnowledgeTab = 'search' | 'ingestion' | 'sandbox';

const KnowledgeHubPage = () => {
  const { toasts, removeToast, success, error: showError } = useToast();
  const [activeTab, setActiveTab] = useState<KnowledgeTab>('search');
  const [stats, setStats] = useState<KnowledgeStoreStats | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);

  // Search OKF state
  const [queryText, setQueryText] = useState('sudo privilege escalation /etc/shadow');
  const [sourceType, setSourceType] = useState<'all' | 'mitre_attack' | 'cve'>('all');
  const [kindFilter, setKindFilter] = useState('');
  const [tacticFilter, setTacticFilter] = useState('');
  const [platformFilter, setPlatformFilter] = useState('');
  const [minCvss, setMinCvss] = useState('');
  const [searchMode, setSearchMode] = useState<'auto' | 'semantic' | 'lexical' | 'graph'>('auto');
  const [topK, setTopK] = useState(8);
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<KnowledgeSearchResponse | null>(null);

  // Source lookup & detail modal
  const [lookupSourceType, setLookupSourceType] = useState<'mitre_attack' | 'cve'>('mitre_attack');
  const [lookupSourceId, setLookupSourceId] = useState('T1548.003');
  const [recordDetail, setRecordDetail] = useState<KnowledgeRecordDetailResponse | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Ingestion state
  const [mitreLimit, setMitreLimit] = useState('100');
  const [mitreDryRun, setMitreDryRun] = useState(true);
  const [mitreIncludeDeprecated, setMitreIncludeDeprecated] = useState(false);
  const [cveLimit, setCveLimit] = useState('100');
  const [cveYears, setCveYears] = useState('2025');
  const [cveIdsInput, setCveIdsInput] = useState('');
  const [cveDryRun, setCveDryRun] = useState(true);
  const [ingesting, setIngesting] = useState(false);
  const [runs, setRuns] = useState<IngestionRunStatus[]>([]);
  const [selectedRun, setSelectedRun] = useState<IngestionRunStatus | null>(null);

  // KCP Batch Sandbox state
  const [batchJson, setBatchJson] = useState(() => JSON.stringify(DEFAULT_BATCH_FIXTURE, null, 2));
  const [sandboxBusy, setSandboxBusy] = useState(false);
  const [normalizedEvents, setNormalizedEvents] = useState<NormalizedEvent[] | null>(null);
  const [preparedInput, setPreparedInput] = useState<InvestigationInput | null>(null);
  const [sandboxInvestigation, setSandboxInvestigation] = useState<InvestigationResult | null>(null);

  const loadStats = useCallback(async () => {
    try {
      setLoadingStats(true);
      const data = await fetchKnowledgeStats();
      setStats(data);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to load knowledge stats');
    } finally {
      setLoadingStats(false);
    }
  }, [showError]);

  const loadRuns = useCallback(async () => {
    try {
      const data = await fetchIngestionStatuses(20);
      setRuns(data);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to load ingestion statuses');
    }
  }, [showError]);

  useEffect(() => {
    loadStats();
    loadRuns();
  }, [loadStats, loadRuns]);

  const handleSearch = async () => {
    if (!queryText.trim()) return;
    try {
      setSearching(true);
      const parsedCvss = minCvss.trim() !== '' ? Number(minCvss) : null;
      const resp = await searchKnowledge({
        query: queryText.trim(),
        source_type: sourceType === 'all' ? null : sourceType,
        kind: kindFilter.trim() || null,
        tactic: tacticFilter.trim() || null,
        platform: platformFilter.trim() || null,
        min_cvss: parsedCvss !== null && !Number.isNaN(parsedCvss) ? parsedCvss : null,
        top_k: topK,
        search_mode: searchMode,
      });
      setSearchResults(resp);
      success(`Retrieved ${resp.total_hits} OKF hit(s) via ${resp.retrieval_mode}`);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'OKF search failed');
    } finally {
      setSearching(false);
    }
  };

  const handleSourceLookup = async () => {
    if (!lookupSourceId.trim()) return;
    try {
      setLoadingDetail(true);
      const detail = await fetchKnowledgeBySource(lookupSourceType, lookupSourceId.trim(), true);
      setRecordDetail(detail);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Source lookup failed');
    } finally {
      setLoadingDetail(false);
    }
  };

  const openRecordDetail = async (recordId: string) => {
    try {
      setLoadingDetail(true);
      const detail = await fetchKnowledgeRecord(recordId, true);
      setRecordDetail(detail);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to fetch record detail');
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleIngestMitre = async () => {
    try {
      setIngesting(true);
      const payload: Record<string, unknown> = {
        dry_run: mitreDryRun,
        include_deprecated: mitreIncludeDeprecated,
      };
      if (mitreLimit.trim()) payload.limit = Number(mitreLimit);
      const run = await ingestMitre(payload);
      setSelectedRun(run);
      success(`MITRE ingestion ${run.status}: parsed=${run.parsed}, inserted=${run.inserted}`);
      await Promise.all([loadStats(), loadRuns()]);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'MITRE ingestion failed');
    } finally {
      setIngesting(false);
    }
  };

  const handleIngestCve = async () => {
    try {
      setIngesting(true);
      const payload: Record<string, unknown> = { dry_run: cveDryRun };
      if (cveLimit.trim()) payload.limit = Number(cveLimit);
      if (cveYears.trim()) {
        payload.years = cveYears
          .split(',')
          .map((y) => Number(y.trim()))
          .filter((y) => !Number.isNaN(y));
      }
      if (cveIdsInput.trim()) {
        payload.cve_ids = cveIdsInput
          .split(',')
          .map((id) => id.trim())
          .filter(Boolean);
      }
      const run = await ingestCve(payload);
      setSelectedRun(run);
      success(`CVE ingestion ${run.status}: parsed=${run.parsed}, inserted=${run.inserted}`);
      await Promise.all([loadStats(), loadRuns()]);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'CVE ingestion failed');
    } finally {
      setIngesting(false);
    }
  };

  const handleInspectRun = async (runId: string) => {
    try {
      const detail = await fetchIngestionRun(runId);
      setSelectedRun(detail);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to load ingestion run');
    }
  };

  const parseBatchPayload = (): BatchIngestRequest | null => {
    try {
      return JSON.parse(batchJson) as BatchIngestRequest;
    } catch (err) {
      showError(`Invalid JSON batch payload: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  };

  const handleNormalizeBatch = async () => {
    const batch = parseBatchPayload();
    if (!batch) return;
    try {
      setSandboxBusy(true);
      const events = await normalizeLogBatch(batch);
      setNormalizedEvents(events);
      success(`KCP normalized ${events.length} event(s)`);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Batch normalization failed');
    } finally {
      setSandboxBusy(false);
    }
  };

  const handlePrepareInvestigation = async () => {
    const batch = parseBatchPayload();
    if (!batch) return;
    try {
      setSandboxBusy(true);
      const invInput = await prepareInvestigationInput(batch, 8);
      setPreparedInput(invInput);
      setNormalizedEvents(invInput.normalized_events);
      success(`Prepared InvestigationInput (${invInput.knowledge_records.length} OKF records)`);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to prepare investigation input');
    } finally {
      setSandboxBusy(false);
    }
  };

  const handleRunSandboxInvestigation = async () => {
    try {
      setSandboxBusy(true);
      let result: InvestigationResult;
      if (preparedInput) {
        result = await runInvestigation(preparedInput);
      } else {
        const batch = parseBatchPayload();
        if (!batch) return;
        result = await runInvestigationFromBatch(batch, 8);
      }
      setSandboxInvestigation(result);
      success(`Multi-agent investigation ${result.investigation_id} completed`);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Multi-agent investigation failed');
    } finally {
      setSandboxBusy(false);
    }
  };

  return (
    <div className="bg-black min-h-screen w-full text-white font-mono">
      <ToastNotification toasts={toasts} removeToast={removeToast} />
      <Navbar />

      <div className="container mx-auto px-4 py-6 max-w-7xl space-y-6">
        {/* Header & OKF Store Stats */}
        <div className="bg-black/80 border border-green-500/30 p-5">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold text-green-400">[OKF_KNOWLEDGE_HUB.DB]</h1>
              <p className="text-cyan-400 text-xs sm:text-sm">
                Cognee + KCP Unified MITRE Enterprise ATT&amp;CK &amp; CVE Knowledge Pipeline
              </p>
            </div>
            <button
              type="button"
              onClick={loadStats}
              disabled={loadingStats}
              className="px-3 py-1.5 border border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10 text-xs cursor-pointer"
            >
              {loadingStats ? '[REFRESHING...]' : '[REFRESH_STATS]'}
            </button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-center">
            <div className="bg-black/60 border border-green-500/30 p-3">
              <div className="text-xl font-bold text-green-400">{stats?.total_records ?? '-'}</div>
              <div className="text-[11px] text-gray-400">TOTAL_OKF_RECORDS</div>
            </div>
            <div className="bg-black/60 border border-red-500/30 p-3">
              <div className="text-xl font-bold text-red-400">{stats?.counts_by_source_type?.mitre_attack ?? '-'}</div>
              <div className="text-[11px] text-gray-400">MITRE_ATTACK</div>
            </div>
            <div className="bg-black/60 border border-orange-500/30 p-3">
              <div className="text-xl font-bold text-orange-400">{stats?.counts_by_source_type?.cve ?? '-'}</div>
              <div className="text-[11px] text-gray-400">CVE_RECORDS</div>
            </div>
            <div className="bg-black/60 border border-cyan-500/30 p-3">
              <div className="text-xl font-bold text-cyan-400">{stats?.total_ingestion_runs ?? '-'}</div>
              <div className="text-[11px] text-gray-400">INGESTION_RUNS</div>
            </div>
            <div className="bg-black/60 border border-purple-500/30 p-3">
              <div className="text-sm font-bold text-purple-300 uppercase pt-1">{stats?.backend ?? 'cognee'}</div>
              <div className="text-[11px] text-gray-400">STORE_BACKEND</div>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex flex-wrap gap-3">
          {[
            { id: 'search' as const, label: 'SEARCH_OKF' },
            { id: 'ingestion' as const, label: 'INGESTION_PIPELINE' },
            { id: 'sandbox' as const, label: 'KCP_BATCH_SANDBOX' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 border-2 text-xs sm:text-sm transition-colors cursor-pointer ${
                activeTab === tab.id
                  ? 'border-green-400 bg-green-500/20 text-green-400'
                  : 'border-green-500/30 bg-black text-green-600 hover:text-green-400'
              }`}
            >
              [{tab.label}]
            </button>
          ))}
        </div>

        {/* Tab 1: Search OKF */}
        {activeTab === 'search' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Search Form */}
              <div className="lg:col-span-2 bg-black/80 border border-cyan-500/30 p-5 space-y-4">
                <h2 className="text-lg font-bold text-cyan-400">[QUERY_OKF_KNOWLEDGE]</h2>
                <div className="flex gap-2">
                  <input
                    value={queryText}
                    onChange={(e) => setQueryText(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                    placeholder="Search MITRE techniques, CVEs, products, tactics..."
                    className="flex-1 bg-black border border-cyan-500/40 px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400"
                  />
                  <button
                    type="button"
                    onClick={handleSearch}
                    disabled={searching}
                    className="px-4 py-2 border-2 border-cyan-500 text-cyan-400 hover:bg-cyan-500/20 text-xs sm:text-sm cursor-pointer"
                  >
                    {searching ? '[SEARCHING...]' : '[SEARCH]'}
                  </button>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div>
                    <label className="text-gray-400 block mb-1">SOURCE_TYPE</label>
                    <select
                      value={sourceType}
                      onChange={(e) => setSourceType(e.target.value as 'all' | 'mitre_attack' | 'cve')}
                      className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                    >
                      <option value="all">All</option>
                      <option value="mitre_attack">mitre_attack</option>
                      <option value="cve">cve</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-gray-400 block mb-1">KIND</label>
                    <input
                      value={kindFilter}
                      onChange={(e) => setKindFilter(e.target.value)}
                      placeholder="attack-pattern / cve-record"
                      className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="text-gray-400 block mb-1">TACTIC</label>
                    <input
                      value={tacticFilter}
                      onChange={(e) => setTacticFilter(e.target.value)}
                      placeholder="credential-access"
                      className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="text-gray-400 block mb-1">PLATFORM</label>
                    <input
                      value={platformFilter}
                      onChange={(e) => setPlatformFilter(e.target.value)}
                      placeholder="Linux"
                      className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="text-gray-400 block mb-1">MIN_CVSS</label>
                    <input
                      type="number"
                      step="0.1"
                      min="0"
                      max="10"
                      value={minCvss}
                      onChange={(e) => setMinCvss(e.target.value)}
                      placeholder="7.0"
                      className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="text-gray-400 block mb-1">SEARCH_MODE</label>
                    <select
                      value={searchMode}
                      onChange={(e) => setSearchMode(e.target.value as 'auto' | 'semantic' | 'lexical' | 'graph')}
                      className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                    >
                      <option value="auto">auto</option>
                      <option value="semantic">semantic</option>
                      <option value="lexical">lexical</option>
                      <option value="graph">graph</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-gray-400 block mb-1">TOP_K</label>
                    <input
                      type="number"
                      min={1}
                      max={50}
                      value={topK}
                      onChange={(e) => setTopK(Number(e.target.value) || 5)}
                      className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                    />
                  </div>
                </div>
              </div>

              {/* Exact Source ID Lookup */}
              <div className="bg-black/80 border border-purple-500/30 p-5 space-y-3">
                <h2 className="text-lg font-bold text-purple-400">[SOURCE_ID_LOOKUP]</h2>
                <p className="text-xs text-gray-400">Fetch exact OKF record &amp; 1-hop graph relationships.</p>
                <div className="space-y-2 text-xs">
                  <select
                    value={lookupSourceType}
                    onChange={(e) => setLookupSourceType(e.target.value as 'mitre_attack' | 'cve')}
                    className="w-full bg-black border border-gray-700 px-2 py-2 text-white"
                  >
                    <option value="mitre_attack">mitre_attack</option>
                    <option value="cve">cve</option>
                  </select>
                  <input
                    value={lookupSourceId}
                    onChange={(e) => setLookupSourceId(e.target.value)}
                    placeholder="T1548.003 or CVE-2025-39447"
                    className="w-full bg-black border border-gray-700 px-3 py-2 text-white"
                  />
                  <button
                    type="button"
                    onClick={handleSourceLookup}
                    disabled={loadingDetail}
                    className="w-full py-2 border-2 border-purple-500 text-purple-300 hover:bg-purple-500/20 cursor-pointer"
                  >
                    {loadingDetail ? '[LOOKING_UP...]' : '[FETCH_SOURCE_RECORD]'}
                  </button>
                </div>
              </div>
            </div>

            {/* Search Hits */}
            {searchResults && (
              <div className="bg-black/80 border border-green-500/30 p-5 space-y-4">
                <div className="flex flex-wrap justify-between items-center gap-2">
                  <h3 className="text-base font-bold text-green-400">
                    [RESULTS: {searchResults.total_hits}] · MODE: {searchResults.retrieval_mode}
                  </h3>
                  <span className="text-xs text-yellow-300 border border-yellow-500/40 px-2 py-1">
                    {searchResults.notice}
                  </span>
                </div>

                {searchResults.hits.length === 0 ? (
                  <p className="text-xs text-gray-400">No matching OKF records found.</p>
                ) : (
                  <div className="space-y-3">
                    {searchResults.hits.map((hit) => {
                      const c = hit.record.content || {};
                      const title = String(c.name || c.title || hit.record.source_id);
                      const desc = String(c.summary || c.description || '');
                      return (
                        <div key={hit.record.record_id} className="bg-black/60 border border-gray-700 p-4 space-y-2 text-xs">
                          <div className="flex flex-wrap justify-between items-center gap-2">
                            <span className="text-sm font-bold text-cyan-300">
                              {hit.record.source_id} — {title}
                            </span>
                            <div className="flex flex-wrap gap-2">
                              <span className="px-2 py-0.5 border border-gray-600 text-gray-300 uppercase">
                                {hit.record.source_type}
                              </span>
                              <span className="px-2 py-0.5 border border-green-500/50 text-green-400">
                                SCORE: {(hit.score * 100).toFixed(1)}%
                              </span>
                              <span className="px-2 py-0.5 border border-cyan-500/40 text-cyan-300">
                                {hit.retrieval_mode}
                              </span>
                            </div>
                          </div>
                          {desc && <p className="text-gray-300 leading-relaxed">{desc.slice(0, 320)}{desc.length > 320 ? '...' : ''}</p>}
                          <div className="flex flex-wrap justify-between items-center gap-2 pt-1">
                            <span className="text-gray-500">
                              id: {hit.record.record_id} · v{hit.record.source_version} · via {hit.matched_via}
                            </span>
                            <button
                              type="button"
                              onClick={() => openRecordDetail(hit.record.record_id)}
                              className="px-3 py-1 border border-purple-500/60 text-purple-300 hover:bg-purple-500/20 cursor-pointer"
                            >
                              [INSPECT_RECORD_&amp;_GRAPH]
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Ingestion Pipeline */}
        {activeTab === 'ingestion' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Ingest MITRE */}
              <div className="bg-black/80 border border-red-500/30 p-5 space-y-3 text-xs">
                <h3 className="text-base font-bold text-red-400">[INGEST_MITRE_ATTACK]</h3>
                <div className="space-y-2">
                  <label className="text-gray-400 block">LIMIT (optional)</label>
                  <input
                    type="number"
                    min={1}
                    value={mitreLimit}
                    onChange={(e) => setMitreLimit(e.target.value)}
                    className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                  />
                  <label className="flex items-center gap-2 text-gray-300">
                    <input type="checkbox" checked={mitreDryRun} onChange={(e) => setMitreDryRun(e.target.checked)} />
                    Dry run (validate &amp; compress without writing)
                  </label>
                  <label className="flex items-center gap-2 text-gray-300">
                    <input
                      type="checkbox"
                      checked={mitreIncludeDeprecated}
                      onChange={(e) => setMitreIncludeDeprecated(e.target.checked)}
                    />
                    Include deprecated STIX objects
                  </label>
                </div>
                <button
                  type="button"
                  onClick={handleIngestMitre}
                  disabled={ingesting}
                  className="w-full py-2 border-2 border-red-500 text-red-300 hover:bg-red-500/20 cursor-pointer"
                >
                  {ingesting ? '[RUNNING...]' : '[RUN_MITRE_INGEST]'}
                </button>
              </div>

              {/* Ingest CVE */}
              <div className="bg-black/80 border border-orange-500/30 p-5 space-y-3 text-xs">
                <h3 className="text-base font-bold text-orange-400">[INGEST_CVE_JSON]</h3>
                <div className="space-y-2">
                  <label className="text-gray-400 block">LIMIT (optional)</label>
                  <input
                    type="number"
                    min={1}
                    value={cveLimit}
                    onChange={(e) => setCveLimit(e.target.value)}
                    className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                  />
                  <label className="text-gray-400 block">YEARS (comma-separated)</label>
                  <input
                    value={cveYears}
                    onChange={(e) => setCveYears(e.target.value)}
                    placeholder="2025, 2026"
                    className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                  />
                  <label className="text-gray-400 block">CVE_IDS (optional comma-separated)</label>
                  <input
                    value={cveIdsInput}
                    onChange={(e) => setCveIdsInput(e.target.value)}
                    placeholder="CVE-2025-39447"
                    className="w-full bg-black border border-gray-700 px-2 py-1.5 text-white"
                  />
                  <label className="flex items-center gap-2 text-gray-300">
                    <input type="checkbox" checked={cveDryRun} onChange={(e) => setCveDryRun(e.target.checked)} />
                    Dry run (validate &amp; compress without writing)
                  </label>
                </div>
                <button
                  type="button"
                  onClick={handleIngestCve}
                  disabled={ingesting}
                  className="w-full py-2 border-2 border-orange-500 text-orange-300 hover:bg-orange-500/20 cursor-pointer"
                >
                  {ingesting ? '[RUNNING...]' : '[RUN_CVE_INGEST]'}
                </button>
              </div>
            </div>

            {/* Ingestion Run History */}
            <div className="bg-black/80 border border-green-500/30 p-5 space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-base font-bold text-green-400">[INGESTION_RUN_HISTORY ({runs.length})]</h3>
                <button
                  type="button"
                  onClick={loadRuns}
                  className="px-3 py-1 border border-green-500/40 text-green-400 text-xs cursor-pointer"
                >
                  [REFRESH]
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-green-500/40 text-cyan-400">
                      <th className="text-left py-2 pr-3">RUN_ID</th>
                      <th className="text-left py-2 pr-3">SOURCE</th>
                      <th className="text-left py-2 pr-3">STATUS</th>
                      <th className="text-left py-2 pr-3">PARSED</th>
                      <th className="text-left py-2 pr-3">INSERTED</th>
                      <th className="text-left py-2 pr-3">SKIPPED</th>
                      <th className="text-left py-2">ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr key={run.run_id} className="border-b border-gray-800">
                        <td className="py-2 pr-3 text-gray-300">{run.run_id}</td>
                        <td className="py-2 pr-3 text-cyan-300">{run.source_type}{run.dry_run ? ' (dry)' : ''}</td>
                        <td className="py-2 pr-3 text-green-400">{run.status}</td>
                        <td className="py-2 pr-3">{run.parsed}</td>
                        <td className="py-2 pr-3">{run.inserted}</td>
                        <td className="py-2 pr-3">{run.skipped}</td>
                        <td className="py-2">
                          <button
                            type="button"
                            onClick={() => handleInspectRun(run.run_id)}
                            className="px-2 py-0.5 border border-cyan-500/40 text-cyan-300 cursor-pointer"
                          >
                            [INSPECT]
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {selectedRun && (
                <div className="bg-black/70 border border-cyan-500/40 p-4 text-xs space-y-2">
                  <div className="flex justify-between">
                    <span className="text-cyan-300 font-bold">Run Detail: {selectedRun.run_id}</span>
                    <button type="button" onClick={() => setSelectedRun(null)} className="text-red-400 cursor-pointer">[CLOSE]</button>
                  </div>
                  <pre className="text-gray-300 overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify(selectedRun, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 3: KCP Batch Sandbox */}
        {activeTab === 'sandbox' && (
          <div className="space-y-6">
            <div className="bg-black/80 border border-cyan-500/30 p-5 space-y-4">
              <h3 className="text-base font-bold text-cyan-400">[KCP_BATCH_TO_MULTI_AGENT_SANDBOX]</h3>
              <p className="text-xs text-gray-400">
                Submit a contract-compliant BatchIngestRequest through KCP normalization, OKF preparation, and direct LangGraph multi-agent investigation.
              </p>
              <textarea
                value={batchJson}
                onChange={(e) => setBatchJson(e.target.value)}
                rows={12}
                className="w-full bg-black border border-gray-700 p-3 text-xs text-green-300 font-mono focus:outline-none focus:border-cyan-400"
              />
              <div className="flex flex-wrap gap-3 text-xs">
                <button
                  type="button"
                  onClick={handleNormalizeBatch}
                  disabled={sandboxBusy}
                  className="px-4 py-2 border-2 border-green-500 text-green-400 hover:bg-green-500/20 cursor-pointer"
                >
                  [1. KCP_NORMALIZE_BATCH]
                </button>
                <button
                  type="button"
                  onClick={handlePrepareInvestigation}
                  disabled={sandboxBusy}
                  className="px-4 py-2 border-2 border-cyan-500 text-cyan-400 hover:bg-cyan-500/20 cursor-pointer"
                >
                  [2. PREPARE_INVESTIGATION_INPUT]
                </button>
                <button
                  type="button"
                  onClick={handleRunSandboxInvestigation}
                  disabled={sandboxBusy}
                  className="px-4 py-2 border-2 border-purple-500 text-purple-300 hover:bg-purple-500/20 cursor-pointer"
                >
                  {sandboxBusy ? '[EXECUTING...]' : preparedInput ? '[3. RUN_PREPARED_INVESTIGATION]' : '[3. RUN_FROM_BATCH]'}
                </button>
              </div>
            </div>

            {normalizedEvents && (
              <div className="bg-black/80 border border-green-500/30 p-5 space-y-2">
                <h4 className="text-sm font-bold text-green-400">[KCP_NORMALIZED_EVENTS ({normalizedEvents.length})]</h4>
                <pre className="text-xs text-gray-300 overflow-x-auto max-h-64">
                  {JSON.stringify(normalizedEvents, null, 2)}
                </pre>
              </div>
            )}

            {preparedInput && (
              <div className="bg-black/80 border border-cyan-500/30 p-5 space-y-2">
                <h4 className="text-sm font-bold text-cyan-400">
                  [PREPARED_INVESTIGATION_INPUT: {preparedInput.investigation_id} ({preparedInput.knowledge_records.length} OKF records)]
                </h4>
                <pre className="text-xs text-gray-300 overflow-x-auto max-h-64">
                  {JSON.stringify(preparedInput, null, 2)}
                </pre>
              </div>
            )}

            {sandboxInvestigation && (
              <InvestigationReportPanel investigation={sandboxInvestigation} />
            )}
          </div>
        )}
      </div>

      {/* Record Detail & 1-Hop Graph Modal */}
      {recordDetail && (
        <div
          className="fixed inset-0 bg-black/85 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={(e) => e.target === e.currentTarget && setRecordDetail(null)}
        >
          <div className="bg-black border-2 border-purple-500/60 max-w-4xl w-full max-h-[85vh] overflow-y-auto p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-gray-800 pb-3">
              <div>
                <h3 className="text-lg font-bold text-purple-300">
                  [{recordDetail.record.source_id}] ({recordDetail.record.source_type})
                </h3>
                <p className="text-xs text-gray-400">
                  {recordDetail.record.record_id} · version {recordDetail.record.source_version}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setRecordDetail(null)}
                className="text-red-400 hover:text-red-300 text-lg font-bold cursor-pointer"
              >
                ×
              </button>
            </div>

            <div>
              <h4 className="text-xs text-cyan-400 font-bold mb-1">[CONTENT]</h4>
              <pre className="bg-black/70 border border-gray-800 p-3 text-xs text-gray-200 overflow-x-auto max-h-56">
                {JSON.stringify(recordDetail.record.content, null, 2)}
              </pre>
            </div>

            <div>
              <h4 className="text-xs text-green-400 font-bold mb-1">[PROVENANCE]</h4>
              <pre className="bg-black/70 border border-gray-800 p-3 text-xs text-green-300 overflow-x-auto">
                {JSON.stringify(recordDetail.record.provenance, null, 2)}
              </pre>
            </div>

            <div>
              <h4 className="text-xs text-orange-400 font-bold mb-2">
                [1_HOP_RELATED_RECORDS ({recordDetail.related_records.length})]
              </h4>
              {recordDetail.related_records.length === 0 ? (
                <p className="text-xs text-gray-500">No 1-hop related records returned.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {recordDetail.related_records.map((rel) => (
                    <button
                      key={rel.record_id}
                      type="button"
                      onClick={() => openRecordDetail(rel.record_id)}
                      className="px-2.5 py-1 border border-orange-500/50 text-orange-300 hover:bg-orange-500/20 text-xs cursor-pointer"
                    >
                      {rel.source_id}: {String(rel.content?.name || rel.source_type)}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default KnowledgeHubPage;

