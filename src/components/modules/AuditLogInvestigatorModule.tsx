import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  TenantSecuritySnapshot,
  UnifiedAuditLogImport,
  UnifiedAuditLogRecord,
  AuditLogFlagsResult,
  SessionHijackFlag,
  MassDeletionFlag,
  PossibleBecFlag,
} from "@/lib/types";
import { AUDIT_INVESTIGATION_TEMPLATES } from "@/lib/data/audit-investigation-templates";
import { Drawer } from "../common/Drawer";
import { Pagination } from "../common/Pagination";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import {
  Search,
  Upload,
  FileSearch,
  Filter,
  Calendar,
  ChevronRight,
  ChevronDown,
  Trash2,
  AlertTriangle,
  Info,
  X,
  Download,
  Fingerprint,
  Laptop,
  User,
  Layers,
  Clock,
  ArrowUpDown,
  Loader2,
  Copy,
  Check,
  ShieldAlert,
  Sparkles,
} from "lucide-react";

interface AuditLogInvestigatorModuleProps {
  snapshot: TenantSecuritySnapshot;
}

interface SearchState {
  search: string;
  operation: string;
  recordType: string;
  workload: string;
  sessionId: string;
  userId: string;
  clientInfo: string;
  startDate: string;
  endDate: string;
  importId: string;
}

const EMPTY_FILTERS: SearchState = {
  search: "",
  operation: "",
  recordType: "",
  workload: "",
  sessionId: "",
  userId: "",
  clientInfo: "",
  startDate: "",
  endDate: "",
  importId: "",
};

const PAGE_SIZE = 50;

export const AuditLogInvestigatorModule: React.FC<AuditLogInvestigatorModuleProps> = ({ snapshot }) => {
  const tenantId = snapshot.tenant.id;

  const [imports, setImports] = useState<UnifiedAuditLogImport[]>([]);
  const [importsLoading, setImportsLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<{ rowsProcessed: number } | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const uploadPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [filters, setFilters] = useState<SearchState>(EMPTY_FILTERS);
  const [page, setPage] = useState(1);
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");

  // Phase 2 - Investigation Templates. Mutually exclusive with the manual
  // Operation dropdown (filters.operation) - picking one clears the other.
  const [activeTemplateId, setActiveTemplateId] = useState<string | null>(null);
  const [templateCounts, setTemplateCounts] = useState<Record<string, number>>({});

  // Phase 3 - heuristic flags, scanned over the whole imported dataset
  // (not just the current search page).
  const [flags, setFlags] = useState<AuditLogFlagsResult | null>(null);
  const [flagsLoading, setFlagsLoading] = useState(false);
  const [flagsPanelOpen, setFlagsPanelOpen] = useState(true);

  const [records, setRecords] = useState<UnifiedAuditLogRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [facets, setFacets] = useState<{ operations: string[]; recordTypes: string[]; workloads: string[] }>({
    operations: [],
    recordTypes: [],
    workloads: [],
  });
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);

  const [selectedRecord, setSelectedRecord] = useState<UnifiedAuditLogRecord | null>(null);
  const [timelineSessionId, setTimelineSessionId] = useState<string | null>(null);
  const [timelineRecords, setTimelineRecords] = useState<UnifiedAuditLogRecord[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(false);

  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const stopUploadPolling = useCallback(() => {
    if (uploadPollRef.current) {
      clearInterval(uploadPollRef.current);
      uploadPollRef.current = null;
    }
  }, []);
  useEffect(() => stopUploadPolling, [stopUploadPolling]);

  const loadImports = useCallback(async () => {
    setImportsLoading(true);
    try {
      const res = await fetch(`/api/tenants/${tenantId}/audit-log/imports`);
      const data = await res.json();
      if (data.success) setImports(data.imports);
    } finally {
      setImportsLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    loadImports();
  }, [loadImports]);

  const runSearch = useCallback(async () => {
    setSearchLoading(true);
    setSearchError(null);
    try {
      const params = new URLSearchParams();
      if (filters.search) params.set("search", filters.search);
      const activeTemplate = AUDIT_INVESTIGATION_TEMPLATES.find((t) => t.id === activeTemplateId);
      if (activeTemplate) {
        params.set("operations", activeTemplate.operations.join(","));
      } else if (filters.operation) {
        params.set("operation", filters.operation);
      }
      if (filters.recordType) params.set("recordType", filters.recordType);
      if (filters.workload) params.set("workload", filters.workload);
      if (filters.sessionId) params.set("sessionId", filters.sessionId);
      if (filters.userId) params.set("userId", filters.userId);
      if (filters.clientInfo) params.set("clientInfo", filters.clientInfo);
      if (filters.startDate) params.set("startDate", filters.startDate);
      // datetime-local values are minute-granularity ("...T09:05") - append
      // seconds so an end time of 09:05 includes the whole minute up to
      // 09:05:59 rather than excluding everything after :05:00 exactly.
      if (filters.endDate) params.set("endDate", `${filters.endDate}:59`);
      if (filters.importId) params.set("importId", filters.importId);
      params.set("page", String(page));
      params.set("pageSize", String(PAGE_SIZE));
      params.set("sortDirection", sortDirection);

      const res = await fetch(`/api/tenants/${tenantId}/audit-log/search?${params.toString()}`);
      const data = await res.json();
      if (!data.success) {
        setSearchError(data.error || "Search failed");
        return;
      }
      setRecords(data.records);
      setTotal(data.total);
      setFacets(data.facets);
    } catch (e: any) {
      setSearchError(e.message || "Search failed");
    } finally {
      setSearchLoading(false);
    }
  }, [tenantId, filters, activeTemplateId, page, sortDirection]);

  // Debounce free-text search inputs (search / clientInfo can type-trigger a
  // request per keystroke otherwise); dropdown/date filters apply immediately
  // via the page-reset effect below, which this effect also fires on.
  useEffect(() => {
    const handle = setTimeout(runSearch, 300);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, activeTemplateId, page, sortDirection]);

  useEffect(() => {
    setPage(1);
  }, [filters.search, filters.operation, filters.recordType, filters.workload, filters.sessionId, filters.userId, filters.clientInfo, filters.startDate, filters.endDate, filters.importId, activeTemplateId]);

  const hasActiveFilters = Object.values(filters).some((v) => v !== "") || activeTemplateId !== null;

  const loadTemplateCounts = useCallback(async () => {
    try {
      const params = filters.importId ? `?importId=${encodeURIComponent(filters.importId)}` : "";
      const res = await fetch(`/api/tenants/${tenantId}/audit-log/template-counts${params}`);
      const data = await res.json();
      if (data.success) setTemplateCounts(data.counts);
    } catch {
      // Non-critical - buttons just show without a count.
    }
  }, [tenantId, filters.importId]);

  const loadFlags = useCallback(async () => {
    setFlagsLoading(true);
    try {
      const params = filters.importId ? `?importId=${encodeURIComponent(filters.importId)}` : "";
      const res = await fetch(`/api/tenants/${tenantId}/audit-log/flags${params}`);
      const data = await res.json();
      if (data.success) setFlags({ sessionHijack: data.sessionHijack, massDeletion: data.massDeletion, possibleBec: data.possibleBec });
    } finally {
      setFlagsLoading(false);
    }
  }, [tenantId, filters.importId]);

  useEffect(() => {
    loadTemplateCounts();
    loadFlags();
  }, [loadTemplateCounts, loadFlags]);

  const handleTemplateClick = (templateId: string) => {
    setActiveTemplateId((current) => (current === templateId ? null : templateId));
    setFilters((f) => (f.operation ? { ...f, operation: "" } : f));
  };

  const handleUpload = async (file: File) => {
    setUploading(true);
    setUploadError(null);
    setUploadProgress({ rowsProcessed: 0 });

    const poll = async () => {
      try {
        const res = await fetch(`/api/tenants/${tenantId}/audit-log/import-progress`);
        const data = await res.json();
        if (data.inProgress) {
          setUploadProgress({ rowsProcessed: data.rowsProcessed });
        }
      } catch {
        // Transient poll failure - keep polling, the upload request itself
        // is the source of truth for success/failure.
      }
    };
    uploadPollRef.current = setInterval(poll, 750);

    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(`/api/tenants/${tenantId}/audit-log/upload`, { method: "POST", body: formData });
      const data = await res.json();
      if (!data.success) {
        setUploadError(data.error || "Import failed");
      } else {
        await loadImports();
        await runSearch();
        await loadTemplateCounts();
        await loadFlags();
      }
    } catch (e: any) {
      setUploadError(e.message || "Import failed");
    } finally {
      stopUploadPolling();
      setUploading(false);
      setUploadProgress(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleDeleteImport = async (importId: string) => {
    await fetch(`/api/tenants/${tenantId}/audit-log/imports?importId=${encodeURIComponent(importId)}`, {
      method: "DELETE",
    });
    if (filters.importId === importId) setFilters((f) => ({ ...f, importId: "" }));
    await loadImports();
    await runSearch();
    await loadTemplateCounts();
    await loadFlags();
  };

  const openSessionTimeline = async (sessionId: string) => {
    setTimelineSessionId(sessionId);
    setTimelineLoading(true);
    try {
      const res = await fetch(`/api/tenants/${tenantId}/audit-log/session/${encodeURIComponent(sessionId)}`);
      const data = await res.json();
      if (data.success) setTimelineRecords(data.records);
    } finally {
      setTimelineLoading(false);
    }
  };

  // "2026-01-01T09" (the SQL hour-bucket) -> a start/end datetime-local pair
  // covering that whole hour, for pre-filling the date-range filter.
  const hourBucketToRange = (hourBucket: string) => ({ start: `${hourBucket}:00`, end: `${hourBucket}:59` });

  const jumpToMassDeletionFlag = (flag: MassDeletionFlag) => {
    const { start, end } = hourBucketToRange(flag.hourBucket);
    setActiveTemplateId("mass_deletion");
    setFilters((f) => ({ ...EMPTY_FILTERS, importId: f.importId, userId: flag.userId, startDate: start, endDate: end }));
  };

  const jumpToBecFlag = (flag: PossibleBecFlag) => {
    const { start, end } = hourBucketToRange(flag.hourBucket);
    setActiveTemplateId("bec");
    setFilters((f) => ({ ...EMPTY_FILTERS, importId: f.importId, userId: flag.userId, startDate: start, endDate: end }));
  };

  // Every distinct ClientIP seen within the open session timeline - 2+ means
  // this session touched more than one network location, exactly the signal
  // Microsoft's own MailItemsAccessed investigation guidance flags as worth
  // a closer look (possible session hijack / AiTM rather than one continuous
  // legitimate session).
  const timelineDistinctIps = useMemo(() => {
    const ips = new Set(timelineRecords.map((r) => r.clientIp).filter(Boolean) as string[]);
    return Array.from(ips);
  }, [timelineRecords]);

  const handleExportCsv = () => {
    const headers = ["CreationDate", "RecordType", "Operation", "UserId", "ClientIp", "SessionId", "ClientInfo", "ResultStatus", "Workload"];
    const rows = records.map((r) => [
      r.creationDate,
      r.recordType || "",
      r.operation || "",
      r.userId || "",
      r.clientIp || "",
      r.sessionId || "",
      r.clientInfo || "",
      r.resultStatus || "",
      r.workload || "",
    ]);
    exportToCsv(csvFilename("AuditLogInvestigator", snapshot.tenant.defaultDomainName), headers, rows);
  };

  const resetFilters = () => {
    setFilters(EMPTY_FILTERS);
    setActiveTemplateId(null);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileSearch size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Audit Log Investigator
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Upload Purview unified audit log CSV exports and search them with Session ID / client correlation Purview&apos;s own search doesn&apos;t offer.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleUpload(file);
            }}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="px-2.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            {uploading ? <Loader2 size={13} className="animate-spin" /> : <Upload size={13} />}
            <span>{uploading ? "Importing..." : "Upload CSV Export"}</span>
          </button>

          {records.length > 0 && (
            <button
              onClick={handleExportCsv}
              title="Export current filtered page to CSV"
              className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
            >
              <Download size={13} className="text-slate-500 dark:text-slate-400" />
              <span>Export CSV</span>
            </button>
          )}
        </div>
      </div>

      {/* Upload progress / error banner */}
      {uploading && uploadProgress && (
        <div className="bg-sky-50 dark:bg-sky-950 border border-sky-300 dark:border-sky-800 p-3 rounded-sm flex items-center gap-2 text-xs text-sky-900 dark:text-sky-300">
          <Loader2 size={14} className="animate-spin" />
          <span>Parsing and indexing rows... {uploadProgress.rowsProcessed.toLocaleString()} processed so far.</span>
        </div>
      )}
      {uploadError && (
        <div className="bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 p-3 rounded-sm flex items-start gap-2 text-xs text-rose-900 dark:text-red-400">
          <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold">Import failed: </span>
            <span>{uploadError}</span>
          </div>
          <button onClick={() => setUploadError(null)} className="text-rose-500 hover:text-rose-700">
            <X size={13} />
          </button>
        </div>
      )}

      {/* Imports list */}
      <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Imported Exports ({imports.length})
          </h3>
        </div>
        {importsLoading ? (
          <div className="p-4 text-xs text-slate-500 dark:text-slate-400">Loading...</div>
        ) : imports.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400">
            <Upload size={20} className="mx-auto text-slate-400 dark:text-slate-500 mb-1" />
            No exports imported yet. Export a CSV from Purview&apos;s audit search and upload it above.
          </div>
        ) : (
          <div className="divide-y divide-slate-100 dark:divide-slate-700">
            {imports.map((imp) => (
              <div
                key={imp.id}
                className={`px-4 py-2.5 flex items-center justify-between gap-3 flex-wrap cursor-pointer transition-colors ${
                  filters.importId === imp.id ? "bg-slate-100 dark:bg-slate-700/60" : "hover:bg-slate-50 dark:hover:bg-slate-700/40"
                }`}
                onClick={() => setFilters((f) => ({ ...f, importId: f.importId === imp.id ? "" : imp.id }))}
              >
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">{imp.filename}</div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                    {imp.rowCount.toLocaleString()} records
                    {imp.skippedRowCount > 0 ? ` · ${imp.skippedRowCount} skipped` : ""}
                    {imp.earliestEvent && imp.latestEvent ? ` · ${new Date(imp.earliestEvent).toLocaleDateString()} - ${new Date(imp.latestEvent).toLocaleDateString()}` : ""}
                    {" · "}
                    Uploaded {new Date(imp.uploadedAt).toLocaleString()}
                  </div>
                  {imp.possiblyCapped && imp.exportCapWarning && (
                    <div className="text-[11px] text-amber-700 dark:text-amber-400 flex items-center gap-1 mt-0.5">
                      <AlertTriangle size={11} className="flex-shrink-0" />
                      <span>{imp.exportCapWarning}</span>
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {filters.importId === imp.id && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-800 text-white rounded-sm">FILTERED</span>
                  )}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteImport(imp.id);
                    }}
                    title="Delete this import and all its records"
                    className="p-1 text-slate-400 dark:text-slate-500 hover:text-rose-600 dark:hover:text-red-400 rounded-sm"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Investigation Templates - one-click canned filters. Mutually
          exclusive with the manual Operation dropdown below. */}
      <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm shadow-2xs">
        <div className="flex items-center gap-1.5 mb-2">
          <Sparkles size={12} className="text-indigo-500 dark:text-indigo-400" />
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
            Investigation Templates
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {AUDIT_INVESTIGATION_TEMPLATES.map((template) => {
            const isActive = activeTemplateId === template.id;
            return (
              <button
                key={template.id}
                onClick={() => handleTemplateClick(template.id)}
                title={template.description}
                className={`px-2.5 py-1.5 text-xs rounded-sm font-medium transition-colors border flex items-center gap-1.5 ${
                  isActive
                    ? "bg-indigo-700 text-white border-indigo-700 shadow-2xs"
                    : "bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700"
                }`}
              >
                <span>{template.name}</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    isActive ? "bg-indigo-600 text-white" : "bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
                  }`}
                >
                  {templateCounts[template.id] ?? 0}
                </span>
                {isActive && <X size={11} />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Filters bar */}
      <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm space-y-2.5 shadow-2xs">
        <div className="flex flex-col md:flex-row items-center gap-2.5">
          <div className="relative w-full md:flex-1">
            <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
            <input
              type="text"
              placeholder="Search operation, user, IP, session ID, raw data..."
              value={filters.search}
              onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
              className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
          </div>

          <button
            onClick={() => setSortDirection(sortDirection === "asc" ? "desc" : "asc")}
            title="Toggle chronological sort order"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-600 rounded-sm flex items-center gap-1.5 transition-colors shrink-0"
          >
            <ArrowUpDown size={13} />
            <span>{sortDirection === "asc" ? "Oldest First" : "Newest First"}</span>
          </button>

          {hasActiveFilters && (
            <button
              onClick={resetFilters}
              className="px-2.5 py-1.5 text-xs text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 border border-slate-300 dark:border-slate-600 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors shrink-0"
            >
              Reset Filters
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {activeTemplateId ? (
            <div className="flex items-center gap-1.5 px-2 py-1 bg-indigo-50 dark:bg-indigo-950 border border-indigo-300 dark:border-indigo-800 rounded-sm">
              <Sparkles size={11} className="text-indigo-600 dark:text-indigo-400" />
              <span className="text-[11px] font-semibold text-indigo-800 dark:text-indigo-300">
                Template: {AUDIT_INVESTIGATION_TEMPLATES.find((t) => t.id === activeTemplateId)?.name}
              </span>
              <button
                onClick={() => setActiveTemplateId(null)}
                title="Clear template, restore the Operation dropdown"
                className="text-indigo-500 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-200"
              >
                <X size={12} />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-1.5">
              <Filter size={12} className="text-slate-500 dark:text-slate-400" />
              <select
                value={filters.operation}
                onChange={(e) => {
                  setActiveTemplateId(null);
                  setFilters((f) => ({ ...f, operation: e.target.value }));
                }}
                className="px-2 py-1 text-[11px] border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 max-w-[180px]"
              >
                <option value="">All Operations ({facets.operations.length})</option>
                {facets.operations.map((op) => (
                  <option key={op} value={op}>
                    {op}
                  </option>
                ))}
              </select>
            </div>
          )}

          <select
            value={filters.recordType}
            onChange={(e) => setFilters((f) => ({ ...f, recordType: e.target.value }))}
            className="px-2 py-1 text-[11px] border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 max-w-[180px]"
          >
            <option value="">All Record Types</option>
            {facets.recordTypes.map((rt) => (
              <option key={rt} value={rt}>
                {rt}
              </option>
            ))}
          </select>

          <select
            value={filters.workload}
            onChange={(e) => setFilters((f) => ({ ...f, workload: e.target.value }))}
            className="px-2 py-1 text-[11px] border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 max-w-[160px]"
          >
            <option value="">All Workloads</option>
            {facets.workloads.map((w) => (
              <option key={w} value={w}>
                {w}
              </option>
            ))}
          </select>

          <div className="flex items-center gap-1 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm px-1.5">
            <Fingerprint size={11} className="text-slate-400 dark:text-slate-500" />
            <input
              type="text"
              placeholder="Session ID"
              value={filters.sessionId}
              onChange={(e) => setFilters((f) => ({ ...f, sessionId: e.target.value }))}
              className="px-1 py-1 text-[11px] bg-transparent focus:outline-none text-slate-900 dark:text-slate-100 w-28"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm px-1.5">
            <User size={11} className="text-slate-400 dark:text-slate-500" />
            <input
              type="text"
              placeholder="User (partial name OK)"
              title="Matches anywhere in the UPN - e.g. typing 'alice' matches alice@contoso.com"
              value={filters.userId}
              onChange={(e) => setFilters((f) => ({ ...f, userId: e.target.value }))}
              className="px-1 py-1 text-[11px] bg-transparent focus:outline-none text-slate-900 dark:text-slate-100 w-36"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm px-1.5">
            <Laptop size={11} className="text-slate-400 dark:text-slate-500" />
            <input
              type="text"
              placeholder="Client / Device text"
              value={filters.clientInfo}
              onChange={(e) => setFilters((f) => ({ ...f, clientInfo: e.target.value }))}
              className="px-1 py-1 text-[11px] bg-transparent focus:outline-none text-slate-900 dark:text-slate-100 w-36"
            />
          </div>

          <div className="flex items-center gap-1">
            <Calendar size={11} className="text-slate-400 dark:text-slate-500" />
            <input
              type="datetime-local"
              value={filters.startDate}
              onChange={(e) => setFilters((f) => ({ ...f, startDate: e.target.value }))}
              className="px-1.5 py-1 text-[11px] border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
            <span className="text-slate-400 dark:text-slate-500 text-[11px]">to</span>
            <input
              type="datetime-local"
              value={filters.endDate}
              onChange={(e) => setFilters((f) => ({ ...f, endDate: e.target.value }))}
              className="px-1.5 py-1 text-[11px] border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
          </div>
        </div>
      </div>

      {searchError && (
        <div className="bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 p-3 rounded-sm text-xs text-rose-900 dark:text-red-400">
          {searchError}
        </div>
      )}

      {/* Flagged Activity - heuristic signals scanned over the whole
          imported dataset, not the current search page. Framed as "worth
          investigating," never a verdict - each card shows the exact
          numbers that triggered it. */}
      {flags && (flags.sessionHijack.length > 0 || flags.massDeletion.length > 0 || flags.possibleBec.length > 0) && (
        <div className="bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 rounded-sm shadow-2xs">
          <button
            onClick={() => setFlagsPanelOpen((o) => !o)}
            className="w-full px-4 py-2.5 flex items-center justify-between text-left"
          >
            <div className="flex items-center gap-2">
              <ShieldAlert size={14} className="text-amber-700 dark:text-amber-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-amber-900 dark:text-amber-400">
                Flagged Activity ({flags.sessionHijack.length + flags.massDeletion.length + flags.possibleBec.length})
              </h3>
              {flagsLoading && <Loader2 size={12} className="animate-spin text-amber-600 dark:text-amber-400" />}
            </div>
            <ChevronDown size={14} className={`text-amber-700 dark:text-amber-400 transition-transform ${flagsPanelOpen ? "rotate-180" : ""}`} />
          </button>

          {flagsPanelOpen && (
            <div className="px-4 pb-3 space-y-2">
              {flags.sessionHijack.map((flag) => (
                <button
                  key={`hijack-${flag.sessionId}`}
                  onClick={() => openSessionTimeline(flag.sessionId)}
                  className="w-full text-left p-2.5 bg-white dark:bg-slate-800 border border-amber-200 dark:border-amber-800 rounded-sm text-xs hover:bg-amber-50/60 dark:hover:bg-amber-900/40 transition-colors"
                >
                  <div className="font-semibold text-slate-900 dark:text-slate-100">Possible session hijack / AiTM</div>
                  <div className="text-slate-600 dark:text-slate-400 mt-0.5">
                    Session <span className="font-mono">{flag.sessionId}</span> spans {flag.distinctIpCount} distinct client IPs
                    ({flag.distinctIps.join(", ")}) across {flag.recordCount} events - click to view its Session Timeline.
                  </div>
                </button>
              ))}

              {flags.massDeletion.map((flag) => (
                <button
                  key={`massdel-${flag.userId}-${flag.hourBucket}`}
                  onClick={() => jumpToMassDeletionFlag(flag)}
                  className="w-full text-left p-2.5 bg-white dark:bg-slate-800 border border-amber-200 dark:border-amber-800 rounded-sm text-xs hover:bg-amber-50/60 dark:hover:bg-amber-900/40 transition-colors"
                >
                  <div className="font-semibold text-slate-900 dark:text-slate-100">Possible mass-deletion event</div>
                  <div className="text-slate-600 dark:text-slate-400 mt-0.5">
                    <span className="font-mono">{flag.userId}</span> performed {flag.deleteCount} delete operations within the
                    hour starting {flag.hourBucket}:00 - click to filter to that user and window.
                  </div>
                </button>
              ))}

              {flags.possibleBec.map((flag) => (
                <button
                  key={`bec-${flag.userId}-${flag.hourBucket}`}
                  onClick={() => jumpToBecFlag(flag)}
                  className="w-full text-left p-2.5 bg-white dark:bg-slate-800 border border-amber-200 dark:border-amber-800 rounded-sm text-xs hover:bg-amber-50/60 dark:hover:bg-amber-900/40 transition-colors"
                >
                  <div className="font-semibold text-slate-900 dark:text-slate-100">Possible BEC / mailbox compromise</div>
                  <div className="text-slate-600 dark:text-slate-400 mt-0.5">
                    <span className="font-mono">{flag.userId}</span> made {flag.inboxRuleChangeCount} inbox-rule/forwarding change(s)
                    and had {flag.mailItemsAccessedCount} mail item accesses within the hour starting {flag.hourBucket}:00 -
                    click to filter to that user and window.
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Results table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Records</h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
            {searchLoading ? "Searching..." : `${total.toLocaleString()} Records Matching`}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-32">Timestamp</th>
                <th className="min-w-[160px]">Record Type</th>
                <th className="min-w-[180px]">Operation</th>
                <th className="min-w-[180px]">User</th>
                <th className="min-w-[120px]">Client IP</th>
                <th className="min-w-[120px]">Session</th>
                <th className="w-16 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {records.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                    <div className="space-y-1">
                      <Info size={20} className="mx-auto text-slate-400 dark:text-slate-500 mb-1" />
                      <div className="font-semibold text-slate-700 dark:text-slate-300">
                        {imports.length === 0 ? "No exports imported yet." : "No records match the active filter criteria."}
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                records.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => setSelectedRecord(r)}
                    tabIndex={0}
                    role="button"
                    className="cursor-pointer transition-colors hover:bg-slate-50 dark:hover:bg-slate-700"
                  >
                    <td className="font-mono text-[11px] text-slate-600 dark:text-slate-400 whitespace-nowrap">
                      {new Date(r.creationDate).toLocaleString()}
                    </td>
                    <td className="text-xs text-slate-700 dark:text-slate-300">{r.recordType || "-"}</td>
                    <td className="text-xs font-semibold text-slate-900 dark:text-slate-100">{r.operation || "-"}</td>
                    <td className="text-xs text-slate-700 dark:text-slate-300 truncate max-w-[180px]">{r.userId || "-"}</td>
                    <td className="font-mono text-[11px] text-slate-600 dark:text-slate-400">{r.clientIp || "-"}</td>
                    <td>
                      {r.sessionId ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            openSessionTimeline(r.sessionId!);
                          }}
                          title="View full Session Timeline"
                          className="font-mono text-[11px] text-sky-700 dark:text-sky-400 hover:underline flex items-center gap-1"
                        >
                          <Layers size={10} />
                          <span className="truncate max-w-[90px]">{r.sessionId}</span>
                        </button>
                      ) : (
                        <span className="text-[11px] text-slate-400 dark:text-slate-500">-</span>
                      )}
                    </td>
                    <td className="text-right">
                      <button
                        aria-label="View record details"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedRecord(r);
                        }}
                        className="p-1 text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:text-slate-100 rounded-sm"
                      >
                        <ChevronRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} pageSize={PAGE_SIZE} totalItems={total} onPageChange={setPage} />
      </div>

      {/* Record detail drawer */}
      {selectedRecord && (
        <Drawer
          isOpen={!!selectedRecord}
          onClose={() => setSelectedRecord(null)}
          title="Audit Record Detail"
          subtitle={`${selectedRecord.operation || "Unknown Operation"} - ${new Date(selectedRecord.creationDate).toLocaleString()}`}
          width="xl"
        >
          <div className="space-y-4">
            {selectedRecord.parseError && (
              <div className="p-3 bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 rounded-sm text-xs text-amber-900 dark:text-amber-400 flex items-start gap-2">
                <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
                <span>This row&apos;s AuditData JSON couldn&apos;t be parsed - showing the raw CSV columns only.</span>
              </div>
            )}

            {/* Quick Copy Action Bar */}
            <div className="flex items-center gap-2 flex-wrap">
              {selectedRecord.userId && (
                <button
                  onClick={() => copyToClipboard(selectedRecord.userId!, "user")}
                  className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
                >
                  {copiedKey === "user" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                  <span>Copy User</span>
                </button>
              )}
              {selectedRecord.clientIp && (
                <button
                  onClick={() => copyToClipboard(selectedRecord.clientIp!, "ip")}
                  className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
                >
                  {copiedKey === "ip" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                  <span>Copy IP ({selectedRecord.clientIp})</span>
                </button>
              )}
              {selectedRecord.sessionId && (
                <button
                  onClick={() => copyToClipboard(selectedRecord.sessionId!, "session")}
                  className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
                >
                  {copiedKey === "session" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                  <span>Copy Session ID</span>
                </button>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs">
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">User:</span>
                <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">{selectedRecord.userId || "Unknown"}</span>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Record Type / Workload:</span>
                <span className="text-slate-800 dark:text-slate-200">{selectedRecord.recordType || "Unknown"} {selectedRecord.workload ? `(${selectedRecord.workload})` : ""}</span>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Client IP:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">{selectedRecord.clientIp || "Unknown"}</span>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Client / Device Info:</span>
                <span className="text-slate-800 dark:text-slate-200 break-words">{selectedRecord.clientInfo || "Not captured for this record type"}</span>
              </div>
              {selectedRecord.sessionId && (
                <div className="col-span-2">
                  <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Session ID:</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-slate-800 dark:text-slate-200">{selectedRecord.sessionId}</span>
                    <button
                      onClick={() => openSessionTimeline(selectedRecord.sessionId!)}
                      className="text-[11px] text-sky-700 dark:text-sky-400 hover:underline flex items-center gap-1"
                    >
                      <Layers size={11} />
                      <span>View Session Timeline</span>
                    </button>
                  </div>
                </div>
              )}
              {selectedRecord.resultStatus && (
                <div>
                  <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Result Status:</span>
                  <span className="text-slate-800 dark:text-slate-200">{selectedRecord.resultStatus}</span>
                </div>
              )}
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Raw Record (AuditData)</h4>
                <button
                  onClick={() => {
                    let text = selectedRecord.rawData;
                    try {
                      text = JSON.stringify(JSON.parse(selectedRecord.rawData), null, 2);
                    } catch {
                      // Malformed AuditData - copy the raw string as-is.
                    }
                    copyToClipboard(text, "json");
                  }}
                  className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
                >
                  {copiedKey === "json" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                  <span>{copiedKey === "json" ? "Copied!" : "Copy JSON"}</span>
                </button>
              </div>
              <pre className="p-3 bg-slate-950 text-emerald-400 font-mono text-[11px] rounded-sm overflow-x-auto select-all leading-relaxed whitespace-pre-wrap break-all">
                {(() => {
                  try {
                    return JSON.stringify(JSON.parse(selectedRecord.rawData), null, 2);
                  } catch {
                    return selectedRecord.rawData;
                  }
                })()}
              </pre>
            </div>
          </div>
        </Drawer>
      )}

      {/* Session Timeline drawer */}
      {timelineSessionId && (
        <Drawer
          isOpen={!!timelineSessionId}
          onClose={() => setTimelineSessionId(null)}
          title="Session Timeline"
          subtitle={`Session ID: ${timelineSessionId} - ${timelineRecords.length} event(s)`}
          width="xl"
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs text-slate-500 dark:text-slate-400 flex-1">
                Every record sharing this Session ID, in chronological order. Microsoft&apos;s own guidance for investigating a
                compromised mailbox is to compare Client IP / client info across a session&apos;s events - a session that jumps
                between distinct IPs is worth a closer look.
              </p>
              <button
                onClick={() => copyToClipboard(timelineSessionId, "timeline-session")}
                className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors shrink-0"
              >
                {copiedKey === "timeline-session" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                <span>Copy Session ID</span>
              </button>
            </div>

            {timelineDistinctIps.length > 1 && (
              <div className="p-3 bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 rounded-sm text-xs text-amber-900 dark:text-amber-400 flex items-start gap-2">
                <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
                <span>
                  This session spans {timelineDistinctIps.length} distinct client IPs ({timelineDistinctIps.join(", ")}) - worth
                  investigating whether this is a hijacked session (AiTM / token replay) rather than one continuous legitimate session.
                </span>
              </div>
            )}

            {timelineLoading ? (
              <div className="text-xs text-slate-500 dark:text-slate-400 p-4 text-center">Loading timeline...</div>
            ) : (
              <div className="space-y-2">
                {timelineRecords.map((r) => (
                  <div key={r.id} className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm text-xs bg-slate-50 dark:bg-slate-800">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-900 dark:text-slate-100">{r.operation || "Unknown Operation"}</span>
                      <span className="font-mono text-[10px] text-slate-500 dark:text-slate-400 flex items-center gap-1">
                        <Clock size={10} />
                        {new Date(r.creationDate).toLocaleString()}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-600 dark:text-slate-400 font-mono">
                      {r.clientIp ? (
                        <button
                          onClick={() => copyToClipboard(r.clientIp!, `timeline-ip-${r.id}`)}
                          title="Copy IP"
                          className="flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100"
                        >
                          {copiedKey === `timeline-ip-${r.id}` ? <Check size={10} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={10} />}
                          <span>{r.clientIp}</span>
                        </button>
                      ) : (
                        <span>No IP</span>
                      )}
                      {r.clientInfo && <span className="truncate max-w-[240px]">{r.clientInfo}</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Drawer>
      )}
    </div>
  );
};
