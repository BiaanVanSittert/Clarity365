import React, { useState, useMemo, useEffect } from "react";
import { TenantSecuritySnapshot, SignInEvent, TimeRangePreset } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Drawer } from "../common/Drawer";
import { Modal } from "../common/Modal";
import { Pagination } from "../common/Pagination";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import {
  Key,
  Search,
  Filter,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  MapPin,
  Laptop,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  ChevronRight,
  AppWindow,
  AlertOctagon,
  ShieldX,
  Sparkles,
  Info,
  Calendar,
  Download,
  Terminal,
  Copy,
  Check,
  CheckCheck,
  RotateCcw,
  RefreshCw,
  SlidersHorizontal,
} from "lucide-react";

interface SignInLogsModuleProps {
  snapshot: TenantSecuritySnapshot;
  onRefresh?: () => void;
}

const ERROR_CODE_TRANSLATIONS: Record<number, { title: string; explanation: string; remediation: string }> = {
  0: {
    title: "Success",
    explanation: "Authentication succeeded and all evaluated Conditional Access policies passed.",
    remediation: "No action required. Normal operational authentication.",
  },
  50126: {
    title: "Invalid Credentials",
    explanation: "Error validating credentials due to invalid username or password.",
    remediation: "Verify user password or investigate possible credential stuffing / brute-force attempt if repeated.",
  },
  53003: {
    title: "Blocked by Conditional Access",
    explanation: "Access has been blocked by Conditional Access policies. The policy conditions blocked token issuance.",
    remediation: "Check applied CA policies in the inspector below. Validate user scope, location, or device compliance requirements.",
  },
  50074: {
    title: "Strong Authentication Required",
    explanation: "Strong Authentication is required (user did not complete or was interrupted during MFA challenge).",
    remediation: "Ensure user has registered Microsoft Authenticator / FIDO2 keys at https://aka.ms/setupmfa.",
  },
  50076: {
    title: "Admin MFA Required",
    explanation: "User was required to perform MFA because of administrator role assignment.",
    remediation: "Enforce CA03 policy compliance and verify admin has strong phishing-resistant auth registered.",
  },
  50053: {
    title: "Account Locked Out",
    explanation: "The account is locked; tried to sign in too many times with an incorrect user ID or password.",
    remediation: "Review Entra ID Smart Lockout settings or unlock user account in Microsoft 365 Admin Center.",
  },
  50140: {
    title: "Keep Me Signed In Interrupt",
    explanation: "Occurred due to 'Keep me signed in' interrupt when user was signing in.",
    remediation: "Normal session checkpoint. Configure KMSI policy under Entra Company Branding if desired.",
  },
  65001: {
    title: "Application Consent Missing",
    explanation: "The user or administrator has not consented to use the application. Interactive authorization required.",
    remediation: "Grant tenant-wide admin consent for this app in Entra ID Enterprise Applications.",
  },
  50058: {
    title: "Silent Session Expired",
    explanation: "User session cookie expired or continuous access evaluation revoked the token.",
    remediation: "Prompt user to re-authenticate interactively.",
  },
  50011: {
    title: "Redirect URI Mismatch",
    explanation: "The redirect URI specified in the request does not match the URIs configured for the application.",
    remediation: "Update Reply URLs in Azure App Registrations.",
  },
  500113: {
    title: "Missing Reply Address",
    explanation: "No reply address is registered for the application.",
    remediation: "Configure valid redirect URI on the target Application Registration.",
  },
};

const STORAGE_KEY_PREFIX = "clarity365_alerts_cleared_";

export const SignInLogsModule: React.FC<SignInLogsModuleProps> = ({ snapshot, onRefresh }) => {
  const { signIns, tenant } = snapshot;

  // Search and general filters
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [errorCodeFilter, setErrorCodeFilter] = useState<number | "all">("all");
  const [selectedEvent, setSelectedEvent] = useState<SignInEvent | null>(null);

  // Time stamp & custom date range filters
  const [timePreset, setTimePreset] = useState<TimeRangePreset>("all");
  const [customStartDate, setCustomStartDate] = useState<string>("");
  const [customEndDate, setCustomEndDate] = useState<string>("");
  const [specificDate, setSpecificDate] = useState<string>("");

  // Copy & export feedback state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [kqlModalOpen, setKqlModalOpen] = useState(false);
  const [isAlertCleared, setIsAlertCleared] = useState(false);

  // Load alert clearance status
  React.useEffect(() => {
    try {
      const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenant.id}`);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.allCleared || parsed.modules?.signin_logs) {
          setIsAlertCleared(true);
        }
      }
    } catch {
      // Fallback
    }
  }, [tenant.id]);

  const handleClearAlerts = () => {
    setIsAlertCleared(true);
    try {
      const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenant.id}`);
      const parsed = stored ? JSON.parse(stored) : { modules: {} };
      parsed.modules = { ...(parsed.modules || {}), signin_logs: true };
      localStorage.setItem(`${STORAGE_KEY_PREFIX}${tenant.id}`, JSON.stringify(parsed));
      // Dispatch storage event for sidebar update
      window.dispatchEvent(new Event("storage"));
    } catch {
      // Ignore
    }
  };

  const handleRestoreAlerts = () => {
    setIsAlertCleared(false);
    try {
      const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenant.id}`);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.modules) {
          delete parsed.modules.signin_logs;
          parsed.allCleared = false;
        }
        localStorage.setItem(`${STORAGE_KEY_PREFIX}${tenant.id}`, JSON.stringify(parsed));
        window.dispatchEvent(new Event("storage"));
      }
    } catch {
      // Ignore
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Compute unique service names for filtering
  const availableServices = useMemo(() => {
    const services = new Set<string>();
    signIns.forEach((s) => {
      if (s.appDisplayName) services.add(s.appDisplayName);
    });
    return Array.from(services).sort();
  }, [signIns]);

  // Compute Top Error Codes for quick filter bar
  const topErrorCodes = useMemo(() => {
    const counts: Record<number, number> = {};
    signIns.forEach((s) => {
      if (s.errorCode !== 0) {
        counts[s.errorCode] = (counts[s.errorCode] || 0) + 1;
      }
    });
    return Object.entries(counts)
      .map(([code, count]) => ({ code: Number(code), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [signIns]);

  // Apply Time Stamp & Date Filtering
  const timeFilteredSignIns = useMemo(() => {
    if (timePreset === "all" && !customStartDate && !customEndDate && !specificDate) {
      return signIns;
    }

    const now = new Date().getTime();

    return signIns.filter((evt) => {
      const evtTime = new Date(evt.createdDateTime).getTime();

      if (timePreset === "24h") {
        const dayAgo = now - 24 * 60 * 60 * 1000;
        return evtTime >= dayAgo;
      }

      if (timePreset === "7d") {
        const weekAgo = now - 7 * 24 * 60 * 60 * 1000;
        return evtTime >= weekAgo;
      }

      if (timePreset === "30d") {
        const monthAgo = now - 30 * 24 * 60 * 60 * 1000;
        return evtTime >= monthAgo;
      }

      if (timePreset === "custom") {
        if (specificDate) {
          const startOfDay = new Date(`${specificDate}T00:00:00`).getTime();
          const endOfDay = new Date(`${specificDate}T23:59:59`).getTime();
          return evtTime >= startOfDay && evtTime <= endOfDay;
        }

        if (customStartDate) {
          const start = new Date(customStartDate).getTime();
          if (evtTime < start) return false;
        }
        if (customEndDate) {
          const end = new Date(customEndDate).getTime() + (customEndDate.includes("T") ? 0 : 24 * 60 * 60 * 1000 - 1);
          if (evtTime > end) return false;
        }
        return true;
      }

      return true;
    });
  }, [signIns, timePreset, customStartDate, customEndDate, specificDate]);

  // Compute analytics on the time-filtered dataset
  const stats = useMemo(() => {
    const total = timeFilteredSignIns.length;
    const successful = timeFilteredSignIns.filter((s) => s.status === "success" || s.errorCode === 0).length;
    const failed = timeFilteredSignIns.filter((s) => s.status === "failed" || (s.errorCode !== 0 && s.status !== "report_only_failed")).length;
    const caBlocked = timeFilteredSignIns.filter((s) => s.status === "ca_blocked" || s.errorCode === 53003).length;
    const reportOnlyFailed = timeFilteredSignIns.filter((s) => s.hasReportOnlyFailure || s.status === "report_only_failed").length;
    const successRate = total > 0 ? Math.round((successful / total) * 100) : 100;

    return { total, successful, failed, caBlocked, reportOnlyFailed, successRate };
  }, [timeFilteredSignIns]);

  // CA Report-Only Impact Analysis
  const reportOnlyImpact = useMemo(() => {
    const impactedUsers = new Set<string>();
    const impactedPolicies: Record<string, number> = {};

    timeFilteredSignIns.forEach((s) => {
      if (s.hasReportOnlyFailure && s.reportOnlyFailedPolicies) {
        impactedUsers.add(s.userPrincipalName);
        s.reportOnlyFailedPolicies.forEach((p) => {
          impactedPolicies[p] = (impactedPolicies[p] || 0) + 1;
        });
      }
    });

    return {
      uniqueUsersImpacted: impactedUsers.size,
      policyHits: impactedPolicies,
    };
  }, [timeFilteredSignIns]);

  // Full filter pipeline
  const filteredSignIns = useMemo(() => {
    return timeFilteredSignIns.filter((evt) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        evt.userPrincipalName.toLowerCase().includes(q) ||
        evt.userDisplayName.toLowerCase().includes(q) ||
        evt.appDisplayName.toLowerCase().includes(q) ||
        (evt.failureReason && evt.failureReason.toLowerCase().includes(q)) ||
        evt.ipAddress.includes(q) ||
        evt.location.city.toLowerCase().includes(q);

      const matchesService = serviceFilter === "all" || evt.appDisplayName === serviceFilter;
      const matchesErrorCode = errorCodeFilter === "all" || evt.errorCode === errorCodeFilter;

      if (!matchesSearch || !matchesService || !matchesErrorCode) return false;

      if (statusFilter === "all") return true;
      if (statusFilter === "success") return evt.status === "success" || evt.errorCode === 0;
      if (statusFilter === "failed") return evt.status === "failed" || (evt.errorCode !== 0 && evt.status !== "report_only_failed");
      if (statusFilter === "ca_blocked") return evt.status === "ca_blocked" || evt.errorCode === 53003;
      if (statusFilter === "report_only_failed") return evt.hasReportOnlyFailure || evt.status === "report_only_failed";
      if (statusFilter === "risky") return evt.isRisky;
      return true;
    });
  }, [timeFilteredSignIns, searchQuery, statusFilter, serviceFilter, errorCodeFilter]);

  // Client-side pagination — a live tenant sync can pull thousands of
  // sign-in rows, and rendering them all as literal <tr>s doesn't scale.
  const SIGNIN_PAGE_SIZE = 50;
  const [page, setPage] = useState(1);
  useEffect(() => {
    setPage(1);
  }, [searchQuery, statusFilter, serviceFilter, errorCodeFilter, timePreset, customStartDate, customEndDate, specificDate]);
  const paginatedSignIns = useMemo(
    () => filteredSignIns.slice((page - 1) * SIGNIN_PAGE_SIZE, page * SIGNIN_PAGE_SIZE),
    [filteredSignIns, page]
  );

  const getStatusDisplay = (evt: SignInEvent) => {
    if (evt.status === "ca_blocked" || evt.errorCode === 53003) {
      return <StatusPill status="fail" label="CA Blocked" size="sm" />;
    }
    if (evt.hasReportOnlyFailure || evt.status === "report_only_failed") {
      return <StatusPill status="warn" label="Report-Only Fail" size="sm" />;
    }
    if (evt.errorCode === 0 || evt.status === "success") {
      return <StatusPill status="pass" label="Succeeded" size="sm" />;
    }
    return <StatusPill status="fail" label={`Failed (${evt.errorCode})`} size="sm" />;
  };

  // Export to CSV
  const handleExportCSV = () => {
    const headers = [
      "Timestamp",
      "UserPrincipalName",
      "UserDisplayName",
      "Service",
      "Status",
      "ErrorCode",
      "FailureReason",
      "IPAddress",
      "City",
      "Country",
      "OS",
      "Browser",
      "ReportOnlyFailures",
    ];

    const rows = filteredSignIns.map((s) => [
      s.createdDateTime,
      s.userPrincipalName,
      s.userDisplayName || "",
      s.appDisplayName,
      s.status,
      s.errorCode,
      s.failureReason || "",
      s.ipAddress,
      s.location.city || "",
      s.location.country || "",
      s.deviceDetail?.operatingSystem || "",
      s.deviceDetail?.browser || "",
      (s.reportOnlyFailedPolicies || []).join("; "),
    ]);

    exportToCsv(csvFilename("SignInLogs", tenant.defaultDomainName), headers, rows);
  };

  // Generate Sentinel / Defender KQL Query
  const generateKqlQuery = () => {
    let kql = `// Microsoft Sentinel / Defender XDR KQL Query\n// Tenant: ${tenant.displayName} (${tenant.defaultDomainName})\n`;
    kql += `SigninLogs\n`;
    if (timePreset === "24h") kql += `| where TimeGenerated >= ago(24h)\n`;
    else if (timePreset === "7d") kql += `| where TimeGenerated >= ago(7d)\n`;
    else if (timePreset === "30d") kql += `| where TimeGenerated >= ago(30d)\n`;
    else if (timePreset === "custom" && customStartDate) kql += `| where TimeGenerated between (datetime(${customStartDate}) .. datetime(${customEndDate || "now()"}))\n`;
    else kql += `| where TimeGenerated >= ago(30d)\n`;

    if (statusFilter === "ca_blocked") kql += `| where ResultType == 53003 or ConditionalAccessStatus == "failure"\n`;
    else if (statusFilter === "failed") kql += `| where ResultType != 0\n`;
    else if (statusFilter === "report_only_failed") kql += `| where ConditionalAccessPolicies has "reportOnlyFailure"\n`;

    if (errorCodeFilter !== "all") kql += `| where ResultType == ${errorCodeFilter}\n`;
    if (serviceFilter !== "all") kql += `| where AppDisplayName =~ "${serviceFilter}"\n`;
    if (searchQuery) kql += `| where UserPrincipalName has "${searchQuery}" or IPAddress == "${searchQuery}"\n`;

    kql += `| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType, ResultDescription, ConditionalAccessPolicies\n`;
    kql += `| order by TimeGenerated desc\n`;
    kql += `| take 250`;
    return kql;
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Key size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 2: Entra ID Sign-In Logs & CA Diagnostic Engine
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time interactive log streamer with time filtering, Conditional Access policy rule-chain inspection, and failure analytics.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Acknowledge / Clear Badges */}
          {isAlertCleared ? (
            <button
              onClick={handleRestoreAlerts}
              title="Restore sign-in alert badge on the sidebar"
              className="px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
            >
              <RotateCcw size={13} className="text-slate-500 dark:text-slate-400" />
              <span>Restore Alert Badge</span>
            </button>
          ) : (
            <button
              onClick={handleClearAlerts}
              title="Acknowledge reviewed sign-in alerts and clear the sidebar number icon"
              className="px-2.5 py-1.5 text-xs font-medium text-emerald-800 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950 hover:bg-emerald-100 dark:hover:bg-emerald-900 border border-emerald-300 dark:border-emerald-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
            >
              <CheckCheck size={14} className="text-emerald-600 dark:text-emerald-400" />
              <span>Mark All Reviewed (Clear Alert)</span>
            </button>
          )}

          {/* Export CSV */}
          <button
            onClick={handleExportCSV}
            title="Export filtered logs to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>

          {/* Sentinel KQL Query */}
          <button
            onClick={() => setKqlModalOpen(true)}
            title="Generate KQL Query for Microsoft Sentinel"
            className="px-2.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Terminal size={13} className="text-emerald-400" />
            <span>KQL Query</span>
          </button>

          {onRefresh && (
            <button
              onClick={onRefresh}
              title="Synchronize live sign-ins from Microsoft Graph"
              className="p-1.5 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
              <RefreshCw size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Time Range & Timestamp Filtering Bar */}
      <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm space-y-3 shadow-2xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Preset Buttons */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[11px] font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mr-1 flex items-center gap-1">
              <Calendar size={13} className="text-slate-500 dark:text-slate-400" />
              <span>Timeframe:</span>
            </span>

            {[
              { id: "all", label: "All Time" },
              { id: "24h", label: "Today (24h)" },
              { id: "7d", label: "Last 7 Days (Week)" },
              { id: "30d", label: "Last 30 Days (Month)" },
              { id: "custom", label: "Custom / Specific Date..." },
            ].map((preset) => {
              const isSelected = timePreset === preset.id;
              return (
                <button
                  key={preset.id}
                  onClick={() => {
                    setTimePreset(preset.id as TimeRangePreset);
                    if (preset.id !== "custom") {
                      setCustomStartDate("");
                      setCustomEndDate("");
                      setSpecificDate("");
                    }
                  }}
                  className={`px-2.5 py-1 text-xs rounded-sm font-medium transition-colors border ${
                    isSelected
                      ? "bg-slate-900 text-white border-slate-900 dark:border-slate-100 shadow-2xs font-semibold"
                      : "bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-700/70"
                  }`}
                >
                  {preset.label}
                </button>
              );
            })}
          </div>

          {/* Quick Active Filter Indicators */}
          <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono flex items-center gap-2">
            <span>Showing:</span>
            <span className="font-bold text-slate-900 dark:text-slate-100 tabular-nums">
              {filteredSignIns.length} of {signIns.length} Events
            </span>
          </div>
        </div>

        {/* Custom Range & Specific Date Inputs (Shown when "custom" selected) */}
        {timePreset === "custom" && (
          <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-3 bg-slate-50 dark:bg-slate-800 p-2.5 rounded-sm">
            {/* Specific Day Picker */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Specific Day:</span>
              <input
                type="date"
                value={specificDate}
                onChange={(e) => {
                  setSpecificDate(e.target.value);
                  setCustomStartDate("");
                  setCustomEndDate("");
                }}
                className="px-2 py-1 text-xs border border-slate-300 dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-800 dark:focus:border-slate-400"
              />
            </div>

            <div className="text-slate-400 dark:text-slate-500 text-xs font-semibold">OR</div>

            {/* Date Range Start -> End */}
            <div className="flex items-center gap-2 flex-wrap">
              <div className="flex items-center gap-1">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Start Date:</span>
                <input
                  type="date"
                  value={customStartDate}
                  onChange={(e) => {
                    setCustomStartDate(e.target.value);
                    setSpecificDate("");
                  }}
                  className="px-2 py-1 text-xs border border-slate-300 dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-800 dark:focus:border-slate-400"
                />
              </div>

              <div className="flex items-center gap-1">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">End Date:</span>
                <input
                  type="date"
                  value={customEndDate}
                  onChange={(e) => {
                    setCustomEndDate(e.target.value);
                    setSpecificDate("");
                  }}
                  className="px-2 py-1 text-xs border border-slate-300 dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-800 dark:focus:border-slate-400"
                />
              </div>

              {(customStartDate || customEndDate || specificDate) && (
                <button
                  onClick={() => {
                    setCustomStartDate("");
                    setCustomEndDate("");
                    setSpecificDate("");
                  }}
                  className="px-2 py-1 text-xs text-rose-700 dark:text-red-400 hover:text-rose-900 dark:text-red-400 border border-rose-200 dark:border-red-800 bg-rose-50 dark:bg-red-950 hover:bg-rose-100 dark:hover:bg-red-900 rounded-sm transition-colors"
                >
                  Clear Date Filter
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Analytics KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Total Sign-Ins</div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">{stats.total}</div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
            {timePreset === "24h" ? "Past 24 Hours" : timePreset === "7d" ? "Past 7 Days" : timePreset === "30d" ? "Past 30 Days" : "Selected Range"}
          </div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-400 uppercase tracking-wider flex items-center gap-1">
            <CheckCircle2 size={12} />
            <span>Succeeded</span>
          </div>
          <div className="text-xl font-bold font-mono text-emerald-900 dark:text-emerald-400 mt-1">
            {stats.successful} <span className="text-xs font-normal text-emerald-600 dark:text-emerald-400">({stats.successRate}%)</span>
          </div>
          <div className="text-[10px] text-emerald-600 dark:text-emerald-400 mt-0.5">Passed all evaluations</div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[11px] font-semibold text-rose-700 dark:text-red-400 uppercase tracking-wider flex items-center gap-1">
            <XCircle size={12} />
            <span>Auth Failures</span>
          </div>
          <div className="text-xl font-bold font-mono text-rose-900 dark:text-red-400 mt-1">{stats.failed}</div>
          <div className="text-[10px] text-rose-600 dark:text-red-400 mt-0.5">Bad credentials / policy blocks</div>
        </div>

        <div
          onClick={() => setStatusFilter(statusFilter === "report_only_failed" ? "all" : "report_only_failed")}
          className={`p-3 border rounded-sm cursor-pointer transition-colors ${
            statusFilter === "report_only_failed"
              ? "bg-amber-100 dark:bg-amber-950 border-amber-400 dark:border-amber-800"
              : "bg-amber-50/60 dark:bg-amber-950 border-amber-200 dark:border-amber-800 hover:bg-amber-100/70 dark:hover:bg-amber-900"
          }`}
        >
          <div className="text-[11px] font-semibold text-amber-800 dark:text-amber-400 uppercase tracking-wider flex items-center gap-1">
            <AlertTriangle size={12} />
            <span>CA Report-Only Failures</span>
          </div>
          <div className="text-xl font-bold font-mono text-amber-950 dark:text-amber-400 mt-1">{stats.reportOnlyFailed}</div>
          <div className="text-[10px] text-amber-700 dark:text-amber-400 mt-0.5">
            {reportOnlyImpact.uniqueUsersImpacted > 0
              ? `${reportOnlyImpact.uniqueUsersImpacted} users impacted (Click to filter)`
              : "No report-only block events"}
          </div>
        </div>
      </div>

      {/* Top Error Code Breakdown Pills */}
      {topErrorCodes.length > 0 && (
        <div className="bg-slate-50 dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 p-2.5 rounded-sm flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 flex items-center gap-1">
            <ShieldAlert size={12} className="text-rose-600 dark:text-red-400" />
            <span>Frequent Error Codes:</span>
          </span>

          <button
            onClick={() => setErrorCodeFilter("all")}
            className={`px-2 py-0.5 text-[11px] font-mono rounded-sm transition-colors border ${
              errorCodeFilter === "all"
                ? "bg-slate-800 text-white border-slate-800 font-bold"
                : "bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-700"
            }`}
          >
            All Codes
          </button>

          {topErrorCodes.map(({ code, count }) => {
            const isSelected = errorCodeFilter === code;
            const meta = ERROR_CODE_TRANSLATIONS[code];
            return (
              <button
                key={code}
                onClick={() => setErrorCodeFilter(isSelected ? "all" : code)}
                title={`${meta?.title || "Error"}: ${meta?.explanation || ""}`}
                className={`px-2 py-0.5 text-[11px] font-mono rounded-sm transition-colors border flex items-center gap-1 ${
                  isSelected
                    ? "bg-rose-700 text-white border-rose-700 font-bold shadow-2xs"
                    : "bg-white dark:bg-slate-800 text-rose-800 dark:text-red-400 border-rose-200 dark:border-red-800 hover:bg-rose-50 dark:bg-red-950"
                }`}
              >
                <span>[{code}]</span>
                <span className="font-sans font-medium text-[10px]">{meta?.title || "Error"}</span>
                <span className="px-1 bg-rose-100 dark:bg-red-950 text-rose-900 dark:text-red-400 rounded text-[9px] font-bold">{count}</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Filters Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full md:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search by User (UPN), Service, Failure Reason, IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Status Filter */}
          <div className="flex items-center gap-1.5">
            <Filter size={13} className="text-slate-500 dark:text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium text-slate-700 dark:text-slate-300"
            >
              <option value="all">All Outcomes</option>
              <option value="success">Succeeded Logins</option>
              <option value="failed">Failed Logins</option>
              <option value="report_only_failed">Failing Report-Only CA</option>
              <option value="ca_blocked">CA Blocked</option>
              <option value="risky">Flagged as Risky</option>
            </select>
          </div>

          {/* Service Filter */}
          <div className="flex items-center gap-1.5">
            <AppWindow size={13} className="text-slate-500 dark:text-slate-400" />
            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium text-slate-700 dark:text-slate-300 max-w-[200px] truncate"
            >
              <option value="all">All Services ({availableServices.length})</option>
              {availableServices.map((svc) => (
                <option key={svc} value={svc}>
                  {svc}
                </option>
              ))}
            </select>
          </div>

          {(statusFilter !== "all" || serviceFilter !== "all" || errorCodeFilter !== "all" || searchQuery || timePreset !== "all") && (
            <button
              onClick={() => {
                setStatusFilter("all");
                setServiceFilter("all");
                setErrorCodeFilter("all");
                setSearchQuery("");
                setTimePreset("all");
                setCustomStartDate("");
                setCustomEndDate("");
                setSpecificDate("");
              }}
              className="px-2.5 py-1 text-xs text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 border border-slate-300 dark:border-slate-600 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
              Reset All Filters
            </button>
          )}
        </div>
      </div>

      {/* Log Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Authentication & Session Audit Stream
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
            {filteredSignIns.length} Records Matching
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-28">Timestamp</th>
                <th className="min-w-[200px]">User (Identity)</th>
                <th className="w-28">Status</th>
                <th className="min-w-[170px]">Service</th>
                <th className="min-w-[260px]">Failure Reason</th>
                <th className="min-w-[200px]">CA Report-Only Failure</th>
                <th className="w-16 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredSignIns.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                    <div className="space-y-1">
                      <Clock size={20} className="mx-auto text-slate-400 dark:text-slate-500 mb-1" />
                      <div className="font-semibold text-slate-700 dark:text-slate-300">No sign-in events match the active filter criteria.</div>
                      <div className="text-[11px] text-slate-400 dark:text-slate-500">Try adjusting the time range or resetting filters.</div>
                    </div>
                  </td>
                </tr>
              ) : (
                paginatedSignIns.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    tabIndex={0}
                    role="button"
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setSelectedEvent(evt))}
                    className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors focus:outline focus:outline-2 focus:outline-slate-400 focus:-outline-offset-2"
                  >
                    {/* Timestamp */}
                    <td className="font-mono text-[11px] text-slate-600 dark:text-slate-400 whitespace-nowrap">
                      <div>{new Date(evt.createdDateTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</div>
                      <div className="text-[10px] text-slate-400 dark:text-slate-500">{new Date(evt.createdDateTime).toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" })}</div>
                    </td>

                    {/* User */}
                    <td>
                      <div className="font-mono font-semibold text-xs text-slate-900 dark:text-slate-100 leading-tight flex items-center gap-1">
                        <span>{evt.userPrincipalName}</span>
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 flex items-center gap-1.5 mt-0.5">
                        <span>{evt.userDisplayName || evt.userPrincipalName}</span>
                        {evt.isRisky && (
                          <span className="text-[9px] font-mono uppercase px-1 bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-400 border border-red-300 dark:border-red-800 rounded-sm">
                            {evt.riskLevel} Risk
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Status */}
                    <td>{getStatusDisplay(evt)}</td>

                    {/* Service */}
                    <td>
                      <div className="font-semibold text-xs text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                        <AppWindow size={13} className="text-slate-400 dark:text-slate-500 flex-shrink-0" />
                        <span className="truncate">{evt.appDisplayName}</span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 mt-0.5 flex items-center gap-1">
                        <MapPin size={10} />
                        <span>{evt.location.city || "Unknown"}, {evt.location.country || "ZA"}</span>
                      </div>
                    </td>

                    {/* Failure Reason */}
                    <td className="text-xs">
                      {evt.errorCode === 0 && !evt.hasReportOnlyFailure ? (
                        <span className="text-slate-400 dark:text-slate-500 text-[11px] italic">None (Authentication Successful)</span>
                      ) : evt.errorCode !== 0 ? (
                        <div className="text-rose-900 dark:text-red-400 bg-rose-50 dark:bg-red-950 border border-rose-200 dark:border-red-800 p-1.5 rounded-sm text-[11px] leading-snug">
                          <span className="font-mono font-bold text-rose-800 dark:text-red-400 mr-1">[{evt.errorCode}]</span>
                          <span>{evt.failureReason || ERROR_CODE_TRANSLATIONS[evt.errorCode]?.explanation || "Authentication failed"}</span>
                        </div>
                      ) : (
                        <span className="text-slate-500 dark:text-slate-400 text-[11px]">{evt.failureReason || "Authentication successful"}</span>
                      )}
                    </td>

                    {/* CA Report-Only Failure */}
                    <td>
                      {evt.hasReportOnlyFailure && evt.reportOnlyFailedPolicies && evt.reportOnlyFailedPolicies.length > 0 ? (
                        <div className="space-y-1">
                          {evt.reportOnlyFailedPolicies.map((polName, idx) => (
                            <div
                              key={idx}
                              className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 text-amber-900 dark:text-amber-400 text-[11px] font-medium rounded-sm"
                              title={`This policy evaluated to 'reportOnlyFailure'. If enabled, it would block or challenge this login.`}
                            >
                              <AlertTriangle size={11} className="text-amber-700 dark:text-amber-400 flex-shrink-0" />
                              <span className="truncate max-w-[200px]">{polName}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[11px] text-slate-400 dark:text-slate-500 flex items-center gap-1 font-mono">
                          <CheckCircle2 size={12} className="text-emerald-500" />
                          <span>Passed / None</span>
                        </span>
                      )}
                    </td>

                    {/* Details Chevron */}
                    <td className="text-right">
                      <button
                        aria-label="View sign-in event details"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
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
        <Pagination
          page={page}
          pageSize={SIGNIN_PAGE_SIZE}
          totalItems={filteredSignIns.length}
          onPageChange={setPage}
        />
      </div>

      {/* Drill-down Diagnostic Drawer */}
      {selectedEvent && (
        <Drawer
          isOpen={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title="Sign-In Diagnostics & CA Rule-Chain Inspector"
          subtitle={`Session ID: ${selectedEvent.id} • ${new Date(selectedEvent.createdDateTime).toLocaleString()}`}
          width="xl"
        >
          <div className="space-y-4">
            {/* Outcome Banner */}
            <div
              className={`p-3.5 border rounded-sm ${
                selectedEvent.status === "success" && !selectedEvent.hasReportOnlyFailure
                  ? "bg-emerald-50 dark:bg-emerald-950 border-emerald-300 dark:border-emerald-800 text-emerald-950"
                  : selectedEvent.status === "ca_blocked" || selectedEvent.errorCode !== 0
                  ? "bg-rose-50 dark:bg-red-950 border-rose-300 dark:border-red-800 text-rose-950 dark:text-red-400"
                  : "bg-amber-50 dark:bg-amber-950 border-amber-300 dark:border-amber-800 text-amber-950 dark:text-amber-400"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider">
                  Status: {selectedEvent.status.toUpperCase()}
                </span>
                <span className="font-mono text-xs font-bold">
                  Error Code: {selectedEvent.errorCode}
                </span>
              </div>
              <p className="text-xs mt-1.5 font-medium leading-relaxed">
                {selectedEvent.failureReason || ERROR_CODE_TRANSLATIONS[selectedEvent.errorCode]?.explanation || "Authentication succeeded."}
              </p>
              {ERROR_CODE_TRANSLATIONS[selectedEvent.errorCode]?.remediation && (
                <div className="mt-2 pt-2 border-t border-current/10 text-[11px] opacity-90">
                  <span className="font-bold">Remediation: </span>
                  <span>{ERROR_CODE_TRANSLATIONS[selectedEvent.errorCode].remediation}</span>
                </div>
              )}
            </div>

            {/* Quick Copy Action Bar */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => copyToClipboard(selectedEvent.userPrincipalName, "upn")}
                className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
              >
                {copiedKey === "upn" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                <span>Copy UPN</span>
              </button>

              <button
                onClick={() => copyToClipboard(selectedEvent.ipAddress, "ip")}
                className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
              >
                {copiedKey === "ip" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                <span>Copy IP ({selectedEvent.ipAddress})</span>
              </button>

              <button
                onClick={() => copyToClipboard(selectedEvent.id, "id")}
                className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 flex items-center gap-1 transition-colors"
              >
                {copiedKey === "id" ? <Check size={11} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={11} />}
                <span>Copy Session ID</span>
              </button>
            </div>

            {/* User & Service Details */}
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs">
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">User (UPN):</span>
                <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">{selectedEvent.userPrincipalName}</span>
                <span className="text-slate-600 dark:text-slate-400 block text-[11px]">{selectedEvent.userDisplayName}</span>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Service (App):</span>
                <span className="font-semibold text-slate-900 dark:text-slate-100">{selectedEvent.appDisplayName}</span>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Client & OS:</span>
                <span className="text-slate-800 dark:text-slate-200">{selectedEvent.clientApp} ({selectedEvent.deviceDetail?.operatingSystem || "Unknown"})</span>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400 block text-[11px]">IP & Location:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">{selectedEvent.ipAddress}</span>
                <span className="text-slate-600 dark:text-slate-400 block text-[11px]">{selectedEvent.location.city || "Unknown"}, {selectedEvent.location.country || "ZA"}</span>
              </div>
            </div>

            {/* CA Evaluation Chain */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 mb-2 flex items-center gap-1.5">
                <Layers size={13} />
                <span>Applied Conditional Access Policy Evaluations</span>
              </h4>

              {selectedEvent.appliedConditionalAccessPolicies.length === 0 ? (
                <div className="p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs text-slate-500 dark:text-slate-400 rounded-sm">
                  No Conditional Access policies were evaluated for this session (e.g. legacy endpoint or excluded application).
                </div>
              ) : (
                <div className="space-y-2">
                  {selectedEvent.appliedConditionalAccessPolicies.map((pol, idx) => {
                    const isReportOnly = pol.result.startsWith("reportOnly");
                    const isFail = pol.result === "failure" || pol.result === "reportOnlyFailure";
                    const isSuccess = pol.result === "success" || pol.result === "reportOnlySuccess";

                    return (
                      <div
                        key={idx}
                        className={`p-2.5 border rounded-sm text-xs ${
                          isFail
                            ? "bg-rose-50 dark:bg-red-950 border-rose-300 dark:border-red-800"
                            : isSuccess
                            ? "bg-emerald-50 dark:bg-emerald-950 border-emerald-200 dark:border-emerald-800"
                            : "bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-900 dark:text-slate-100">{pol.displayName}</span>
                          <span
                            className={`px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase rounded-xs ${
                              isFail
                                ? "bg-rose-600 text-white"
                                : isSuccess
                                ? "bg-emerald-600 text-white"
                                : "bg-slate-300 dark:bg-slate-600 text-slate-700 dark:text-slate-300"
                            }`}
                          >
                            {pol.result}
                          </span>
                        </div>
                        <div className="mt-1 text-[11px] text-slate-600 dark:text-slate-400 flex items-center justify-between">
                          <span>Mode: {isReportOnly ? "Report-Only (Simulation)" : "Enforced"}</span>
                          <span>Controls: {pol.enforcedGrantControls.join(", ") || "None"}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </Drawer>
      )}

      {/* KQL Query Generator Modal */}
      <Modal
        isOpen={kqlModalOpen}
        onClose={() => setKqlModalOpen(false)}
        title="Microsoft Sentinel / Defender KQL Query"
        maxWidth="2xl"
      >
        <div className="space-y-3">
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Copy and execute this KQL query in the Microsoft Defender XDR Advanced Hunting portal or Microsoft Sentinel workspace:
          </p>

          <pre className="p-3 bg-slate-950 text-emerald-400 font-mono text-xs rounded-sm overflow-x-auto select-all leading-relaxed">
            {generateKqlQuery()}
          </pre>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
            <button
              onClick={() => setKqlModalOpen(false)}
              className="px-3 py-1.5 text-xs text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-sm border border-slate-300 dark:border-slate-600"
            >
              Close
            </button>
            <button
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(generateKqlQuery());
                  setCopiedKey("kql");
                  setTimeout(() => setCopiedKey(null), 2000);
                } catch {
                  // Clipboard write failed (e.g. permission denied) — don't
                  // show a false "Copied" success state.
                }
              }}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5"
            >
              {copiedKey === "kql" ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
              <span>{copiedKey === "kql" ? "Copied to Clipboard!" : "Copy KQL Query"}</span>
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

