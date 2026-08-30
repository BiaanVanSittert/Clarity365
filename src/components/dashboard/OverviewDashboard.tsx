import React from "react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Skeleton } from "../common/SkeletonLoader";
import { computeExchangeMailflowScore } from "@/lib/services/exchange-mailflow-score";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
  HardDrive,
  Mail,
  Share2,
  Lock,
  ArrowUpRight,
  ArrowDownRight,
  TrendingUp,
  ExternalLink,
  AlertTriangle,
  FileSpreadsheet,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  Flame,
} from "lucide-react";

import { CA_BASELINE_STANDARDS } from "@/lib/data/baseline-definitions";

interface OverviewDashboardProps {
  snapshot: TenantSecuritySnapshot | null;
  isLoading: boolean;
  onNavigate: (view: string) => void;
  onOpenRemediation: (findingType?: string) => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  snapshot,
  isLoading,
  onNavigate,
  onOpenRemediation,
}) => {
  if (isLoading || !snapshot) {
    return (
      <div className="p-5 space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Skeleton variant="card" className="h-44" />
          <Skeleton variant="card" className="h-44" />
          <Skeleton variant="card" className="h-44" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Skeleton variant="card" className="h-64" />
          <Skeleton variant="card" className="h-64" />
        </div>
      </div>
    );
  }

  const { tenant, secureScore, conditionalAccess, signIns, accountClassification, mailboxes, emailForwarding, intune, capabilities, highRiskThreatIndicators, sharePoint } = snapshot;

  // Derived live from emailForwarding - see types/index.ts's removal comment
  // for why this is no longer a separate stored counter.
  const externalForwardingCount = emailForwarding.filter((r) => r.isExternal && r.state === "Enabled").length;

  // Derived live from sharePoint.sites - same removal reasoning as
  // externalForwardingCount above (see types/index.ts).
  const openSharePointSitesCount = sharePoint.sites.filter((s) => s.sharingCapability === "Anyone").length;

  const exchangeMailflowScore = computeExchangeMailflowScore(snapshot);

  const deployedCodes = new Set<string>();
  conditionalAccess.policies.forEach((p) => {
    if (p.baselineCode) {
      deployedCodes.add(p.baselineCode);
    } else {
      const m = p.name.match(/CA(0[1-9]|10)/i);
      if (m) deployedCodes.add(`CA${m[1]}`);
    }
  });

  const baselineDefinitions = CA_BASELINE_STANDARDS;
  const missingCABaselineCount = baselineDefinitions.length - deployedCodes.size;

  const sharedMailboxesCount = mailboxes.filter((m) => m.recipientType === "SharedMailbox").length;
  const licensedSharedMailboxWasteCount = mailboxes.filter((m) => m.recipientType === "SharedMailbox" && m.hasDirectLicense).length;

  const activeCriticalIncidents = (snapshot.incidents || []).filter(
    (i) => (i.severity === "critical" || i.severity === "high") && i.status !== "resolved"
  );

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Top Banner / Tenant Posture Bar */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-3.5 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              {tenant.displayName} Posture Overview
            </h2>
            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-sm font-semibold">
              {tenant.tier.replace("_", " ")}
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Primary Domain: <code className="font-mono text-slate-700 dark:text-slate-300">{tenant.defaultDomainName}</code> • Org ID: <code className="font-mono text-[11px] text-slate-600 dark:text-slate-400">{tenant.organizationId}</code>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onOpenRemediation("all")}
            className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <ShieldAlert size={14} className="text-amber-400" />
            <span>Generate Remediation Playbook</span>
          </button>
        </div>
      </div>

      {/* Active High/Critical Incident SOC Banner */}
      {activeCriticalIncidents.length > 0 && (
        <div className="p-3.5 bg-red-50 dark:bg-red-950/60 border border-red-300 dark:border-red-800 text-red-950 dark:text-red-200 rounded-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-red-600 text-white rounded-sm">
              <Flame size={16} className="animate-pulse" />
            </div>
            <div>
              <div className="text-xs font-bold text-red-900 dark:text-red-100">
                {activeCriticalIncidents.length} Critical/High Security Incident{activeCriticalIncidents.length > 1 ? "s" : ""} Requiring Immediate Containment
              </div>
              <p className="text-[11px] text-red-800 dark:text-red-300 mt-0.5">
                Active threat activity detected in Microsoft Defender XDR / Entra ID: <strong>{activeCriticalIncidents[0].displayName}</strong>
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate("event_response")}
            className="px-3 py-1.5 text-xs font-semibold text-white bg-red-700 hover:bg-red-800 rounded-sm whitespace-nowrap inline-flex items-center gap-1.5 shadow-sm transition-colors"
          >
            <span>Triage in Event Response</span>
            <ExternalLink size={12} />
          </button>
        </div>
      )}

      {/* TOP 6 PRIORITY WIDGETS GRID */}

      {/* ROW 1: Core Metrics (Widgets 1, 3, 5) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* WIDGET 1: Microsoft Defender Secure Score Card */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-4 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2 mb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck size={16} className="text-slate-800 dark:text-slate-200" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  1. Microsoft Secure Score
                </h3>
              </div>
              <button
                onClick={() => onNavigate("sec_score")}
                className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 font-medium flex items-center gap-0.5"
              >
                <span>Details</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="flex items-baseline justify-between">
              <div className="space-y-0.5">
                <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums">
                  {secureScore.percentage.toFixed(1)}%
                </div>
                <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                  {secureScore.currentScore} / {secureScore.maxScore} Attainable Points
                </div>
              </div>

              <div className="text-right space-y-1">
                <div className="flex items-center gap-1 text-xs font-mono">
                  {secureScore.delta30Days >= 0 ? (
                    <span className="text-emerald-700 dark:text-emerald-400 flex items-center gap-0.5 font-semibold">
                      <ArrowUpRight size={13} /> +{secureScore.delta30Days.toFixed(1)}% (30d)
                    </span>
                  ) : (
                    <span className="text-red-700 dark:text-red-400 flex items-center gap-0.5 font-semibold">
                      <ArrowDownRight size={13} /> {secureScore.delta30Days.toFixed(1)}% (30d)
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  Benchmark: <span className="font-mono font-medium">{secureScore.industryBenchmark}%</span>
                </div>
              </div>
            </div>

            {/* Progress bar */}
            <div className="w-full bg-[#E2E8F0] dark:bg-slate-700 h-2 rounded-sm overflow-hidden mt-3">
              <div
                className={`h-full ${
                  secureScore.percentage >= 75
                    ? "bg-emerald-600"
                    : secureScore.percentage >= 50
                    ? "bg-amber-600 dark:bg-amber-500"
                    : "bg-red-600 dark:bg-red-500"
                }`}
                style={{ width: `${Math.min(100, secureScore.percentage)}%` }}
              />
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-[#E2E8F0] dark:border-slate-700 flex items-center justify-between text-[11px]">
            <span className="text-slate-600 dark:text-slate-400">
              Unresolved actions: <strong>{secureScore.controls.filter((c) => c.status === "Unresolved").length}</strong>
            </span>
            <button
              onClick={() => onOpenRemediation("conditional_access")}
              className="text-slate-800 dark:text-slate-200 font-semibold hover:underline"
            >
              Remediate Top Impact &rarr;
            </button>
          </div>
        </div>

        {/* WIDGET 3: Identity & Asset Count Matrix */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-4 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2 mb-3">
              <div className="flex items-center gap-2">
                <Users size={16} className="text-slate-800 dark:text-slate-200" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  3. Identity & Asset Matrix
                </h3>
              </div>
              <button
                onClick={() => onNavigate("user_class")}
                className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 font-medium flex items-center gap-0.5"
              >
                <span>Directory</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {/* Licensed Users */}
              <div
                onClick={() => onNavigate("user_class")}
                className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800 border border-[#E2E8F0] dark:border-slate-700 rounded-sm cursor-pointer transition-colors group"
              >
                <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 font-semibold flex items-center justify-between">
                  <span>Licensed Users</span>
                  <ArrowUpRight size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">
                  {accountClassification.licensedUsersCount}
                </div>
                <div className="text-[10px] text-emerald-700 dark:text-emerald-400 font-medium mt-0.5">Active SKU Assigned</div>
              </div>

              {/* Unlicensed Active Accounts */}
              <div
                onClick={() => onNavigate("user_class")}
                className="p-2.5 bg-[#FFFBEB] dark:bg-amber-950/60 hover:bg-amber-100 dark:hover:bg-amber-950 border border-[#F59E0B] dark:border-amber-800 rounded-sm cursor-pointer transition-colors group"
              >
                <div className="text-[10px] uppercase font-mono text-[#92400E] dark:text-amber-400 font-semibold flex items-center justify-between">
                  <div className="flex items-center gap-1">
                    <AlertTriangle size={11} />
                    <span>Unlicensed Active</span>
                  </div>
                  <ArrowUpRight size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <div className="text-lg font-bold font-mono text-[#92400E] dark:text-amber-400 tabular-nums mt-0.5">
                  {accountClassification.unlicensedActiveCount}
                </div>
                <div className="text-[10px] text-[#92400E] dark:text-amber-400 font-medium mt-0.5">Orphaned Risk Flag</div>
              </div>

              {/* Shared Mailboxes */}
              <div
                onClick={() => onNavigate("mailbox_perm")}
                className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800 border border-[#E2E8F0] dark:border-slate-700 rounded-sm cursor-pointer transition-colors group"
              >
                <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 font-semibold flex items-center justify-between">
                  <span>Shared Mailboxes</span>
                  <ArrowUpRight size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">
                  {sharedMailboxesCount}
                </div>
                <div className="text-[10px] text-slate-600 dark:text-slate-400 font-medium mt-0.5">
                  {licensedSharedMailboxWasteCount > 0 ? (
                    <span className="text-amber-700 dark:text-amber-400 font-semibold">{licensedSharedMailboxWasteCount} paid licenses</span>
                  ) : (
                    "0 license waste"
                  )}
                </div>
              </div>

              {/* Intune Managed Devices */}
              <div
                onClick={() => onNavigate("intune")}
                className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800 border border-[#E2E8F0] dark:border-slate-700 rounded-sm cursor-pointer transition-colors group"
              >
                <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 font-semibold flex items-center justify-between">
                  <span>Intune Devices</span>
                  <ArrowUpRight size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">
                  {intune.totalDevices}
                </div>
                <div className="text-[10px] font-mono text-slate-600 dark:text-slate-400 mt-0.5">
                  <span className="text-emerald-700 dark:text-emerald-400 font-semibold">{intune.compliantDevices} Pass</span> •{" "}
                  <span className="text-red-700 dark:text-red-400 font-semibold">{intune.nonCompliantDevices} Fail</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* WIDGET 5: Conditional Access Baseline Health (CA01–CA10) */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-4 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2 mb-3">
              <div className="flex items-center gap-2">
                <Lock size={16} className="text-slate-800 dark:text-slate-200" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  5. CA Baseline Health
                </h3>
              </div>
              <button
                onClick={() => onNavigate("ca_baseline")}
                className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 font-medium flex items-center gap-0.5"
              >
                <span>All CA01-10</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums">
                  {deployedCodes.size} / 10
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">Baseline Standards Deployed</div>
              </div>

              <StatusPill
                status={missingCABaselineCount === 0 ? "pass" : missingCABaselineCount <= 3 ? "warn" : "fail"}
                label={missingCABaselineCount === 0 ? "100% Baseline Compliant" : `${missingCABaselineCount} Standards Missing`}
              />
            </div>

            {/* Grid of CA01 to CA10 pills */}
            <div className="grid grid-cols-5 gap-1.5 mt-3 pt-2 border-t border-[#E2E8F0] dark:border-slate-700">
              {baselineDefinitions.map((std) => {
                const policy = conditionalAccess.policies.find((p) => p.baselineCode === std.code || p.name.toUpperCase().includes(std.code));
                const isPass = policy && policy.state === "enabled";
                const isReportOnly = policy && policy.state === "enabledForReportingButNotEnforced";
                return (
                  <div
                    key={std.code}
                    title={`${std.code}: ${std.name} (${policy ? (isPass ? "Enabled (Enforced)" : isReportOnly ? "Report-Only" : "Disabled") : "Not Deployed"})`}
                    className={`py-1 text-center font-mono text-[11px] font-bold border rounded-sm transition-transform hover:scale-105 cursor-default ${
                      isPass
                        ? "bg-[#ECFDF5] dark:bg-emerald-950 border-[#10B981] dark:border-emerald-800 text-[#065F46] dark:text-emerald-400"
                        : isReportOnly
                        ? "bg-[#FFFBEB] dark:bg-amber-950 border-[#F59E0B] dark:border-amber-800 text-[#92400E] dark:text-amber-400"
                        : "bg-[#FEF2F2] dark:bg-red-950 border-[#EF4444] dark:border-red-800 text-[#991B1B] dark:text-red-400"
                    }`}
                  >
                    {std.code}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-3 text-[11px] text-slate-500 dark:text-slate-400 flex justify-between items-center">
            <span>Standard: <code className="font-mono text-slate-700 dark:text-slate-300">CA01-CA10 Baseline</code></span>
            <span className="text-slate-400 dark:text-slate-500">Strict Prefix Matching</span>
          </div>
        </div>
      </div>

      {/* ROW 2: Threat & Activity (Widgets 2, 4, 6) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* WIDGET 2: Recent Critical Security & Sign-In Events (Streamer) */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-4 flex flex-col justify-between shadow-xs lg:col-span-1">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2 mb-2">
              <div className="flex items-center gap-2">
                <Clock size={16} className="text-slate-800 dark:text-slate-200" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  2. Critical Sign-In Events
                </h3>
              </div>
              <button
                onClick={() => onNavigate("signin_logs")}
                className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 font-medium flex items-center gap-0.5"
              >
                <span>Live Logs</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="space-y-2 max-h-56 overflow-y-auto divide-y divide-slate-100">
              {signIns.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-400 dark:text-slate-500">No recent sign-in telemetry available.</div>
              ) : (
                signIns.slice(0, 4).map((event) => (
                  <div key={event.id} className="pt-2 first:pt-0 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate max-w-[170px]">
                        {event.userPrincipalName}
                      </span>
                      <StatusPill
                        status={
                          event.status === "success" && !event.hasReportOnlyFailure
                            ? "pass"
                            : event.status === "ca_blocked" || event.errorCode !== 0
                            ? "fail"
                            : "warn"
                        }
                        label={
                          event.status === "ca_blocked"
                            ? "CA Blocked"
                            : event.errorCode !== 0
                            ? `Failed (${event.errorCode})`
                            : event.hasReportOnlyFailure
                            ? "Report-Only Fail"
                            : "Succeeded"
                        }
                        size="sm"
                      />
                    </div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400 flex items-center justify-between">
                      <span className="font-medium truncate max-w-[160px]">{event.appDisplayName}</span>
                      <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                        {event.location.city || "Unknown"}, {event.location.country || "ZA"}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-[#E2E8F0] dark:border-slate-700 flex items-center justify-between text-[11px]">
            <span className="text-slate-500 dark:text-slate-400 font-mono">Streamer Active</span>
            <button
              onClick={() => onNavigate("signin_logs")}
              className="text-slate-800 dark:text-slate-200 font-semibold hover:underline"
            >
              Analyze Risky Sign-ins &rarr;
            </button>
          </div>
        </div>

        {/* WIDGET 4: Tenant License & Capability Matrix */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-4 flex flex-col justify-between shadow-xs lg:col-span-1">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2 mb-3">
              <div className="flex items-center gap-2">
                <Layers size={16} className="text-slate-800 dark:text-slate-200" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  4. License & Capability Matrix
                </h3>
              </div>
              <span className="text-[10px] font-mono uppercase bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 px-1.5 py-0.5 rounded-sm border border-slate-200 dark:border-slate-700">
                SKU Detected
              </span>
            </div>

            <div className="space-y-2">
              {capabilities.map((cap) => (
                <div
                  key={cap.id}
                  className="flex items-center justify-between p-2 border border-[#E2E8F0] dark:border-slate-700 rounded-sm bg-[#F8FAFC] dark:bg-slate-900/50"
                >
                  <div className="truncate pr-2">
                    <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">{cap.name}</div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">{cap.description}</div>
                  </div>
                  <div className="shrink-0">
                    <StatusPill
                      status={cap.licensed ? "pass" : "disabled"}
                      label={cap.licensed ? cap.tier : "Unlicensed"}
                      size="sm"
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* WIDGET 6: High-Risk Threat Indicators */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm p-4 flex flex-col justify-between shadow-xs lg:col-span-1">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2 mb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className="text-red-600 dark:text-red-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  6. High-Risk Threat Indicators
                </h3>
              </div>
              <button
                onClick={() => onOpenRemediation("all")}
                className="text-[11px] text-red-700 dark:text-red-400 hover:underline font-semibold"
              >
                Remediate All
              </button>
            </div>

            <div className="space-y-2.5">
              {/* External Forwarding Rules */}
              <div className="flex items-center justify-between p-2.5 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
                <div className="flex items-center gap-2">
                  <Share2 size={15} className="text-slate-600 dark:text-slate-400" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">External Forwarding Rules</div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">Inbox & Transport redirect vectors</div>
                  </div>
                </div>
                <StatusPill
                  status={externalForwardingCount > 0 ? "fail" : "pass"}
                  label={`${externalForwardingCount} Active`}
                />
              </div>

              {/* Exchange & Mailflow Security Score - rollup of MDO's baseline,
                  the Mail Flow Rules baseline, Domain Auth, and the mailbox
                  audit-logging gate into one trackable percentage. */}
              {exchangeMailflowScore.totalCount > 0 && (
                <div className="flex items-center justify-between p-2.5 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
                  <div className="flex items-center gap-2">
                    <Mail size={15} className="text-slate-600 dark:text-slate-400" />
                    <div>
                      <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">Exchange & Mailflow Security Score</div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400">
                        MDO, mail flow rules, domain auth & mailbox auditing combined
                      </div>
                    </div>
                  </div>
                  <StatusPill
                    status={exchangeMailflowScore.percent >= 75 ? "pass" : exchangeMailflowScore.percent >= 50 ? "warn" : "fail"}
                    label={`${exchangeMailflowScore.percent}% (${exchangeMailflowScore.metCount}/${exchangeMailflowScore.totalCount})`}
                  />
                </div>
              )}

              {/* Open SharePoint Links */}
              <div className="flex items-center justify-between p-2.5 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
                <div className="flex items-center gap-2">
                  <FileSpreadsheet size={15} className="text-slate-600 dark:text-slate-400" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">Open SharePoint Links</div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">Sites with &apos;Anyone&apos; anonymous links</div>
                  </div>
                </div>
                <StatusPill
                  status={openSharePointSitesCount > 0 ? "warn" : "pass"}
                  label={`${openSharePointSitesCount} Sites`}
                />
              </div>

              {/* Unprotected Global Admins */}
              <div className="flex items-center justify-between p-2.5 border border-[#E2E8F0] dark:border-slate-700 rounded-sm">
                <div className="flex items-center gap-2">
                  <Lock size={15} className="text-slate-600 dark:text-slate-400" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">Unprotected Global Admins</div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">Admins missing CA01 or FIDO2</div>
                  </div>
                </div>
                <StatusPill
                  status={highRiskThreatIndicators.unprotectedAdminsCount > 0 ? "fail" : "pass"}
                  label={`${highRiskThreatIndicators.unprotectedAdminsCount} High Risk`}
                />
              </div>
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-[#E2E8F0] dark:border-slate-700 text-[11px] text-slate-500 dark:text-slate-400 flex justify-between items-center">
            <span>Audit Standard: NIST / CIS M365 v3.0</span>
            <span className="font-mono font-bold text-slate-700 dark:text-slate-300">Real-Time Sync</span>
          </div>
        </div>
      </div>
    </div>
  );
};
