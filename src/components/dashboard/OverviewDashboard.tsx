import React from "react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Skeleton } from "../common/SkeletonLoader";
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
} from "lucide-react";

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

  const { tenant, secureScore, conditionalAccess, signIns, accountClassification, mailboxes, intune, capabilities, highRiskThreatIndicators } = snapshot;

  const deployedCodes = new Set(conditionalAccess.policies.map((p) => p.baselineCode).filter(Boolean));
  const missingCABaselineCount = conditionalAccess.baselineDefinitions.length - deployedCodes.size;

  const sharedMailboxesCount = mailboxes.filter((m) => m.recipientType === "SharedMailbox").length;
  const licensedSharedMailboxWasteCount = mailboxes.filter((m) => m.recipientType === "SharedMailbox" && m.hasDirectLicense).length;

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Top Banner / Tenant Posture Bar */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-3.5 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              {tenant.displayName} Posture Overview
            </h2>
            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 bg-slate-200 text-slate-800 rounded-sm font-semibold">
              {tenant.tier.replace("_", " ")}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Primary Domain: <code className="font-mono text-slate-700">{tenant.defaultDomainName}</code> • Org ID: <code className="font-mono text-[11px] text-slate-600">{tenant.organizationId}</code>
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

      {/* TOP 6 PRIORITY WIDGETS GRID */}

      {/* ROW 1: Core Metrics (Widgets 1, 3, 5) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* WIDGET 1: Microsoft Defender Secure Score Card */}
        <div className="border border-[#CBD5E1] bg-white rounded-sm p-4 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck size={16} className="text-slate-800" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  1. Microsoft Secure Score
                </h3>
              </div>
              <button
                onClick={() => onNavigate("sec_score")}
                className="text-[11px] text-slate-500 hover:text-slate-900 font-medium flex items-center gap-0.5"
              >
                <span>Details</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="flex items-baseline justify-between">
              <div className="space-y-0.5">
                <div className="text-2xl font-bold font-mono text-slate-900 tabular-nums">
                  {secureScore.percentage.toFixed(1)}%
                </div>
                <div className="text-xs font-mono text-slate-500">
                  {secureScore.currentScore} / {secureScore.maxScore} Attainable Points
                </div>
              </div>

              <div className="text-right space-y-1">
                <div className="flex items-center gap-1 text-xs font-mono">
                  {secureScore.delta30Days >= 0 ? (
                    <span className="text-emerald-700 flex items-center gap-0.5 font-semibold">
                      <ArrowUpRight size={13} /> +{secureScore.delta30Days.toFixed(1)}% (30d)
                    </span>
                  ) : (
                    <span className="text-red-700 flex items-center gap-0.5 font-semibold">
                      <ArrowDownRight size={13} /> {secureScore.delta30Days.toFixed(1)}% (30d)
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-500">
                  Benchmark: <span className="font-mono font-medium">{secureScore.industryBenchmark}%</span>
                </div>
              </div>
            </div>

            {/* Progress bar */}
            <div className="w-full bg-[#E2E8F0] h-2 rounded-sm overflow-hidden mt-3">
              <div
                className={`h-full ${
                  secureScore.percentage >= 75
                    ? "bg-emerald-600"
                    : secureScore.percentage >= 50
                    ? "bg-amber-500"
                    : "bg-red-500"
                }`}
                style={{ width: `${Math.min(100, secureScore.percentage)}%` }}
              />
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-[#E2E8F0] flex items-center justify-between text-[11px]">
            <span className="text-slate-600">
              Unresolved actions: <strong>{secureScore.controls.filter((c) => c.status === "Unresolved").length}</strong>
            </span>
            <button
              onClick={() => onOpenRemediation("conditional_access")}
              className="text-slate-800 font-semibold hover:underline"
            >
              Remediate Top Impact &rarr;
            </button>
          </div>
        </div>

        {/* WIDGET 3: Identity & Asset Count Matrix */}
        <div className="border border-[#CBD5E1] bg-white rounded-sm p-4 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-3">
              <div className="flex items-center gap-2">
                <Users size={16} className="text-slate-800" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  3. Identity & Asset Matrix
                </h3>
              </div>
              <button
                onClick={() => onNavigate("user_class")}
                className="text-[11px] text-slate-500 hover:text-slate-900 font-medium flex items-center gap-0.5"
              >
                <span>Directory</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {/* Licensed Users */}
              <div className="p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-sm">
                <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold">Licensed Users</div>
                <div className="text-lg font-bold font-mono text-slate-900 tabular-nums mt-0.5">
                  {accountClassification.licensedUsersCount}
                </div>
                <div className="text-[10px] text-emerald-700 font-medium mt-0.5">Active SKU Assigned</div>
              </div>

              {/* Unlicensed Active Accounts */}
              <div className="p-2.5 bg-[#FFFBEB] border border-[#F59E0B] rounded-sm">
                <div className="text-[10px] uppercase font-mono text-[#92400E] font-semibold flex items-center gap-1">
                  <AlertTriangle size={11} />
                  <span>Unlicensed Active</span>
                </div>
                <div className="text-lg font-bold font-mono text-[#92400E] tabular-nums mt-0.5">
                  {accountClassification.unlicensedActiveCount}
                </div>
                <div className="text-[10px] text-[#92400E] font-medium mt-0.5">Orphaned Risk Flag</div>
              </div>

              {/* Shared Mailboxes */}
              <div className="p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-sm">
                <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold">Shared Mailboxes</div>
                <div className="text-lg font-bold font-mono text-slate-900 tabular-nums mt-0.5">
                  {sharedMailboxesCount}
                </div>
                <div className="text-[10px] text-slate-600 font-medium mt-0.5">
                  {licensedSharedMailboxWasteCount > 0 ? (
                    <span className="text-amber-700 font-semibold">{licensedSharedMailboxWasteCount} paid licenses</span>
                  ) : (
                    "0 license waste"
                  )}
                </div>
              </div>

              {/* Intune Managed Devices */}
              <div className="p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-sm">
                <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold">Intune Devices</div>
                <div className="text-lg font-bold font-mono text-slate-900 tabular-nums mt-0.5">
                  {intune.totalDevices}
                </div>
                <div className="text-[10px] font-mono text-slate-600 mt-0.5">
                  <span className="text-emerald-700 font-semibold">{intune.compliantDevices} Pass</span> •{" "}
                  <span className="text-red-700 font-semibold">{intune.nonCompliantDevices} Fail</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* WIDGET 5: Conditional Access Baseline Health (CA01–CA10) */}
        <div className="border border-[#CBD5E1] bg-white rounded-sm p-4 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-3">
              <div className="flex items-center gap-2">
                <Lock size={16} className="text-slate-800" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  5. CA Baseline Health
                </h3>
              </div>
              <button
                onClick={() => onNavigate("ca_baseline")}
                className="text-[11px] text-slate-500 hover:text-slate-900 font-medium flex items-center gap-0.5"
              >
                <span>All CA01-10</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold font-mono text-slate-900 tabular-nums">
                  {deployedCodes.size} / 10
                </div>
                <div className="text-xs text-slate-500">Baseline Standards Deployed</div>
              </div>

              <StatusPill
                status={missingCABaselineCount === 0 ? "pass" : missingCABaselineCount <= 3 ? "warn" : "fail"}
                label={missingCABaselineCount === 0 ? "100% Baseline Compliant" : `${missingCABaselineCount} Standards Missing`}
              />
            </div>

            {/* Grid of CA01 to CA10 pills */}
            <div className="grid grid-cols-5 gap-1.5 mt-3 pt-2 border-t border-[#E2E8F0]">
              {conditionalAccess.baselineDefinitions.map((std) => {
                const policy = conditionalAccess.policies.find((p) => p.baselineCode === std.code);
                const isPass = policy && policy.state === "enabled";
                const isReportOnly = policy && policy.state === "enabledForReportingButNotEnforced";
                return (
                  <div
                    key={std.code}
                    title={`${std.code}: ${std.name} (${policy ? policy.state : "Missing"})`}
                    className={`py-1 text-center font-mono text-[11px] font-bold border rounded-sm ${
                      isPass
                        ? "bg-[#ECFDF5] border-[#10B981] text-[#065F46]"
                        : isReportOnly
                        ? "bg-[#FFFBEB] border-[#F59E0B] text-[#92400E]"
                        : "bg-[#FEF2F2] border-[#EF4444] text-[#991B1B]"
                    }`}
                  >
                    {std.code}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-3 text-[11px] text-slate-500 flex justify-between items-center">
            <span>Standard: <code className="font-mono text-slate-700">CA01-CA10 Baseline</code></span>
            <span className="text-slate-400">Strict Prefix Matching</span>
          </div>
        </div>
      </div>

      {/* ROW 2: Threat & Activity (Widgets 2, 4, 6) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* WIDGET 2: Recent Critical Security & Sign-In Events (Streamer) */}
        <div className="border border-[#CBD5E1] bg-white rounded-sm p-4 flex flex-col justify-between shadow-xs lg:col-span-1">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-2">
              <div className="flex items-center gap-2">
                <Clock size={16} className="text-slate-800" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  2. Critical Sign-In Events
                </h3>
              </div>
              <button
                onClick={() => onNavigate("signin_logs")}
                className="text-[11px] text-slate-500 hover:text-slate-900 font-medium flex items-center gap-0.5"
              >
                <span>Live Logs</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="space-y-2 max-h-56 overflow-y-auto divide-y divide-slate-100">
              {signIns.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-400">No recent sign-in telemetry available.</div>
              ) : (
                signIns.slice(0, 4).map((event) => (
                  <div key={event.id} className="pt-2 first:pt-0 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-900 truncate max-w-[170px]">
                        {event.userDisplayName || event.userPrincipalName}
                      </span>
                      <StatusPill
                        status={
                          event.status === "success"
                            ? "pass"
                            : event.status === "ca_blocked" || event.status === "failed"
                            ? "fail"
                            : "warn"
                        }
                        label={
                          event.status === "ca_blocked"
                            ? "CA Blocked"
                            : event.status === "failed"
                            ? `Failed (${event.errorCode})`
                            : event.status === "report_only_failed"
                            ? "Report-Only Fail"
                            : "Passed"
                        }
                        size="sm"
                      />
                    </div>
                    <div className="text-[11px] font-mono text-slate-500 flex items-center justify-between">
                      <span>{event.location.city}, {event.location.country}</span>
                      <span>{event.clientApp}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-[#E2E8F0] flex items-center justify-between text-[11px]">
            <span className="text-slate-500 font-mono">Streamer Active</span>
            <button
              onClick={() => onNavigate("signin_logs")}
              className="text-slate-800 font-semibold hover:underline"
            >
              Analyze Risky Sign-ins &rarr;
            </button>
          </div>
        </div>

        {/* WIDGET 4: Tenant License & Capability Matrix */}
        <div className="border border-[#CBD5E1] bg-white rounded-sm p-4 flex flex-col justify-between shadow-xs lg:col-span-1">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-3">
              <div className="flex items-center gap-2">
                <Layers size={16} className="text-slate-800" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  4. License & Capability Matrix
                </h3>
              </div>
              <span className="text-[10px] font-mono uppercase bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded-sm border border-slate-200">
                SKU Detected
              </span>
            </div>

            <div className="space-y-2">
              {capabilities.map((cap) => (
                <div
                  key={cap.id}
                  className="flex items-center justify-between p-2 border border-[#E2E8F0] rounded-sm bg-[#F8FAFC]"
                >
                  <div className="truncate pr-2">
                    <div className="text-xs font-semibold text-slate-900 truncate">{cap.name}</div>
                    <div className="text-[11px] text-slate-500 truncate">{cap.description}</div>
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
        <div className="border border-[#CBD5E1] bg-white rounded-sm p-4 flex flex-col justify-between shadow-xs lg:col-span-1">
          <div>
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className="text-red-600" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  6. High-Risk Threat Indicators
                </h3>
              </div>
              <button
                onClick={() => onOpenRemediation("all")}
                className="text-[11px] text-red-700 hover:underline font-semibold"
              >
                Remediate All
              </button>
            </div>

            <div className="space-y-2.5">
              {/* External Forwarding Rules */}
              <div className="flex items-center justify-between p-2.5 border border-[#E2E8F0] rounded-sm">
                <div className="flex items-center gap-2">
                  <Share2 size={15} className="text-slate-600" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900">External Forwarding Rules</div>
                    <div className="text-[11px] text-slate-500">Inbox & Transport redirect vectors</div>
                  </div>
                </div>
                <StatusPill
                  status={highRiskThreatIndicators.externalForwardingCount > 0 ? "fail" : "pass"}
                  label={`${highRiskThreatIndicators.externalForwardingCount} Active`}
                />
              </div>

              {/* Open SharePoint Links */}
              <div className="flex items-center justify-between p-2.5 border border-[#E2E8F0] rounded-sm">
                <div className="flex items-center gap-2">
                  <FileSpreadsheet size={15} className="text-slate-600" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900">Open SharePoint Links</div>
                    <div className="text-[11px] text-slate-500">Sites with 'Anyone' anonymous links</div>
                  </div>
                </div>
                <StatusPill
                  status={highRiskThreatIndicators.openSharePointSitesCount > 0 ? "warn" : "pass"}
                  label={`${highRiskThreatIndicators.openSharePointSitesCount} Sites`}
                />
              </div>

              {/* Unprotected Global Admins */}
              <div className="flex items-center justify-between p-2.5 border border-[#E2E8F0] rounded-sm">
                <div className="flex items-center gap-2">
                  <Lock size={15} className="text-slate-600" />
                  <div>
                    <div className="text-xs font-semibold text-slate-900">Unprotected Global Admins</div>
                    <div className="text-[11px] text-slate-500">Admins missing CA01 or FIDO2</div>
                  </div>
                </div>
                <StatusPill
                  status={highRiskThreatIndicators.unprotectedAdminsCount > 0 ? "fail" : "pass"}
                  label={`${highRiskThreatIndicators.unprotectedAdminsCount} High Risk`}
                />
              </div>
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-[#E2E8F0] text-[11px] text-slate-500 flex justify-between items-center">
            <span>Audit Standard: NIST / CIS M365 v3.0</span>
            <span className="font-mono font-bold text-slate-700">Real-Time Sync</span>
          </div>
        </div>
      </div>
    </div>
  );
};
