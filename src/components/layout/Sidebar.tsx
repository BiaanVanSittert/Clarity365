import React, { useState, useEffect } from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  Key,
  ShieldCheck,
  Users,
  Mail,
  Share2,
  HardDrive,
  Cpu,
  Layers,
  FileSpreadsheet,
  AlertTriangle,
  Server,
  Lock,
  BellOff,
  BellRing,
  CheckCheck,
  RotateCcw,
  History,
  ChevronsLeft,
  ChevronsRight,
  GitBranch,
  Fingerprint,
} from "lucide-react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { evaluateMdoBaseline } from "@/lib/services/mdo-baseline-matcher";
import { evaluateMailflowBaseline } from "@/lib/services/mailflow-baseline-matcher";

interface SidebarProps {
  activeView: string;
  onSelectView: (view: string) => void;
  snapshot: TenantSecuritySnapshot | null;
  dismissedAlerts?: Record<string, boolean>;
  onClearAllAlerts?: () => void;
  onRestoreAlerts?: () => void;
  onDismissModuleAlert?: (moduleId: string) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

interface NavGroup {
  label: string;
  items: {
    id: string;
    label: string;
    icon: React.ElementType;
    badgeCount?: number;
    badgeStatus?: "warn" | "fail" | "info" | "pass";
    // Optional breakdown shown as the hover tooltip alongside the label —
    // useful when badgeCount sums signals of different kinds (e.g. MDO's
    // config-gap count plus its active-threat count) that read as one
    // ambiguous number otherwise.
    badgeDetail?: string;
  }[];
}

const STORAGE_KEY_PREFIX = "clarity365_alerts_cleared_";

export const Sidebar: React.FC<SidebarProps> = ({
  activeView,
  onSelectView,
  snapshot,
  dismissedAlerts: propDismissedAlerts,
  onClearAllAlerts: propOnClearAllAlerts,
  onRestoreAlerts: propOnRestoreAlerts,
  onDismissModuleAlert: propOnDismissModuleAlert,
  isCollapsed,
  onToggleCollapse,
}) => {
  const tenantId = snapshot?.tenant?.id || "global";

  // Local storage alert dismissal state
  const [localDismissed, setLocalDismissed] = useState<Record<string, boolean>>({});
  const [allCleared, setAllCleared] = useState<boolean>(false);

  const readDismissedState = () => {
    try {
      const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenantId}`);
      if (stored) {
        const parsed = JSON.parse(stored);
        setLocalDismissed(parsed.modules || {});
        setAllCleared(!!parsed.allCleared);
      } else {
        setLocalDismissed({});
        setAllCleared(false);
      }
    } catch {
      // Fallback
    }
  };

  useEffect(() => {
    readDismissedState();
    // Modules dispatch a synthetic "storage" event after they write an
    // alert-clearance change to localStorage (see e.g. ConditionalAccessModule's
    // handleClearAlerts) so the sidebar badge updates immediately instead of
    // only on the next tenant switch/reload.
    window.addEventListener("storage", readDismissedState);
    return () => window.removeEventListener("storage", readDismissedState);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  const saveDismissedState = (newAllCleared: boolean, newModules: Record<string, boolean>) => {
    setAllCleared(newAllCleared);
    setLocalDismissed(newModules);
    try {
      localStorage.setItem(
        `${STORAGE_KEY_PREFIX}${tenantId}`,
        JSON.stringify({ allCleared: newAllCleared, modules: newModules, updatedAt: new Date().toISOString() })
      );
    } catch {
      // Ignore
    }
  };

  const handleClearAll = (e: React.MouseEvent) => {
    e.stopPropagation();
    saveDismissedState(true, {
      ca_baseline: true,
      signin_logs: true,
      mfa_audit: true,
      user_class: true,
      mailboxes: true,
      forwarding: true,
      mailflow_rules: true,
      domain_auth: true,
      groups: true,
      mdo_tabl: true,
    });
    if (propOnClearAllAlerts) propOnClearAllAlerts();
  };

  const handleRestoreAll = (e: React.MouseEvent) => {
    e.stopPropagation();
    saveDismissedState(false, {});
    if (propOnRestoreAlerts) propOnRestoreAlerts();
  };

  const isModuleDismissed = (moduleId: string) => {
    if (propDismissedAlerts && propDismissedAlerts[moduleId] !== undefined) {
      return propDismissedAlerts[moduleId];
    }
    return allCleared || !!localDismissed[moduleId];
  };

  const missingCABaselineCount = snapshot
    ? snapshot.conditionalAccess.baselineDefinitions.length -
      new Set(snapshot.conditionalAccess.policies.map((p) => p.baselineCode).filter(Boolean)).size
    : 0;

  const riskySignInsCount = snapshot
    ? snapshot.signIns.filter((s) => s.isRisky || s.status === "ca_blocked" || s.status === "failed").length
    : 0;

  const weakMfaCount = snapshot ? snapshot.mfaAudit.filter((m) => m.isWeakAuth || !m.mfaRegistered).length : 0;

  const orphanedUsersCount = snapshot ? snapshot.accountClassification.unlicensedActiveCount : 0;

  // Derived live from emailForwarding rather than a separate stored counter —
  // the old highRiskThreatIndicators.externalForwardingCount was mock-only
  // and never updated by a live sync (see types/index.ts's removal comment).
  const externalForwardingCount = snapshot
    ? snapshot.emailForwarding.filter((r) => r.isExternal && r.state === "Enabled").length
    : 0;

  const mailboxAuditGapCount = snapshot && snapshot.mailboxAuditingEnabled === false ? 1 : 0;

  const mailflowRuleGapCount = snapshot
    ? evaluateMailflowBaseline({
        transportRules: snapshot.mailflowTransportRules,
        policies: snapshot.mdoThreat.policies,
        connectors: snapshot.mailflowConnectors,
        remoteDomainAutoForwardBlocked: snapshot.remoteDomainAutoForwardBlocked,
        externalSenderTagEnabled: snapshot.externalSenderTagEnabled,
      }).results.filter((r) => !r.met).length
    : 0;

  const domainAuthGapCount = snapshot
    ? snapshot.domainAuth.filter((d) => d.dkim.status !== "pass" || d.spf.status !== "pass" || d.dmarc.status !== "pass").length
    : 0;

  const groupsCount = snapshot ? snapshot.groups.length : 0;

  const mdoBaselineGapCount = snapshot
    ? evaluateMdoBaseline(snapshot.mdoThreat.policies).results.filter((r) => !r.met).length
    : 0;
  const mdoUnresolvedHighAlertCount = snapshot
    ? snapshot.mdoThreat.alerts.filter((a) => a.status !== "resolved" && a.severity === "high").length
    : 0;
  const mdoIssueCount = mdoBaselineGapCount + mdoUnresolvedHighAlertCount;

  const totalRawAlertCount =
    (missingCABaselineCount > 0 ? missingCABaselineCount : 0) +
    (riskySignInsCount > 0 ? riskySignInsCount : 0) +
    (weakMfaCount > 0 ? weakMfaCount : 0) +
    (orphanedUsersCount > 0 ? orphanedUsersCount : 0) +
    (externalForwardingCount > 0 ? externalForwardingCount : 0) +
    mailboxAuditGapCount +
    (mailflowRuleGapCount > 0 ? mailflowRuleGapCount : 0) +
    (domainAuthGapCount > 0 ? domainAuthGapCount : 0) +
    (mdoIssueCount > 0 ? mdoIssueCount : 0);

  const navGroups: NavGroup[] = [
    {
      label: "Overview",
      items: [
        {
          id: "overview",
          label: "Executive Dashboard",
          icon: LayoutDashboard,
        },
      ],
    },
    {
      label: "Identity & Access",
      items: [
        {
          id: "ca_baseline",
          label: "CA Policy Baseline (CA01-10)",
          icon: Lock,
          badgeCount: missingCABaselineCount > 0 ? missingCABaselineCount : undefined,
          badgeStatus: "warn",
        },
        {
          id: "signin_logs",
          label: "Sign-In Logs & CA Engine",
          icon: Key,
          badgeCount: riskySignInsCount > 0 ? riskySignInsCount : undefined,
          badgeStatus: "fail",
        },
        {
          id: "mfa_audit",
          label: "MFA & Auth Methods",
          icon: ShieldCheck,
          badgeCount: weakMfaCount > 0 ? weakMfaCount : undefined,
          badgeStatus: weakMfaCount > 0 ? "fail" : "pass",
        },
        {
          id: "user_class",
          label: "User Classification",
          icon: Users,
          badgeCount: orphanedUsersCount > 0 ? orphanedUsersCount : undefined,
          badgeStatus: "warn",
        },
      ],
    },
    {
      label: "Threat & Endpoint",
      items: [
        {
          id: "sec_score",
          label: "Defender Secure Score",
          icon: ShieldAlert,
        },
        {
          id: "intune",
          label: "Intune Security (AV & EDR)",
          icon: HardDrive,
        },
      ],
    },
    {
      // Everything in this group is sourced from the same Exchange Online
      // admin connection (MDO's device-code EXO connection, established for
      // Module 8, is reused by every check below it) — consolidated into one
      // group so a security admin has a single place to go for "everything
      // about my mail security" rather than it being split across groups.
      label: "Exchange & Mailflow",
      items: [
        {
          id: "mdo_tabl",
          label: "MDO Policies & TABL",
          icon: Layers,
          badgeCount: mdoIssueCount > 0 ? mdoIssueCount : undefined,
          badgeStatus: mdoUnresolvedHighAlertCount > 0 ? "fail" : "warn",
          badgeDetail:
            mdoIssueCount > 0
              ? `${mdoBaselineGapCount} baseline gap(s), ${mdoUnresolvedHighAlertCount} unresolved high-severity alert(s)`
              : undefined,
        },
        {
          id: "mailboxes",
          label: "Mailbox Delegations",
          icon: Mail,
          badgeCount: mailboxAuditGapCount > 0 ? mailboxAuditGapCount : undefined,
          badgeStatus: "warn",
          badgeDetail: mailboxAuditGapCount > 0 ? "Mailbox audit logging is off — delegation findings can't be investigated after the fact" : undefined,
        },
        {
          id: "forwarding",
          label: "Email Forwarding Audit",
          icon: Share2,
          badgeCount: externalForwardingCount > 0 ? externalForwardingCount : undefined,
          badgeStatus: "fail",
        },
        {
          id: "mailflow_rules",
          label: "Transport & Mail Flow Rules",
          icon: GitBranch,
          badgeCount: mailflowRuleGapCount > 0 ? mailflowRuleGapCount : undefined,
          badgeStatus: "warn",
        },
        {
          id: "domain_auth",
          label: "Domain Authentication (SPF/DKIM/DMARC)",
          icon: Fingerprint,
          badgeCount: domainAuthGapCount > 0 ? domainAuthGapCount : undefined,
          badgeStatus: "warn",
        },
      ],
    },
    {
      label: "Collaboration & Governance",
      items: [
        {
          id: "groups",
          label: "Groups & Distribution",
          icon: Users,
          badgeCount: groupsCount > 0 ? groupsCount : undefined,
          badgeStatus: "info",
        },
        {
          id: "sharepoint",
          label: "SharePoint & Storage",
          icon: FileSpreadsheet,
        },
      ],
    },
    {
      label: "System & Integration",
      items: [
        {
          id: "app_regs",
          label: "App Registrations & OAuth",
          icon: Server,
        },
        {
          id: "mcp",
          label: "MCP Tools & Playground",
          icon: Cpu,
        },
        {
          id: "audit_log",
          label: "Audit Log",
          icon: History,
        },
      ],
    },
  ];

  return (
    <aside
      className={`${
        isCollapsed ? "w-14" : "w-64"
      } border-r border-[#CBD5E1] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-800 flex flex-col h-[calc(100vh-3rem)] select-none shrink-0 overflow-y-auto overflow-x-hidden transition-[width] duration-150`}
    >
      {/* Alert Clearance Status Bar — hidden when collapsed; it's inherently
          text-heavy with no meaningful icon-only equivalent at rail width. */}
      {!isCollapsed && (
      <div className="px-3 pt-3 pb-1 border-b border-[#E2E8F0] dark:border-slate-700 bg-white/70 dark:bg-slate-900/40">
        <div className="flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-1.5 font-medium text-slate-700 dark:text-slate-300">
            {allCleared ? (
              <BellOff size={13} className="text-slate-400 dark:text-slate-500" />
            ) : totalRawAlertCount > 0 ? (
              <BellRing size={13} className="text-amber-600 dark:text-amber-400 animate-pulse" />
            ) : (
              <CheckCheck size={13} className="text-emerald-600 dark:text-emerald-400" />
            )}
            <span>{allCleared ? "Alerts Muted" : `${totalRawAlertCount} Active Alerts`}</span>
          </div>

          <div>
            {allCleared ? (
              <button
                onClick={handleRestoreAll}
                title="Restore sidebar alert badges"
                className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-slate-100 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded border border-slate-300 dark:border-slate-600 transition-colors"
              >
                <RotateCcw size={10} />
                <span>Restore</span>
              </button>
            ) : (
              <button
                onClick={handleClearAll}
                title="Clear and mute all sidebar alert number badges"
                className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-slate-100 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200/80 dark:hover:bg-slate-600 rounded border border-slate-300 dark:border-slate-600 transition-colors"
              >
                <CheckCheck size={11} className="text-slate-500 dark:text-slate-400" />
                <span>Clear Badges</span>
              </button>
            )}
          </div>
        </div>
      </div>
      )}

      <div className={isCollapsed ? "p-2 space-y-3" : "p-3 space-y-4"}>
        {navGroups.map((group, gIdx) => (
          <div key={gIdx} className="space-y-1">
            {isCollapsed ? (
              gIdx > 0 && <div className="mx-1 border-t border-[#E2E8F0] dark:border-slate-700" />
            ) : (
              <div className="px-2 text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">
                {group.label}
              </div>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeView === item.id;
                const isDismissed = isModuleDismissed(item.id);
                const hasBadge = item.badgeCount !== undefined && item.badgeCount > 0;

                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectView(item.id)}
                    title={item.badgeDetail ? `${item.label} — ${item.badgeDetail}` : isCollapsed ? item.label : undefined}
                    className={`w-full text-left px-2.5 py-1.5 text-xs flex items-center rounded-sm transition-colors ${
                      isCollapsed ? "justify-center" : "justify-between"
                    } ${
                      isActive
                        ? "bg-white dark:bg-slate-700 border border-[#CBD5E1] dark:border-slate-600 font-semibold text-slate-900 dark:text-slate-100 shadow-sm"
                        : "text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-200/60 dark:hover:bg-slate-700/60"
                    }`}
                  >
                    <div className={`flex items-center gap-2 truncate ${isCollapsed ? "relative" : ""}`}>
                      <Icon size={14} className={isActive ? "text-slate-900 dark:text-slate-100" : "text-slate-500 dark:text-slate-400"} />
                      {!isCollapsed && <span className="truncate">{item.label}</span>}
                      {isCollapsed && hasBadge && !isDismissed && (
                        <span
                          className={`absolute -top-1.5 -right-1.5 min-w-[13px] h-[13px] px-0.5 rounded-full text-[8px] font-mono font-bold flex items-center justify-center tabular-nums ${
                            item.badgeStatus === "fail"
                              ? "bg-red-600 dark:bg-red-500 text-white"
                              : item.badgeStatus === "warn"
                              ? "bg-amber-600 dark:bg-amber-500 text-white"
                              : item.badgeStatus === "pass"
                              ? "bg-emerald-600 dark:bg-emerald-500 text-white"
                              : "bg-slate-400 dark:bg-slate-500 text-white"
                          }`}
                        >
                          {item.badgeCount! > 99 ? "99+" : item.badgeCount}
                        </span>
                      )}
                    </div>

                    {!isCollapsed && hasBadge && (
                      isDismissed ? (
                        <span
                          title="Alert badge acknowledged/cleared"
                          className="text-[9px] font-mono text-slate-400 dark:text-slate-500 opacity-60"
                        >
                          ✓
                        </span>
                      ) : (
                        <span
                          className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-sm border tabular-nums ${
                            item.badgeStatus === "fail"
                              ? "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800"
                              : item.badgeStatus === "warn"
                              ? "bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-400 border-amber-200 dark:border-amber-800"
                              : item.badgeStatus === "pass"
                              ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800"
                              : "bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-600"
                          }`}
                        >
                          {item.badgeCount}
                        </span>
                      )
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <button
        onClick={onToggleCollapse}
        title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="mt-auto mx-2 mb-2 p-2 flex items-center justify-center text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-200/60 dark:hover:bg-slate-700/60 rounded-sm transition-colors border border-transparent hover:border-[#CBD5E1] dark:hover:border-slate-600"
      >
        {isCollapsed ? <ChevronsRight size={14} /> : <ChevronsLeft size={14} />}
      </button>
    </aside>
  );
};

