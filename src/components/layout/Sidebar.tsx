import React from "react";
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
} from "lucide-react";
import { TenantSecuritySnapshot } from "@/lib/types";

interface SidebarProps {
  activeView: string;
  onSelectView: (view: string) => void;
  snapshot: TenantSecuritySnapshot | null;
}

interface NavGroup {
  label: string;
  items: {
    id: string;
    label: string;
    icon: React.ElementType;
    badgeCount?: number;
    badgeStatus?: "warn" | "fail" | "info" | "pass";
  }[];
}

export const Sidebar: React.FC<SidebarProps> = ({ activeView, onSelectView, snapshot }) => {
  const missingCABaselineCount = snapshot
    ? snapshot.conditionalAccess.baselineDefinitions.length -
      new Set(snapshot.conditionalAccess.policies.map((p) => p.baselineCode).filter(Boolean)).size
    : 0;

  const riskySignInsCount = snapshot
    ? snapshot.signIns.filter((s) => s.isRisky || s.status === "ca_blocked" || s.status === "failed").length
    : 0;

  const weakMfaCount = snapshot ? snapshot.mfaAudit.filter((m) => m.isWeakAuth || !m.mfaRegistered).length : 0;

  const orphanedUsersCount = snapshot ? snapshot.accountClassification.unlicensedActiveCount : 0;

  const externalForwardingCount = snapshot ? snapshot.highRiskThreatIndicators.externalForwardingCount : 0;

  const groupsCount = snapshot ? snapshot.groups.length : 0;

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
        {
          id: "mdo_tabl",
          label: "MDO Policies & TABL",
          icon: Layers,
        },
      ],
    },
    {
      label: "Exchange & Mailflow",
      items: [
        {
          id: "mailboxes",
          label: "Mailbox Delegations",
          icon: Mail,
        },
        {
          id: "forwarding",
          label: "Email Forwarding Audit",
          icon: Share2,
          badgeCount: externalForwardingCount > 0 ? externalForwardingCount : undefined,
          badgeStatus: "fail",
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
      ],
    },
  ];

  return (
    <aside className="w-64 border-r border-[#CBD5E1] bg-[#F8FAFC] flex flex-col h-[calc(100vh-3rem)] select-none shrink-0 overflow-y-auto">
      <div className="p-3 space-y-4">
        {navGroups.map((group, gIdx) => (
          <div key={gIdx} className="space-y-1">
            <div className="px-2 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
              {group.label}
            </div>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeView === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectView(item.id)}
                    className={`w-full text-left px-2.5 py-1.5 text-xs flex items-center justify-between rounded-sm transition-colors ${
                      isActive
                        ? "bg-white border border-[#CBD5E1] font-semibold text-slate-900 shadow-sm"
                        : "text-slate-600 hover:text-slate-900 hover:bg-slate-200/60"
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <Icon size={14} className={isActive ? "text-slate-900" : "text-slate-500"} />
                      <span className="truncate">{item.label}</span>
                    </div>

                    {item.badgeCount !== undefined && (
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-sm border tabular-nums ${
                          item.badgeStatus === "fail"
                            ? "bg-red-50 text-red-700 border-red-200"
                            : item.badgeStatus === "warn"
                            ? "bg-amber-50 text-amber-800 border-amber-200"
                            : item.badgeStatus === "pass"
                            ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                            : "bg-slate-100 text-slate-700 border-slate-200"
                        }`}
                      >
                        {item.badgeCount}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
};
