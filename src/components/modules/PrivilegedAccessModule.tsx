import React, { useMemo, useState } from "react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { EmptyStateRow } from "../common/EmptyStateRow";
import { SyncErrorBanner } from "../common/SyncErrorBanner";
import { getSyncErrorsForPrefixes } from "@/lib/utils/sync-errors";
import { getAllPrivilegedAccounts } from "@/lib/services/admin-hygiene-matcher";
import { Crown, ShieldCheck, ShieldX, AlertTriangle, Ban, Search, Download, Terminal } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import {
  classifyPrivilegedAccessTier,
  PRIVILEGED_ACCESS_TIER_LABEL,
  MFA_RISK_TIER_SEVERITY,
  PrivilegedAccessTier,
} from "@/lib/utils/privileged-access-risk-tier";

interface PrivilegedAccessModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

// Same visual language as MfaAuditModule.tsx's tier styling, so the two
// modules read as one consistent system. Critical gets a solid filled badge
// and a distinct icon (not just a darker red) so it is unmistakably worse
// than Red at a glance, in both light and dark mode.
const TIER_ICON: Record<PrivilegedAccessTier, React.ElementType> = {
  critical: ShieldX,
  red: AlertTriangle,
  green: ShieldCheck,
  disabled: Ban,
};

const TIER_CHIP_CLASSES: Record<PrivilegedAccessTier, { active: string; inactive: string; text: string }> = {
  critical: {
    active: "bg-rose-900 dark:bg-rose-950 border-rose-950 dark:border-rose-800 ring-1 ring-rose-900",
    inactive: "bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-900 hover:bg-rose-100/60",
    text: "text-rose-900 dark:text-rose-300",
  },
  red: {
    active: "bg-red-100 dark:bg-red-950/70 border-red-500 ring-1 ring-red-500",
    inactive: "bg-red-50 dark:bg-red-950/30 border-red-300 dark:border-red-800 hover:bg-red-100/60",
    text: "text-red-800 dark:text-red-400",
  },
  green: {
    active: "bg-emerald-100 dark:bg-emerald-950/70 border-emerald-500 ring-1 ring-emerald-500",
    inactive: "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-300 dark:border-emerald-800 hover:bg-emerald-100/60",
    text: "text-emerald-800 dark:text-emerald-400",
  },
  disabled: {
    active: "bg-slate-200 dark:bg-slate-800 border-slate-500 ring-1 ring-slate-400",
    inactive: "bg-slate-100 dark:bg-slate-800/60 border-slate-300 dark:border-slate-700 hover:bg-slate-200/60",
    text: "text-slate-600 dark:text-slate-400",
  },
};

const TIER_ROW_CLASSES: Record<PrivilegedAccessTier, string> = {
  critical: "bg-rose-50/70 dark:bg-rose-950/30 hover:bg-rose-100/70 dark:hover:bg-rose-900/40 border-l-4 border-l-rose-800",
  red: "bg-red-50/50 dark:bg-red-950/20 hover:bg-red-100/60 dark:hover:bg-red-900/30 border-l-4 border-l-red-500",
  green: "hover:bg-slate-50 dark:hover:bg-slate-800/60",
  disabled: "opacity-60 hover:bg-slate-50 dark:hover:bg-slate-800/40",
};

const TIER_BADGE_CLASSES: Record<PrivilegedAccessTier, string> = {
  critical: "bg-rose-900 dark:bg-rose-950 text-white border-rose-950 dark:border-rose-800 font-bold",
  red: "bg-red-50 dark:bg-red-950 text-red-800 dark:text-red-400 border-red-300 dark:border-red-800",
  green: "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800",
  disabled: "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-600",
};

const TIER_ORDER: PrivilegedAccessTier[] = ["critical", "red", "green", "disabled"];

export const PrivilegedAccessModule: React.FC<PrivilegedAccessModuleProps> = ({ snapshot, onOpenRemediation }) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [tierFilter, setTierFilter] = useState<PrivilegedAccessTier | "all">("all");
  const [includeDisabled, setIncludeDisabled] = useState(false);

  const privilegedAccessSyncErrors = getSyncErrorsForPrefixes(snapshot, ["Directory roles:", "Users:"]);
  const privilegedAccounts = getAllPrivilegedAccounts(snapshot);
  const isLeanFootprint = privilegedAccounts.length <= 5;

  const accountsWithTier = useMemo(
    () =>
      privilegedAccounts.map((account) => ({
        account,
        tier: classifyPrivilegedAccessTier({
          accountEnabled: account.accountEnabled,
          mfaRegistered: account.mfaRegistered,
          isLicensedForDailyUse: account.isLicensedForDailyUse,
        }),
      })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [privilegedAccounts]
  );

  // Respects the disabled toggle but not search or the tier filter itself,
  // so a chip's count always matches what clicking it would show.
  const toggleVisible = accountsWithTier.filter(({ tier }) => includeDisabled || tier !== "disabled");

  const tierCounts = TIER_ORDER.reduce((acc, tier) => {
    acc[tier] = toggleVisible.filter((a) => a.tier === tier).length;
    return acc;
  }, {} as Record<PrivilegedAccessTier, number>);

  const filteredAccounts = useMemo(() => {
    return toggleVisible
      .filter(({ account, tier }) => {
        const q = searchQuery.toLowerCase();
        const matchesSearch =
          !q || account.displayName.toLowerCase().includes(q) || account.userPrincipalName.toLowerCase().includes(q);
        const matchesTier = tierFilter === "all" || tier === tierFilter;
        return matchesSearch && matchesTier;
      })
      .sort((a, b) => MFA_RISK_TIER_SEVERITY[a.tier] - MFA_RISK_TIER_SEVERITY[b.tier]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toggleVisible, searchQuery, tierFilter]);

  const handleExportCSV = () => {
    const headers = [
      "DisplayName",
      "UserPrincipalName",
      "AdminRoles",
      "AccountEnabled",
      "LastSignIn",
      "MfaRegistered",
      "AuthStrength",
      "LicensedForDailyUse",
      "RiskTier",
    ];
    const rows = filteredAccounts.map(({ account: a, tier }) => [
      a.displayName,
      a.userPrincipalName,
      a.adminRoles.join(", "),
      a.accountEnabled ? "Yes" : "No",
      a.lastSignInDateTime,
      a.mfaRegistered ? "Yes" : "No",
      a.defaultMethod === "passkey_fido2" ? "Phishing-Resistant" : a.isUnprotected ? "Weak / Missing" : "Strong",
      a.isLicensedForDailyUse ? "Yes" : "No",
      PRIVILEGED_ACCESS_TIER_LABEL[tier].label,
    ]);
    exportToCsv(csvFilename("PrivilegedAccess", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Crown size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Privileged Access Review</h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Consolidated roster of every account holding an administrative directory role, colored by MFA status and daily-use
            license exposure. Role-assignable group membership and service-principal privilege are tracked separately (Groups
            Management, App Registrations) and are not yet correlated here.
          </p>
        </div>

        <button
          onClick={() => onOpenRemediation("unprotected_admins")}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <Terminal size={14} className="text-amber-400" />
          <span>Secure Unprotected Admins</span>
        </button>
      </div>

      <SyncErrorBanner errors={privilegedAccessSyncErrors} title="Directory roles sync error - data below may be stale" />

      {/* Tier legend and filter chips */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        {TIER_ORDER.filter((tier) => tier !== "disabled" || includeDisabled).map((tier) => {
          const Icon = TIER_ICON[tier];
          const isActive = tierFilter === tier;
          const classes = TIER_CHIP_CLASSES[tier];
          return (
            <div
              key={tier}
              onClick={() => setTierFilter(isActive ? "all" : tier)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setTierFilter(isActive ? "all" : tier))}
              title={PRIVILEGED_ACCESS_TIER_LABEL[tier].description}
              className={`p-2.5 border rounded-sm cursor-pointer transition-colors ${isActive ? classes.active : classes.inactive}`}
            >
              <div className={`flex items-center gap-1.5 text-[10px] uppercase font-mono font-semibold ${tier === "critical" && isActive ? "text-white" : classes.text}`}>
                <Icon size={13} />
                <span>{PRIVILEGED_ACCESS_TIER_LABEL[tier].label}</span>
              </div>
              <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${tier === "critical" && isActive ? "text-white" : classes.text}`}>
                {tierCounts[tier]}
              </div>
            </div>
          );
        })}

        <div className="p-2.5 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="flex items-center gap-1.5 text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold">
            <ShieldCheck size={13} />
            <span>Least-Privilege Benchmark</span>
          </div>
          <div className="mt-1">
            <StatusPill status={isLeanFootprint ? "pass" : "warn"} label={isLeanFootprint ? "Lean Footprint" : "Review for Sprawl"} size="sm" />
          </div>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search admins by name or UPN..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap w-full sm:w-auto justify-between sm:justify-end">
          <label className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeDisabled}
              onChange={(e) => {
                setIncludeDisabled(e.target.checked);
                if (!e.target.checked && tierFilter === "disabled") setTierFilter("all");
              }}
              className="accent-slate-700"
            />
            <span>Include disabled accounts</span>
          </label>

          <button
            onClick={handleExportCSV}
            title="Export filtered accounts to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Roster Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Privileged Account Roster</h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredAccounts.length} Accounts Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Account / UPN</th>
                <th>Directory Roles</th>
                <th>Auth Strength</th>
                <th>License Exposure</th>
                <th>Account Status</th>
                <th className="w-28">Last Sign-In</th>
                <th className="w-32 text-right">Risk Tier</th>
              </tr>
            </thead>
            <tbody>
              {filteredAccounts.length === 0 ? (
                <EmptyStateRow
                  colSpan={7}
                  entityLabel="privileged accounts"
                  isFiltered={searchQuery.trim().length > 0 || tierFilter !== "all"}
                />
              ) : (
                filteredAccounts.map(({ account: a, tier }) => {
                  const TierIcon = TIER_ICON[tier];
                  return (
                    <tr key={a.userId} className={`transition-colors ${TIER_ROW_CLASSES[tier]}`}>
                      <td>
                        <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">{a.displayName}</div>
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{a.userPrincipalName}</div>
                      </td>
                      <td className="text-[11px] text-slate-700 dark:text-slate-300 max-w-xs">
                        {a.adminRoles.length === 0 ? (
                          <span className="text-slate-400 dark:text-slate-500 italic">Directory Admin</span>
                        ) : (
                          a.adminRoles.join(", ")
                        )}
                      </td>
                      <td>
                        {a.defaultMethod === "passkey_fido2" ? (
                          <StatusPill status="pass" label="Phishing-Resistant" size="sm" />
                        ) : a.isUnprotected ? (
                          <StatusPill status="fail" label="Weak / Missing MFA" size="sm" />
                        ) : (
                          <StatusPill status="pass" label="Strong" size="sm" />
                        )}
                      </td>
                      <td>
                        {a.isLicensedForDailyUse ? (
                          <StatusPill status="warn" label="Exchange/Teams License" size="sm" />
                        ) : (
                          <span className="text-[11px] text-emerald-700 dark:text-emerald-400 font-medium">No Daily-Use License</span>
                        )}
                      </td>
                      <td>
                        <span className={`text-xs font-medium ${a.accountEnabled ? "text-emerald-700 dark:text-emerald-400" : "text-slate-500 dark:text-slate-400"}`}>
                          {a.accountEnabled ? "Sign-In Allowed" : "Blocked"}
                        </span>
                      </td>
                      <td className="font-mono text-[11px] text-slate-600 dark:text-slate-400">
                        {a.lastSignInDateTime ? new Date(a.lastSignInDateTime).toLocaleDateString() : "N/A"}
                      </td>
                      <td className="text-right">
                        <span className={`inline-flex items-center gap-1 font-mono text-[10px] px-2 py-0.5 rounded-sm border ${TIER_BADGE_CLASSES[tier]}`}>
                          <TierIcon size={11} />
                          <span>{PRIVILEGED_ACCESS_TIER_LABEL[tier].label}</span>
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
