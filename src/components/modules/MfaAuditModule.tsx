import React, { useMemo, useState } from "react";
import { TenantSecuritySnapshot, UserMfaProfile, AuthMethodType } from "@/lib/types";
import { Search, Shield, ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, Ban, Sparkles, Download } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { EmptyStateRow } from "../common/EmptyStateRow";
import { SyncErrorBanner } from "../common/SyncErrorBanner";
import { getSyncErrorsForPrefixes } from "@/lib/utils/sync-errors";
import { resolveUserLastSignIn } from "@/lib/services/fleet-analyzer";
import {
  classifyMfaRiskTier,
  MFA_RISK_TIER_LABEL,
  MFA_RISK_TIER_SEVERITY,
  MfaRiskTier,
} from "@/lib/utils/mfa-risk-tier";

interface MfaAuditModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

const METHOD_LABELS: Record<AuthMethodType, { name: string; isWeak: boolean; isPhishingResistant: boolean }> = {
  passkey_fido2: { name: "Passkey (FIDO2) / Hardware Token", isWeak: false, isPhishingResistant: true },
  ms_authenticator_push: { name: "Microsoft Authenticator (Push)", isWeak: false, isPhishingResistant: false },
  ms_authenticator_totp: { name: "Microsoft Authenticator (TOTP)", isWeak: false, isPhishingResistant: false },
  sms: { name: "SMS / Text Message", isWeak: true, isPhishingResistant: false },
  voice_call: { name: "Voice Call", isWeak: true, isPhishingResistant: false },
  email_otp: { name: "Email OTP", isWeak: true, isPhishingResistant: false },
  app_password: { name: "App Password", isWeak: true, isPhishingResistant: false },
  none: { name: "None (MFA Not Registered)", isWeak: true, isPhishingResistant: false },
};

// Icon + Tailwind classes per tier. Kept here (not in the shared lib/utils
// classifier) since icons and styling are presentation concerns specific to
// this module, matching how other modules in this app keep their own badge
// styling inline. Critical gets a solid filled badge and a distinct icon
// (not just a darker tint of red) so it reads as unmistakably worse than
// plain red at a glance.
const TIER_ICON: Record<MfaRiskTier, React.ElementType> = {
  critical: ShieldX,
  red: AlertTriangle,
  orange: ShieldAlert,
  green: ShieldCheck,
  disabled: Ban,
};

const TIER_CHIP_CLASSES: Record<MfaRiskTier, { active: string; inactive: string; text: string }> = {
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
  orange: {
    active: "bg-orange-100 dark:bg-orange-950/70 border-orange-500 ring-1 ring-orange-500",
    inactive: "bg-orange-50 dark:bg-orange-950/30 border-orange-300 dark:border-orange-800 hover:bg-orange-100/60",
    text: "text-orange-800 dark:text-orange-400",
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

const TIER_ROW_CLASSES: Record<MfaRiskTier, string> = {
  critical: "bg-rose-50/70 dark:bg-rose-950/30 hover:bg-rose-100/70 dark:hover:bg-rose-900/40 border-l-4 border-l-rose-800",
  red: "bg-red-50/50 dark:bg-red-950/20 hover:bg-red-100/60 dark:hover:bg-red-900/30 border-l-4 border-l-red-500",
  orange: "bg-orange-50/50 dark:bg-orange-950/20 hover:bg-orange-100/60 dark:hover:bg-orange-900/30 border-l-4 border-l-orange-500",
  green: "hover:bg-slate-50 dark:hover:bg-slate-800/60",
  disabled: "opacity-60 hover:bg-slate-50 dark:hover:bg-slate-800/40",
};

const TIER_BADGE_CLASSES: Record<MfaRiskTier, string> = {
  critical: "bg-rose-900 dark:bg-rose-950 text-white border-rose-950 dark:border-rose-800 font-bold",
  red: "bg-red-50 dark:bg-red-950 text-red-800 dark:text-red-400 border-red-300 dark:border-red-800",
  orange: "bg-orange-50 dark:bg-orange-950 text-orange-800 dark:text-orange-400 border-orange-300 dark:border-orange-800",
  green: "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800",
  disabled: "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-600",
};

const TIER_ORDER: MfaRiskTier[] = ["critical", "red", "orange", "green", "disabled"];

export const MfaAuditModule: React.FC<MfaAuditModuleProps> = ({ snapshot, onOpenRemediation }) => {
  const { mfaAudit } = snapshot;
  const mfaSyncErrors = getSyncErrorsForPrefixes(snapshot, ["MFA registration details:", "Users:"]);
  const [searchQuery, setSearchQuery] = useState("");
  const [tierFilter, setTierFilter] = useState<MfaRiskTier | "all">("all");
  const [includeDisabled, setIncludeDisabled] = useState(false);
  const [privilegedOnly, setPrivilegedOnly] = useState(false);

  const accountMap = new Map(
    (snapshot.accountClassification?.users || []).map((u) => [u.userPrincipalName.toLowerCase(), u])
  );

  const isUserLicensed = (upn: string) => {
    const acct = accountMap.get(upn.toLowerCase());
    return Boolean(acct && (acct.classification === "licensed" || (acct.licenses && acct.licenses.length > 0)));
  };

  const getUserLicenses = (upn: string): string[] => {
    const acct = accountMap.get(upn.toLowerCase());
    return acct?.licenses || [];
  };

  const usersWithTier = useMemo(
    () =>
      mfaAudit.map((user) => ({
        user,
        tier: classifyMfaRiskTier({
          accountEnabled: user.accountEnabled,
          isAdmin: user.isAdmin,
          mfaRegistered: user.mfaRegistered,
          isLicensed: isUserLicensed(user.userPrincipalName),
        }),
      })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [mfaAudit]
  );

  // Respects the two toggles but not search or the tier filter itself - this
  // is the population the chip counts are drawn from, so a chip's number
  // always matches what clicking it would show.
  const togglesVisible = usersWithTier.filter(
    ({ user, tier }) => (includeDisabled || tier !== "disabled") && (!privilegedOnly || user.isAdmin)
  );

  const tierCounts = TIER_ORDER.reduce((acc, tier) => {
    acc[tier] = togglesVisible.filter((u) => u.tier === tier).length;
    return acc;
  }, {} as Record<MfaRiskTier, number>);

  const phishingResistantCount = togglesVisible.filter((u) => u.user.defaultMethod === "passkey_fido2").length;

  const filteredUsers = useMemo(() => {
    return togglesVisible
      .filter(({ user, tier }) => {
        const matchesSearch =
          user.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
          user.userPrincipalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
          user.department.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesTier = tierFilter === "all" || tier === tierFilter;
        return matchesSearch && matchesTier;
      })
      .sort((a, b) => MFA_RISK_TIER_SEVERITY[a.tier] - MFA_RISK_TIER_SEVERITY[b.tier]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [togglesVisible, searchQuery, tierFilter]);

  // Export to CSV
  const handleExportCSV = () => {
    const headers = [
      "DisplayName",
      "UserPrincipalName",
      "PrivilegeLevel",
      "IsLicensed",
      "AssignedLicenses",
      "LastSignInDate",
      "DaysInactive",
      "DefaultAuthMethod",
      "RegisteredMethods",
      "MfaEnforcedByPolicy",
      "RiskTier",
    ];

    const rows = filteredUsers.map(({ user, tier }) => {
      const methodMeta = METHOD_LABELS[user.defaultMethod];
      const isLicensed = isUserLicensed(user.userPrincipalName);
      const licenses = getUserLicenses(user.userPrincipalName);
      const { lastSignInDateTime, daysInactive } = resolveUserLastSignIn(user, snapshot);
      return [
        user.displayName,
        user.userPrincipalName,
        user.isAdmin ? user.adminRoles?.[0] || "Directory Admin" : user.department || "Standard User",
        isLicensed ? "Yes" : "No",
        licenses.join("; "),
        lastSignInDateTime ? new Date(lastSignInDateTime).toLocaleDateString() : "No record",
        `${daysInactive} days`,
        methodMeta.name,
        user.registeredMethods.map((m) => METHOD_LABELS[m]?.name || m).join("; "),
        user.mfaEnforcedByPolicy ? "Yes" : "No",
        MFA_RISK_TIER_LABEL[tier].label,
      ];
    });

    exportToCsv(csvFilename("MfaAudit", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 4: MFA Enforcement & Authentication Method Audit
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Five tier risk model: license and MFA status decide the color, a privileged account with no MFA is always Critical.
          </p>
        </div>

        <button
          onClick={() => onOpenRemediation("mfa_audit")}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <ShieldAlert size={14} className="text-amber-400" />
          <span>Enforce Strong MFA Policy</span>
        </button>
      </div>

      <SyncErrorBanner errors={mfaSyncErrors} title="MFA audit sync error - data below may be stale" />

      {/* Tier legend and filter chips */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
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
              title={MFA_RISK_TIER_LABEL[tier].description}
              className={`p-2.5 border rounded-sm cursor-pointer transition-colors ${isActive ? classes.active : classes.inactive}`}
            >
              <div className={`flex items-center gap-1.5 text-[10px] uppercase font-mono font-semibold ${tier === "critical" && isActive ? "text-white" : classes.text}`}>
                <Icon size={13} />
                <span>{MFA_RISK_TIER_LABEL[tier].label}</span>
              </div>
              <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${tier === "critical" && isActive ? "text-white" : classes.text}`}>
                {tierCounts[tier]}
              </div>
            </div>
          );
        })}
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-72">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search users by name, UPN, or department..."
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

          <label className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={privilegedOnly}
              onChange={(e) => setPrivilegedOnly(e.target.checked)}
              className="accent-slate-700"
            />
            <span className="flex items-center gap-1">
              <Shield size={12} />
              Privileged only
            </span>
          </label>

          <span className="flex items-center gap-1 text-[11px] font-mono text-slate-500 dark:text-slate-400" title="Accounts whose default method is a Passkey/FIDO2 security key">
            <Sparkles size={12} className="text-emerald-500" />
            {phishingResistantCount} phishing resistant
          </span>

          <button
            onClick={handleExportCSV}
            title="Export filtered users to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* User Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            User Authentication Method Audit & Policy Compliance
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredUsers.length} Accounts Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>User / Identity</th>
                <th>Privilege Level</th>
                <th>Last Sign-In</th>
                <th>Default Auth Method</th>
                <th>Registered Methods</th>
                <th>MFA Enforced by Policy</th>
                <th className="w-36 text-right">Risk Tier</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.length === 0 ? (
                <EmptyStateRow
                  colSpan={7}
                  entityLabel="users"
                  isFiltered={searchQuery.trim().length > 0 || tierFilter !== "all" || privilegedOnly}
                />
              ) : (
                filteredUsers.map(({ user, tier }) => {
                  const methodMeta = METHOD_LABELS[user.defaultMethod];
                  const TierIcon = TIER_ICON[tier];
                  const { lastSignInDateTime, daysInactive } = resolveUserLastSignIn(user, snapshot);

                  return (
                    <tr key={user.id} className={`transition-colors ${TIER_ROW_CLASSES[tier]}`}>
                      <td>
                        <div className="flex items-center gap-1.5">
                          <span className="font-semibold text-xs text-slate-900 dark:text-slate-100">{user.displayName}</span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{user.userPrincipalName}</div>
                      </td>
                      <td>
                        {user.isAdmin ? (
                          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-bold px-1.5 py-0.5 bg-red-100 dark:bg-red-950 text-red-900 dark:text-red-400 border border-red-300 dark:border-red-800 rounded-sm">
                            <Shield size={10} />
                            <span>{user.adminRoles?.[0] || "Directory Admin"}</span>
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-600 dark:text-slate-400 font-medium">{user.department || "Standard User"}</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap font-mono text-xs">
                        {lastSignInDateTime ? (
                          <div className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full ${daysInactive > 90 ? "bg-amber-500" : "bg-emerald-500"}`} />
                            <div>
                              <div className="text-slate-900 dark:text-slate-100 font-semibold text-[11px]">
                                {new Date(lastSignInDateTime).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
                              </div>
                              <div className="text-[10px] text-slate-400">{daysInactive === 0 ? "Today" : `${daysInactive} days ago`}</div>
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5 text-slate-400">
                            <span className="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-600" />
                            <span className="text-[11px]">{daysInactive > 0 ? `Created ${daysInactive}d ago (No logins)` : "No login records"}</span>
                          </div>
                        )}
                      </td>
                      <td>
                        <div className="text-xs font-medium text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                          {methodMeta.name}
                        </div>
                      </td>
                      <td className="font-mono text-[11px] text-slate-600 dark:text-slate-400">
                        {user.registeredMethods.length === 0 ? (
                          <span className="text-red-700 dark:text-red-400 italic">None</span>
                        ) : (
                          user.registeredMethods.map((m) => METHOD_LABELS[m]?.name || m).join(", ")
                        )}
                      </td>
                      <td>
                        <span
                          className={`inline-flex items-center gap-1 font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded-sm border ${
                            user.mfaEnforcedByPolicy
                              ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
                              : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-600"
                          }`}
                        >
                          {user.mfaEnforcedByPolicy ? "Policy Enforced" : "Not Enforced"}
                        </span>
                      </td>
                      <td className="text-right">
                        <span
                          className={`inline-flex items-center gap-1 font-mono text-[10px] px-2 py-0.5 rounded-sm border ${TIER_BADGE_CLASSES[tier]}`}
                        >
                          <TierIcon size={11} />
                          <span>{MFA_RISK_TIER_LABEL[tier].label}</span>
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
