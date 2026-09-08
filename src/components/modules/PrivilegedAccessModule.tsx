import React, { useState } from "react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { EmptyStateRow } from "../common/EmptyStateRow";
import { getAllPrivilegedAccounts } from "@/lib/services/admin-hygiene-matcher";
import { Crown, ShieldAlert, Wallet, ShieldCheck, Search, Download, Terminal } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";

interface PrivilegedAccessModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

export const PrivilegedAccessModule: React.FC<PrivilegedAccessModuleProps> = ({ snapshot, onOpenRemediation }) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "unprotected" | "licensed">("all");

  const privilegedAccounts = getAllPrivilegedAccounts(snapshot);
  const unprotectedCount = privilegedAccounts.filter((a) => a.isUnprotected).length;
  const licensedForDailyUseCount = privilegedAccounts.filter((a) => a.isLicensedForDailyUse).length;
  const isLeanFootprint = privilegedAccounts.length <= 5;

  const filteredAccounts = privilegedAccounts.filter((a) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q || a.displayName.toLowerCase().includes(q) || a.userPrincipalName.toLowerCase().includes(q);
    if (!matchesSearch) return false;
    if (filterType === "unprotected") return a.isUnprotected;
    if (filterType === "licensed") return a.isLicensedForDailyUse;
    return true;
  });

  const handleExportCSV = () => {
    const headers = [
      "DisplayName",
      "UserPrincipalName",
      "AdminRoles",
      "AccountEnabled",
      "LastSignIn",
      "MfaRegistered",
      "AuthStrength",
      "IsUnprotected",
      "LicensedForDailyUse",
    ];
    const rows = filteredAccounts.map((a) => [
      a.displayName,
      a.userPrincipalName,
      a.adminRoles.join(", "),
      a.accountEnabled ? "Yes" : "No",
      a.lastSignInDateTime,
      a.mfaRegistered ? "Yes" : "No",
      a.defaultMethod === "passkey_fido2" ? "Phishing-Resistant" : a.isUnprotected ? "Weak / Missing" : "Strong",
      a.isUnprotected ? "Yes" : "No",
      a.isLicensedForDailyUse ? "Yes" : "No",
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
            Consolidated roster of every account holding an administrative directory role - roles, authentication strength, and license
            exposure in one view. Role-assignable group membership and service-principal privilege are tracked separately (Groups
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

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div
          onClick={() => setFilterType("all")}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setFilterType("all"))}
          className={`p-3 bg-white dark:bg-slate-800 border rounded-sm cursor-pointer transition-colors hover:bg-slate-50 dark:hover:bg-slate-700 ${
            filterType === "all" ? "border-slate-900 dark:border-slate-100 ring-1 ring-slate-900" : "border-[#CBD5E1] dark:border-slate-700"
          }`}
        >
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold">Total Privileged Accounts</div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">{privilegedAccounts.length}</div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Holding an admin directory role</div>
        </div>

        <div
          onClick={() => setFilterType("unprotected")}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setFilterType("unprotected"))}
          className={`p-3 bg-[#FEF2F2] dark:bg-red-950 border rounded-sm cursor-pointer transition-colors hover:bg-red-100/50 dark:hover:bg-red-900 ${
            filterType === "unprotected" ? "border-[#EF4444] dark:border-red-800 ring-1 ring-[#EF4444]" : "border-[#EF4444] dark:border-red-800"
          }`}
        >
          <div className="text-[10px] uppercase font-mono text-[#991B1B] dark:text-red-400 font-semibold flex items-center gap-1">
            <ShieldAlert size={11} />
            <span>Unprotected Admins</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#991B1B] dark:text-red-400 tabular-nums mt-0.5">{unprotectedCount}</div>
          <div className="text-[11px] text-[#991B1B] dark:text-red-400 mt-0.5">Weak or missing MFA</div>
        </div>

        <div
          onClick={() => setFilterType("licensed")}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setFilterType("licensed"))}
          className={`p-3 bg-[#FFFBEB] dark:bg-amber-950 border rounded-sm cursor-pointer transition-colors hover:bg-amber-100/40 dark:hover:bg-amber-900 ${
            filterType === "licensed" ? "border-[#F59E0B] dark:border-amber-800 ring-1 ring-[#F59E0B]" : "border-[#F59E0B] dark:border-amber-800"
          }`}
        >
          <div className="text-[10px] uppercase font-mono text-[#92400E] dark:text-amber-400 font-semibold flex items-center gap-1">
            <Wallet size={11} />
            <span>Licensed for Daily Use</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#92400E] dark:text-amber-400 tabular-nums mt-0.5">{licensedForDailyUseCount}</div>
          <div className="text-[11px] text-[#92400E] dark:text-amber-400 mt-0.5">Admin role + Exchange/Teams license</div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold flex items-center gap-1">
            <ShieldCheck size={11} />
            <span>Least-Privilege Benchmark</span>
          </div>
          <div className="mt-1">
            <StatusPill status={isLeanFootprint ? "pass" : "warn"} label={isLeanFootprint ? "Lean Footprint" : "Review for Sprawl"} size="sm" />
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Feeds Essential Eight control E8.PRIV.1 in the Compliance Matrix</div>
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

        <div className="flex items-center gap-1 border border-[#CBD5E1] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-900/50 p-0.5 rounded-sm">
          <button
            onClick={() => setFilterType("all")}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
              filterType === "all" ? "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 font-semibold text-slate-900 dark:text-slate-100 shadow-xs" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100"
            }`}
          >
            All ({privilegedAccounts.length})
          </button>
          <button
            onClick={() => setFilterType("unprotected")}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
              filterType === "unprotected" ? "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 font-semibold text-red-800 dark:text-red-400 shadow-xs" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100"
            }`}
          >
            Unprotected
          </button>
          <button
            onClick={() => setFilterType("licensed")}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
              filterType === "licensed" ? "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 font-semibold text-amber-800 dark:text-amber-400 shadow-xs" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100"
            }`}
          >
            Licensed for Daily Use
          </button>
        </div>

        <button
          onClick={handleExportCSV}
          title="Export filtered accounts to CSV"
          className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
        >
          <Download size={13} className="text-slate-500 dark:text-slate-400" />
          <span>Export CSV</span>
        </button>
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
                <th className="w-32 text-right">Last Sign-In</th>
              </tr>
            </thead>
            <tbody>
              {filteredAccounts.length === 0 ? (
                <EmptyStateRow colSpan={6} entityLabel="privileged accounts" isFiltered={searchQuery.trim().length > 0 || filterType !== "all"} />
              ) : (
                filteredAccounts.map((a) => (
                  <tr key={a.userId} className={a.isUnprotected ? "bg-red-50/20 dark:bg-red-950" : ""}>
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
                    <td className="text-right font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      {a.lastSignInDateTime ? new Date(a.lastSignInDateTime).toLocaleDateString() : "-"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
