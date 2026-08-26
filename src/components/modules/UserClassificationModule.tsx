import React, { useState } from "react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Users, AlertTriangle, ShieldCheck, UserX, Search, Filter, Terminal, CheckCircle2, Download } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { EmptyStateRow } from "../common/EmptyStateRow";

interface UserClassificationModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

export const UserClassificationModule: React.FC<UserClassificationModuleProps> = ({
  snapshot,
  onOpenRemediation,
}) => {
  const { accountClassification } = snapshot;
  const [activeTab, setActiveTab] = useState<"licensed" | "unlicensed_active" | "disabled" | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");

  const users = accountClassification.users;

  const filteredUsers = users.filter((u) => {
    const matchesSearch =
      u.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.userPrincipalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.department.toLowerCase().includes(searchQuery.toLowerCase());

    if (activeTab === "all") return matchesSearch;
    return matchesSearch && u.classification === activeTab;
  });

  const handleExportCSV = () => {
    const headers = ["DisplayName", "UserPrincipalName", "Classification", "Licenses", "AccountEnabled", "Department", "RiskFlag"];
    const rows = filteredUsers.map((user) => [
      user.displayName,
      user.userPrincipalName,
      user.classification,
      user.licenses.join(", "),
      user.accountEnabled ? "Yes" : "No",
      user.department,
      user.riskFlag || "",
    ]);
    exportToCsv(csvFilename("UserClassification", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Users size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 5: User & Account Lifecycle Classification
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Strict separation between Licensed Users, Unlicensed Active Accounts (Orphan Risk), and Disabled Accounts.
          </p>
        </div>

        <button
          onClick={() => onOpenRemediation("user_classification")}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <Terminal size={14} className="text-emerald-400" />
          <span>Remediate Orphaned Accounts</span>
        </button>
      </div>

      {/* 3 Count Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div
          onClick={() => setActiveTab("licensed")}
          className={`p-3.5 border rounded-sm cursor-pointer transition-colors ${
            activeTab === "licensed" ? "bg-slate-50 dark:bg-slate-800 border-slate-900 dark:border-slate-100 shadow-xs" : "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700"
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 font-semibold">1. Licensed Users</span>
            <ShieldCheck size={16} className="text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-1">
            {accountClassification.licensedUsersCount}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Assigned paid product licenses</div>
        </div>

        <div
          onClick={() => setActiveTab("unlicensed_active")}
          className={`p-3.5 border rounded-sm cursor-pointer transition-colors ${
            activeTab === "unlicensed_active" ? "bg-amber-50 dark:bg-amber-950 border-amber-500 dark:border-amber-800 shadow-xs" : "bg-[#FFFBEB] dark:bg-amber-950 border-[#F59E0B] dark:border-amber-800 hover:bg-amber-100/40 dark:hover:bg-amber-900"
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-[#92400E] dark:text-amber-400 font-semibold flex items-center gap-1">
              <AlertTriangle size={12} />
              <span>2. Unlicensed Active</span>
            </span>
            <span className="text-[10px] font-mono uppercase font-bold text-amber-800 dark:text-amber-400 bg-amber-200 dark:bg-amber-950 px-1 py-0.5 rounded-sm">
              ORPHAN RISK
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-[#92400E] dark:text-amber-400 tabular-nums mt-1">
            {accountClassification.unlicensedActiveCount}
          </div>
          <div className="text-[11px] text-[#92400E] dark:text-amber-400 mt-0.5">accountEnabled == true with 0 licenses</div>
        </div>

        <div
          onClick={() => setActiveTab("disabled")}
          className={`p-3.5 border rounded-sm cursor-pointer transition-colors ${
            activeTab === "disabled" ? "bg-slate-50 dark:bg-slate-800 border-slate-900 dark:border-slate-100 shadow-xs" : "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700"
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 font-semibold">3. Disabled Accounts</span>
            <UserX size={16} className="text-slate-400 dark:text-slate-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-1">
            {accountClassification.disabledAccountsCount}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Sign-in explicitly blocked</div>
        </div>
      </div>

      {/* Search & Tabs */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Filter accounts by name or UPN..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-1 border border-[#CBD5E1] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-900/50 p-0.5 rounded-sm">
          <button
            onClick={() => setActiveTab("all")}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
              activeTab === "all" ? "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 font-semibold text-slate-900 dark:text-slate-100 shadow-xs" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100"
            }`}
          >
            All Accounts ({users.length})
          </button>
          <button
            onClick={() => setActiveTab("licensed")}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
              activeTab === "licensed" ? "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 font-semibold text-slate-900 dark:text-slate-100 shadow-xs" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100"
            }`}
          >
            Licensed
          </button>
          <button
            onClick={() => setActiveTab("unlicensed_active")}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
              activeTab === "unlicensed_active" ? "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 font-semibold text-amber-800 dark:text-amber-400 shadow-xs" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100"
            }`}
          >
            Unlicensed Active
          </button>
          <button
            onClick={() => setActiveTab("disabled")}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${
              activeTab === "disabled" ? "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 font-semibold text-slate-900 dark:text-slate-100 shadow-xs" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100"
            }`}
          >
            Disabled
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

      {/* Directory Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Account Inventory & License Assignment Details
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredUsers.length} Users Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Account / User Principal Name</th>
                <th>Classification Tier</th>
                <th>Assigned Licenses</th>
                <th>Account Status</th>
                <th>Department</th>
                <th className="w-36 text-right">Risk Assessment</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.length === 0 ? (
                <EmptyStateRow colSpan={6} entityLabel="accounts" isFiltered={searchQuery.trim().length > 0 || activeTab !== "all"} />
              ) : (
                filteredUsers.map((user) => (
                  <tr key={user.id} className={user.classification === "unlicensed_active" ? "bg-amber-50/40 dark:bg-amber-950" : ""}>
                    <td>
                      <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">{user.displayName}</div>
                      <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{user.userPrincipalName}</div>
                    </td>
                    <td>
                      <StatusPill
                        status={
                          user.classification === "licensed"
                            ? "pass"
                            : user.classification === "unlicensed_active"
                            ? "warn"
                            : "info"
                        }
                        label={
                          user.classification === "licensed"
                            ? "Licensed User"
                            : user.classification === "unlicensed_active"
                            ? "Unlicensed Active"
                            : "Disabled"
                        }
                        size="sm"
                      />
                    </td>
                    <td className="font-mono text-[11px] text-slate-700 dark:text-slate-300">
                      {user.licenses.length === 0 ? (
                        <span className="text-slate-400 dark:text-slate-500 italic">None</span>
                      ) : (
                        user.licenses.join(", ")
                      )}
                    </td>
                    <td>
                      <span className={`text-xs font-medium ${user.accountEnabled ? "text-emerald-700 dark:text-emerald-400" : "text-slate-500 dark:text-slate-400"}`}>
                        {user.accountEnabled ? "Sign-In Allowed" : "Blocked"}
                      </span>
                    </td>
                    <td className="text-xs text-slate-600 dark:text-slate-400">{user.department}</td>
                    <td className="text-right">
                      {user.riskFlag ? (
                        <span className="text-[11px] font-semibold text-amber-800 dark:text-amber-400">
                          {user.riskFlag}
                        </span>
                      ) : (
                        <span className="text-[11px] text-emerald-700 dark:text-emerald-400 font-medium">Standard</span>
                      )}
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
