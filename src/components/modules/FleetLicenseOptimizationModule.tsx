import React, { useState, useMemo } from "react";
import {
  FleetLicenseOptimizationSummary,
  FleetLicenseOptimizationItem,
} from "@/lib/types";
import {
  DollarSign,
  TrendingDown,
  Mail,
  Users,
  AlertTriangle,
  Download,
  Search,
  Filter,
  ChevronRight,
  ShieldAlert,
  ArrowRight,
  UserX,
  CreditCard,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";
import { Skeleton } from "../common/SkeletonLoader";

interface FleetLicenseOptimizationModuleProps {
  wasteSummary: FleetLicenseOptimizationSummary | null;
  isLoading: boolean;
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
}

export const FleetLicenseOptimizationModule: React.FC<FleetLicenseOptimizationModuleProps> = ({
  wasteSummary,
  isLoading,
  onSelectTenant,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [tenantFilter, setTenantFilter] = useState("all");

  const items = useMemo(() => wasteSummary?.items || [], [wasteSummary?.items]);

  const uniqueTenants = useMemo(() => {
    const map = new Map<string, string>();
    for (const it of items) {
      map.set(it.tenantId, it.tenantName);
    }
    return Array.from(map.entries()).map(([id, name]) => ({ id, name }));
  }, [items]);

  const allLicensedUsers = useMemo(
    () =>
      items.filter(
        (i) =>
          i.category === "active_licensed_user" ||
          i.category === "inactive_licensed_user" ||
          i.category === "disabled_licensed_user"
      ),
    [items]
  );

  const activeLicensedCount = items.filter((i) => i.category === "active_licensed_user").length;
  const inactiveUsersCount = items.filter((i) => i.category === "inactive_licensed_user").length;
  const sharedMbCount = items.filter((i) => i.category === "licensed_shared_mailbox").length;
  const disabledUsersCount = items.filter((i) => i.category === "disabled_licensed_user").length;
  const orphanedCount = items.filter((i) => i.category === "orphaned_account").length;

  const filteredItems = useMemo(() => {
    return items.filter((it) => {
      const q = searchQuery.toLowerCase();
      if (
        q &&
        !it.title.toLowerCase().includes(q) &&
        !it.impactedIdentity.toLowerCase().includes(q) &&
        !(it.displayName || "").toLowerCase().includes(q) &&
        !it.tenantName.toLowerCase().includes(q) &&
        !(it.department || "").toLowerCase().includes(q)
      ) {
        return false;
      }
      if (tenantFilter !== "all" && it.tenantId !== tenantFilter) return false;
      if (categoryFilter === "all") return true;
      if (categoryFilter === "all_licensed") {
        return (
          it.category === "active_licensed_user" ||
          it.category === "inactive_licensed_user" ||
          it.category === "disabled_licensed_user"
        );
      }
      if (categoryFilter === "waste_only") {
        return (
          it.category === "licensed_shared_mailbox" ||
          it.category === "inactive_licensed_user" ||
          it.category === "disabled_licensed_user"
        );
      }
      return it.category === categoryFilter;
    });
  }, [items, searchQuery, categoryFilter, tenantFilter]);

  const handleExportCsv = () => {
    if (!wasteSummary) return;
    const headers = [
      "Tenant Name",
      "Waste Category",
      "Display Name",
      "Impacted Identity",
      "Department",
      "Last Sign-In Date",
      "Days Inactive",
      "License SKU",
      "Est. Monthly Cost ($)",
      "Est. Annual Cost ($)",
      "Remediation Action",
    ];
    const rows = filteredItems.map((it) => [
      it.tenantName,
      it.category.replace(/_/g, " ").toUpperCase(),
      it.displayName || "N/A",
      it.impactedIdentity,
      it.department || "N/A",
      it.lastSignInDateTime ? new Date(it.lastSignInDateTime).toLocaleDateString() : "No record",
      it.daysInactive !== undefined ? `${it.daysInactive} days` : "N/A",
      it.licenseSku || "N/A",
      `$${it.estimatedMonthlyCostUsd.toFixed(2)}`,
      `$${(it.estimatedMonthlyCostUsd * 12).toFixed(2)}`,
      it.remediationAction,
    ]);
    exportToCsv(`clarity365-fleet-license-waste-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
  };

  if (isLoading || !wasteSummary) {
    return (
      <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
          <Skeleton variant="card" className="h-28" />
          <Skeleton variant="card" className="h-28" />
          <Skeleton variant="card" className="h-28" />
          <Skeleton variant="card" className="h-28" />
          <Skeleton variant="card" className="h-28" />
        </div>
        <Skeleton variant="card" className="h-96" />
      </div>
    );
  }

  const { totalMonthlyWasteUsd, totalAnnualWasteUsd, wasteByCategory } = wasteSummary;
  const totalWasteAnnual = totalAnnualWasteUsd || 0;
  const totalWasteMonthly = totalMonthlyWasteUsd || 0;
  const wasteInactive = wasteByCategory?.inactiveLicensedUsers || 0;
  const wasteSharedMb = wasteByCategory?.licensedSharedMailboxes || 0;
  const wasteDisabled = wasteByCategory?.disabledLicensedUsers || 0;

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none">
      {/* Top Banner */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-emerald-700 text-white rounded-sm">
              <DollarSign size={18} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
                  Fleet License & Cost Optimization Engine
                </h1>
                <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 rounded-sm">
                  ${totalWasteAnnual.toLocaleString(undefined, { minimumFractionDigits: 0 })}/yr Recoverable Waste
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Multi-tenant inventory of paid employee seats, dormant accounts (&gt;90d), direct licenses on shared mailboxes, and disabled accounts holding paid seats.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <Download size={13} />
            <span>Export Waste Audit (CSV)</span>
          </button>
        </div>
      </div>

      {/* KPI Cards (Clickable Category Filters) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {/* Total Recoverable Savings */}
        <div
          onClick={() => setCategoryFilter(categoryFilter === "waste_only" ? "all" : "waste_only")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            categoryFilter === "waste_only"
              ? "bg-emerald-100 dark:bg-emerald-950/70 border-emerald-500 ring-1 ring-emerald-500"
              : "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 hover:bg-emerald-100/60"
          }`}
          title="Click to view all wasted licenses (Shared MBs, Dormant, Disabled)"
        >
          <div className="flex items-center justify-between text-xs text-emerald-900 dark:text-emerald-300 font-semibold uppercase tracking-wider text-[10px]">
            <span>Annual Waste</span>
            <TrendingDown size={15} className="text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-950 dark:text-emerald-100 mt-1">
            ${totalWasteAnnual.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 0 })}
          </div>
          <div className="text-[11px] text-emerald-800 dark:text-emerald-300 mt-1">
            ${totalWasteMonthly.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 0 })} / month across fleet
          </div>
        </div>

        {/* All Licensed Seats */}
        <div
          onClick={() => setCategoryFilter(categoryFilter === "all_licensed" ? "all" : "all_licensed")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            categoryFilter === "all_licensed"
              ? "bg-slate-200 dark:bg-slate-800 border-slate-600 ring-1 ring-slate-400"
              : "bg-[#F8FAFC] dark:bg-slate-900/40 border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          }`}
          title="Click to view all paid licensed seats across customer tenants"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>All Licensed Seats</span>
            <CreditCard size={14} className="text-slate-500" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {allLicensedUsers.length} Seats
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
            {activeLicensedCount} active, {inactiveUsersCount} dormant
          </div>
        </div>

        {/* Inactive Licensed Users */}
        <div
          onClick={() => setCategoryFilter(categoryFilter === "inactive_licensed_user" ? "all" : "inactive_licensed_user")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            categoryFilter === "inactive_licensed_user"
              ? "bg-blue-100 dark:bg-blue-950/70 border-blue-500 ring-1 ring-blue-500"
              : "bg-[#F8FAFC] dark:bg-slate-900/40 border-[#CBD5E1] dark:border-slate-700 hover:bg-blue-50/50 hover:border-blue-400"
          }`}
          title="Click to view dormant users with no sign-in for >90 days"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>Dormant (&gt;90d)</span>
            <Users size={14} className="text-blue-500" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {inactiveUsersCount} Users
          </div>
          <div className="text-[11px] text-blue-700 dark:text-blue-400 font-mono mt-1">
            ${wasteInactive.toFixed(0)}/mo waste
          </div>
        </div>

        {/* Licensed Shared Mailboxes */}
        <div
          onClick={() => setCategoryFilter(categoryFilter === "licensed_shared_mailbox" ? "all" : "licensed_shared_mailbox")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            categoryFilter === "licensed_shared_mailbox"
              ? "bg-amber-100 dark:bg-amber-950/70 border-amber-500 ring-1 ring-amber-500"
              : "bg-[#F8FAFC] dark:bg-slate-900/40 border-[#CBD5E1] dark:border-slate-700 hover:bg-amber-50/50 hover:border-amber-400"
          }`}
          title="Click to view shared mailboxes paying for direct license"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>Shared MB Waste</span>
            <Mail size={14} className="text-amber-500" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {sharedMbCount} Mailboxes
          </div>
          <div className="text-[11px] text-amber-700 dark:text-amber-400 font-mono mt-1">
            ${wasteSharedMb.toFixed(0)}/mo waste
          </div>
        </div>

        {/* Disabled Accounts with License */}
        <div
          onClick={() => setCategoryFilter(categoryFilter === "disabled_licensed_user" ? "all" : "disabled_licensed_user")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            categoryFilter === "disabled_licensed_user"
              ? "bg-purple-100 dark:bg-purple-950/70 border-purple-500 ring-1 ring-purple-500"
              : "bg-[#F8FAFC] dark:bg-slate-900/40 border-[#CBD5E1] dark:border-slate-700 hover:bg-purple-50/50 hover:border-purple-400"
          }`}
          title="Click to view disabled accounts still consuming paid licenses"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>Disabled / Unused</span>
            <UserX size={14} className="text-purple-500" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {disabledUsersCount} Accounts
          </div>
          <div className="text-[11px] text-purple-700 dark:text-purple-400 font-mono mt-1">
            ${wasteDisabled.toFixed(0)}/mo waste
          </div>
        </div>
      </div>

      {/* Items Table */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm overflow-hidden">
        {/* Table Filters */}
        <div className="p-3 border-b border-[#CBD5E1] dark:border-slate-700 bg-white/70 dark:bg-slate-900/60 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <div className="relative flex-1">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by mailbox, user, department, or organization..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1 text-xs bg-[#F8FAFC] dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-500 font-sans placeholder:text-slate-400"
              />
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-2.5 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200 font-semibold"
            >
              <option value="all">All Items & Inventories ({items.length})</option>
              <option value="all_licensed">All Paid Licensed Seats ({allLicensedUsers.length})</option>
              <option value="waste_only">All Wasted Licenses (${totalWasteAnnual.toFixed(0)}/yr)</option>
              <option value="active_licensed_user">Active Licensed Users ({activeLicensedCount})</option>
              <option value="inactive_licensed_user">Dormant Licensed Accounts &gt;90d ({inactiveUsersCount})</option>
              <option value="licensed_shared_mailbox">Licensed Shared Mailboxes ({sharedMbCount})</option>
              <option value="disabled_licensed_user">Disabled Accounts with License ({disabledUsersCount})</option>
              <option value="orphaned_account">Orphaned Active Accounts ({orphanedCount})</option>
            </select>

            {/* Tenant Filter */}
            <select
              value={tenantFilter}
              onChange={(e) => setTenantFilter(e.target.value)}
              className="px-2 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
            >
              <option value="all">All Customer Tenants ({uniqueTenants.length})</option>
              {uniqueTenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#CBD5E1] dark:border-slate-700 bg-slate-100/70 dark:bg-slate-800/80 text-[11px] font-mono text-slate-600 dark:text-slate-300 uppercase tracking-wider">
                <th className="py-2.5 px-3.5 whitespace-nowrap">Customer Tenant</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Optimization Category</th>
                <th className="py-2.5 px-3">Identity & Account</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Last Interactive Sign-In</th>
                <th className="py-2.5 px-3 whitespace-nowrap">SKU & Monthly Cost</th>
                <th className="py-2.5 px-3">Remediation Guidance</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700/60 bg-white dark:bg-slate-900/30 font-sans">
              {filteredItems.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 dark:text-slate-400">
                    No license findings match the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredItems.map((it) => (
                  <tr
                    key={it.id}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors group"
                  >
                    {/* Tenant */}
                    <td className="py-3 px-3.5 font-bold text-slate-900 dark:text-slate-100 whitespace-nowrap">
                      {it.tenantName}
                    </td>

                    {/* Category Badge (Strictly whitespace-nowrap to prevent multiline wrapping) */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded-sm border whitespace-nowrap inline-flex items-center shrink-0 ${
                          it.category === "licensed_shared_mailbox"
                            ? "bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800"
                            : it.category === "inactive_licensed_user"
                            ? "bg-blue-50 dark:bg-blue-950 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-800"
                            : it.category === "disabled_licensed_user"
                            ? "bg-purple-50 dark:bg-purple-950 text-purple-800 dark:text-purple-300 border-purple-300 dark:border-purple-800"
                            : it.category === "active_licensed_user"
                            ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800"
                            : "bg-rose-50 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800"
                        }`}
                      >
                        {it.category.replace(/_/g, " ")}
                      </span>
                    </td>

                    {/* Impacted Identity */}
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-900 dark:text-slate-100 font-mono text-xs flex items-center gap-1.5">
                        <span>{it.displayName || it.impactedIdentity}</span>
                        {it.department && (
                          <span className="text-[10px] font-sans text-slate-400">({it.department})</span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                        {it.impactedIdentity}
                      </div>
                    </td>

                    {/* Last Interactive Sign-In */}
                    <td className="py-3 px-3 whitespace-nowrap font-mono text-xs">
                      {it.accountState === "shared_mailbox" ? (
                        <span className="text-slate-400 text-[11px]">N/A (Shared Mailbox)</span>
                      ) : it.lastSignInDateTime ? (
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`w-2 h-2 rounded-full ${
                              it.daysInactive && it.daysInactive > 90
                                ? "bg-amber-500"
                                : "bg-emerald-500"
                            }`}
                          />
                          <div>
                            <div className="text-slate-900 dark:text-slate-100 font-semibold text-[11px]">
                              {new Date(it.lastSignInDateTime).toLocaleDateString(undefined, {
                                month: "short",
                                day: "numeric",
                                year: "numeric",
                              })}
                            </div>
                            <div className="text-[10px] text-slate-400">
                              {it.daysInactive === 0 ? "Today" : `${it.daysInactive} days ago`}
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5 text-slate-400">
                          <span className="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-600" />
                          <span className="text-[11px]">
                            {it.daysInactive && it.daysInactive > 0
                              ? `Created ${it.daysInactive}d ago (No logins)`
                              : "No login records"}
                          </span>
                        </div>
                      )}
                    </td>

                    {/* SKU & Cost Waste */}
                    <td className="py-3 px-3 font-mono text-xs whitespace-nowrap">
                      {it.estimatedMonthlyCostUsd > 0 ? (
                        <div>
                          <span
                            className={`font-bold ${
                              it.category === "active_licensed_user"
                                ? "text-slate-700 dark:text-slate-300"
                                : "text-amber-700 dark:text-amber-400"
                            }`}
                          >
                            ${(it.estimatedMonthlyCostUsd || 0).toFixed(2)}/mo
                          </span>
                          <span className="text-[11px] text-slate-400 ml-1">
                            (${ ((it.estimatedMonthlyCostUsd || 0) * 12).toFixed(0) }/yr)
                          </span>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            Tier: {it.licenseSku}
                          </div>
                        </div>
                      ) : (
                        <span className="text-slate-400">Governance Risk ($0)</span>
                      )}
                    </td>

                    {/* Remediation Guidance */}
                    <td className="py-3 px-3 text-xs text-slate-600 dark:text-slate-300 max-w-md">
                      {it.remediationAction}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-3.5 text-right whitespace-nowrap">
                      <button
                        onClick={() => onSelectTenant(it.tenantId, "license_optimizer", it.impactedIdentity || it.id)}
                        className="px-2.5 py-1 text-xs font-semibold text-slate-800 dark:text-slate-200 hover:text-white bg-slate-100 dark:bg-slate-800 hover:bg-slate-900 dark:hover:bg-slate-100 dark:hover:text-slate-900 rounded-sm border border-slate-300 dark:border-slate-700 transition-colors inline-flex items-center gap-1"
                      >
                        <span>Triage</span>
                        <ChevronRight size={13} />
                      </button>
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
