import React, { useState, useMemo } from "react";
import { FleetPostureSummary, FleetTenantPosture, TrafficStatus } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Skeleton } from "../common/SkeletonLoader";
import {
  Building2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Flame,
  DollarSign,
  Users,
  HardDrive,
  ExternalLink,
  Search,
  Filter,
  ArrowUpRight,
  TrendingUp,
  Download,
  AlertTriangle,
  Layers,
  Clock,
  ChevronRight,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";

interface FleetOverviewDashboardProps {
  summary: FleetPostureSummary | null;
  isLoading: boolean;
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
  onOpenUniversalSearch: () => void;
}

export const FleetOverviewDashboard: React.FC<FleetOverviewDashboardProps> = ({
  summary,
  isLoading,
  onSelectTenant,
  onOpenUniversalSearch,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [tierFilter, setTierFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [sortField, setSortField] = useState<"compositeRiskScore" | "secureScore" | "activeIncidentsCount" | "displayName">("compositeRiskScore");
  const [sortAsc, setSortAsc] = useState(false);

  const tenants = useMemo(() => summary?.tenants || [], [summary?.tenants]);

  const filteredTenants = useMemo(() => {
    return tenants
      .filter((t) => {
        const q = searchQuery.toLowerCase();
        if (q && !t.displayName.toLowerCase().includes(q) && !t.defaultDomainName.toLowerCase().includes(q)) {
          return false;
        }
        if (tierFilter !== "all" && t.tier !== tierFilter) return false;
        if (riskFilter !== "all" && t.riskLevel !== riskFilter) return false;
        if (statusFilter !== "all" && t.connectionStatus !== statusFilter) return false;
        return true;
      })
      .sort((a, b) => {
        let valA: any = a[sortField];
        let valB: any = b[sortField];
        if (sortField === "secureScore") {
          valA = a.secureScore.percentage;
          valB = b.secureScore.percentage;
        }
        if (typeof valA === "string") {
          return sortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
        }
        return sortAsc ? valA - valB : valB - valA;
      });
  }, [tenants, searchQuery, tierFilter, riskFilter, statusFilter, sortField, sortAsc]);

  const handleExportCsv = () => {
    if (!summary) return;
    const headers = [
      "Tenant Name",
      "Domain",
      "License Tier",
      "Connection Status",
      "Composite Risk Score (0-100)",
      "Risk Level",
      "Secure Score %",
      "Managed Users",
      "Managed Devices",
      "Active Incidents",
      "Critical/High Incidents",
      "Missing CA Baselines",
      "Weak MFA Users",
      "Est. Monthly Waste ($)",
    ];
    const rows = filteredTenants.map((t) => [
      t.displayName,
      t.defaultDomainName,
      t.tier,
      t.connectionStatus,
      t.compositeRiskScore,
      t.riskLevel.toUpperCase(),
      `${t.secureScore.percentage}%`,
      t.totalUsers,
      t.totalDevices,
      t.activeIncidentsCount,
      t.criticalHighIncidentsCount,
      t.missingCABaselinesCount,
      t.weakMfaCount,
      `$${t.monthlyEstimatedWasteUsd.toFixed(2)}`,
    ]);
    exportToCsv(`clarity365-fleet-posture-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
  };

  if (isLoading || !summary) {
    return (
      <div className="p-5 space-y-5 max-w-[1600px] mx-auto">
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

  const {
    totalTenants,
    healthyTenantsCount,
    totalManagedUsers,
    totalManagedDevices,
    averageSecureScore,
    totalActiveIncidents,
    totalCriticalHighIncidents,
    totalMonthlyEstimatedWasteUsd,
    topFailingBaselines,
    recentCrossTenantIncidents,
  } = summary;

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none">
      {/* Top Banner */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-sm">
              <Building2 size={18} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
                  MSP Global Fleet Command & Security Posture
                </h1>
                <span className="text-[10px] font-mono font-semibold uppercase px-1.5 py-0.5 bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 rounded-sm">
                  {totalTenants} Organizations Active
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Centralized cross-tenant posture intelligence, universal threat hunting, and automated compliance auditing.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onOpenUniversalSearch}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <Search size={13} className="text-slate-400 dark:text-slate-500" />
            <span>Universal Search</span>
            <kbd className="text-[10px] font-mono bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 px-1 rounded text-slate-500">
              Ctrl+Shift+F
            </kbd>
          </button>

          <button
            onClick={handleExportCsv}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <Download size={13} />
            <span>Export Fleet Posture (CSV)</span>
          </button>
        </div>
      </div>

      {/* KPI Overview Cards (Clickable Fast-Filters) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {/* Managed Seats */}
        <div
          onClick={onOpenUniversalSearch}
          className="bg-[#F8FAFC] dark:bg-slate-900/40 border border-[#CBD5E1] dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500 p-3 rounded-sm cursor-pointer transition-colors group shadow-xs"
          title="Search users across all organizations"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-semibold uppercase tracking-wider text-[10px]">Managed Identities</span>
            <Users size={14} className="text-slate-400 group-hover:text-slate-700 dark:group-hover:text-slate-200 transition-colors" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {totalManagedUsers.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 flex items-center justify-between">
            <span>Across {totalTenants} organizations</span>
            <Search size={11} className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-400" />
          </div>
        </div>

        {/* Managed Devices */}
        <div
          onClick={onOpenUniversalSearch}
          className="bg-[#F8FAFC] dark:bg-slate-900/40 border border-[#CBD5E1] dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500 p-3 rounded-sm cursor-pointer transition-colors group shadow-xs"
          title="Search devices across all organizations"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-semibold uppercase tracking-wider text-[10px]">Fleet Endpoints</span>
            <HardDrive size={14} className="text-slate-400 group-hover:text-slate-700 dark:group-hover:text-slate-200 transition-colors" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {totalManagedDevices.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 flex items-center justify-between">
            <span>Intune MDM & Defender</span>
            <Search size={11} className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-400" />
          </div>
        </div>

        {/* Fleet Secure Score */}
        <div className="bg-[#F8FAFC] dark:bg-slate-900/40 border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-semibold uppercase tracking-wider text-[10px]">Avg Secure Score</span>
            <ShieldCheck size={14} className="text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {averageSecureScore}%
            </span>
            <span className="text-[10px] text-slate-500 font-mono">avg benchmark</span>
          </div>
          <div className="w-full bg-slate-200 dark:bg-slate-700 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className={`h-full ${
                averageSecureScore >= 70
                  ? "bg-emerald-500"
                  : averageSecureScore >= 50
                  ? "bg-amber-500"
                  : "bg-rose-500"
              }`}
              style={{ width: `${Math.min(100, Math.max(0, averageSecureScore))}%` }}
            />
          </div>
        </div>

        {/* Active Threat Incidents */}
        <div
          onClick={() => onSelectTenant("fleet", "event_response")}
          className={`p-3 rounded-sm border cursor-pointer transition-all shadow-xs group ${
            totalCriticalHighIncidents > 0
              ? "bg-red-50 dark:bg-red-950/40 border-red-300 dark:border-red-800 hover:bg-red-100/60"
              : "bg-[#F8FAFC] dark:bg-slate-900/40 border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
          }`}
          title="Jump to Cross-Tenant Incidents Feed"
        >
          <div className="flex items-center justify-between text-xs">
            <span className={`font-semibold uppercase tracking-wider text-[10px] ${
              totalCriticalHighIncidents > 0 ? "text-red-900 dark:text-red-300" : "text-slate-500 dark:text-slate-400"
            }`}>
              Active Incidents
            </span>
            <Flame size={14} className={totalCriticalHighIncidents > 0 ? "text-red-600 dark:text-red-400 animate-pulse" : "text-slate-400"} />
          </div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className={`text-xl font-bold font-mono ${
              totalCriticalHighIncidents > 0 ? "text-red-950 dark:text-red-200" : "text-slate-900 dark:text-slate-100"
            }`}>
              {totalActiveIncidents}
            </span>
            {totalCriticalHighIncidents > 0 && (
              <span className="text-[10px] font-bold text-red-700 dark:text-red-300 font-mono">
                ({totalCriticalHighIncidents} Crit/High)
              </span>
            )}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 flex items-center justify-between">
            <span>Across all tenants</span>
            <ChevronRight size={12} className="opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* Monthly License Waste */}
        <div
          onClick={() => onSelectTenant("fleet", "fleet_licenses")}
          className="bg-[#F8FAFC] dark:bg-slate-900/40 border border-[#CBD5E1] dark:border-slate-700 hover:border-amber-400 hover:bg-amber-50/30 dark:hover:bg-amber-950/20 p-3 rounded-sm cursor-pointer transition-colors group shadow-xs"
          title="Jump to Global Fleet License & Cost Optimizer"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-semibold uppercase tracking-wider text-[10px]">Est. Monthly Waste</span>
            <DollarSign size={14} className="text-amber-500 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            ${totalMonthlyEstimatedWasteUsd.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 0 })}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 flex items-center justify-between">
            <span>${(totalMonthlyEstimatedWasteUsd * 12).toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 0 })}/yr recoverable</span>
            <ChevronRight size={12} className="opacity-0 group-hover:opacity-100 transition-opacity text-amber-500" />
          </div>
        </div>
      </div>

      {/* Main Tenant Posture Matrix Table */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm overflow-hidden">
        {/* Table Filters & Toolbar */}
        <div className="p-3 border-b border-[#CBD5E1] dark:border-slate-700 bg-white/70 dark:bg-slate-900/60 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <div className="relative flex-1">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Filter by organization name or domain..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1 text-xs bg-[#F8FAFC] dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-500 font-sans placeholder:text-slate-400"
              />
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Risk Filter */}
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="px-2 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical Risk (≥70)</option>
              <option value="high">High Risk (≥45)</option>
              <option value="medium">Medium Risk</option>
              <option value="low">Low Risk</option>
            </select>

            {/* Tier Filter */}
            <select
              value={tierFilter}
              onChange={(e) => setTierFilter(e.target.value)}
              className="px-2 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
            >
              <option value="all">All License Tiers</option>
              <option value="M365_E5">M365 E5</option>
              <option value="M365_E3">M365 E3</option>
              <option value="M365_BP">Business Premium</option>
            </select>

            {/* Sort By */}
            <select
              value={sortField}
              onChange={(e) => setSortField(e.target.value as any)}
              className="px-2 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200 font-medium"
            >
              <option value="compositeRiskScore">Sort: Highest Risk</option>
              <option value="secureScore">Sort: Secure Score</option>
              <option value="activeIncidentsCount">Sort: Most Incidents</option>
              <option value="displayName">Sort: Alphabetical</option>
            </select>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#CBD5E1] dark:border-slate-700 bg-slate-100/70 dark:bg-slate-800/80 text-[11px] font-mono text-slate-600 dark:text-slate-300 uppercase tracking-wider">
                <th className="py-2.5 px-3.5">Customer Organization</th>
                <th className="py-2.5 px-3">Sync Status</th>
                <th className="py-2.5 px-3">Composite Risk</th>
                <th className="py-2.5 px-3">Secure Score</th>
                <th className="py-2.5 px-3">Active Incidents</th>
                <th className="py-2.5 px-3">CA Baselines</th>
                <th className="py-2.5 px-3">Identities & Endpoints</th>
                <th className="py-2.5 px-3">Est. Waste</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700/60 bg-white dark:bg-slate-900/30 font-sans">
              {filteredTenants.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 dark:text-slate-400">
                    No customer organizations match the active filter criteria.
                  </td>
                </tr>
              ) : (
                filteredTenants.map((t) => (
                  <tr
                    key={t.tenantId}
                    onClick={() => onSelectTenant(t.tenantId)}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/60 cursor-pointer transition-colors group"
                  >
                    {/* Organization & Domain */}
                    <td className="py-3 px-3.5">
                      <div className="flex items-center gap-2">
                        {t.isDemo ? (
                          <span className="text-[9px] font-mono uppercase px-1 py-0.5 bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-600 rounded-sm font-semibold">
                            DEMO
                          </span>
                        ) : (
                          <span className="text-[9px] font-mono uppercase px-1 py-0.5 bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800 rounded-sm font-semibold">
                            LIVE
                          </span>
                        )}
                        <span className="font-bold text-slate-900 dark:text-slate-100 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                          {t.displayName}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">
                        {t.defaultDomainName} • {t.tier.replace("_", " ")}
                      </div>
                    </td>

                    {/* Sync Status */}
                    <td className="py-3 px-3">
                      <StatusPill
                        status={t.connectionStatus === "healthy" ? "pass" : t.connectionStatus === "degraded" ? "warn" : "fail"}
                        label={t.connectionStatus === "healthy" ? "Healthy" : t.connectionStatus === "degraded" ? "Degraded" : "Error"}
                        size="sm"
                      />
                    </td>

                    {/* Composite Risk Score */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded-sm border ${
                            t.riskLevel === "critical"
                              ? "bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-200 border-red-300 dark:border-red-800"
                              : t.riskLevel === "high"
                              ? "bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-200 border-amber-300 dark:border-amber-800"
                              : t.riskLevel === "medium"
                              ? "bg-orange-50 dark:bg-orange-950 text-orange-800 dark:text-orange-200 border-orange-200 dark:border-orange-800"
                              : "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-200 border-emerald-200 dark:border-emerald-800"
                          }`}
                        >
                          {t.compositeRiskScore} / 100
                        </span>
                        <span className="text-[10px] font-mono uppercase text-slate-400">
                          {t.riskLevel}
                        </span>
                      </div>
                    </td>

                    {/* Secure Score */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-slate-200 dark:bg-slate-700 h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              t.secureScore.percentage >= 70
                                ? "bg-emerald-500"
                                : t.secureScore.percentage >= 50
                                ? "bg-amber-500"
                                : "bg-rose-500"
                            }`}
                            style={{ width: `${Math.min(100, Math.max(0, t.secureScore.percentage))}%` }}
                          />
                        </div>
                        <span className="font-mono text-xs font-semibold text-slate-800 dark:text-slate-200">
                          {t.secureScore.percentage}%
                        </span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                        {t.secureScore.current}/{t.secureScore.max} pts
                      </div>
                    </td>

                    {/* Active Incidents */}
                    <td className="py-3 px-3">
                      {t.activeIncidentsCount > 0 ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectTenant(t.tenantId, "event_response");
                          }}
                          title="View active incidents for this tenant"
                          className="flex items-center gap-1.5 hover:opacity-80 transition-opacity"
                        >
                          <span
                            className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded-sm border ${
                              t.criticalHighIncidentsCount > 0
                                ? "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300 border-red-300 dark:border-red-800"
                                : "bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-800"
                            }`}
                          >
                            {t.activeIncidentsCount} Active
                          </span>
                          {t.criticalHighIncidentsCount > 0 && (
                            <span className="text-[10px] font-mono font-bold text-red-600 dark:text-red-400">
                              {t.criticalHighIncidentsCount} High
                            </span>
                          )}
                        </button>
                      ) : (
                        <span className="text-xs text-slate-400 font-mono">0 Incidents</span>
                      )}
                    </td>

                    {/* CA Baseline Coverage */}
                    <td className="py-3 px-3">
                      {t.missingCABaselinesCount > 0 ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectTenant(t.tenantId, "ca_baseline");
                          }}
                          title="View missing CA baseline policies"
                          className="text-xs font-mono text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950 hover:bg-amber-100 dark:hover:bg-amber-900 px-1.5 py-0.5 rounded-sm border border-amber-300 dark:border-amber-800 transition-colors"
                        >
                          {t.missingCABaselinesCount} missing
                        </button>
                      ) : (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectTenant(t.tenantId, "ca_baseline");
                          }}
                          title="View deployed baseline policies"
                          className="text-xs font-mono text-emerald-700 dark:text-emerald-400 flex items-center gap-1 hover:underline"
                        >
                          <CheckCircle2 size={12} />
                          <span>10/10 Baseline</span>
                        </button>
                      )}
                    </td>

                    {/* Identities & Endpoints */}
                    <td className="py-3 px-3 text-xs font-mono text-slate-700 dark:text-slate-300">
                      <div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectTenant(t.tenantId, "user_class");
                          }}
                          title="View user accounts"
                          className="hover:text-indigo-600 dark:hover:text-indigo-400 hover:underline"
                        >
                          {t.totalUsers} users
                        </button>{" "}
                        (
                        {t.weakMfaCount > 0 ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectTenant(t.tenantId, "mfa_audit");
                            }}
                            title="View weak MFA users"
                            className="text-amber-600 dark:text-amber-400 hover:underline font-semibold"
                          >
                            {t.weakMfaCount} weak MFA
                          </button>
                        ) : (
                          "100% MFA"
                        )}
                        )
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectTenant(t.tenantId, "intune");
                          }}
                          title="View managed Intune devices"
                          className="hover:text-indigo-600 dark:hover:text-indigo-400 hover:underline"
                        >
                          {t.totalDevices} devices
                        </button>{" "}
                        {t.nonCompliantDevices > 0 && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectTenant(t.tenantId, "intune");
                            }}
                            title="View non-compliant devices"
                            className="text-rose-600 dark:text-rose-400 hover:underline font-semibold"
                          >
                            ({t.nonCompliantDevices} non-compliant)
                          </button>
                        )}
                      </div>
                    </td>

                    {/* Monthly Cost Waste */}
                    <td className="py-3 px-3 text-xs font-mono text-slate-700 dark:text-slate-300">
                      {t.monthlyEstimatedWasteUsd > 0 ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectTenant(t.tenantId, "license_optimizer");
                          }}
                          title="View license waste breakdown"
                          className="text-amber-700 dark:text-amber-400 font-bold hover:underline"
                        >
                          ${t.monthlyEstimatedWasteUsd.toFixed(0)}/mo
                        </button>
                      ) : (
                        <span className="text-slate-400">$0</span>
                      )}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectTenant(t.tenantId);
                        }}
                        className="px-2.5 py-1 text-xs font-semibold text-slate-800 dark:text-slate-200 hover:text-white bg-slate-100 dark:bg-slate-800 hover:bg-slate-900 dark:hover:bg-slate-100 dark:hover:text-slate-900 rounded-sm border border-slate-300 dark:border-slate-700 transition-colors inline-flex items-center gap-1"
                      >
                        <span>Open</span>
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

      {/* Bottom Row: Top Failing Baselines Across Fleet + Cross-Tenant Incident Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Failing Baselines Across Fleet */}
        <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#CBD5E1] dark:border-slate-700">
            <div className="flex items-center gap-2">
              <ShieldAlert size={16} className="text-amber-500" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-100">
                Top Fleet Policy Gaps & Failing Baselines
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Ranked by affected tenants
            </span>
          </div>

          <div className="mt-3 space-y-2.5">
            {topFailingBaselines.slice(0, 5).map((b) => (
              <div
                key={b.code}
                onClick={() => {
                  const targetTenant = tenants.find((t) => b.failingTenantNames.includes(t.displayName));
                  const targetTenantId = targetTenant ? targetTenant.tenantId : tenants[0]?.tenantId;
                  if (targetTenantId) {
                    onSelectTenant(targetTenantId, "ca_baseline", b.code);
                  }
                }}
                className="p-2.5 bg-white dark:bg-slate-800/80 border border-[#CBD5E1] dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500 rounded-sm flex items-center justify-between gap-3 cursor-pointer transition-colors group"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-sm group-hover:bg-amber-100 dark:group-hover:bg-amber-950 transition-colors">
                      {b.code}
                    </span>
                    <span className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate group-hover:text-amber-700 dark:group-hover:text-amber-400 transition-colors">
                      {b.name}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 truncate">
                    Failing in: <strong>{b.failingTenantNames.join(", ")}</strong>
                  </div>
                </div>

                <div className="text-right shrink-0 flex items-center gap-1.5">
                  <span className="text-xs font-mono font-bold text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950 px-2 py-0.5 rounded-sm border border-amber-200 dark:border-amber-800">
                    {b.failingTenantsCount} / {b.totalTenantsCount} Tenants
                  </span>
                  <ChevronRight size={13} className="text-slate-400 group-hover:text-slate-900 dark:group-hover:text-slate-100 transition-colors" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Cross-Tenant Recent Incident Feed */}
        <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#CBD5E1] dark:border-slate-700">
            <div className="flex items-center gap-2">
              <Flame size={16} className="text-red-500" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-100">
                Cross-Tenant Active Incident Feed
              </h2>
            </div>
            <button
              onClick={() => onSelectTenant("fleet", "event_response")}
              className="text-[11px] font-mono text-indigo-600 dark:text-indigo-400 hover:underline flex items-center gap-0.5"
            >
              <span>View All Incidents</span>
              <ChevronRight size={11} />
            </button>
          </div>

          <div className="mt-3 space-y-2.5 max-h-[320px] overflow-y-auto pr-1">
            {recentCrossTenantIncidents.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-400">
                No active incidents reported across customer tenants.
              </div>
            ) : (
              recentCrossTenantIncidents.slice(0, 5).map((inc) => (
                <div
                  key={`${inc.tenantId}-${inc.id}`}
                  onClick={() => onSelectTenant(inc.tenantId, "event_response", inc.incidentId)}
                  className="p-2.5 bg-white dark:bg-slate-800/80 border border-[#CBD5E1] dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500 rounded-sm flex items-center justify-between gap-3 cursor-pointer transition-colors group"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.5 rounded-sm border ${
                          inc.severity === "critical"
                            ? "bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-200 border-red-300 dark:border-red-800"
                            : inc.severity === "high"
                            ? "bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-200 border-amber-300 dark:border-amber-800"
                            : "bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-600"
                        }`}
                      >
                        {inc.severity}
                      </span>
                      <span className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate group-hover:text-red-600 dark:group-hover:text-red-400 transition-colors">
                        [{inc.incidentId}] {inc.displayName}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-1 truncate">
                      Tenant: <strong>{inc.tenantName}</strong> • {inc.impactedUsers?.map((u) => u.displayName).join(", ") || "No impacted users"}
                    </div>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-[10px] font-mono text-slate-400 group-hover:text-slate-900 dark:group-hover:text-slate-100 inline-flex items-center gap-1 transition-colors">
                      <span>Triage</span>
                      <ChevronRight size={12} />
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
