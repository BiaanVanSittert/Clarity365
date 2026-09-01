import React, { useState, useMemo } from "react";
import { Tenant, TenantSecuritySnapshot, CAPolicyRule } from "@/lib/types";
import { CA_BASELINE_STANDARDS, CABaselinePolicyDefinition } from "@/lib/data/baseline-definitions";
import {
  Layers,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Download,
  Filter,
  Search,
  ShieldAlert,
  ShieldCheck,
  Check,
  X,
  ExternalLink,
  Info,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";
import { FleetBulkDeployModal } from "../modals/FleetBulkDeployModal";

interface FleetBaselineRolloutModuleProps {
  tenants: Tenant[];
  snapshots: TenantSecuritySnapshot[];
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
  onRefresh?: () => void;
}

export const FleetBaselineRolloutModule: React.FC<FleetBaselineRolloutModuleProps> = ({
  tenants,
  snapshots,
  onSelectTenant,
  onRefresh,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [tierFilter, setTierFilter] = useState("all");
  const [selectedBaselineCodes, setSelectedBaselineCodes] = useState<string[]>([]);
  const [selectedTenantIds, setSelectedTenantIds] = useState<string[]>(tenants.map((t) => t.id));
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);

  // Snapshot lookup by tenant id
  const snapshotMap = useMemo(() => {
    const map = new Map<string, TenantSecuritySnapshot>();
    for (const snap of snapshots) {
      map.set(snap.tenant.id, snap);
    }
    return map;
  }, [snapshots]);

  // Unique license tiers
  const uniqueTiers = useMemo(() => {
    return Array.from(new Set(tenants.map((t) => t.tier)));
  }, [tenants]);

  // Filtered tenants
  const filteredTenants = useMemo(() => {
    return tenants.filter((t) => {
      const q = searchQuery.toLowerCase();
      if (q && !t.displayName.toLowerCase().includes(q) && !t.defaultDomainName.toLowerCase().includes(q)) {
        return false;
      }
      if (tierFilter !== "all" && t.tier !== tierFilter) {
        return false;
      }
      return true;
    });
  }, [tenants, searchQuery, tierFilter]);

  // Evaluates a tenant's status for a given baseline
  const getTenantBaselineStatus = (
    tenantId: string,
    baseline: CABaselinePolicyDefinition
  ): {
    status: "enabled" | "reportOnly" | "missing" | "p2_missing";
    policyName?: string;
  } => {
    const snap = snapshotMap.get(tenantId);
    if (!snap) return { status: "missing" };

    const policies = snap.conditionalAccess?.policies || [];
    const hasP2 =
      snap.capabilities?.some((c) => c.licensed && (c.name.toLowerCase().includes("p2") || c.name.toLowerCase().includes("e5"))) ||
      snap.tenant.tier === "M365_E5" ||
      (snap.tenant.tier as string) === "Microsoft 365 E5";

    if (baseline.requiresEntraP2 && !hasP2) {
      // Check if policy is still somehow configured
      const deployed = policies.find(
        (p) => p.baselineCode?.toUpperCase() === baseline.code.toUpperCase() || p.name.includes(baseline.code)
      );
      if (deployed) {
        return {
          status: deployed.state === "enabled" ? "enabled" : deployed.state === "disabled" ? "missing" : "reportOnly",
          policyName: deployed.name,
        };
      }
      return { status: "p2_missing" };
    }

    const deployed = policies.find(
      (p) => p.baselineCode?.toUpperCase() === baseline.code.toUpperCase() || p.name.includes(baseline.code)
    );

    if (!deployed) return { status: "missing" };
    if (deployed.state === "enabled") return { status: "enabled", policyName: deployed.name };
    if (deployed.state === "disabled") return { status: "missing", policyName: deployed.name };
    return { status: "reportOnly", policyName: deployed.name };
  };

  // Rollout statistics
  const stats = useMemo(() => {
    let totalCells = 0;
    let enabledCells = 0;
    let reportOnlyCells = 0;
    let missingCells = 0;

    for (const t of tenants) {
      for (const b of CA_BASELINE_STANDARDS) {
        totalCells++;
        const res = getTenantBaselineStatus(t.id, b);
        if (res.status === "enabled") enabledCells++;
        else if (res.status === "reportOnly") reportOnlyCells++;
        else missingCells++;
      }
    }

    const fleetCoveragePercentage = totalCells > 0 ? Math.round(((enabledCells + reportOnlyCells) / totalCells) * 100) : 0;

    return {
      totalCells,
      enabledCells,
      reportOnlyCells,
      missingCells,
      fleetCoveragePercentage,
    };
  }, [tenants, snapshots, snapshotMap]);

  const toggleSelectAllBaselines = () => {
    if (selectedBaselineCodes.length === CA_BASELINE_STANDARDS.length) {
      setSelectedBaselineCodes([]);
    } else {
      setSelectedBaselineCodes(CA_BASELINE_STANDARDS.map((b) => b.code));
    }
  };

  const toggleSelectAllTenants = () => {
    if (selectedTenantIds.length === filteredTenants.length) {
      setSelectedTenantIds([]);
    } else {
      setSelectedTenantIds(filteredTenants.map((t) => t.id));
    }
  };

  const handleExportCsv = () => {
    const headers = [
      "Tenant Name",
      "Domain",
      "License Tier",
      ...CA_BASELINE_STANDARDS.map((b) => `${b.code}: ${b.name}`),
    ];
    const rows = tenants.map((t) => {
      const row = [t.displayName, t.defaultDomainName, t.tier];
      for (const b of CA_BASELINE_STANDARDS) {
        const res = getTenantBaselineStatus(t.id, b);
        row.push(
          res.status === "enabled"
            ? "ENABLED"
            : res.status === "reportOnly"
            ? "REPORT-ONLY"
            : res.status === "p2_missing"
            ? "P2-MISSING"
            : "MISSING"
        );
      }
      return row;
    });

    exportToCsv(`clarity365-fleet-baseline-rollout-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
  };

  const selectedTenantsObjects = tenants.filter((t) => selectedTenantIds.includes(t.id));

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none font-sans">
      {/* Top Banner */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-slate-900 dark:bg-slate-800 text-white rounded-sm border border-slate-700">
              <Layers size={18} className="text-amber-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
                  Fleet Baseline Rollout Engine (CA01–CA10)
                </h1>
                <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 bg-blue-100 dark:bg-blue-950 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800 rounded-sm">
                  {stats.fleetCoveragePercentage}% Fleet Alignment
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Multi-tenant configuration matrix and bulk baseline deployment engine across all customer tenants simultaneously in Report-Only mode.
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
            <span>Export Matrix (CSV)</span>
          </button>
          <button
            onClick={() => setIsDeployModalOpen(true)}
            disabled={selectedBaselineCodes.length === 0 || selectedTenantIds.length === 0}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Zap size={13} className="text-amber-400" />
            <span>Deploy Selected ({selectedBaselineCodes.length} Baselines × {selectedTenantIds.length} Tenants)</span>
          </button>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-3 bg-white dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-[10px] font-semibold uppercase tracking-wider">
            <span>Fleet Coverage</span>
            <CheckCircle2 size={14} className="text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {stats.fleetCoveragePercentage}%
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            {stats.enabledCells + stats.reportOnlyCells} of {stats.totalCells} total baseline instances
          </div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-[10px] font-semibold uppercase tracking-wider">
            <span>Enforced (On)</span>
            <ShieldCheck size={14} className="text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-700 dark:text-emerald-400 mt-1">
            {stats.enabledCells} Active
          </div>
          <div className="text-[11px] text-emerald-600 dark:text-emerald-400 mt-0.5">
            Strictly enforcing zero-trust access
          </div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-[10px] font-semibold uppercase tracking-wider">
            <span>Report-Only Mode</span>
            <Info size={14} className="text-amber-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-700 dark:text-amber-400 mt-1">
            {stats.reportOnlyCells} Staged
          </div>
          <div className="text-[11px] text-amber-700 dark:text-amber-400 mt-0.5">
            Evaluating logs without blocking users
          </div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-[10px] font-semibold uppercase tracking-wider">
            <span>Missing Policy Gaps</span>
            <AlertTriangle size={14} className="text-rose-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-700 dark:text-rose-400 mt-1">
            {stats.missingCells} Missing
          </div>
          <div className="text-[11px] text-rose-700 dark:text-rose-400 mt-0.5">
            Deployable in bulk via Fleet Rollout
          </div>
        </div>
      </div>

      {/* Matrix Controls & Filters */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search customer tenant or domain..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-500 font-sans placeholder:text-slate-400"
            />
          </div>

          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value)}
            className="px-2.5 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
          >
            <option value="all">All License Tiers</option>
            {uniqueTiers.map((t) => (
              <option key={t} value={t}>
                {t.replace("_", " ")}
              </option>
            ))}
          </select>
        </div>

        {/* Quick Bulk Selection Toggles */}
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <button
            type="button"
            onClick={toggleSelectAllBaselines}
            className="px-2.5 py-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-sm font-medium transition-colors"
          >
            {selectedBaselineCodes.length === CA_BASELINE_STANDARDS.length ? "Deselect All Baselines" : "Select All Baselines (CA01–CA10)"}
          </button>
          <button
            type="button"
            onClick={toggleSelectAllTenants}
            className="px-2.5 py-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-sm font-medium transition-colors"
          >
            {selectedTenantIds.length === filteredTenants.length ? "Deselect All Tenants" : "Select All Tenants"}
          </button>
        </div>
      </div>

      {/* Baseline Selector Chips */}
      <div className="p-3 bg-white dark:bg-slate-900/40 border border-[#CBD5E1] dark:border-slate-700 rounded-sm space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-300 font-bold uppercase tracking-wider text-[11px]">
          <span>Select Baselines to Roll Out ({selectedBaselineCodes.length} of {CA_BASELINE_STANDARDS.length} selected)</span>
          <span className="text-slate-400 font-normal lowercase">Click badge to toggle</span>
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          {CA_BASELINE_STANDARDS.map((b) => {
            const isSelected = selectedBaselineCodes.includes(b.code);
            return (
              <button
                key={b.code}
                type="button"
                onClick={() => {
                  if (isSelected) {
                    setSelectedBaselineCodes(selectedBaselineCodes.filter((c) => c !== b.code));
                  } else {
                    setSelectedBaselineCodes([...selectedBaselineCodes, b.code]);
                  }
                }}
                className={`px-2.5 py-1 rounded-sm text-xs font-mono font-bold transition-all border flex items-center gap-1.5 ${
                  isSelected
                    ? "bg-slate-900 text-white border-slate-900 dark:bg-emerald-600 dark:border-emerald-600 shadow-2xs"
                    : "bg-slate-50 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:bg-slate-100"
                }`}
              >
                <span>{b.code}</span>
                {b.requiresEntraP2 && (
                  <span className="text-[9px] px-1 py-0.2 bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 border border-indigo-200 rounded-sm font-sans">
                    P2
                  </span>
                )}
                {isSelected && <Check size={11} className="text-emerald-400" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Fleet Rollout Matrix Table */}
      <div className="bg-white dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#CBD5E1] dark:border-slate-700 bg-slate-100/70 dark:bg-slate-800/80 text-[11px] font-mono text-slate-600 dark:text-slate-300 uppercase tracking-wider">
                <th className="py-2.5 px-3 whitespace-nowrap w-10">
                  <input
                    type="checkbox"
                    checked={selectedTenantIds.length === filteredTenants.length && filteredTenants.length > 0}
                    onChange={toggleSelectAllTenants}
                    className="rounded border-slate-300 text-slate-900 focus:ring-slate-500"
                  />
                </th>
                <th className="py-2.5 px-3.5 whitespace-nowrap min-w-[200px]">Customer Tenant</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Tier</th>
                {CA_BASELINE_STANDARDS.map((b) => (
                  <th
                    key={b.code}
                    className="py-2.5 px-2 text-center whitespace-nowrap font-bold"
                    title={`${b.code}: ${b.name}`}
                  >
                    <div className="flex flex-col items-center">
                      <span>{b.code}</span>
                      {b.requiresEntraP2 && <span className="text-[8px] text-indigo-500 font-sans">P2</span>}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700/60 bg-white dark:bg-slate-900/30">
              {filteredTenants.length === 0 ? (
                <tr>
                  <td colSpan={13} className="py-8 text-center text-slate-500 dark:text-slate-400">
                    No customer organizations match the criteria.
                  </td>
                </tr>
              ) : (
                filteredTenants.map((tenant) => {
                  const isTenantSelected = selectedTenantIds.includes(tenant.id);

                  return (
                    <tr
                      key={tenant.id}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors group"
                    >
                      {/* Checkbox */}
                      <td className="py-3 px-3">
                        <input
                          type="checkbox"
                          checked={isTenantSelected}
                          onChange={() => {
                            if (isTenantSelected) {
                              setSelectedTenantIds(selectedTenantIds.filter((id) => id !== tenant.id));
                            } else {
                              setSelectedTenantIds([...selectedTenantIds, tenant.id]);
                            }
                          }}
                          className="rounded border-slate-300 text-slate-900 focus:ring-slate-500"
                        />
                      </td>

                      {/* Tenant Name */}
                      <td className="py-3 px-3.5">
                        <button
                          type="button"
                          onClick={() => onSelectTenant(tenant.id, "ca_baseline")}
                          className="font-bold text-slate-900 dark:text-slate-100 hover:underline text-left"
                        >
                          {tenant.displayName}
                        </button>
                        <div className="text-[11px] font-mono text-slate-400">{tenant.defaultDomainName}</div>
                      </td>

                      {/* Tier */}
                      <td className="py-3 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-400 whitespace-nowrap">
                        {tenant.tier.replace("_", " ")}
                      </td>

                      {/* Baselines CA01 through CA10 */}
                      {CA_BASELINE_STANDARDS.map((baseline) => {
                        const { status, policyName } = getTenantBaselineStatus(tenant.id, baseline);

                        return (
                          <td key={baseline.code} className="py-2.5 px-2 text-center whitespace-nowrap">
                            {status === "enabled" ? (
                              <span
                                title={`Enforced (On): ${policyName || baseline.name}`}
                                className="inline-flex items-center justify-center w-7 h-7 rounded-sm bg-emerald-50 dark:bg-emerald-950/70 border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 shadow-2xs"
                              >
                                <Check size={14} className="stroke-[3]" />
                              </span>
                            ) : status === "reportOnly" ? (
                              <span
                                title={`Report-Only: ${policyName || baseline.name}`}
                                className="inline-flex items-center justify-center w-7 h-7 rounded-sm bg-amber-50 dark:bg-amber-950/70 border border-amber-300 dark:border-amber-800 text-amber-700 dark:text-amber-400 shadow-2xs font-mono font-bold text-[10px]"
                              >
                                RO
                              </span>
                            ) : status === "p2_missing" ? (
                              <span
                                title={`Requires Entra ID Plan 2 License to implement ${baseline.code}`}
                                className="inline-flex items-center justify-center w-7 h-7 rounded-sm bg-slate-100 dark:bg-slate-800/60 border border-slate-300 dark:border-slate-700 text-slate-400 shadow-2xs font-mono text-[10px]"
                              >
                                P2
                              </span>
                            ) : (
                              <span
                                title={`Missing: ${baseline.name}`}
                                className="inline-flex items-center justify-center w-7 h-7 rounded-sm bg-rose-50 dark:bg-rose-950/70 border border-rose-300 dark:border-rose-800 text-rose-600 dark:text-rose-400 shadow-2xs"
                              >
                                <X size={14} className="stroke-[2.5]" />
                              </span>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bulk Deploy Confirmation Modal */}
      <FleetBulkDeployModal
        isOpen={isDeployModalOpen}
        onClose={() => setIsDeployModalOpen(false)}
        selectedBaselineCodes={selectedBaselineCodes}
        selectedTenants={selectedTenantsObjects}
        onDeployComplete={() => {
          if (onRefresh) onRefresh();
        }}
      />
    </div>
  );
};
