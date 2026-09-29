"use client";

import React, { useMemo, useState } from "react";
import { Tenant } from "@/lib/types";
import {
  DATA_PROTECTION_RECOMMENDATIONS,
  REGULATION_LABELS,
  DATA_CATEGORY_LABELS,
  Regulation,
  DataCategory,
} from "@/lib/data/data-protection-recommendations";
import { getTierEligibility } from "@/lib/utils/data-protection-tier-gating";
import { ShieldEllipsis, Check, AlertTriangle, HelpCircle, Eye } from "lucide-react";

// Read-only cross-tenant visibility ONLY - no action of any kind lives on
// this screen. This is a hard rule, not a style choice: no button, export or
// generated document here may ever touch more than one tenant in a single
// action - see the "No cross-tenant actions, ever" rule in
// ai-context-vault/Optimization/DLP & Sensitivity Labels Plan.md and
// DLP Stage 5 - Fleet Rollout.md. Clicking a tenant navigates to that
// tenant's own (already single-tenant) Data Protection module; nothing here
// writes to, or generates anything for, any tenant.
interface FleetDataProtectionModuleProps {
  tenants: Tenant[];
  onSelectTenant: (tenantId: string, targetModule?: string) => void;
}

// Short column labels for the matrix - a display-only concern for this view,
// kept local rather than added to the shared catalog type so the
// already-reviewed catalog content in data-protection-recommendations.ts
// doesn't need touching for a fleet-matrix-only formatting need.
const SHORT_LABELS: Record<string, string> = {
  "popia-sa-id-and-health": "POPIA ID + Health",
  "hipaa-phi": "HIPAA PHI",
  "gdpr-uk-government-id-and-special-category": "GDPR ID + Special Cat.",
  "credentials-and-secrets-leak-prevention": "Credentials",
  "financial-banking-data": "Banking",
  "payment-card-data": "Payment Cards",
  "bulk-pii-exfiltration": "Bulk PII",
  "ip-contracts-source-code": "IP / Contracts",
  "popia-cross-border-transfer": "POPIA Cross-Border",
  "label-baseline-taxonomy": "Label Taxonomy",
  "label-highly-confidential-encryption": "Label Encryption",
  "label-auto-labeling-sensitive-categories": "Auto-Labeling",
  "label-container-labels": "Container Labels",
};

export const FleetDataProtectionModule: React.FC<FleetDataProtectionModuleProps> = ({
  tenants,
  onSelectTenant,
}) => {
  const [regulationFilter, setRegulationFilter] = useState<Regulation | "all">("all");
  const [categoryFilter, setCategoryFilter] = useState<DataCategory | "all">("all");

  const filteredRecommendations = useMemo(() => {
    return DATA_PROTECTION_RECOMMENDATIONS.filter((r) => {
      if (regulationFilter !== "all" && !r.regulations.includes(regulationFilter)) return false;
      if (categoryFilter !== "all" && !r.dataCategories.includes(categoryFilter)) return false;
      return true;
    });
  }, [regulationFilter, categoryFilter]);

  const sortedTenants = useMemo(
    () => [...tenants].sort((a, b) => (a.displayName || "").localeCompare(b.displayName || "")),
    [tenants]
  );

  const selectClass =
    "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-600 rounded-sm px-2.5 py-1.5 text-xs text-slate-700 dark:text-slate-200";

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldEllipsis size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Fleet Data Protection Visibility
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 max-w-2xl">
            Read-only. Shows which clients are licence-eligible for which DLP/label recommendation, so you can see
            gaps across the fleet at a glance. Nothing on this screen deploys, generates, or changes anything for any
            tenant - click a tenant to open its own Data Protection module and work with it there, one tenant at a
            time.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={regulationFilter}
            onChange={(e) => setRegulationFilter(e.target.value as Regulation | "all")}
            className={selectClass}
          >
            <option value="all">All regulations</option>
            {(Object.keys(REGULATION_LABELS) as Regulation[]).map((r) => (
              <option key={r} value={r}>
                {REGULATION_LABELS[r]}
              </option>
            ))}
          </select>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as DataCategory | "all")}
            className={selectClass}
          >
            <option value="all">All data types</option>
            {(Object.keys(DATA_CATEGORY_LABELS) as DataCategory[]).map((c) => (
              <option key={c} value={c}>
                {DATA_CATEGORY_LABELS[c]}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex items-center gap-4 text-[11px] text-slate-500 dark:text-slate-400 px-1">
        <span className="flex items-center gap-1">
          <Check size={12} className="text-emerald-600 dark:text-emerald-400" /> Tier eligible
        </span>
        <span className="flex items-center gap-1">
          <AlertTriangle size={12} className="text-amber-600 dark:text-amber-400" /> Needs E5
        </span>
        <span className="flex items-center gap-1">
          <HelpCircle size={12} className="text-slate-400" /> Tier entitlement not confirmed (see caveats)
        </span>
      </div>

      {/* Matrix - horizontally scrollable, sticky first column so the tenant
          name stays visible while scrolling through recommendation columns. */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm shadow-xs overflow-x-auto">
        <table className="min-w-full text-xs border-collapse">
          <thead>
            <tr className="border-b border-[#E2E8F0] dark:border-slate-700">
              <th className="sticky left-0 z-10 bg-[#F8FAFC] dark:bg-slate-900/50 text-left font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300 px-3 py-2.5 border-r border-[#E2E8F0] dark:border-slate-700 whitespace-nowrap">
                Tenant
              </th>
              {filteredRecommendations.map((r) => (
                <th
                  key={r.id}
                  title={r.title}
                  className="text-center font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300 px-2.5 py-2.5 whitespace-nowrap"
                >
                  {SHORT_LABELS[r.id] || r.title}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedTenants.map((tenant, idx) => (
              <tr
                key={tenant.id}
                className={`border-b border-[#E2E8F0] dark:border-slate-800 ${
                  idx % 2 === 1 ? "bg-[#F8FAFC]/50 dark:bg-slate-900/30" : ""
                }`}
              >
                <td className="sticky left-0 z-10 bg-inherit border-r border-[#E2E8F0] dark:border-slate-700">
                  <button
                    onClick={() => onSelectTenant(tenant.id, "data_protection")}
                    title={`Open ${tenant.displayName}'s Data Protection module`}
                    className="w-full text-left px-3 py-2 hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5 text-slate-700 dark:text-slate-300 font-medium"
                  >
                    <Eye size={11} className="text-slate-400 flex-shrink-0" />
                    <span className="truncate max-w-[180px]">{tenant.displayName}</span>
                    <span className="text-[10px] text-slate-400 font-normal whitespace-nowrap">({tenant.tier})</span>
                  </button>
                </td>
                {filteredRecommendations.map((r) => {
                  const eligibility = getTierEligibility(tenant.tier, r.minimumLicenseTier);
                  return (
                    <td key={r.id} className="text-center px-2.5 py-2">
                      {eligibility === "eligible" && (
                        <Check size={13} className="inline text-emerald-600 dark:text-emerald-400" />
                      )}
                      {eligibility === "requires_e5" && (
                        <AlertTriangle
                          size={13}
                          className="inline text-amber-600 dark:text-amber-400"
                          aria-label="Needs E5"
                        />
                      )}
                      {eligibility === "unknown" && (
                        <HelpCircle size={13} className="inline text-slate-400" aria-label="Not confirmed" />
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
            {sortedTenants.length === 0 && (
              <tr>
                <td colSpan={filteredRecommendations.length + 1} className="text-center text-slate-500 dark:text-slate-400 px-3 py-6">
                  No tenants yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="text-[11px] text-slate-500 dark:text-slate-400 px-1 leading-relaxed">
        Tier eligibility is estimated from each tenant's own licence tier label, not a live-verified Purview
        entitlement check - confirm real licensing before treating a tenant as ineligible or eligible on this basis
        alone. See <span className="font-mono">DLP Stage 5 - Fleet Rollout</span> in the vault for the full caveat.
      </div>
    </div>
  );
};
