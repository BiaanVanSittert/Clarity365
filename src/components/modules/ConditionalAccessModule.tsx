import React, { useState } from "react";
import { TenantSecuritySnapshot, CAPolicyRule, CABaselineItem } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { ShieldCheck, AlertTriangle, Lock, Plus, Terminal, CheckCircle2, XCircle, Search, Filter } from "lucide-react";

interface ConditionalAccessModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

export const ConditionalAccessModule: React.FC<ConditionalAccessModuleProps> = ({
  snapshot,
  onOpenRemediation,
}) => {
  const { conditionalAccess } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [filterState, setFilterState] = useState<string>("all");

  const deployedPolicies = conditionalAccess.policies;
  const baselineDefinitions = conditionalAccess.baselineDefinitions;

  // Analysis
  const baselineMap = new Map<string, CAPolicyRule>();
  deployedPolicies.forEach((p) => {
    if (p.baselineCode) {
      baselineMap.set(p.baselineCode, p);
    }
  });

  const missingBaselineCount = baselineDefinitions.filter((b) => !baselineMap.has(b.code)).length;
  const coveragePercent = Math.round(((baselineDefinitions.length - missingBaselineCount) / baselineDefinitions.length) * 100);

  const filteredBaseline = baselineDefinitions.filter((item) => {
    const matchesSearch =
      item.code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase());

    const policy = baselineMap.get(item.code);
    if (filterState === "all") return matchesSearch;
    if (filterState === "deployed") return matchesSearch && !!policy;
    if (filterState === "missing") return matchesSearch && !policy;
    if (filterState === "report_only") return matchesSearch && policy?.state === "enabledForReportingButNotEnforced";
    return matchesSearch;
  });

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header & Coverage Summary */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Lock size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 1: Conditional Access Policy Scanner & CA01-CA10 Baseline
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Strict prefix/name verification against the CIS / Microsoft Zero Trust standard baseline (CA01 through CA10).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-xs font-semibold text-slate-700">Baseline Compliance</div>
            <div className="text-lg font-bold font-mono text-slate-900 tabular-nums">
              {coveragePercent}% ({baselineDefinitions.length - missingBaselineCount}/{baselineDefinitions.length})
            </div>
          </div>

          <button
            onClick={() => onOpenRemediation("conditional_access")}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Terminal size={14} className="text-emerald-400" />
            <span>Deploy Missing Baseline</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search baseline standards or policies..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={filterState}
            onChange={(e) => setFilterState(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          >
            <option value="all">All Standards (CA01 - CA10)</option>
            <option value="deployed">Deployed Only</option>
            <option value="missing">Missing Baseline (Warnings)</option>
            <option value="report_only">Report-Only Mode</option>
          </select>
        </div>
      </div>

      {/* CA Baseline Audit Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Standard Baseline Specification & Deployed Policy Alignment
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            {filteredBaseline.length} Standards Shown
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-20">Code</th>
                <th className="w-72">Baseline Standard</th>
                <th>Target Scope & Conditions</th>
                <th>Risk Mitigated</th>
                <th className="w-40">Deployed Policy State</th>
                <th className="w-28 text-right">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredBaseline.map((baseline) => {
                const policy = baselineMap.get(baseline.code);
                const isDeployed = !!policy;
                const isEnabled = policy?.state === "enabled";
                const isReportOnly = policy?.state === "enabledForReportingButNotEnforced";

                return (
                  <tr key={baseline.code} className={!isDeployed ? "bg-amber-50/30" : ""}>
                    <td className="font-mono font-bold text-slate-900 text-xs">
                      {baseline.code}
                    </td>
                    <td>
                      <div className="font-semibold text-slate-900 text-xs">{baseline.name}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5">{baseline.description}</div>
                    </td>
                    <td className="text-[11px] text-slate-600 font-mono">
                      {baseline.targetScope}
                    </td>
                    <td className="text-[11px] text-slate-600">
                      {baseline.riskMitigated}
                    </td>
                    <td>
                      {isDeployed ? (
                        <div className="space-y-0.5">
                          <div className="text-[11px] font-mono text-slate-800 font-semibold truncate max-w-[180px]">
                            {policy.name}
                          </div>
                          <StatusPill
                            status={isEnabled ? "pass" : isReportOnly ? "warn" : "disabled"}
                            label={isEnabled ? "Enforced (Enabled)" : isReportOnly ? "Report-Only" : "Disabled"}
                            size="sm"
                          />
                        </div>
                      ) : (
                        <span className="text-[11px] text-amber-700 font-medium italic">
                          Not Deployed in Tenant
                        </span>
                      )}
                    </td>
                    <td className="text-right">
                      {isEnabled ? (
                        <StatusPill status="pass" label="Pass" size="sm" />
                      ) : isReportOnly ? (
                        <StatusPill status="warn" label="Advisory" size="sm" />
                      ) : (
                        <StatusPill status="warn" label="Missing" size="sm" />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Custom & Non-Baseline Policies Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Tenant Custom / Legacy Conditional Access Policies
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            {deployedPolicies.filter((p) => !p.baselineCode).length} Custom Policies
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Policy Display Name</th>
                <th>Enforced Grant Controls</th>
                <th>State</th>
                <th>Baseline Matching Note</th>
              </tr>
            </thead>
            <tbody>
              {deployedPolicies.filter((p) => !p.baselineCode).length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-4 text-center text-xs text-slate-500">
                    All deployed Conditional Access policies strictly match the standard CA01 through CA10 naming baseline.
                  </td>
                </tr>
              ) : (
                deployedPolicies
                  .filter((p) => !p.baselineCode)
                  .map((pol) => (
                    <tr key={pol.id}>
                      <td className="font-semibold text-xs text-slate-900">{pol.name}</td>
                      <td className="text-[11px] font-mono text-slate-600">
                        {pol.grantControls.join(", ")}
                      </td>
                      <td>
                        <StatusPill status={pol.state} label={pol.state} size="sm" />
                      </td>
                      <td className="text-[11px] text-amber-700">
                        {pol.recommendation || "Non-standard policy name. Recommend renaming or consolidating into CA01-CA10."}
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
