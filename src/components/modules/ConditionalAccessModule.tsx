import React, { useState, useEffect, useRef } from "react";
import { TenantSecuritySnapshot, CAPolicyRule } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { CA_BASELINE_STANDARDS, CABaselinePolicyDefinition } from "@/lib/data/baseline-definitions";
import { DeployCaPolicyModal } from "../modals/DeployCaPolicyModal";
import { ShieldCheck, Lock, Terminal, Search, Filter, ShieldAlert, Code2, CheckCheck, RotateCcw, Key, Download, AlertTriangle } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { validateCaPolicyCompliance, matchCaBaselineCode } from "@/lib/services/ca-baseline-matcher";

interface ConditionalAccessModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
  onRefresh?: () => void;
  onNavigate?: (view: string) => void;
  highlightEntityId?: string | null;
  onClearHighlight?: () => void;
}

const STORAGE_KEY_PREFIX = "clarity365_alerts_cleared_";

export const ConditionalAccessModule: React.FC<ConditionalAccessModuleProps> = ({
  snapshot,
  onOpenRemediation,
  onRefresh,
  onNavigate,
  highlightEntityId,
  onClearHighlight,
}) => {
  const { conditionalAccess, tenant, capabilities } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [filterState, setFilterState] = useState<string>("all");
  const [deployModalPolicy, setDeployModalPolicy] = useState<CABaselinePolicyDefinition | null>(null);
  const [isAlertCleared, setIsAlertCleared] = useState(false);

  const highlightedRowRef = useRef<HTMLTableRowElement | null>(null);

  useEffect(() => {
    if (highlightEntityId && highlightedRowRef.current) {
      highlightedRowRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [highlightEntityId]);

  // Load alert clearance status
  useEffect(() => {
    try {
      const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenant.id}`);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.allCleared || parsed.modules?.ca_baseline) {
          setIsAlertCleared(true);
        }
      }
    } catch {
      // Fallback
    }
  }, [tenant.id]);

  const handleClearAlerts = () => {
    setIsAlertCleared(true);
    try {
      const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenant.id}`);
      const parsed = stored ? JSON.parse(stored) : { modules: {} };
      parsed.modules = { ...(parsed.modules || {}), ca_baseline: true };
      localStorage.setItem(`${STORAGE_KEY_PREFIX}${tenant.id}`, JSON.stringify(parsed));
      window.dispatchEvent(new Event("storage"));
    } catch {
      // Ignore
    }
  };

  const handleRestoreAlerts = () => {
    setIsAlertCleared(false);
    try {
      const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenant.id}`);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.modules) {
          delete parsed.modules.ca_baseline;
          parsed.allCleared = false;
        }
        localStorage.setItem(`${STORAGE_KEY_PREFIX}${tenant.id}`, JSON.stringify(parsed));
        window.dispatchEvent(new Event("storage"));
      }
    } catch {
      // Ignore
    }
  };

  const deployedPolicies = conditionalAccess.policies;
  const baselineDefinitions = CA_BASELINE_STANDARDS;

  // Check if tenant has Entra ID P2 (E5 native, EMS E5, or Entra ID P2 license)
  const hasEntraP2 = Boolean(
    capabilities?.some(
      (c) =>
        c.licensed &&
        (c.id === "cap-entra-p2" ||
          c.name.toLowerCase().includes("entra id p2") ||
          c.name.toLowerCase().includes("azure ad premium p2") ||
          c.name.toLowerCase().includes("identity protection"))
    ) ||
    tenant.tier === "M365_E5" ||
    (tenant.tier as string) === "Microsoft 365 E5" ||
    (tenant.tier as string) === "EMS_E5"
  );

  // Map deployed policies strictly by name AND verified properties
  const baselineMap = new Map<string, CAPolicyRule>();
  const misconfiguredMap = new Map<string, { policy: CAPolicyRule; missingProperties: string[] }>();

  deployedPolicies.forEach((p) => {
    let candidateCode = p.baselineCode || null;
    if (!candidateCode) {
      const match = p.name.match(/(?:CA|CA-|\bCA\s*)(0[1-9]|10|[1-9])\b/i);
      if (match) {
        const num = parseInt(match[1], 10);
        candidateCode = num < 10 ? `CA0${num}` : `CA${num}`;
      }
    }

    if (candidateCode) {
      const validation = validateCaPolicyCompliance(p, candidateCode);
      if (validation.isValid) {
        baselineMap.set(candidateCode, p);
      } else {
        misconfiguredMap.set(candidateCode, {
          policy: p,
          missingProperties: validation.missingProperties || ["Properties do not meet standard requirements"],
        });
      }
    } else {
      const matched = matchCaBaselineCode(p);
      if (matched && !baselineMap.has(matched)) {
        baselineMap.set(matched, p);
      }
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
    const misconfigured = misconfiguredMap.get(item.code);
    if (filterState === "all") return matchesSearch;
    if (filterState === "deployed") return matchesSearch && !!policy;
    if (filterState === "missing") return matchesSearch && !policy;
    if (filterState === "report_only") return matchesSearch && policy?.state === "enabledForReportingButNotEnforced";
    if (filterState === "misconfigured") return matchesSearch && !!misconfigured;
    return matchesSearch;
  });

  const customPolicies = deployedPolicies.filter((p) => {
    const isMatched = Array.from(baselineMap.values()).some((bp) => bp.id === p.id);
    return !isMatched;
  });

  const handleExportBaselineCSV = () => {
    const headers = ["Code", "BaselineStandard", "TargetScope", "DeployedPolicyName", "DeployedState", "Status"];
    const rows = filteredBaseline.map((baseline) => {
      const policy = baselineMap.get(baseline.code);
      const isEnabled = policy?.state === "enabled";
      const isReportOnly = policy?.state === "enabledForReportingButNotEnforced";
      return [
        baseline.code,
        baseline.name,
        baseline.targetScope,
        policy?.name || "",
        policy?.state || "Not Deployed",
        isEnabled ? "Pass" : isReportOnly ? "Report-Only" : "Missing",
      ];
    });
    exportToCsv(csvFilename("CaBaseline", tenant.defaultDomainName), headers, rows);
  };

  const handleExportCustomPoliciesCSV = () => {
    const headers = ["PolicyDisplayName", "GrantControls", "State"];
    const rows = customPolicies.map((pol) => [
      pol.name,
      pol.grantControls.length > 0 ? pol.grantControls.join(", ") : "None / Block",
      pol.state,
    ]);
    exportToCsv(csvFilename("CaCustomPolicies", tenant.defaultDomainName), headers, rows);
  };

  return (
    <div
      className="p-5 space-y-4 max-w-[1600px] mx-auto select-none"
      onClick={() => {
        if (highlightEntityId && onClearHighlight) {
          onClearHighlight();
        }
      }}
    >
      {/* Header & Coverage Summary */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Lock size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 1: Conditional Access Policy Baseline Scanner (CA01–CA10)
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Strict verification against the CIS Microsoft 365 Foundations & Zero-Trust standard baseline (CA01 through CA10).
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="text-right">
            <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">Baseline Compliance</div>
            <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums">
              {coveragePercent}% ({baselineDefinitions.length - missingBaselineCount}/{baselineDefinitions.length})
            </div>
          </div>

          {/* Alert Dismissal Button */}
          {isAlertCleared ? (
            <button
              onClick={handleRestoreAlerts}
              title="Restore baseline warning badge on sidebar"
              className="px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
            >
              <RotateCcw size={13} className="text-slate-500 dark:text-slate-400" />
              <span>Restore Badge</span>
            </button>
          ) : (
            <button
              onClick={handleClearAlerts}
              title="Acknowledge baseline warnings and clear the sidebar number badge"
              className="px-2.5 py-1.5 text-xs font-medium text-emerald-800 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950 hover:bg-emerald-100 dark:hover:bg-emerald-900 border border-emerald-300 dark:border-emerald-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
            >
              <CheckCheck size={14} className="text-emerald-600 dark:text-emerald-400" />
              <span>Mark Reviewed (Clear Alert)</span>
            </button>
          )}

          {onNavigate && (
            <button
              onClick={() => onNavigate("signin_logs")}
              title="Inspect real-time Sign-in logs evaluating these CA policies"
              className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
            >
              <Key size={13} className="text-slate-600 dark:text-slate-400" />
              <span>View Sign-In Logs</span>
            </button>
          )}

          <button
            onClick={() => onOpenRemediation("conditional_access")}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Terminal size={14} className="text-emerald-400" />
            <span>Generate Remediation Script</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search baseline standards or policies..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 dark:text-slate-400" />
          <select
            value={filterState}
            onChange={(e) => setFilterState(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          >
            <option value="all">All Standards (CA01 - CA10)</option>
            <option value="deployed">Deployed Only</option>
            <option value="missing">Missing Baseline (Warnings)</option>
            <option value="report_only">Report-Only Mode</option>
          </select>

          <button
            onClick={handleExportBaselineCSV}
            title="Export filtered baseline standards to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* CA Baseline Audit Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Standard Baseline Specification & Deployed Policy Alignment
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
            {filteredBaseline.length} Standards Shown
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-16">Code</th>
                <th className="w-64">Baseline Standard</th>
                <th>Target Scope & Conditions</th>
                <th>Risk Mitigated</th>
                <th className="w-44">Deployed Policy State</th>
                <th className="w-24">Status</th>
                <th className="w-40 text-right">Deployment Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredBaseline.map((baseline) => {
                const policy = baselineMap.get(baseline.code);
                const misconfigured = misconfiguredMap.get(baseline.code);
                const isDeployed = !!policy;
                const isMisconfigured = !isDeployed && !!misconfigured;
                const isEnabled = policy?.state === "enabled";
                const isReportOnly = policy?.state === "enabledForReportingButNotEnforced";

                const isHighlighted =
                  Boolean(highlightEntityId) &&
                  (highlightEntityId === baseline.code ||
                    highlightEntityId?.toLowerCase() === baseline.name.toLowerCase() ||
                    (policy && (highlightEntityId === policy.id || highlightEntityId?.toLowerCase() === policy.name.toLowerCase())) ||
                    (misconfigured && (highlightEntityId === misconfigured.policy.id || highlightEntityId?.toLowerCase() === misconfigured.policy.name.toLowerCase())));

                return (
                  <tr
                    key={baseline.code}
                    ref={isHighlighted ? highlightedRowRef : null}
                    className={`transition-colors ${
                      isHighlighted
                        ? "animate-slow-flash"
                        : isMisconfigured
                        ? "bg-rose-50/20 dark:bg-rose-950/20 hover:bg-rose-50/40 dark:hover:bg-rose-950/40"
                        : !isDeployed
                        ? "bg-amber-50/20 dark:bg-amber-950/20 hover:bg-amber-50/40 dark:hover:bg-amber-950/40"
                        : "hover:bg-slate-50 dark:hover:bg-slate-800/60"
                    }`}
                  >
                    <td className="font-mono font-bold text-slate-900 dark:text-slate-100 text-xs">
                      {baseline.code}
                    </td>
                    <td>
                      <div className="font-semibold text-slate-900 dark:text-slate-100 text-xs flex items-center gap-1.5 flex-wrap">
                        <span>{baseline.name}</span>
                        {baseline.requiresEntraP2 && (
                          hasEntraP2 ? (
                            <span
                              title="Microsoft Entra ID Plan 2 is active for this tenant. Risk-based policy can be implemented."
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-700 text-emerald-800 dark:text-emerald-300 text-[10px] font-bold rounded-sm whitespace-nowrap shadow-2xs"
                            >
                              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                              <span>Entra ID P2 Licensed (Ready to Implement)</span>
                            </span>
                          ) : (
                            <span
                              title="Requires Microsoft Entra ID Plan 2 license. Upgrade tenant license to enable."
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-rose-50 dark:bg-rose-950/60 border border-rose-300 dark:border-rose-700 text-rose-800 dark:text-rose-300 text-[10px] font-bold rounded-sm whitespace-nowrap shadow-2xs"
                            >
                              <ShieldAlert className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400 shrink-0" />
                              <span>Requires Entra ID Plan 2</span>
                            </span>
                          )
                        )}
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{baseline.description}</div>
                      {baseline.requiresEntraP2 && !hasEntraP2 && (
                        <div className="text-[11px] text-rose-900 dark:text-rose-200 mt-1.5 p-2 bg-rose-50/90 dark:bg-rose-950/50 border border-rose-300 dark:border-rose-800 rounded-sm flex items-start gap-1.5 shadow-2xs">
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                          <div>
                            <span className="font-bold">License Requirement (Entra ID P2): </span>
                            <span>
                              This risk-based policy ({baseline.code}) requires a Microsoft Entra ID Plan 2 (or Microsoft 365 E5) license. If you would like this policy implemented, obtain an Entra ID Plan 2 license for this organization.
                            </span>
                          </div>
                        </div>
                      )}
                    </td>
                    <td className="text-[11px] text-slate-600 dark:text-slate-400 font-mono">
                      {baseline.targetScope}
                    </td>
                    <td className="text-[11px] text-slate-600 dark:text-slate-400">
                      {baseline.riskMitigated}
                    </td>
                    <td>
                      {isDeployed ? (
                        <div className="space-y-0.5">
                          <div className="text-[11px] font-mono text-slate-800 dark:text-slate-200 font-semibold truncate max-w-[180px]" title={policy.name}>
                            {policy.name}
                          </div>
                          <StatusPill
                            status={isEnabled ? "pass" : isReportOnly ? "warn" : "disabled"}
                            label={isEnabled ? "On (Enabled)" : isReportOnly ? "Report-Only" : "Disabled"}
                            size="sm"
                          />
                        </div>
                      ) : isMisconfigured ? (
                        <div className="space-y-1">
                          <div className="text-[11px] font-mono text-rose-900 dark:text-rose-200 font-semibold truncate max-w-[180px]" title={misconfigured.policy.name}>
                            {misconfigured.policy.name}
                          </div>
                          <div className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-rose-50 dark:bg-rose-950/70 border border-rose-300 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-[10px] font-bold rounded-sm">
                            <AlertTriangle size={11} className="text-rose-600 dark:text-rose-400" />
                            <span>Misconfigured</span>
                          </div>
                          <div className="text-[10px] text-rose-600 dark:text-rose-400 leading-tight">
                            Missing: {misconfigured.missingProperties.join("; ")}
                          </div>
                        </div>
                      ) : (
                        <span className="text-[11px] text-amber-700 dark:text-amber-400 font-medium italic">
                          Not Deployed
                        </span>
                      )}
                    </td>
                    <td>
                      {isDeployed && isEnabled ? (
                        <StatusPill status="pass" label="Pass" size="sm" />
                      ) : isDeployed && isReportOnly ? (
                        <StatusPill status="warn" label="Report-Only" size="sm" />
                      ) : isMisconfigured ? (
                        <StatusPill status="fail" label="Invalid Props" size="sm" />
                      ) : (
                        <StatusPill status="fail" label="Missing" size="sm" />
                      )}
                    </td>
                    <td className="text-right">
                      <button
                        onClick={() => setDeployModalPolicy(baseline)}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-sm transition-colors border ${
                          isDeployed && isEnabled
                            ? "bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
                            : "bg-slate-900 border-slate-900 dark:border-slate-100 text-white hover:bg-slate-800"
                        }`}
                      >
                        <Code2 size={12} className={isDeployed && isEnabled ? "text-slate-500 dark:text-slate-400" : "text-emerald-400"} />
                        <span>{isDeployed ? "View Command" : isMisconfigured ? "Reconfigure Policy" : "Deploy (Report-Only)"}</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Custom & Non-Baseline Policies Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Tenant Custom / Legacy Conditional Access Policies
          </h3>
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
              {customPolicies.length} Policies Detected
            </span>
            <button
              onClick={handleExportCustomPoliciesCSV}
              title="Export custom policies to CSV"
              className="px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1 transition-colors"
            >
              <Download size={12} className="text-slate-500 dark:text-slate-400" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Policy Display Name</th>
                <th>Enforced Grant Controls</th>
                <th>State</th>
                <th>Baseline Matching Status</th>
              </tr>
            </thead>
            <tbody>
              {customPolicies.length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-4 text-center text-xs text-slate-500 dark:text-slate-400">
                    All deployed Conditional Access policies strictly match the standard CA01 through CA10 naming baseline.
                  </td>
                </tr>
              ) : (
                customPolicies
                  .map((pol) => (
                    <tr key={pol.id}>
                      <td className="font-semibold text-xs text-slate-900 dark:text-slate-100">{pol.name}</td>
                      <td className="text-[11px] font-mono text-slate-600 dark:text-slate-400">
                        {pol.grantControls.length > 0 ? pol.grantControls.join(", ") : "None / Block"}
                      </td>
                      <td>
                        <StatusPill status={pol.state} label={pol.state} size="sm" />
                      </td>
                      <td className="text-[11px] text-slate-600 dark:text-slate-400">
                        Custom policy. Recommend validating scope against standard CA01–CA10 controls.
                      </td>
                    </tr>
                  ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deploy CA Policy Modal */}
      <DeployCaPolicyModal
        isOpen={!!deployModalPolicy}
        onClose={() => setDeployModalPolicy(null)}
        policy={deployModalPolicy}
        tenantId={tenant.id}
        tenantName={tenant.displayName}
        tenantDomain={tenant.defaultDomainName}
        hasEntraP2={hasEntraP2}
        onPolicyDeployed={onRefresh}
      />
    </div>
  );
};
