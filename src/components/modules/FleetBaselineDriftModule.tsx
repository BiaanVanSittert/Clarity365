import React, { useState, useMemo, useEffect } from "react";
import { TenantSecuritySnapshot, FleetDriftSummary, TenantDriftFinding } from "@/lib/types";
import { evaluateFleetDrift, DEFAULT_GOLDEN_BASELINE } from "@/lib/services/drift-analyzer";
import {
  Compass,
  TrendingDown,
  CheckCircle2,
  AlertTriangle,
  Download,
  Search,
  RefreshCw,
  Zap,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  ChevronRight,
  Sliders,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";
import { ChangeConfirmationModal, ChangeItemSummary } from "../modals/ChangeConfirmationModal";

interface FleetBaselineDriftModuleProps {
  snapshots: TenantSecuritySnapshot[];
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
  onRefresh?: () => void;
}

export const FleetBaselineDriftModule: React.FC<FleetBaselineDriftModuleProps> = ({
  snapshots,
  onSelectTenant,
  onRefresh,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [tenantFilter, setTenantFilter] = useState("all");
  const [isRealigning, setIsRealigning] = useState(false);
  const [realignSuccess, setRealignSuccess] = useState<string | null>(null);
  const [realignError, setRealignError] = useState<string | null>(null);

  // Change Confirmation Modal State
  const [confirmModalData, setConfirmModalData] = useState<{
    isOpen: boolean;
    title: string;
    warningMessage?: string;
    findings: TenantDriftFinding[];
  }>({
    isOpen: false,
    title: "",
    findings: [],
  });

  // Compute fleet drift summary from snapshots
  const driftSummary: FleetDriftSummary = useMemo(() => {
    return evaluateFleetDrift(snapshots, DEFAULT_GOLDEN_BASELINE);
  }, [snapshots]);

  const { overallFleetAlignmentPercentage, inSyncCount, minorDriftCount, criticalDriftCount, allFindings, tenantAssessments } =
    driftSummary;

  const uniqueTenants = useMemo(() => {
    return tenantAssessments.map((t) => ({ id: t.tenantId, name: t.tenantName }));
  }, [tenantAssessments]);

  const filteredFindings = useMemo(() => {
    return allFindings.filter((f) => {
      const q = searchQuery.toLowerCase();
      if (
        q &&
        !f.tenantName.toLowerCase().includes(q) &&
        !f.ruleName.toLowerCase().includes(q) &&
        !f.ruleCode.toLowerCase().includes(q) &&
        !f.driftDescription.toLowerCase().includes(q)
      ) {
        return false;
      }
      if (severityFilter !== "all" && f.severity !== severityFilter) {
        return false;
      }
      if (tenantFilter !== "all" && f.tenantId !== tenantFilter) {
        return false;
      }
      return true;
    });
  }, [allFindings, searchQuery, severityFilter, tenantFilter]);

  const promptRealignFinding = (finding: TenantDriftFinding) => {
    setRealignError(null);
    setConfirmModalData({
      isOpen: true,
      title: `Confirm Baseline Realignment: ${finding.ruleCode} (${finding.tenantName})`,
      warningMessage: `You are about to realign policy '${finding.ruleCode}' on ${finding.tenantName} back to the MSP Golden Baseline. This change will be deployed in Audit / Report-Only mode first.`,
      findings: [finding],
    });
  };

  const promptRealignAllCritical = () => {
    const criticalFindings = allFindings.filter((f) => f.severity === "critical" && f.remediationSupported);
    if (criticalFindings.length === 0) return;

    setRealignError(null);
    setConfirmModalData({
      isOpen: true,
      title: `Confirm Fleet Realignment: ${criticalFindings.length} Critical Configuration Gaps`,
      warningMessage: `You are about to batch-realign ${criticalFindings.length} critical configuration drifts across multiple customer tenants. All missing policies will be created in Audit / Report-Only mode to avoid user disruption.`,
      findings: criticalFindings,
    });
  };

  const handleExecuteConfirmedRealign = async () => {
    const targetFindings = confirmModalData.findings;
    if (targetFindings.length === 0) return;

    setIsRealigning(true);
    setRealignError(null);
    setRealignSuccess(null);

    try {
      let count = 0;
      // Group by tenantId
      const tenantGroupMap = new Map<string, string[]>();
      for (const f of targetFindings) {
        const list = tenantGroupMap.get(f.tenantId) || [];
        list.push(f.id);
        tenantGroupMap.set(f.tenantId, list);
      }

      for (const [tenantId, findingIds] of tenantGroupMap.entries()) {
        const res = await fetch("/api/fleet/drift", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tenantId, findingIds }),
        });
        const data = await res.json();
        if (data.success) {
          count += data.realignedCount || 0;
        } else {
          throw new Error(data.error || "Failed to realign tenant drift.");
        }
      }

      setRealignSuccess(
        `Successfully realigned ${count} configuration drift(s) across customer tenants in Audit / Report-Only Mode!`
      );
      setConfirmModalData({ isOpen: false, title: "", findings: [] });
      if (onRefresh) onRefresh();
    } catch (err: any) {
      setRealignError(err.message || "Failed to apply realignment changes.");
    } finally {
      setIsRealigning(false);
    }
  };

  const changesSummaryList: ChangeItemSummary[] = useMemo(() => {
    return confirmModalData.findings.map((f) => ({
      tenantName: f.tenantName,
      targetComponent: f.component.toUpperCase(),
      actionDescription: `${f.ruleCode}: ${f.ruleName} — ${f.remediationAction}`,
      beforeState: f.actualState,
      afterState: `${f.expectedState} (Report-Only)`,
      isReportOnly: true,
    }));
  }, [confirmModalData.findings]);

  const handleExportCsv = () => {
    const headers = [
      "Tenant Name",
      "Rule Code",
      "Rule Name",
      "Severity",
      "Expected Golden State",
      "Actual Tenant State",
      "Drift Details",
      "Remediation Guidance",
    ];
    const rows = filteredFindings.map((f) => [
      f.tenantName,
      f.ruleCode,
      f.ruleName,
      f.severity.toUpperCase(),
      f.expectedState,
      f.actualState,
      f.driftDescription,
      f.remediationAction,
    ]);

    exportToCsv(`clarity365-fleet-baseline-drift-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none font-sans">
      {/* Top Banner */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-slate-900 dark:bg-slate-800 text-white rounded-sm border border-slate-700">
              <Compass size={18} className="text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
                  Golden Security Baseline Drift Monitor
                </h1>
                <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 rounded-sm">
                  {overallFleetAlignmentPercentage}% Fleet Baseline Alignment
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Continuous compliance monitor comparing all tenant configurations against the MSP Golden Standard (CA01–CA10, external forwarding killswitches, mailbox audit logging).
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
            <span>Export Drift Audit (CSV)</span>
          </button>
          <button
            onClick={promptRealignAllCritical}
            disabled={isRealigning || allFindings.filter((f) => f.severity === "critical" && f.remediationSupported).length === 0}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs disabled:opacity-40"
          >
            {isRealigning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap size={13} className="text-amber-400" />}
            <span>Realign All Critical Drift</span>
          </button>
        </div>
      </div>

      {/* Success Notification */}
      {realignSuccess && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/70 border border-emerald-300 dark:border-emerald-800 text-emerald-950 dark:text-emerald-300 rounded-sm flex items-center gap-2 text-xs font-medium">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
          <span>{realignSuccess}</span>
        </div>
      )}

      {/* KPI Cards (Clickable Severity / Status Filters) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Overall Alignment */}
        <div
          onClick={() => setSeverityFilter("all")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            severityFilter === "all"
              ? "bg-emerald-100 dark:bg-emerald-950/70 border-emerald-500 ring-1 ring-emerald-500"
              : "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 hover:bg-emerald-100/60"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-emerald-900 dark:text-emerald-300 font-semibold uppercase tracking-wider text-[10px]">
            <span>Fleet Alignment</span>
            <ShieldCheck size={15} className="text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-950 dark:text-emerald-100 mt-1">
            {overallFleetAlignmentPercentage}%
          </div>
          <div className="text-[11px] text-emerald-800 dark:text-emerald-300 mt-0.5">
            {inSyncCount} of {tenantAssessments.length} tenants fully in sync
          </div>
        </div>

        {/* Critical Drift */}
        <div
          onClick={() => setSeverityFilter(severityFilter === "critical" ? "all" : "critical")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            severityFilter === "critical"
              ? "bg-rose-100 dark:bg-rose-950/70 border-rose-500 ring-1 ring-rose-500"
              : "bg-white dark:bg-slate-900/40 border-[#CBD5E1] dark:border-slate-700 hover:bg-rose-50/50 hover:border-rose-400"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>Critical Drift</span>
            <AlertTriangle size={15} className="text-rose-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-700 dark:text-rose-400 mt-1">
            {allFindings.filter((f) => f.severity === "critical").length} Findings
          </div>
          <div className="text-[11px] text-rose-700 dark:text-rose-400 mt-0.5">
            {criticalDriftCount} tenant(s) with disabled policies/forwarding
          </div>
        </div>

        {/* High Severity Drift */}
        <div
          onClick={() => setSeverityFilter(severityFilter === "high" ? "all" : "high")}
          className={`p-3 rounded-sm cursor-pointer transition-all border shadow-xs ${
            severityFilter === "high"
              ? "bg-amber-100 dark:bg-amber-950/70 border-amber-500 ring-1 ring-amber-500"
              : "bg-white dark:bg-slate-900/40 border-[#CBD5E1] dark:border-slate-700 hover:bg-amber-50/50 hover:border-amber-400"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>High Drift Gaps</span>
            <Sliders size={15} className="text-amber-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-700 dark:text-amber-400 mt-1">
            {allFindings.filter((f) => f.severity === "high").length} Findings
          </div>
          <div className="text-[11px] text-amber-700 dark:text-amber-400 mt-0.5">
            Missing baselines & un-audited mailboxes
          </div>
        </div>

        {/* In Sync Tenants */}
        <div
          onClick={() => setSeverityFilter("all")}
          className="p-3 bg-white dark:bg-slate-900/40 border border-[#CBD5E1] dark:border-slate-700 rounded-sm shadow-xs"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>In-Sync Tenants</span>
            <CheckCircle2 size={15} className="text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {inSyncCount} / {tenantAssessments.length}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            100% compliant with Golden Standard
          </div>
        </div>
      </div>

      {/* Drift Findings Table */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm overflow-hidden">
        {/* Table Filters */}
        <div className="p-3 border-b border-[#CBD5E1] dark:border-slate-700 bg-white/70 dark:bg-slate-900/60 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <div className="relative flex-1">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by rule, tenant, or drift description..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1 text-xs bg-[#F8FAFC] dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-500 font-sans placeholder:text-slate-400"
              />
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2.5 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200 font-semibold"
            >
              <option value="all">All Severities ({allFindings.length})</option>
              <option value="critical">Critical Severity ({allFindings.filter((f) => f.severity === "critical").length})</option>
              <option value="high">High Severity ({allFindings.filter((f) => f.severity === "high").length})</option>
              <option value="medium">Medium Severity ({allFindings.filter((f) => f.severity === "medium").length})</option>
              <option value="low">Low / Advisory ({allFindings.filter((f) => f.severity === "low").length})</option>
            </select>

            <select
              value={tenantFilter}
              onChange={(e) => setTenantFilter(e.target.value)}
              className="px-2.5 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
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
                <th className="py-2.5 px-3 whitespace-nowrap">Severity</th>
                <th className="py-2.5 px-3">Rule & Drift Issue</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Golden Standard vs Actual</th>
                <th className="py-2.5 px-3">Remediation Action</th>
                <th className="py-2.5 px-3 text-right whitespace-nowrap">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700/60 bg-white dark:bg-slate-900/30">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 dark:text-slate-400">
                    No configuration drifts match the current criteria. All systems aligned.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors group"
                  >
                    {/* Tenant */}
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onSelectTenant(finding.tenantId, "ca_baseline")}
                        className="font-bold text-slate-900 dark:text-slate-100 hover:underline text-left block"
                      >
                        {finding.tenantName}
                      </button>
                    </td>

                    {/* Severity Pill */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded-sm border whitespace-nowrap inline-flex items-center shrink-0 ${
                          finding.severity === "critical"
                            ? "bg-rose-50 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800"
                            : finding.severity === "high"
                            ? "bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800"
                            : finding.severity === "medium"
                            ? "bg-blue-50 dark:bg-blue-950 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-800"
                            : "bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700"
                        }`}
                      >
                        {finding.severity}
                      </span>
                    </td>

                    {/* Rule & Description */}
                    <td className="py-3 px-3 max-w-md">
                      <div className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5 font-mono text-xs">
                        <span>{finding.ruleCode}</span>
                        <span className="text-slate-400 font-sans font-normal">—</span>
                        <span className="font-sans">{finding.ruleName}</span>
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
                        {finding.driftDescription}
                      </div>
                    </td>

                    {/* Expected vs Actual Diff */}
                    <td className="py-3 px-3 font-mono text-[11px] whitespace-nowrap">
                      <div className="text-emerald-700 dark:text-emerald-400 font-medium">
                        Expected: {finding.expectedState}
                      </div>
                      <div className="text-rose-600 dark:text-rose-400 font-medium mt-0.5">
                        Actual: {finding.actualState}
                      </div>
                    </td>

                    {/* Remediation Action */}
                    <td className="py-3 px-3 text-xs text-slate-600 dark:text-slate-300 max-w-xs">
                      {finding.remediationAction}
                    </td>

                    {/* Action Button */}
                    <td className="py-3 px-3.5 text-right whitespace-nowrap">
                      {finding.remediationSupported ? (
                        <button
                          type="button"
                          onClick={() => promptRealignFinding(finding)}
                          disabled={isRealigning}
                          className="px-2.5 py-1 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 rounded-sm inline-flex items-center gap-1 transition-colors disabled:opacity-50"
                        >
                          <Zap size={12} className="text-amber-400" />
                          <span>Realign</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => onSelectTenant(finding.tenantId, "ca_baseline")}
                          className="px-2.5 py-1 text-xs font-semibold text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-sm inline-flex items-center gap-1 hover:bg-slate-50"
                        >
                          <span>Review</span>
                          <ChevronRight size={12} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pre-Change Confirmation & Audit Warning Modal */}
      <ChangeConfirmationModal
        isOpen={confirmModalData.isOpen}
        onClose={() => setConfirmModalData({ isOpen: false, title: "", findings: [] })}
        onConfirm={handleExecuteConfirmedRealign}
        title={confirmModalData.title}
        warningMessage={confirmModalData.warningMessage}
        isAuditMode={true}
        changes={changesSummaryList}
        confirmButtonText="Confirm & Deploy in Audit Mode"
        isExecuting={isRealigning}
        error={realignError}
      />
    </div>
  );
};
